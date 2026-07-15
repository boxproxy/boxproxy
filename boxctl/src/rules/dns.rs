use super::*;

impl<'a> RuleManager<'a> {
    pub(super) fn dns_mode_is_redirect(&self) -> bool {
        self.config.dns_hijack_mode == "redirect"
    }

    pub(super) fn dns_mode_is_disable(&self) -> bool {
        self.config.dns_hijack_mode == "disable"
    }

    pub(super) fn dns_tcp_enabled(&self) -> bool {
        self.config.dns_hijack_tcp
    }

    pub(super) fn dns_udp_enabled(&self) -> bool {
        self.config.dns_hijack_udp
    }

    pub(super) fn dns_should_use_mihomo_forward(&self) -> bool {
        self.config.mihomo_dns_forward == "enable"
            && self.config.bin_name == "mihomo"
            && !self.dns_mode_is_redirect()
            && !self.dns_mode_is_disable()
    }

    pub(super) fn dns_target_port(&self) -> String {
        let port = self.config.mihomo_dns_port.trim();
        if port.is_empty() {
            "1053".to_string()
        } else {
            port.to_string()
        }
    }

    pub(super) fn ensure_dns_nat_hijack(
        &self,
        family: Family,
        context: &RuleContext,
    ) -> Result<()> {
        if !self.dns_mode_is_redirect() && !self.dns_should_use_mihomo_forward() {
            return Ok(());
        }
        if family == Family::V6 && !self.probe_capabilities().ip6_nat {
            logger::warn_key(
                self.config,
                LogKey::Ip6NatUnavailable,
                &[logger::nat_target_arg("target", "DNS redirect")],
            );
            return self.setup_ipv6_dns_fallback(context);
        }

        let kind = if self.dns_mode_is_redirect() {
            DnsNatKind::Hijack
        } else {
            DnsNatKind::Forward
        };
        self.setup_nat_dns_chain(family, kind, context)
    }

    pub(super) fn setup_ipv6_dns_fallback(&self, context: &RuleContext) -> Result<()> {
        self.ensure_chain(Family::V6, "filter", IPV6_DNS_FALLBACK_CHAIN)?;
        if !self.add_core_bypass_rule(Family::V6, "filter", IPV6_DNS_FALLBACK_CHAIN, "-A", context)
        {
            self.cleanup_ipv6_dns_fallback();
            logger::warn_key(
                self.config,
                LogKey::DnsCoreBypassFailed,
                &[logger::dns_nat_target_arg("target", "IPv6 fallback")],
            );
            return Ok(());
        }

        let mut protocols = Vec::new();
        if self.dns_tcp_enabled() {
            self.ensure_rule_append(
                Family::V6,
                "filter",
                IPV6_DNS_FALLBACK_CHAIN,
                &["-p", "tcp", "--dport", "53", "-j", "REJECT"],
            )?;
            protocols.push("TCP");
        }
        if self.dns_udp_enabled() {
            self.ensure_rule_append(
                Family::V6,
                "filter",
                IPV6_DNS_FALLBACK_CHAIN,
                &["-p", "udp", "--dport", "53", "-j", "REJECT"],
            )?;
            protocols.push("UDP");
        }
        if protocols.is_empty() {
            self.cleanup_ipv6_dns_fallback();
            return Ok(());
        }

        self.ensure_jump(Family::V6, "filter", "OUTPUT", IPV6_DNS_FALLBACK_CHAIN)?;
        logger::info_key(
            self.config,
            LogKey::Ipv6DnsFallbackApplied,
            &[arg("protocols", protocols.join("/"))],
        );
        Ok(())
    }

    pub(super) fn cleanup_ipv6_dns_fallback(&self) {
        self.del_jump(Family::V6, "filter", "OUTPUT", IPV6_DNS_FALLBACK_CHAIN);
        self.cleanup_chain_fast(Family::V6, "filter", IPV6_DNS_FALLBACK_CHAIN);
    }

    pub(super) fn setup_nat_dns_chain(
        &self,
        family: Family,
        kind: DnsNatKind,
        context: &RuleContext,
    ) -> Result<()> {
        if kind == DnsNatKind::Forward {
            return self.setup_nat_dns_forward_chain(family, context);
        }

        let pre_chain = dns_pre_chain(family, kind);
        let out_chain = dns_out_chain(family, kind);
        let port = self.dns_target_port();

        self.ensure_chain(family, "nat", pre_chain)?;
        self.ensure_chain(family, "nat", out_chain)?;

        self.append_dns_nat_rules(family, pre_chain, kind, &port, true)?;
        if !self.add_core_bypass_rule(family, "nat", out_chain, "-I", context)
            && family == Family::V4
        {
            logger::warn_key(
                self.config,
                LogKey::DnsCoreBypassFailed,
                &[dns_target_arg(kind)],
            );
        }
        self.append_dns_nat_rules(family, out_chain, kind, &port, false)?;

        self.ensure_jump(family, "nat", "PREROUTING", pre_chain)?;
        self.ensure_jump(family, "nat", "OUTPUT", out_chain)
    }

    pub(super) fn setup_nat_dns_forward_chain(
        &self,
        family: Family,
        context: &RuleContext,
    ) -> Result<()> {
        let chain = dns_pre_chain(family, DnsNatKind::Forward);
        let port = self.dns_target_port();

        self.ensure_chain(family, "nat", chain)?;
        if !self.add_core_bypass_rule(family, "nat", chain, "-I", context) && family == Family::V4 {
            logger::warn_key(
                self.config,
                LogKey::DnsCoreBypassFailed,
                &[dns_target_arg(DnsNatKind::Forward)],
            );
        }
        self.append_dns_nat_rules(family, chain, DnsNatKind::Forward, &port, true)?;
        self.ensure_jump(family, "nat", "OUTPUT", chain)
    }

    pub(super) fn append_dns_nat_rules(
        &self,
        family: Family,
        chain: &str,
        kind: DnsNatKind,
        port: &str,
        inbound: bool,
    ) -> Result<()> {
        if inbound && family == Family::V4 {
            for iface in &self.config.blocked_interfaces {
                self.ensure_rule_append_owned(
                    family,
                    "nat",
                    chain,
                    vec!["-i".into(), iface.clone(), "-j".into(), "RETURN".into()],
                )?;
            }
        }

        match kind {
            DnsNatKind::Hijack => {
                if self.dns_tcp_enabled() {
                    self.ensure_rule_append(
                        family,
                        "nat",
                        chain,
                        &[
                            "-p",
                            "tcp",
                            "--dport",
                            "53",
                            "-j",
                            "REDIRECT",
                            "--to-ports",
                            port,
                        ],
                    )?;
                }
                if self.dns_udp_enabled() {
                    self.ensure_rule_append(
                        family,
                        "nat",
                        chain,
                        &[
                            "-p",
                            "udp",
                            "--dport",
                            "53",
                            "-j",
                            "REDIRECT",
                            "--to-ports",
                            port,
                        ],
                    )?;
                }
            }
            DnsNatKind::Forward => {
                if self.dns_udp_enabled() {
                    self.ensure_rule_append(
                        family,
                        "nat",
                        chain,
                        &[
                            "-p",
                            "udp",
                            "--dport",
                            "53",
                            "-j",
                            "REDIRECT",
                            "--to-ports",
                            port,
                        ],
                    )?;
                }
            }
        }
        Ok(())
    }

    pub(super) fn apply_mangle_dns_rules(
        &self,
        family: Family,
        chain: &str,
        action: ProxyAction,
    ) -> Result<()> {
        if self.dns_mode_is_redirect()
            || self.dns_mode_is_disable()
            || self.dns_should_use_mihomo_forward()
        {
            return self.append_dns_return_rules(family, chain);
        }

        match action {
            ProxyAction::Tproxy => self.append_dns_tproxy_rules(family, chain),
            ProxyAction::Mark => self.append_dns_mark_rules(family, chain),
            ProxyAction::Redirect => Ok(()),
        }
    }

    pub(super) fn append_dns_return_rules(&self, family: Family, chain: &str) -> Result<()> {
        if self.config.network_mode != "enhance" && self.dns_tcp_enabled() {
            self.ensure_rule_append(
                family,
                "mangle",
                chain,
                &["-p", "tcp", "--dport", "53", "-j", "RETURN"],
            )?;
        }
        if self.dns_udp_enabled() {
            self.ensure_rule_append(
                family,
                "mangle",
                chain,
                &["-p", "udp", "--dport", "53", "-j", "RETURN"],
            )?;
        }
        Ok(())
    }

    pub(super) fn append_dns_tproxy_rules(&self, family: Family, chain: &str) -> Result<()> {
        if self.config.network_mode != "enhance" && self.dns_tcp_enabled() && self.config.proxy_tcp
        {
            self.append_tproxy_dispatch_rule(
                family,
                chain,
                vec!["-p".into(), "tcp".into(), "--dport".into(), "53".into()],
            )?;
        }
        if self.dns_udp_enabled() && self.config.proxy_udp {
            self.append_tproxy_dispatch_rule(
                family,
                chain,
                vec!["-p".into(), "udp".into(), "--dport".into(), "53".into()],
            )?;
        }
        Ok(())
    }

    pub(super) fn append_dns_mark_rules(&self, family: Family, chain: &str) -> Result<()> {
        if self.config.network_mode != "enhance" && self.dns_tcp_enabled() && self.config.proxy_tcp
        {
            self.ensure_rule_append(
                family,
                "mangle",
                chain,
                &[
                    "-p",
                    "tcp",
                    "--dport",
                    "53",
                    "-j",
                    "MARK",
                    "--set-xmark",
                    FWMARK,
                ],
            )?;
        }
        if self.dns_udp_enabled() && self.config.proxy_udp {
            self.ensure_rule_append(
                family,
                "mangle",
                chain,
                &[
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "-j",
                    "MARK",
                    "--set-xmark",
                    FWMARK,
                ],
            )?;
        }
        Ok(())
    }
}
