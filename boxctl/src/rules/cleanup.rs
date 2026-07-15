use super::*;

impl<'a> RuleManager<'a> {
    pub(super) fn cleanup_iptables_for_mode(&self, mode: &str) {
        for family in [Family::V4, Family::V6] {
            self.cleanup_iptables_family(family, mode);
        }
    }

    pub(super) fn cleanup_mode_for_clear(&self) -> String {
        match self.runtime_env_value("network_mode") {
            Some(mode)
                if matches!(
                    mode.as_str(),
                    "redirect" | "tproxy" | "mixed" | "enhance" | "tun"
                ) =>
            {
                mode
            }
            _ => "all".to_string(),
        }
    }

    pub(super) fn cleanup_mode_for_apply(&self) -> String {
        let Some(old_mode) = self.runtime_env_value("network_mode") else {
            return if self.has_existing_box_rules() {
                "all".to_string()
            } else {
                "none".to_string()
            };
        };
        if old_mode.is_empty() {
            return "all".to_string();
        }

        let checks = [
            ("bin_name", self.config.bin_name.as_str()),
            ("ipv6_mode", self.config.ipv6_mode.as_str()),
            ("dns_hijack_mode", self.config.dns_hijack_mode.as_str()),
            ("tproxy_port", self.config.tproxy_port.as_str()),
            ("redir_port", self.config.redir_port.as_str()),
            ("tun_device", self.config.tun_device.as_str()),
        ];

        if checks.iter().any(|(key, expected)| {
            self.runtime_env_value(key)
                .map(|value| value != *expected)
                .unwrap_or(true)
        }) {
            "all".to_string()
        } else if old_mode == self.config.network_mode {
            old_mode
        } else {
            "all".to_string()
        }
    }

    pub(super) fn cleanup_iptables_family(&self, family: Family, mode: &str) {
        match mode {
            "none" => return,
            "redirect" => self.stop_redirect(family),
            "tproxy" => self.stop_tproxy(family),
            "enhance" => {
                self.stop_redirect(family);
                self.stop_tproxy(family);
            }
            "mixed" => {
                self.stop_redirect(family);
                self.forward(family, false).ok();
            }
            "tun" => {
                self.stop_tun_bypass(family);
                self.forward(family, false).ok();
            }
            _ => {
                self.stop_redirect(family);
                self.stop_tproxy(family);
                self.stop_tun_bypass(family);
                self.forward(family, false).ok();
            }
        }
        if family == Family::V6 {
            self.cleanup_ipv6_dns_fallback();
            self.del_rule(
                family,
                "filter",
                "OUTPUT",
                &["-p", "udp", "--destination-port", "53", "-j", "DROP"],
            );
        }
    }

    pub(super) fn has_existing_box_rules(&self) -> bool {
        [Family::V4, Family::V6].iter().any(|family| {
            ["nat", "mangle", "filter"]
                .iter()
                .any(|table| self.table_has_box_rules(*family, table))
        })
    }

    pub(super) fn table_has_box_rules(&self, family: Family, table: &str) -> bool {
        if self.runner.dry_run() {
            return true;
        }
        let args = strings(&["-t", table, "-S"]);
        self.runner
            .run(iptables_cmd(family), &args)
            .ok()
            .filter(|output| output.ok)
            .map(|output| output.stdout.lines().any(is_box_rule_line))
            .unwrap_or(false)
    }

    pub(super) fn cleanup_dns_nat_chains(&self, family: Family) {
        if family == Family::V6 && !self.probe_capabilities().ip6_nat {
            return;
        }
        for chain in [
            dns_pre_chain(family, DnsNatKind::Hijack),
            dns_out_chain(family, DnsNatKind::Hijack),
            dns_pre_chain(family, DnsNatKind::Forward),
            dns_out_chain(family, DnsNatKind::Forward),
        ] {
            self.del_jump(family, "nat", "PREROUTING", chain);
            self.del_jump(family, "nat", "OUTPUT", chain);
            self.cleanup_chain_fast(family, "nat", chain);
        }
    }

    pub(super) fn cleanup_perf_chains(&self, family: Family, table: &str, chains: &[&str]) {
        for chain in chains {
            self.cleanup_chain_fast(family, table, chain);
        }
    }
}
