use super::*;

impl<'a> RuleManager<'a> {
    pub(super) fn append_cnip_force_proxy_local_rules(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        action: ProxyAction,
        context: &RuleContext,
    ) -> Result<()> {
        if !self.config.bypass_cn_ip
            || context.cnip_force_uids.is_empty()
            || !self.cnip_matcher_enabled_for_family(family)
        {
            return Ok(());
        }

        if self.cnip_uses_ebpf() {
            match action {
                ProxyAction::Redirect => {
                    if self.config.proxy_tcp {
                        if let Some(args) =
                            self.cnip_force_match_args(family, vec!["-p".into(), "tcp".into()])
                        {
                            self.append_redirect_dispatch_rule(family, chain, args)?;
                        }
                    }
                }
                ProxyAction::Mark => {
                    self.append_cnip_mark_rules(family, table, chain, |proto| {
                        self.cnip_force_match_args(family, vec!["-p".into(), proto.into()])
                    })?;
                }
                ProxyAction::Tproxy => {}
            }
            return Ok(());
        }

        for uid in &context.cnip_force_uids {
            if uid.is_empty() {
                continue;
            }
            match action {
                ProxyAction::Redirect => {
                    if self.config.proxy_tcp {
                        let Some(args) = self.cnip_match_args(
                            family,
                            chain,
                            vec![
                                "-p".into(),
                                "tcp".into(),
                                "-m".into(),
                                "owner".into(),
                                "--uid-owner".into(),
                                uid.clone(),
                            ],
                        ) else {
                            continue;
                        };
                        self.append_redirect_dispatch_rule(family, chain, args)?;
                    }
                }
                ProxyAction::Mark => {
                    self.append_cnip_mark_rules(family, table, chain, |proto| {
                        self.cnip_match_args(
                            family,
                            chain,
                            vec![
                                "-p".into(),
                                proto.into(),
                                "-m".into(),
                                "owner".into(),
                                "--uid-owner".into(),
                                uid.clone(),
                            ],
                        )
                    })?;
                }
                ProxyAction::Tproxy => {}
            }
        }
        Ok(())
    }

    fn append_cnip_mark_rules(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        mut base_for_proto: impl FnMut(&str) -> Option<Vec<String>>,
    ) -> Result<()> {
        for proto in ["tcp", "udp"] {
            if proto == "tcp" && (self.config.network_mode == "enhance" || !self.config.proxy_tcp) {
                continue;
            }
            if proto == "udp" && !self.config.proxy_udp {
                continue;
            }
            let Some(base) = base_for_proto(proto) else {
                continue;
            };
            let mut mark = base.clone();
            mark.extend([
                "-j".into(),
                "MARK".into(),
                "--set-xmark".into(),
                FWMARK.into(),
            ]);
            self.ensure_rule_append_owned(family, table, chain, mark)?;
            let mut ret = base;
            ret.extend(["-j".into(), "RETURN".into()]);
            self.ensure_rule_append_owned(family, table, chain, ret)?;
        }
        Ok(())
    }

    pub(super) fn apply_local_proxy_rules(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        action: ProxyAction,
        context: &RuleContext,
    ) -> Result<()> {
        let uid_ebpf = self.app_uid_ebpf_active(family, context);
        match self.config.proxy_mode.as_str() {
            "core" => {
                self.append_local_protocol_rule(family, table, chain, "tcp", action, None)?;
                self.append_local_protocol_rule(family, table, chain, "udp", action, None)?;
            }
            "blacklist" | "black" => {
                if uid_ebpf {
                    let mut args = self.app_uid_match_args(family, Vec::new());
                    args.extend(["-j".into(), "RETURN".into()]);
                    self.ensure_rule_append_owned(family, table, chain, args)?;
                } else {
                    for uid in &context.selected_uids {
                        self.ensure_rule_append_owned(
                            family,
                            table,
                            chain,
                            vec![
                                "-m".into(),
                                "owner".into(),
                                "--uid-owner".into(),
                                uid.clone(),
                                "-j".into(),
                                "RETURN".into(),
                            ],
                        )?;
                    }
                }
                for gid in &context.selected_gids {
                    self.ensure_rule_append_owned(
                        family,
                        table,
                        chain,
                        vec![
                            "-m".into(),
                            "owner".into(),
                            "--gid-owner".into(),
                            gid.clone(),
                            "-j".into(),
                            "RETURN".into(),
                        ],
                    )?;
                }
                self.append_local_protocol_rule(family, table, chain, "tcp", action, None)?;
                self.append_local_protocol_rule(family, table, chain, "udp", action, None)?;
            }
            "whitelist" | "white" => {
                if context.selected_uids.is_empty() && context.selected_gids.is_empty() {
                    self.append_local_protocol_rule(family, table, chain, "tcp", action, None)?;
                    self.append_local_protocol_rule(family, table, chain, "udp", action, None)?;
                    return Ok(());
                }

                if uid_ebpf {
                    self.append_local_protocol_bpf_rule(family, table, chain, "tcp", action)?;
                    self.append_local_protocol_bpf_rule(family, table, chain, "udp", action)?;
                } else {
                    for uid in &context.selected_uids {
                        self.append_local_protocol_rule(
                            family,
                            table,
                            chain,
                            "tcp",
                            action,
                            Some(("uid-owner", uid.as_str())),
                        )?;
                        self.append_local_protocol_rule(
                            family,
                            table,
                            chain,
                            "udp",
                            action,
                            Some(("uid-owner", uid.as_str())),
                        )?;
                    }
                }
                for uid in ["0", "1052"] {
                    self.append_local_protocol_rule(
                        family,
                        table,
                        chain,
                        "tcp",
                        action,
                        Some(("uid-owner", uid)),
                    )?;
                    self.append_local_protocol_rule(
                        family,
                        table,
                        chain,
                        "udp",
                        action,
                        Some(("uid-owner", uid)),
                    )?;
                }
                for gid in &context.selected_gids {
                    self.append_local_protocol_rule(
                        family,
                        table,
                        chain,
                        "tcp",
                        action,
                        Some(("gid-owner", gid.as_str())),
                    )?;
                    self.append_local_protocol_rule(
                        family,
                        table,
                        chain,
                        "udp",
                        action,
                        Some(("gid-owner", gid.as_str())),
                    )?;
                }
            }
            _ => {
                logger::warn_key(
                    self.config,
                    LogKey::ProxyModeInvalid,
                    &[arg("mode", &self.config.proxy_mode)],
                );
                self.append_local_protocol_rule(family, table, chain, "tcp", action, None)?;
                self.append_local_protocol_rule(family, table, chain, "udp", action, None)?;
            }
        }
        Ok(())
    }

    pub(super) fn append_local_protocol_rule(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        proto: &str,
        action: ProxyAction,
        owner: Option<(&str, &str)>,
    ) -> Result<()> {
        if proto == "tcp" && !self.config.proxy_tcp {
            return Ok(());
        }
        if proto == "udp" && !self.config.proxy_udp {
            return Ok(());
        }

        let mut args = vec!["-p".to_string(), proto.to_string()];
        if let Some((kind, value)) = owner {
            args.extend([
                "-m".to_string(),
                "owner".to_string(),
                format!("--{kind}"),
                value.to_string(),
            ]);
        }

        match action {
            ProxyAction::Redirect => {
                if proto != "tcp" {
                    return Ok(());
                }
                self.append_redirect_dispatch_rule(family, chain, args)
            }
            ProxyAction::Mark => {
                if proto == "tcp" && self.config.network_mode == "enhance" {
                    return Ok(());
                }
                args.extend([
                    "-j".into(),
                    "MARK".into(),
                    "--set-xmark".into(),
                    FWMARK.into(),
                ]);
                self.ensure_rule_append_owned(family, table, chain, args)
            }
            ProxyAction::Tproxy => Ok(()),
        }
    }

    pub(super) fn append_local_protocol_bpf_rule(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        proto: &str,
        action: ProxyAction,
    ) -> Result<()> {
        if proto == "tcp" && !self.config.proxy_tcp {
            return Ok(());
        }
        if proto == "udp" && !self.config.proxy_udp {
            return Ok(());
        }

        let args = self.app_uid_match_args(family, vec!["-p".to_string(), proto.to_string()]);
        match action {
            ProxyAction::Redirect => {
                if proto != "tcp" {
                    return Ok(());
                }
                self.append_redirect_dispatch_rule(family, chain, args)
            }
            ProxyAction::Mark => {
                if proto == "tcp" && self.config.network_mode == "enhance" {
                    return Ok(());
                }
                let mut args = args;
                args.extend([
                    "-j".into(),
                    "MARK".into(),
                    "--set-xmark".into(),
                    FWMARK.into(),
                ]);
                self.ensure_rule_append_owned(family, table, chain, args)
            }
            ProxyAction::Tproxy => Ok(()),
        }
    }

    pub(super) fn append_redirect_dispatch_rule(
        &self,
        family: Family,
        chain: &str,
        mut args: Vec<String>,
    ) -> Result<()> {
        args.extend([
            "-j".into(),
            "REDIRECT".into(),
            "--to-ports".into(),
            self.config.redir_port.clone(),
        ]);
        self.ensure_rule_append_owned(family, "nat", chain, args)
    }

    pub(super) fn append_tproxy_dispatch_rule(
        &self,
        family: Family,
        chain: &str,
        mut args: Vec<String>,
    ) -> Result<()> {
        args.extend([
            "-j".into(),
            "TPROXY".into(),
            "--on-port".into(),
            self.config.tproxy_port.clone(),
            "--tproxy-mark".into(),
            FWMARK.into(),
        ]);
        self.ensure_rule_append_owned(family, "mangle", chain, args)
    }
}
