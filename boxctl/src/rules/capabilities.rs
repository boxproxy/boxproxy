use super::*;

const CAP_CACHE_FILE: &str = "iptables.cap.cache";

impl<'a> RuleManager<'a> {
    pub(super) fn probe_capabilities(&self) -> &Capabilities {
        self.capabilities.get_or_init(|| {
            if self.runner.dry_run() {
                return self.probe_capabilities_raw();
            }
            if let Some(caps) = self.load_capability_cache() {
                return caps;
            }
            let caps = self.probe_capabilities_raw();
            self.save_capability_cache(&caps);
            caps
        })
    }

    fn capability_cache_path(&self) -> PathBuf {
        self.config.paths.state.join(CAP_CACHE_FILE)
    }

    fn capability_cache_signature(&self) -> Option<String> {
        let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
        let boot_id = boot_id.trim();
        if boot_id.is_empty() {
            return None;
        }
        Some(format!(
            "{boot_id}|cnip={}|ipv6={}",
            self.config.bypass_cn_ip as u8, self.config.ipv6 as u8
        ))
    }

    fn load_capability_cache(&self) -> Option<Capabilities> {
        let signature = self.capability_cache_signature()?;
        let text = fs::read_to_string(self.capability_cache_path()).ok()?;
        let mut fields = std::collections::HashMap::new();
        for line in text.lines() {
            if let Some((key, value)) = line.split_once('=') {
                fields.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
        if fields.get("signature").map(String::as_str) != Some(signature.as_str()) {
            return None;
        }
        let flag = |key: &str| -> Option<bool> {
            match fields.get(key).map(String::as_str)? {
                "1" => Some(true),
                "0" => Some(false),
                _ => None,
            }
        };
        Some(Capabilities {
            tproxy4: flag("tproxy4")?,
            tproxy6: flag("tproxy6")?,
            socket_match: flag("socket_match")?,
            socket_transparent: flag("socket_transparent")?,
            addrtype: flag("addrtype")?,
            conntrack_match: flag("conntrack_match")?,
            connmark_match: flag("connmark_match")?,
            connmark_target: flag("connmark_target")?,
            ipset: flag("ipset")?,
            bpf_match: flag("bpf_match")?,
            ip6_nat: flag("ip6_nat")?,
            restore4: flag("restore4")?,
            restore6: flag("restore6")?,
        })
    }

    fn save_capability_cache(&self, caps: &Capabilities) {
        let Some(signature) = self.capability_cache_signature() else {
            return;
        };
        let bit = |value: bool| if value { 1 } else { 0 };
        let body = format!(
            "signature={signature}\n\
             tproxy4={}\ntproxy6={}\nsocket_match={}\nsocket_transparent={}\n\
             addrtype={}\nconntrack_match={}\nconnmark_match={}\nconnmark_target={}\n\
             ipset={}\nbpf_match={}\nip6_nat={}\nrestore4={}\nrestore6={}\n",
            bit(caps.tproxy4),
            bit(caps.tproxy6),
            bit(caps.socket_match),
            bit(caps.socket_transparent),
            bit(caps.addrtype),
            bit(caps.conntrack_match),
            bit(caps.connmark_match),
            bit(caps.connmark_target),
            bit(caps.ipset),
            bit(caps.bpf_match),
            bit(caps.ip6_nat),
            bit(caps.restore4),
            bit(caps.restore6),
        );
        let _ = fs::create_dir_all(&self.config.paths.state);
        let _ = fs::write(self.capability_cache_path(), body);
    }

    pub(super) fn probe_capabilities_raw(&self) -> Capabilities {
        if self.runner.dry_run() {
            return Capabilities {
                tproxy4: true,
                tproxy6: true,
                socket_match: true,
                socket_transparent: true,
                addrtype: true,
                conntrack_match: true,
                connmark_match: true,
                connmark_target: true,
                ipset: true,
                bpf_match: true,
                ip6_nat: true,
                restore4: false,
                restore6: false,
            };
        }

        let mut caps = Capabilities {
            tproxy4: self.cap_has_target(Family::V4, "TPROXY"),
            tproxy6: self.cap_has_target(Family::V6, "TPROXY"),
            socket_match: self.cap_has_match(Family::V4, "socket")
                || self.cap_has_match(Family::V6, "socket"),
            addrtype: self.cap_has_match(Family::V4, "addrtype")
                || self.cap_has_match(Family::V6, "addrtype"),
            conntrack_match: self.cap_has_match(Family::V4, "conntrack")
                || self.cap_has_match(Family::V6, "conntrack"),
            connmark_match: self.cap_has_match(Family::V4, "connmark")
                || self.cap_has_match(Family::V6, "connmark"),
            connmark_target: self.cap_has_target(Family::V4, "CONNMARK")
                || self.cap_has_target(Family::V6, "CONNMARK"),
            ipset: self.config.bypass_cn_ip && self.ipset_available(),
            bpf_match: self.cap_has_match(Family::V4, "bpf")
                || self.cap_has_match(Family::V6, "bpf"),
            ip6_nat: self.config.ipv6 && self.ip6_nat_supported(),
            restore4: self.probe_restore_support(Family::V4),
            restore6: self.config.ipv6 && self.probe_restore_support(Family::V6),
            ..Default::default()
        };
        caps.socket_transparent = self.cap_socket_transparent(caps.socket_match);
        caps
    }

    pub(super) fn probe_restore_support(&self, family: Family) -> bool {
        const PROBE_CHAIN: &str = "BOX_RESTORE_PROBE";
        let probe = format!("*mangle\n:{PROBE_CHAIN} - [0:0]\nCOMMIT\n");
        let restore_args = strings(&["-w", IPTABLES_LOCK_WAIT_SECS, "--noflush"]);
        let ok = self
            .runner
            .run_with_stdin_output(restore_cmd(family), &restore_args, &probe)
            .map(|output| output.ok)
            .unwrap_or(false);

        self.ipt_silent(family, &["-t", "mangle", "-F", PROBE_CHAIN]);
        self.ipt_silent(family, &["-t", "mangle", "-X", PROBE_CHAIN]);
        ok
    }

    pub(super) fn cap_has_target(&self, family: Family, target: &str) -> bool {
        let path = match family {
            Family::V4 => "/proc/net/ip_tables_targets",
            Family::V6 => "/proc/net/ip6_tables_targets",
        };
        fs::read_to_string(path)
            .map(|text| text.split_whitespace().any(|value| value == target))
            .unwrap_or(false)
    }

    pub(super) fn cap_has_match(&self, family: Family, target: &str) -> bool {
        let path = match family {
            Family::V4 => "/proc/net/ip_tables_matches",
            Family::V6 => "/proc/net/ip6_tables_matches",
        };
        fs::read_to_string(path)
            .map(|text| text.split_whitespace().any(|value| value == target))
            .unwrap_or(false)
    }

    pub(super) fn cap_socket_transparent(&self, socket_match: bool) -> bool {
        if !socket_match {
            return false;
        }
        let chain = "BOX_SOCKET_PROBE";
        self.ipt_silent(Family::V4, &["-t", "mangle", "-N", chain]);
        self.ipt_silent(Family::V4, &["-t", "mangle", "-F", chain]);
        let ok = self.ipt_try_owned(
            Family::V4,
            strings(&[
                "-t",
                "mangle",
                "-A",
                chain,
                "-p",
                "tcp",
                "-m",
                "socket",
                "--transparent",
                "-j",
                "RETURN",
            ]),
        );
        self.cleanup_chain_fast(Family::V4, "mangle", chain);
        ok
    }

    pub(super) fn ip6_nat_supported(&self) -> bool {
        if self.runner.dry_run() {
            return true;
        }
        self.ipt_check(Family::V6, &["-t", "nat", "-L"])
    }
}
