use super::*;

impl<'a> RuleManager<'a> {
    pub(super) fn refresh_local_ip_rules(&self) -> Result<()> {
        let need_mangle = mode_needs_local_ip_mangle(&self.config.network_mode);
        let need_nat = mode_needs_local_ip_nat(&self.config.network_mode);
        if !need_mangle && !need_nat {
            return Ok(());
        }

        let ipv4 = self.local_ip_cidrs(Family::V4);
        let ipv6 = if self.config.ipv6 {
            self.local_ip_cidrs(Family::V6)
        } else {
            Vec::new()
        };
        let refresh_key = self.local_ip_refresh_key(&ipv4, &ipv6, need_mangle, need_nat);
        if self.local_ip_refresh_key_matches(&refresh_key) {
            return Ok(());
        }
        let mut summaries = Vec::new();

        if need_mangle {
            let (ok, failed) = self.rebuild_local_ip_chain(Family::V4, "mangle", &ipv4)?;
            summaries.push(logger::LocalIpLoopSummary {
                table: "mangle",
                family: "IPv4",
                count: ipv4.len(),
                cidrs: join_display_cidrs(&ipv4),
                ok,
                failed,
            });
            if self.config.ipv6 {
                let (ok, failed) = self.rebuild_local_ip_chain(Family::V6, "mangle", &ipv6)?;
                summaries.push(logger::LocalIpLoopSummary {
                    table: "mangle",
                    family: "IPv6",
                    count: ipv6.len(),
                    cidrs: join_display_cidrs(&ipv6),
                    ok,
                    failed,
                });
            }
        }
        if need_nat {
            let (ok, failed) = self.rebuild_local_ip_chain(Family::V4, "nat", &ipv4)?;
            summaries.push(logger::LocalIpLoopSummary {
                table: "nat",
                family: "IPv4",
                count: ipv4.len(),
                cidrs: join_display_cidrs(&ipv4),
                ok,
                failed,
            });
        }

        logger::net_info_key(
            self.config,
            logger::LogKey::LocalIpLoopRefreshed,
            &[logger::local_ip_loop_summary_arg("summary", &summaries)],
        );
        self.save_local_ip_refresh_key(&refresh_key);
        Ok(())
    }

    pub(super) fn wait_tun_ready(&self) {
        if self.runner.dry_run() {
            return;
        }
        for _ in 0..12 {
            if Path::new("/sys/class/net")
                .join(&self.config.tun_device)
                .exists()
                || self
                    .runner
                    .run_ok("ip", &["link", "show", self.config.tun_device.as_str()])
            {
                logger::debug_key(
                    self.config,
                    LogKey::TunDeviceDetected,
                    &[arg("device", &self.config.tun_device)],
                );
                return;
            }
            thread::sleep(Duration::from_secs(1));
        }
        logger::warn_key(
            self.config,
            LogKey::TunDeviceMissing,
            &[arg("device", &self.config.tun_device)],
        );
    }

    pub(super) fn ipv6_enable(&self) {
        self.runner
            .run_ignore("sysctl", &["-w", "net.ipv4.ip_forward=1"]);
        self.runner
            .run_ignore("sysctl", &["-w", "net.ipv6.conf.all.forwarding=1"]);
        self.restore_ipv6_ra_conf();
    }

    pub(super) fn restore_ipv6_ra_conf(&self) {
        self.set_ipv6_conf_all("disable_ipv6", "0");
        self.set_ipv6_conf_all("autoconf", "1");
        self.set_ipv6_conf_all("accept_ra", "2");
    }

    pub(super) fn apply_ipv6_system_mode(&self) {
        if self.config.ipv6_mode == "disable" {
            self.disable_system_ipv6();
        } else {
            self.ipv6_enable();
        }
    }

    pub(super) fn disable_system_ipv6(&self) {
        self.runner
            .run_ignore("sysctl", &["-w", "net.ipv4.ip_forward=1"]);
        self.runner
            .run_ignore("sysctl", &["-w", "net.ipv6.conf.all.forwarding=0"]);
        self.set_ipv6_conf_all("accept_ra", "0");
        self.set_ipv6_conf_all("autoconf", "0");
        self.set_ipv6_conf_all("disable_ipv6", "1");
        logger::net_info_key(self.config, LogKey::Ipv6SystemModeRefreshed, &[]);
    }

    pub(super) fn set_ipv6_conf_all(&self, key: &str, value: &str) {
        if self.runner.dry_run() {
            return;
        }
        let Ok(entries) = fs::read_dir("/proc/sys/net/ipv6/conf") else {
            return;
        };
        for entry in entries.filter_map(|entry| entry.ok()) {
            let name = entry.file_name();
            self.write_ipv6_conf_value(&name.to_string_lossy(), key, value);
        }
    }

    pub(super) fn write_ipv6_conf_value(&self, iface: &str, key: &str, value: &str) {
        if self.runner.dry_run() {
            return;
        }
        let path = Path::new("/proc/sys/net/ipv6/conf").join(iface).join(key);
        if !path.exists() {
            return;
        }
        if let Ok(current) = fs::read_to_string(&path) {
            if current.trim() == value {
                return;
            }
        }
        let _ = fs::write(path, value);
    }

    pub(super) fn ensure_local_ip_chain(&self, family: Family, table: &str) -> Result<()> {
        let key = (family, table.to_string());
        if !self.local_ip_chains_built.borrow_mut().insert(key) {
            return Ok(());
        }
        let cidrs = self.local_ip_cidrs(family);
        self.rebuild_local_ip_chain(family, table, &cidrs)?;
        Ok(())
    }

    pub(super) fn rebuild_local_ip_chain(
        &self,
        family: Family,
        table: &str,
        cidrs: &[String],
    ) -> Result<(usize, usize)> {
        let chain = local_ip_chain(family);
        self.ensure_chain(family, table, chain)?;

        let mut ok = 0;
        let mut failed = 0;
        for cidr in cidrs {
            if self.append_local_ip_ruleset(family, table, chain, cidr) {
                ok += 1;
            } else {
                failed += 1;
            }
        }
        Ok((ok, failed))
    }

    pub(super) fn append_local_ip_ruleset(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        cidr: &str,
    ) -> bool {
        let udp_non_dns = self
            .ensure_rule_append(
                family,
                table,
                chain,
                &[
                    "-d", cidr, "-p", "udp", "!", "--dport", "53", "-j", "ACCEPT",
                ],
            )
            .is_ok();
        let non_udp = self
            .ensure_rule_append(
                family,
                table,
                chain,
                &["-d", cidr, "!", "-p", "udp", "-j", "ACCEPT"],
            )
            .is_ok();
        udp_non_dns || non_udp
    }

    pub(super) fn bypass_subnets(&self, family: Family) -> Vec<String> {
        // Memoize per family: `ip addr show` output is stable for the duration of
        // a single apply/clear/renew, and these are queried several times per
        // family/chain. The old shell collected the subnet arrays once at script
        // load; the first Rust rewrite re-forked `ip` on every call.
        let cell = match family {
            Family::V4 => &self.bypass_subnets_v4,
            Family::V6 => &self.bypass_subnets_v6,
        };
        cell.get_or_init(|| self.compute_bypass_subnets(family))
            .clone()
    }

    fn compute_bypass_subnets(&self, family: Family) -> Vec<String> {
        let mut subnets = match family {
            Family::V4 => self.config.intranet_cidrs4.clone(),
            Family::V6 => self.config.intranet_cidrs6.clone(),
        };
        subnets.extend(self.dynamic_bypass_subnets(family));
        subnets = subnets
            .into_iter()
            .filter_map(|subnet| normalize_cidr(family, &subnet))
            .collect();
        subnets.sort();
        subnets.dedup();
        subnets
    }

    pub(super) fn dynamic_bypass_subnets(&self, family: Family) -> Vec<String> {
        let args = match family {
            Family::V4 => strings(&["-4", "addr", "show", "up"]),
            Family::V6 => strings(&["-6", "addr", "show", "up"]),
        };
        self.runner
            .run("ip", &args)
            .ok()
            .filter(|output| output.ok)
            .map(|output| parse_ip_addr_subnets(&output.stdout, family, &self.config.tun_device))
            .unwrap_or_default()
    }

    pub(super) fn local_ip_cidrs(&self, family: Family) -> Vec<String> {
        // Memoized for the same reason as `bypass_subnets`: `ensure_local_ip_chain`
        // is invoked once per (BOX_EXTERNAL, BOX_LOCAL) chain within the same
        // table/family, so without the cache the identical `ip -o addr show` ran
        // twice (plus more from `refresh_local_ip_rules`).
        let cell = match family {
            Family::V4 => &self.local_cidrs_v4,
            Family::V6 => &self.local_cidrs_v6,
        };
        cell.get_or_init(|| self.compute_local_ip_cidrs(family))
            .clone()
    }

    fn compute_local_ip_cidrs(&self, family: Family) -> Vec<String> {
        let args = match family {
            Family::V4 => strings(&["-o", "-4", "addr", "show", "up"]),
            Family::V6 => strings(&["-o", "-6", "addr", "show", "up", "scope", "global"]),
        };
        let mut cidrs = self
            .runner
            .run("ip", &args)
            .ok()
            .filter(|output| output.ok)
            .map(|output| parse_ip_o_addr_cidrs(&output.stdout, family, &self.config.tun_device))
            .unwrap_or_default();
        cidrs.sort();
        cidrs.dedup();
        cidrs
    }

    pub(super) fn local_ip_refresh_key_path(&self) -> PathBuf {
        self.config.paths.state.join("local_ip_refresh.key")
    }

    pub(super) fn local_ip_refresh_key_matches(&self, key: &str) -> bool {
        fs::read_to_string(self.local_ip_refresh_key_path())
            .ok()
            .map(|value| value.trim() == key)
            .unwrap_or(false)
    }

    pub(super) fn save_local_ip_refresh_key(&self, key: &str) {
        let _ = fs::create_dir_all(&self.config.paths.state);
        let _ = fs::write(self.local_ip_refresh_key_path(), key);
    }

    pub(super) fn local_ip_refresh_key(
        &self,
        ipv4: &[String],
        ipv6: &[String],
        need_mangle: bool,
        need_nat: bool,
    ) -> String {
        format!(
            "mode={}|ipv6={}|tun={}|mangle={}|nat={}|v4={}|v6={}",
            self.config.network_mode,
            self.config.ipv6,
            self.config.tun_device,
            need_mangle,
            need_nat,
            ipv4.join(","),
            ipv6.join(",")
        )
    }
}
