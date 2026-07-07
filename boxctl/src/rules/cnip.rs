use super::*;

impl<'a> RuleManager<'a> {
    pub(super) fn setup_cn_ipset_if_needed(&self, capabilities: &Capabilities) -> Result<()> {
        if !self.config.bypass_cn_ip {
            logger::debug_key(self.config, LogKey::CnipSkipDisabled, &[]);
            return Ok(());
        }
        if self.cnip_uses_ebpf() {
            logger::debug_key(self.config, LogKey::CnipSkipEbpf, &[]);
            return Ok(());
        }
        if !self.cnip_uses_ipset() {
            logger::info_key(
                self.config,
                LogKey::CnipModeSkipIpset,
                &[arg("mode", &self.config.cnip_mode)],
            );
            return Ok(());
        }
        if !capabilities.ipset {
            logger::warn_key(self.config, LogKey::CnipIpsetUnavailable, &[]);
            return Ok(());
        }

        if self.config.bypass_cn_ip_v4 {
            self.restore_ipset("cnip", "inet", &self.config.cn_ip_file)?;
        }
        if self.config.ipv6 && self.config.bypass_cn_ip_v6 {
            self.restore_ipset("cnip6", "inet6", &self.config.cn_ipv6_file)?;
        }
        Ok(())
    }

    pub(super) fn setup_rule_ebpf_if_needed(
        &self,
        capabilities: &Capabilities,
        context: &RuleContext,
    ) -> Result<()> {
        self.ensure_rule_ebpf_if_needed(capabilities, context, EbpfApplyMode::Start)
    }

    pub(super) fn reload_cn_ipset(&self) -> Result<()> {
        let capabilities = self.probe_capabilities();
        let context = self.prepare_context();
        self.setup_cn_ipset_if_needed(capabilities)?;
        self.reload_rule_ebpf_if_needed(capabilities, &context)?;
        if self.cnip_uses_ipset() {
            logger::info_key(self.config, LogKey::CnipIpsetRefreshed, &[]);
        } else if self.cnip_uses_ebpf() {
            logger::info_key(self.config, LogKey::CnipEbpfRefreshed, &[]);
        }
        Ok(())
    }

    pub(super) fn restore_ipset(&self, name: &str, family: &str, source: &PathBuf) -> Result<()> {
        if !source.exists() {
            logger::debug_key(
                self.config,
                LogKey::CnipFileMissing,
                &[arg("name", name), arg("path", source.display())],
            );
            return Ok(());
        }
        if !self.ipset_should_reload(name, source) {
            logger::debug_key(self.config, LogKey::CnipUnchanged, &[arg("name", name)]);
            return Ok(());
        }

        let text = fs::read_to_string(source)
            .map_err(|err| format!("read CNIP file {} failed: {err}", source.display()))?;
        let mut input = format!(
            "create {name} hash:net family {family} hashsize 8192 maxelem 65536 -exist\nflush {name}\n"
        );
        for line in text.lines() {
            let value = line.trim();
            if value.is_empty() || value.starts_with('#') {
                continue;
            }
            input.push_str("add ");
            input.push_str(name);
            input.push(' ');
            input.push_str(value);
            input.push('\n');
        }

        let args = strings(&["restore", "-exist"]);
        let output = self.runner.run_with_stdin_output("ipset", &args, &input)?;
        if output.ok {
            self.write_ipset_stamp(name, source);
            logger::info_key(self.config, LogKey::CnipImported, &[arg("name", name)]);
            Ok(())
        } else {
            self.log_command_failure("ipset import failed", "ipset", &args, &output);
            Err(command_failure_message("ipset", &args, &output))
        }
    }

    pub(super) fn cleanup_cn_ipset_keep(&self) {
        if self.config.bypass_cn_ip && self.cnip_uses_ipset() {
            logger::debug_key(self.config, LogKey::CnipKeepIpset, &[]);
        }
    }

    pub(super) fn cleanup_rule_ebpf(&self) {
        if self.config.bpf_matcher_path.exists() || self.runner.dry_run() {
            let _ = self.run_ebpf_matcher("--clear", None, false);
        }
        self.runner.run_ignore(
            "rm",
            &[
                "-f",
                EBPF_OUT4,
                EBPF_OUT6,
                EBPF_PRE4,
                EBPF_PRE6,
                EBPF_FORCE_OUT4,
                EBPF_FORCE_OUT6,
                EBPF_APP_OUT4,
                EBPF_APP_OUT6,
                EBPF_MAP_RUNTIME,
                EBPF_MAP4,
                EBPF_MAP6,
                EBPF_FORCE_UID_MAP,
                EBPF_APP_UID_MAP,
            ],
        );
        self.runner.run_ignore("rmdir", &[EBPF_PIN_DIR]);
    }

    pub(super) fn write_rule_ebpf_config(&self, context: &RuleContext) -> Result<PathBuf> {
        let dir = self.config.paths.state.join("ebpf");
        fs::create_dir_all(&dir)
            .map_err(|err| format!("create eBPF state directory failed: {err}"))?;

        let empty_v4 = dir.join("empty-v4.txt");
        let empty_v6 = dir.join("empty-v6.txt");
        let force_uids = dir.join("force-uids.txt");
        let app_uids = dir.join("app-uids.txt");
        ensure_empty_file(&empty_v4)?;
        ensure_empty_file(&empty_v6)?;
        write_lines_file(&force_uids, &normalized_list(&self.config.cnip_force_uids))?;

        let app_uid_path = if self.app_uid_ebpf_requested(context) {
            write_lines_file(&app_uids, &context.selected_uids)?;
            app_uids.display().to_string()
        } else {
            String::new()
        };

        let cnip_ebpf = self.cnip_ebpf_requested();
        let cidr4 = if cnip_ebpf && self.config.bypass_cn_ip_v4 {
            require_file(&self.config.cn_ip_file, "CNIP IPv4")?
        } else {
            empty_v4
        };
        let enable_v6 = cnip_ebpf && self.config.ipv6 && self.config.bypass_cn_ip_v6;
        let cidr6 = if enable_v6 {
            require_file(&self.config.cn_ipv6_file, "CNIP IPv6")?
        } else {
            empty_v6
        };

        let config = serde_json::json!({
            "ipv6": self.config.ipv6,
            "cidrHitIsMatch": true,
            "cidr4": cidr4.display().to_string(),
            "cidr6": cidr6.display().to_string(),
            "forceUids": force_uids.display().to_string(),
            "appUids": app_uid_path,
            "pinCidrOut4": EBPF_OUT4,
            "pinCidrOut6": EBPF_OUT6,
            "pinCidrPre4": EBPF_PRE4,
            "pinCidrPre6": EBPF_PRE6,
            "pinForceOut4": EBPF_FORCE_OUT4,
            "pinForceOut6": EBPF_FORCE_OUT6,
            "pinAppOut4": EBPF_APP_OUT4,
            "pinAppOut6": EBPF_APP_OUT6,
            "mapRuntime": EBPF_MAP_RUNTIME,
            "mapCidr4": EBPF_MAP4,
            "mapCidr6": EBPF_MAP6,
            "mapForceUid": EBPF_FORCE_UID_MAP,
            "mapAppUid": EBPF_APP_UID_MAP,
        });
        let config_path = self.rule_ebpf_config_path();
        let text = serde_json::to_string_pretty(&config)
            .map_err(|err| format!("serialize eBPF config failed: {err}"))?;
        fs::write(&config_path, format!("{text}\n"))
            .map_err(|err| format!("write eBPF config {} failed: {err}", config_path.display()))?;
        Ok(config_path)
    }

    pub(super) fn rule_ebpf_config_path(&self) -> PathBuf {
        self.config
            .paths
            .state
            .join("ebpf")
            .join("rule-config.json")
    }

    pub(super) fn run_ebpf_matcher(
        &self,
        action: &str,
        config_path: Option<&Path>,
        required: bool,
    ) -> Result<()> {
        let mut args = vec![action.to_string()];
        if let Some(config_path) = config_path {
            args.push("--config".to_string());
            args.push(config_path.display().to_string());
        }
        let program = self.config.bpf_matcher_path.display().to_string();
        let output = self.runner.run(&program, &args)?;
        if output.ok || !required {
            return Ok(());
        }
        if let Some(reason) = ebpf_failure_reason(&output.stderr) {
            logger::error_key(
                self.config,
                LogKey::EbpfUnsupported,
                &[logger::ebpf_failure_reason_arg("reason", reason)],
            );
        }
        self.log_command_failure("eBPF matcher execution failed", &program, &args, &output);
        Err(command_failure_message(&program, &args, &output))
    }

    pub(super) fn reload_rule_ebpf_if_needed(
        &self,
        capabilities: &Capabilities,
        context: &RuleContext,
    ) -> Result<()> {
        self.ensure_rule_ebpf_if_needed(capabilities, context, EbpfApplyMode::UpdateThenStart)
    }

    pub(super) fn ensure_rule_ebpf_if_needed(
        &self,
        capabilities: &Capabilities,
        context: &RuleContext,
        mode: EbpfApplyMode,
    ) -> Result<()> {
        let cnip_required = self.cnip_ebpf_requested();
        let app_requested = self.app_uid_ebpf_requested(context);
        if !cnip_required && !app_requested {
            return Ok(());
        }

        if !capabilities.bpf_match {
            if !cnip_required {
                return Ok(());
            }
            let action = match mode {
                EbpfApplyMode::Start => "enable",
                EbpfApplyMode::UpdateThenStart => "refresh",
            };
            return Err(format!(
                "iptables bpf match unavailable, cannot {action} eBPF rule matcher"
            ));
        }
        if !self.config.bpf_matcher_path.is_file() {
            if !cnip_required {
                return Ok(());
            }
            return Err(format!(
                "eBPF matcher not found: {}",
                self.config.bpf_matcher_path.display()
            ));
        }

        let config_path = self.write_rule_ebpf_config(context)?;
        self.apply_ebpf_selinux_policy();
        self.runner.run_ignore(
            "chmod",
            &[
                "755".into(),
                self.config.bpf_matcher_path.display().to_string(),
            ],
        );

        match mode {
            EbpfApplyMode::Start => {
                self.run_ebpf_matcher("--clear", None, false)?;
                match self.run_ebpf_matcher("--apply", Some(&config_path), cnip_required) {
                    Ok(()) => {
                        if cnip_required {
                            logger::info_key(self.config, LogKey::CnipEbpfLoaded, &[]);
                        }
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
            EbpfApplyMode::UpdateThenStart => {
                match self.run_ebpf_matcher("--update", Some(&config_path), true) {
                    Ok(()) => {
                        logger::info_key(self.config, LogKey::EbpfMapHotUpdated, &[]);
                        Ok(())
                    }
                    Err(err) => {
                        logger::warn_key(
                            self.config,
                            LogKey::EbpfMapHotUpdateFailed,
                            &[arg("error", err)],
                        );
                        self.run_ebpf_matcher("--apply", Some(&config_path), cnip_required)
                    }
                }
            }
        }
    }

    pub(super) fn apply_ebpf_selinux_policy(&self) {
        let rule = "allow netd * bpf { prog_run map_read map_write }".to_string();
        let policy_args = vec!["--live".to_string(), rule.clone()];
        for tool in [
            "magiskpolicy",
            "/data/adb/magisk/magiskpolicy",
            "supolicy",
            "/system/xbin/supolicy",
            "/system/bin/supolicy",
        ] {
            if self.runner.run_ok(tool, &policy_args) {
                return;
            }
        }

        let ksu_args = vec!["sepolicy".to_string(), "patch".to_string(), rule];
        for tool in ["ksud", "/data/adb/ksud", "/data/adb/ksu/bin/ksud"] {
            if self.runner.run_ok(tool, &ksu_args) {
                return;
            }
        }
    }

    pub(super) fn ipset_enabled_for_family(&self, family: Family) -> bool {
        if !self.cnip_uses_ipset() {
            return false;
        }
        if !self.probe_capabilities().ipset {
            return false;
        }
        self.cnip_bypass_enabled_for_family(family)
    }

    pub(super) fn cnip_matcher_enabled_for_family(&self, family: Family) -> bool {
        if !self.cnip_bypass_enabled_for_family(family) {
            return false;
        }
        if self.cnip_uses_ipset() {
            return self.ipset_enabled_for_family(family);
        }
        if self.cnip_uses_ebpf() {
            return self.probe_capabilities().bpf_match;
        }
        false
    }

    pub(super) fn cnip_match_args(
        &self,
        family: Family,
        chain: &str,
        mut base: Vec<String>,
    ) -> Option<Vec<String>> {
        if !self.cnip_matcher_enabled_for_family(family) {
            return None;
        }
        if self.cnip_uses_ipset() {
            base.extend([
                "-m".into(),
                "set".into(),
                "--match-set".into(),
                cnip_set_name(family).into(),
                "dst".into(),
            ]);
            return Some(base);
        }
        if self.cnip_uses_ebpf() {
            base.extend([
                "-m".into(),
                "bpf".into(),
                "--object-pinned".into(),
                cnip_ebpf_pin_path(family, chain).into(),
            ]);
            return Some(base);
        }
        None
    }

    pub(super) fn cnip_force_match_args(
        &self,
        family: Family,
        mut base: Vec<String>,
    ) -> Option<Vec<String>> {
        if !self.cnip_matcher_enabled_for_family(family) || !self.cnip_uses_ebpf() {
            return None;
        }
        base.extend([
            "-m".into(),
            "bpf".into(),
            "--object-pinned".into(),
            cnip_force_ebpf_pin_path(family).into(),
        ]);
        Some(base)
    }

    pub(super) fn app_uid_match_args(&self, family: Family, mut base: Vec<String>) -> Vec<String> {
        base.extend([
            "-m".into(),
            "bpf".into(),
            "--object-pinned".into(),
            app_uid_ebpf_pin_path(family).into(),
        ]);
        base
    }

    pub(super) fn app_uid_ebpf_active(&self, family: Family, context: &RuleContext) -> bool {
        self.app_uid_ebpf_requested(context) && self.app_uid_ebpf_pin_loaded(family)
    }

    pub(super) fn app_uid_ebpf_pin_loaded(&self, family: Family) -> bool {
        self.runner.dry_run() || Path::new(app_uid_ebpf_pin_path(family)).exists()
    }

    pub(super) fn app_uid_ebpf_requested(&self, context: &RuleContext) -> bool {
        self.config.performance_mode
            && !context.selected_uids.is_empty()
            && matches!(
                self.config.proxy_mode.as_str(),
                "blacklist" | "black" | "whitelist" | "white"
            )
    }

    pub(super) fn cnip_ebpf_requested(&self) -> bool {
        self.config.bypass_cn_ip && self.cnip_uses_ebpf()
    }

    pub(super) fn cnip_bypass_enabled_for_family(&self, family: Family) -> bool {
        if !self.config.bypass_cn_ip {
            return false;
        }
        match family {
            Family::V4 => self.config.bypass_cn_ip_v4,
            Family::V6 => self.config.ipv6 && self.config.bypass_cn_ip_v6,
        }
    }

    pub(super) fn cnip_uses_ipset(&self) -> bool {
        self.config.cnip_mode == "ipset"
    }

    pub(super) fn cnip_uses_ebpf(&self) -> bool {
        self.config.cnip_mode == "ebpf"
    }

    pub(super) fn ipset_available(&self) -> bool {
        if self.runner.dry_run() {
            return true;
        }
        self.runner
            .run("ipset", &["--version"])
            .ok()
            .map(|output| output.ok)
            .unwrap_or(false)
    }

    pub(super) fn ipset_has_entries(&self, name: &str) -> bool {
        let output = self
            .runner
            .run("ipset", &["list", "-terse", name])
            .ok()
            .filter(|output| output.ok)
            .map(|output| output.stdout)
            .unwrap_or_default();
        output.lines().any(|line| {
            line.trim()
                .strip_prefix("Number of entries:")
                .and_then(|value| value.trim().parse::<usize>().ok())
                .map(|count| count > 0)
                .unwrap_or(false)
        })
    }

    pub(super) fn ipset_should_reload(&self, name: &str, source: &Path) -> bool {
        if !self.ipset_has_entries(name) {
            return true;
        }
        let Some(current) = ipset_source_stamp(source) else {
            return true;
        };
        let old = fs::read_to_string(self.ipset_stamp_path(name)).unwrap_or_default();
        old.trim() != current
    }

    pub(super) fn write_ipset_stamp(&self, name: &str, source: &Path) {
        let Some(stamp) = ipset_source_stamp(source) else {
            return;
        };
        let path = self.ipset_stamp_path(name);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(path, format!("{stamp}\n"));
    }

    pub(super) fn ipset_stamp_path(&self, name: &str) -> PathBuf {
        self.config
            .paths
            .state
            .join("ipset.stamp")
            .join(format!("{name}.stamp"))
    }
}

pub(super) fn ebpf_failure_reason(stderr: &str) -> Option<logger::EbpfFailureReason> {
    let text = stderr.to_ascii_lowercase();
    if text.contains("ebpf program load rejected")
        || text.contains("load bpf program failed")
        || text.contains("invalid argument")
    {
        return Some(logger::EbpfFailureReason::ProgramRejected);
    }
    if text.contains("permission denied") || text.contains("operation not permitted") {
        return Some(logger::EbpfFailureReason::PermissionDenied);
    }
    if text.contains("no such file") {
        return Some(logger::EbpfFailureReason::PinnedPathUnavailable);
    }
    None
}
