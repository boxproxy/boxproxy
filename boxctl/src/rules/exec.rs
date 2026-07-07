use super::*;

impl<'a> RuleManager<'a> {
    pub(super) fn add_core_bypass_rule(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        op: &str,
        context: &RuleContext,
    ) -> bool {
        for mut args in core_bypass_variants(context) {
            let mut full = vec!["-t".into(), table.into(), op.into(), chain.into()];
            full.append(&mut args);
            if self.ipt_try_owned(family, full) {
                return true;
            }
        }
        false
    }

    pub(super) fn ensure_chain(&self, family: Family, table: &str, chain: &str) -> Result<()> {
        if self.batch_record_chain(family, table, chain) {
            return Ok(());
        }
        self.ipt_silent(family, &["-t", table, "-N", chain]);
        self.ipt(family, &["-t", table, "-F", chain])
    }

    pub(super) fn cleanup_chain_fast(&self, family: Family, table: &str, chain: &str) {
        self.ipt_silent(family, &["-t", table, "-F", chain]);
        self.ipt_silent(family, &["-t", table, "-X", chain]);
    }

    pub(super) fn ensure_jump(
        &self,
        family: Family,
        table: &str,
        parent: &str,
        target: &str,
    ) -> Result<()> {
        if self.ipt_check(family, &["-t", table, "-C", parent, "-j", target]) {
            return Ok(());
        }
        self.ipt(family, &["-t", table, "-I", parent, "-j", target])
    }

    pub(super) fn del_jump(&self, family: Family, table: &str, parent: &str, target: &str) {
        self.del_rule(family, table, parent, &["-j", target]);
    }

    pub(super) fn ensure_rule_append(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        args: &[&str],
    ) -> Result<()> {
        self.ensure_rule_append_owned(
            family,
            table,
            chain,
            args.iter().map(|value| (*value).to_string()).collect(),
        )
    }

    pub(super) fn ensure_rule_append_owned(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        args: Vec<String>,
    ) -> Result<()> {
        if !is_box_custom_chain(chain) {
            let mut check = vec!["-t".into(), table.into(), "-C".into(), chain.into()];
            check.extend(args.iter().cloned());
            if self.ipt_check_owned(family, &check) {
                return Ok(());
            }
        } else if self.batch_record_append(family, table, chain, args.clone()) {
            return Ok(());
        }

        let mut full = vec!["-t".into(), table.into(), "-A".into(), chain.into()];
        full.extend(args);
        self.ipt_owned(family, full)
    }

    pub(super) fn ensure_rule_insert(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        args: &[&str],
    ) {
        let mut check = vec!["-t".into(), table.into(), "-C".into(), chain.into()];
        check.extend(args.iter().map(|value| (*value).to_string()));
        if self.ipt_check_owned(family, &check) {
            return;
        }

        let mut full = vec!["-t".into(), table.into(), "-I".into(), chain.into()];
        full.extend(args.iter().map(|value| (*value).to_string()));
        if let Err(err) = self.ipt_owned(family, full) {
            logger::warn_key(
                self.config,
                LogKey::IptablesInsertRuleFailed,
                &[arg("error", err)],
            );
        }
    }

    pub(super) fn del_rule(&self, family: Family, table: &str, chain: &str, args: &[&str]) {
        // `-D` already no-ops (non-zero, ignored) when the rule is absent, so the
        // previous `-C` pre-check just doubled the number of iptables forks on the
        // stop path. The old shell `del_rule_silent` was a single `-D || true`.
        let mut full = vec!["-t".into(), table.into(), "-D".into(), chain.into()];
        full.extend(args.iter().map(|value| (*value).to_string()));
        self.ipt_silent_owned(family, full);
    }

    fn wait_supported(&self, family: Family) -> bool {
        let cell = match family {
            Family::V4 => &self.wait_support_v4,
            Family::V6 => &self.wait_support_v6,
        };
        *cell.get_or_init(|| self.probe_wait_support(family))
    }

    fn probe_wait_support(&self, family: Family) -> bool {
        if self.runner.dry_run() {
            return true;
        }
        self.runner.run_ok(
            iptables_cmd(family),
            &strings(&["-w", IPTABLES_LOCK_WAIT_SECS, "-S"]),
        )
    }

    fn with_wait(&self, family: Family, args: Vec<String>) -> Vec<String> {
        if !self.wait_supported(family) {
            return args;
        }
        let mut full = Vec::with_capacity(args.len() + 2);
        full.push("-w".to_string());
        full.push(IPTABLES_LOCK_WAIT_SECS.to_string());
        full.extend(args);
        full
    }

    pub(super) fn ipt(&self, family: Family, args: &[&str]) -> Result<()> {
        self.ipt_owned(family, strings(args))
    }

    pub(super) fn ipt_owned(&self, family: Family, args: Vec<String>) -> Result<()> {
        self.flush_batch();
        let full = self.with_wait(family, args);
        if self.runner.dry_run() {
            self.runner.preview(iptables_cmd(family), &full);
            return Ok(());
        }

        let output = self.runner.run(iptables_cmd(family), &full)?;
        if output.ok {
            return Ok(());
        }
        self.log_command_failure("iptables rule failed", iptables_cmd(family), &full, &output);
        Err(command_failure_message(
            iptables_cmd(family),
            &full,
            &output,
        ))
    }

    pub(super) fn ipt_silent(&self, family: Family, args: &[&str]) {
        self.ipt_silent_owned(family, strings(args));
    }

    pub(super) fn ipt_silent_owned(&self, family: Family, args: Vec<String>) {
        self.flush_batch();
        let full = self.with_wait(family, args);
        if self.runner.dry_run() {
            self.runner.preview(iptables_cmd(family), &full);
            return;
        }
        self.runner.run_ignore(iptables_cmd(family), &full);
    }

    pub(super) fn ipt_try_owned(&self, family: Family, args: Vec<String>) -> bool {
        self.flush_batch();
        let full = self.with_wait(family, args);
        if self.runner.dry_run() {
            self.runner.preview(iptables_cmd(family), &full);
            return true;
        }
        self.runner.run_ok(iptables_cmd(family), &full)
    }

    pub(super) fn ipt_check(&self, family: Family, args: &[&str]) -> bool {
        self.ipt_check_owned(family, &strings(args))
    }

    pub(super) fn ipt_check_owned(&self, family: Family, args: &[String]) -> bool {
        self.flush_batch();
        if self.runner.dry_run() {
            return false;
        }
        let full = self.with_wait(family, args.to_vec());
        self.runner.run_ok(iptables_cmd(family), &full)
    }

    pub(super) fn ip_ignore(&self, family: Family, args: &[&str]) {
        self.flush_batch();
        let full = ip_args(family, args);
        self.runner.run_ignore("ip", &full);
    }

    pub(super) fn ip_required(&self, family: Family, args: &[&str]) -> Result<()> {
        self.flush_batch();
        let full = ip_args(family, args);
        let output = self.runner.run("ip", &full)?;
        if output.ok {
            return Ok(());
        }
        self.log_command_failure("ip policy route failed", "ip", &full, &output);
        Err(command_failure_message("ip", &full, &output))
    }

    pub(super) fn ip_rule_output(&self, family: Family, args: &[&str]) -> Option<String> {
        self.flush_batch();
        let full = ip_args(family, args);
        self.runner
            .run("ip", &full)
            .ok()
            .filter(|output| output.ok)
            .map(|output| output.stdout)
    }

    pub(super) fn ip_rule_exists(
        &self,
        family: Family,
        mark: &str,
        table: &str,
        pref: &str,
    ) -> bool {
        let Some(output) = self.ip_rule_output(family, &["rule", "show", "pref", pref]) else {
            return false;
        };
        let marks = fwmark_match_values(mark);
        output.lines().any(|line| {
            marks.iter().any(|mark| line.contains(mark))
                && line.contains(&format!("lookup {table}"))
        })
    }

    pub(super) fn ensure_ip_rule(
        &self,
        family: Family,
        mark: &str,
        table: &str,
        pref: &str,
    ) -> Result<()> {
        if !self.ip_rule_exists(family, mark, table, pref) {
            self.ip_required(
                family,
                &["rule", "add", "fwmark", mark, "table", table, "pref", pref],
            )?;
        }
        Ok(())
    }

    pub(super) fn del_ip_rule_if_exists(
        &self,
        family: Family,
        mark: &str,
        table: &str,
        pref: &str,
    ) {
        if self.ip_rule_exists(family, mark, table, pref) {
            self.ip_ignore(
                family,
                &["rule", "del", "fwmark", mark, "table", table, "pref", pref],
            );
        }
    }

    pub(super) fn ip_route_local_default_exists(&self, family: Family, table: &str) -> bool {
        self.ip_rule_output(family, &["route", "show", "table", table])
            .unwrap_or_default()
            .lines()
            .any(|line| line.starts_with("local default dev lo"))
    }

    pub(super) fn ensure_ip_route_local_default(&self, family: Family, table: &str) -> Result<()> {
        if !self.ip_route_local_default_exists(family, table) {
            self.ip_required(
                family,
                &[
                    "route", "add", "local", "default", "dev", "lo", "table", table,
                ],
            )?;
        }
        Ok(())
    }

    pub(super) fn del_ip_route_local_default_if_exists(&self, family: Family, table: &str) {
        if self.ip_route_local_default_exists(family, table) {
            self.ip_ignore(
                family,
                &[
                    "route", "del", "local", "default", "dev", "lo", "table", table,
                ],
            );
        }
    }

    pub(super) fn log_command_failure(
        &self,
        stage: &str,
        program: &str,
        args: &[String],
        output: &Output,
    ) {
        logger::warn_key(
            self.config,
            LogKey::CommandFailure,
            &[
                logger::command_stage_arg("stage", stage),
                arg("command", crate::exec::shell_join(program, args)),
                arg("stdout", empty_dash(&output.stdout)),
                arg("stderr", empty_dash(&output.stderr)),
            ],
        );
    }
}
