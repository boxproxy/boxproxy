use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct RuleBatch {
    family: Family,
    tables: BTreeMap<String, TableBatch>,
}

#[derive(Default)]
struct TableBatch {
    decls: Vec<String>,
    declared: BTreeSet<String>,
    appends: Vec<(String, Vec<String>)>,
}

impl RuleBatch {
    fn new(family: Family) -> Self {
        Self {
            family,
            tables: BTreeMap::new(),
        }
    }
}

impl<'a> RuleManager<'a> {
    pub(super) fn begin_batch(&self, family: Family) {
        if self.runner.dry_run() || !self.restore_supported(family) {
            return;
        }
        *self.batch.borrow_mut() = Some(RuleBatch::new(family));
    }

    pub(super) fn end_batch(&self) {
        self.flush_batch();
        *self.batch.borrow_mut() = None;
    }

    pub(super) fn restore_supported(&self, family: Family) -> bool {
        let caps = self.probe_capabilities();
        match family {
            Family::V4 => caps.restore4,
            Family::V6 => caps.restore6,
        }
    }

    pub(super) fn batch_record_chain(&self, family: Family, table: &str, chain: &str) -> bool {
        if !is_box_custom_chain(chain) {
            return false;
        }
        let mut guard = self.batch.borrow_mut();
        let Some(batch) = guard.as_mut() else {
            return false;
        };
        if batch.family != family {
            return false;
        }
        let tb = batch.tables.entry(table.to_string()).or_default();
        if !tb.declared.contains(chain) && !tb.decls.iter().any(|existing| existing == chain) {
            tb.decls.push(chain.to_string());
        }
        true
    }

    pub(super) fn batch_record_append(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        args: Vec<String>,
    ) -> bool {
        let mut guard = self.batch.borrow_mut();
        let Some(batch) = guard.as_mut() else {
            return false;
        };
        if batch.family != family {
            return false;
        }
        let tb = batch.tables.entry(table.to_string()).or_default();
        tb.appends.push((chain.to_string(), args));
        true
    }

    pub(super) fn flush_batch(&self) {
        let Some(mut batch) = self.batch.borrow_mut().take() else {
            return;
        };
        let family = batch.family;

        for (table, tb) in batch.tables.iter_mut() {
            if tb.decls.is_empty() && tb.appends.is_empty() {
                continue;
            }

            let applied = self.run_restore(family, table, &tb.decls, &tb.appends);
            if !applied {
                for chain in &tb.decls {
                    let _ = self.ensure_chain(family, table, chain);
                }
                for (chain, args) in &tb.appends {
                    let _ = self.ensure_rule_append_owned(family, table, chain, args.clone());
                }
            }

            for chain in tb.decls.drain(..) {
                tb.declared.insert(chain);
            }
            tb.appends.clear();
        }

        *self.batch.borrow_mut() = Some(batch);
    }

    fn run_restore(
        &self,
        family: Family,
        table: &str,
        decls: &[String],
        appends: &[(String, Vec<String>)],
    ) -> bool {
        let mut input = format!("*{table}\n");
        for chain in decls {
            input.push_str(&format!(":{chain} - [0:0]\n"));
        }
        for (chain, args) in appends {
            input.push_str("-A ");
            input.push_str(chain);
            for value in args {
                input.push(' ');
                input.push_str(value);
            }
            input.push('\n');
        }
        input.push_str("COMMIT\n");

        let restore_args = strings(&["-w", IPTABLES_LOCK_WAIT_SECS, "--noflush"]);
        match self
            .runner
            .run_with_stdin_output(restore_cmd(family), &restore_args, &input)
        {
            Ok(output) if output.ok => true,
            Ok(output) => {
                self.log_command_failure(
                    "iptables-restore batch failed",
                    restore_cmd(family),
                    &restore_args,
                    &output,
                );
                false
            }
            Err(err) => {
                logger::warn_key(
                    self.config,
                    LogKey::CommandFailure,
                    &[
                        logger::command_stage_arg("stage", "iptables-restore batch failed"),
                        arg("command", restore_cmd(family)),
                        arg("error", err),
                    ],
                );
                false
            }
        }
    }
}
