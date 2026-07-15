use crate::config::Config;
use crate::exec::{Output, Runner};
use crate::logger;
use crate::Result;
use logger::{arg, LogKey};
mod batch;
mod capabilities;
mod cleanup;
mod cnip;
mod context;
mod dns;
mod exec;
mod external;
mod local_ip;
mod local_proxy;
mod performance;
mod routing;
mod runtime;
mod tun;
mod util;
mod vendor_firewall;
use std::cell::{OnceCell, RefCell};
use std::collections::HashSet;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, UNIX_EPOCH};
use util::*;

const IPTABLES_LOCK_WAIT_SECS: &str = "5";
const FWMARK: &str = "16777216/16777216";
const TPROXY_TABLE: &str = "2024";
const TPROXY_PREF: &str = "100";
const TUN_BYPASS_MARK: &str = "33554432/33554432";
const TUN_BYPASS_PREF: &str = "98";
const TUN_ROUTE_MARK: &str = "50331648/50331648";
const TUN_ROUTE_TABLE: &str = "2025";
const TUN_ROUTE_PREF: &str = "99";
const IPV6_DNS_FALLBACK_CHAIN: &str = "BOX_DNS6_FALLBACK";
const EBPF_PIN_DIR: &str = "/sys/fs/bpf/box";
const EBPF_OUT4: &str = "/sys/fs/bpf/box/box_cidr_out4";
const EBPF_OUT6: &str = "/sys/fs/bpf/box/box_cidr_out6";
const EBPF_PRE4: &str = "/sys/fs/bpf/box/box_cidr_pre4";
const EBPF_PRE6: &str = "/sys/fs/bpf/box/box_cidr_pre6";
const EBPF_FORCE_OUT4: &str = "/sys/fs/bpf/box/box_force_out4";
const EBPF_FORCE_OUT6: &str = "/sys/fs/bpf/box/box_force_out6";
const EBPF_APP_OUT4: &str = "/sys/fs/bpf/box/box_uid_out4";
const EBPF_APP_OUT6: &str = "/sys/fs/bpf/box/box_uid_out6";
const EBPF_MAP_RUNTIME: &str = "/sys/fs/bpf/box/box_runtime_cfg";
const EBPF_MAP4: &str = "/sys/fs/bpf/box/box_cidr4_lpm";
const EBPF_MAP6: &str = "/sys/fs/bpf/box/box_cidr6_lpm";
const EBPF_FORCE_UID_MAP: &str = "/sys/fs/bpf/box/box_force_uid_set";
const EBPF_APP_UID_MAP: &str = "/sys/fs/bpf/box/box_app_uid_set";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Family {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxyAction {
    Redirect,
    Tproxy,
    Mark,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DnsNatKind {
    Hijack,
    Forward,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EbpfApplyMode {
    Start,
    UpdateThenStart,
}

#[derive(Clone, Debug)]
struct RuleContext {
    box_uid: String,
    box_gid: String,
    selected_uids: Vec<String>,
    selected_gids: Vec<String>,
    cnip_force_uids: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct Capabilities {
    tproxy4: bool,
    tproxy6: bool,
    socket_match: bool,
    socket_transparent: bool,
    addrtype: bool,
    conntrack_match: bool,
    connmark_match: bool,
    connmark_target: bool,
    ipset: bool,
    bpf_match: bool,
    ip6_nat: bool,
    restore4: bool,
    restore6: bool,
}

struct RuleManager<'a> {
    config: &'a Config,
    runner: &'a Runner,
    capabilities: OnceCell<Capabilities>,
    addrtype_v4_fallback_warned: OnceCell<()>,
    addrtype_v6_fallback_warned: OnceCell<()>,
    batch: RefCell<Option<batch::RuleBatch>>,
    wait_support_v4: OnceCell<bool>,
    wait_support_v6: OnceCell<bool>,
    bypass_subnets_v4: OnceCell<Vec<String>>,
    bypass_subnets_v6: OnceCell<Vec<String>>,
    local_cidrs_v4: OnceCell<Vec<String>>,
    local_cidrs_v6: OnceCell<Vec<String>>,
    local_ip_chains_built: RefCell<HashSet<(Family, String)>>,
}

pub fn apply(config: &Config, runner: &Runner) -> Result<()> {
    RuleManager::new(config, runner).apply()
}

pub fn clear(config: &Config, runner: &Runner) -> Result<()> {
    RuleManager::new(config, runner).clear()
}

pub fn renew(config: &Config, runner: &Runner) -> Result<()> {
    let manager = RuleManager::new(config, runner);
    manager.clear()?;
    manager.apply()
}

pub fn refresh_local_ip_rules(config: &Config, runner: &Runner) -> Result<()> {
    RuleManager::new(config, runner).refresh_local_ip_rules()
}

pub fn reload_cn_ipset(config: &Config, runner: &Runner) -> Result<()> {
    RuleManager::new(config, runner).reload_cn_ipset()
}

impl<'a> RuleManager<'a> {
    fn new(config: &'a Config, runner: &'a Runner) -> Self {
        Self {
            config,
            runner,
            capabilities: OnceCell::new(),
            addrtype_v4_fallback_warned: OnceCell::new(),
            addrtype_v6_fallback_warned: OnceCell::new(),
            batch: RefCell::new(None),
            wait_support_v4: OnceCell::new(),
            wait_support_v6: OnceCell::new(),
            bypass_subnets_v4: OnceCell::new(),
            bypass_subnets_v6: OnceCell::new(),
            local_cidrs_v4: OnceCell::new(),
            local_cidrs_v6: OnceCell::new(),
            local_ip_chains_built: RefCell::new(HashSet::new()),
        }
    }

    fn apply(&self) -> Result<()> {
        fs::create_dir_all(&self.config.paths.state)
            .map_err(|err| format!("create state directory failed: {err}"))?;

        let context = self.prepare_context();
        let capabilities = self.probe_capabilities();
        logger::info_key(
            self.config,
            LogKey::CoreConfigRead,
            &logger::core_config_args(self.config),
        );
        self.log_apply_context(&context, capabilities);
        self.cleanup_vendor_firewall_if_needed();
        self.cleanup_iptables_for_mode(&self.cleanup_mode_for_apply());
        self.cleanup_rule_ebpf();
        self.setup_cn_ipset_if_needed(capabilities)?;
        self.setup_rule_ebpf_if_needed(capabilities, &context)?;
        self.log_performance_mode_context(&context, capabilities);

        match self.config.network_mode.as_str() {
            "redirect" => self.apply_redirect(&context)?,
            "tproxy" => self.apply_tproxy(&context, capabilities)?,
            "mixed" => self.apply_mixed(&context)?,
            "enhance" => self.apply_enhance(&context, capabilities)?,
            "tun" => self.apply_tun(&context)?,
            other => return Err(format!("unknown network mode: {other}")),
        }

        self.runtime_save()?;
        logger::info_key(
            self.config,
            LogKey::InboundRulesApplied,
            &[
                arg("mode", &self.config.network_mode),
                arg("core", &self.config.bin_name),
            ],
        );
        Ok(())
    }

    fn clear(&self) -> Result<()> {
        logger::warn_key(
            self.config,
            LogKey::InboundRulesClearing,
            &[
                arg("mode", &self.config.network_mode),
                arg("core", &self.config.bin_name),
            ],
        );
        self.ipv6_enable();
        // Tear down only the mode that was actually applied (recorded in the
        // runtime snapshot) instead of every mode. Cleaning all of
        // redirect+tproxy+tun when only one was active spends most of its time
        // forking iptables to delete chains that do not exist, which made stop
        // noticeably slower than start. Fall back to "all" when the mode is
        // unknown (missing snapshot / legacy state) so nothing is ever left behind.
        self.cleanup_iptables_for_mode(&self.cleanup_mode_for_clear());
        self.cleanup_rule_ebpf();
        self.cleanup_cn_ipset_keep();
        self.runtime_clear();
        logger::warn_key(self.config, LogKey::InboundRulesCleared, &[]);
        Ok(())
    }

    fn apply_dual_stack(&self, mut per_family: impl FnMut(Family) -> Result<()>) -> Result<()> {
        // Each family builds its box chains under a batch session: box-chain
        // creates/appends are buffered and flushed to iptables-restore in one
        // shot per table, collapsing hundreds of `iptables` forks into a few.
        // end_batch always flushes (even on error) so rollback observes the
        // same applied state the per-rule path would have left behind.
        self.begin_batch(Family::V4);
        let v4 = per_family(Family::V4);
        self.end_batch();
        v4?;

        if self.config.ipv6 {
            self.ipv6_enable();
            self.begin_batch(Family::V6);
            let v6 = per_family(Family::V6);
            self.end_batch();
            v6?;
        } else {
            self.apply_ipv6_system_mode();
        }
        Ok(())
    }

    fn apply_redirect(&self, context: &RuleContext) -> Result<()> {
        logger::info_key(
            self.config,
            LogKey::RuleModeCreating,
            &[arg("mode", "Redirect")],
        );
        self.apply_dual_stack(|family| self.apply_redirect_family(family, context))
    }

    fn apply_tproxy(&self, context: &RuleContext, capabilities: &Capabilities) -> Result<()> {
        logger::info_key(
            self.config,
            LogKey::RuleModeCreating,
            &[arg("mode", "TPROXY")],
        );
        self.apply_dual_stack(|family| self.apply_tproxy_family(family, context, capabilities))
    }

    fn apply_mixed(&self, context: &RuleContext) -> Result<()> {
        logger::info_key(
            self.config,
            LogKey::RuleModeCreating,
            &[arg("mode", "Mixed")],
        );
        self.wait_tun_ready();
        self.apply_dual_stack(|family| self.apply_mixed_family(family, context))
    }

    fn apply_enhance(&self, context: &RuleContext, capabilities: &Capabilities) -> Result<()> {
        logger::info_key(
            self.config,
            LogKey::RuleModeCreating,
            &[arg("mode", "Enhance")],
        );
        self.apply_dual_stack(|family| self.apply_enhance_family(family, context, capabilities))
    }

    fn apply_tun(&self, context: &RuleContext) -> Result<()> {
        logger::info_key(
            self.config,
            LogKey::RuleTunCreating,
            &[
                arg("device", &self.config.tun_device),
                logger::enabled_arg("cnip", self.config.bypass_cn_ip),
            ],
        );
        self.wait_tun_ready();
        self.apply_dual_stack(|family| self.apply_tun_family(family, context))
    }

    fn apply_redirect_family(&self, family: Family, context: &RuleContext) -> Result<()> {
        match self.start_redirect(family, context) {
            Ok(()) => {
                logger::info_key(
                    self.config,
                    LogKey::FamilyRulesCreated,
                    &[
                        family_arg(family),
                        logger::rule_kind_arg("kind", "REDIRECT"),
                    ],
                );
                Ok(())
            }
            Err(err) => {
                logger::error_key(
                    self.config,
                    LogKey::FamilyRuleFailed,
                    &[
                        family_arg(family),
                        logger::rule_kind_arg("kind", "REDIRECT"),
                        arg("error", &err),
                    ],
                );
                self.stop_redirect(family);
                Err(err)
            }
        }
    }

    fn apply_tproxy_family(
        &self,
        family: Family,
        context: &RuleContext,
        capabilities: &Capabilities,
    ) -> Result<()> {
        match self.start_tproxy(family, context, capabilities) {
            Ok(()) => {
                logger::info_key(
                    self.config,
                    LogKey::FamilyRulesCreated,
                    &[family_arg(family), logger::rule_kind_arg("kind", "TPROXY")],
                );
                Ok(())
            }
            Err(err) if family == Family::V6 => {
                logger::warn_key(
                    self.config,
                    LogKey::FamilyRulesSkipped,
                    &[
                        family_arg(family),
                        logger::rule_kind_arg("kind", "TPROXY"),
                        arg("error", &err),
                    ],
                );
                self.stop_tproxy(family);
                Ok(())
            }
            Err(err) => {
                logger::error_key(
                    self.config,
                    LogKey::FamilyRuleFailed,
                    &[
                        family_arg(family),
                        logger::rule_kind_arg("kind", "TPROXY"),
                        arg("error", &err),
                    ],
                );
                self.stop_tproxy(family);
                Err(err)
            }
        }
    }

    fn apply_mixed_family(&self, family: Family, context: &RuleContext) -> Result<()> {
        self.forward(family, true)?;
        self.apply_redirect_family(family, context)
    }

    fn apply_enhance_family(
        &self,
        family: Family,
        context: &RuleContext,
        capabilities: &Capabilities,
    ) -> Result<()> {
        self.start_redirect(family, context)?;
        match self.start_tproxy(family, context, capabilities) {
            Ok(()) => {
                logger::info_key(
                    self.config,
                    LogKey::FamilyRulesCreated,
                    &[family_arg(family), logger::rule_kind_arg("kind", "Enhance")],
                );
                Ok(())
            }
            Err(err) if family == Family::V6 => {
                logger::warn_key(
                    self.config,
                    LogKey::FamilyRulesSkipped,
                    &[
                        family_arg(family),
                        logger::rule_kind_arg("kind", "Enhance TPROXY"),
                        arg("error", err),
                    ],
                );
                Ok(())
            }
            Err(err) => {
                self.stop_redirect(family);
                self.stop_tproxy(family);
                Err(err)
            }
        }
    }

    fn apply_tun_family(&self, family: Family, context: &RuleContext) -> Result<()> {
        if let Err(err) = self.forward(family, true) {
            self.forward(family, false).ok();
            return Err(format!(
                "{} TUN forwarding rule creation failed: {err}",
                family_label(family)
            ));
        }

        if !self.tun_route_managed_by_box() {
            self.stop_tun_bypass(family);
            logger::info_key(
                self.config,
                LogKey::FamilyRulesCreated,
                &[family_arg(family), logger::rule_kind_arg("kind", "TUN")],
            );
            return Ok(());
        }

        match self.start_tun_bypass(family, context) {
            Ok(()) => {
                logger::info_key(
                    self.config,
                    LogKey::FamilyRulesCreated,
                    &[
                        family_arg(family),
                        logger::rule_kind_arg(
                            "kind",
                            if self.config.bypass_cn_ip {
                                "TUN CNIP bypass"
                            } else {
                                "TUN"
                            },
                        ),
                    ],
                );
                Ok(())
            }
            Err(err) => {
                self.stop_tun_bypass(family);
                self.forward(family, false).ok();
                let rule_label = if self.config.bypass_cn_ip {
                    "TUN CNIP bypass"
                } else {
                    "TUN managed route"
                };
                Err(format!(
                    "{} {rule_label} rule creation failed: {err}",
                    family_label(family)
                ))
            }
        }
    }

    fn start_redirect(&self, family: Family, context: &RuleContext) -> Result<()> {
        if family == Family::V6 && !self.probe_capabilities().ip6_nat {
            logger::warn_key(
                self.config,
                LogKey::Ip6NatUnavailable,
                &[logger::nat_target_arg("target", "REDIRECT")],
            );
            return Ok(());
        }

        self.setup_redirect_external_chain(family, context)?;
        self.setup_redirect_local_chain(family, context)?;
        self.apply_loopback_reject_rule(family, &self.config.redir_port, context);
        Ok(())
    }

    fn stop_redirect(&self, family: Family) {
        self.cleanup_loopback_reject_rule(family, &self.config.redir_port);
        self.cleanup_external_chain_common(family, "nat", "BOX_EXTERNAL", "PREROUTING");
        self.cleanup_local_chain_common(family, "nat", "BOX_LOCAL", "OUTPUT");
        self.cleanup_perf_chains(family, "nat", &redirect_perf_chains());
        self.cleanup_dns_nat_chains(family);
    }

    fn start_tproxy(
        &self,
        family: Family,
        context: &RuleContext,
        capabilities: &Capabilities,
    ) -> Result<()> {
        match family {
            Family::V4 if !capabilities.tproxy4 => {
                return Err("IPv4 TPROXY support not detected".to_string());
            }
            Family::V6 if !capabilities.tproxy6 => {
                return Err("IPv6 TPROXY support not detected".to_string());
            }
            _ => {}
        }

        self.setup_tproxy_policy_routing(family)?;
        self.setup_tproxy_external_chain(family, context, capabilities)?;
        self.setup_tproxy_local_chain(family, context, capabilities)?;
        self.setup_tproxy_divert_chain(family, capabilities)?;
        self.apply_quic_block_rules(family);

        if self.config.network_mode != "enhance" {
            self.apply_loopback_reject_rule(family, &self.config.tproxy_port, context);
        }

        self.ensure_dns_nat_hijack(family, context)?;
        self.setup_fake_ip_icmp_rules(family);
        Ok(())
    }

    fn stop_tproxy(&self, family: Family) {
        self.cleanup_tproxy_policy_routing(family);
        self.cleanup_external_chain_common(family, "mangle", "BOX_EXTERNAL", "PREROUTING");
        self.cleanup_local_chain_common(family, "mangle", "BOX_LOCAL", "OUTPUT");
        self.cleanup_perf_chains(family, "mangle", &tproxy_perf_chains());
        self.cleanup_tproxy_divert_chain(family);
        self.cleanup_quic_block_rules(family);
        self.cleanup_loopback_reject_rule(family, &self.config.tproxy_port);
        if family == Family::V4 {
            self.cleanup_fake_ip_icmp_rules(family);
        }
        self.cleanup_dns_nat_chains(family);
    }

    fn start_tun_bypass(&self, family: Family, context: &RuleContext) -> Result<()> {
        let pre_chain = tun_pre_chain(family);
        let out_chain = tun_out_chain(family);

        self.ensure_chain(family, "mangle", pre_chain)?;
        self.ensure_chain(family, "mangle", out_chain)?;

        self.ensure_rule_append(
            family,
            "mangle",
            pre_chain,
            &["-i", &self.config.tun_device, "-j", "RETURN"],
        )?;
        self.append_tun_external_interface_policy_rules(family, pre_chain)?;
        self.append_tun_dns_rules(family, pre_chain)?;
        self.append_tun_force_proxy_destination_rules(family, pre_chain)?;
        self.append_tun_bypass_destination_rules(family, pre_chain)?;

        self.append_tun_core_bypass_rules(family, out_chain, context);
        self.append_tun_dns_rules(family, out_chain)?;
        self.append_cnip_force_proxy_tun_rules(family, out_chain, context)?;
        self.append_tun_force_proxy_destination_rules(family, out_chain)?;
        self.append_tun_proxy_mode_rules(family, out_chain, context)?;
        self.append_tun_bypass_destination_rules(family, out_chain)?;

        self.ensure_jump(family, "mangle", "PREROUTING", pre_chain)?;
        self.ensure_jump(family, "mangle", "OUTPUT", out_chain)?;
        self.apply_tun_route_rules(family)
    }

    fn stop_tun_bypass(&self, family: Family) {
        self.cleanup_tun_route_rules(family);
        self.del_jump(family, "mangle", "PREROUTING", tun_pre_chain(family));
        self.del_jump(family, "mangle", "OUTPUT", tun_out_chain(family));
        self.cleanup_chain_fast(family, "mangle", tun_pre_chain(family));
        self.cleanup_chain_fast(family, "mangle", tun_out_chain(family));
    }

    fn setup_redirect_external_chain(&self, family: Family, context: &RuleContext) -> Result<()> {
        self.setup_external_chain_common(family, "nat", "BOX_EXTERNAL")?;
        self.apply_redirect_reply_bypass_rules(family, "BOX_EXTERNAL")?;
        self.ensure_dns_nat_hijack(family, context)?;
        self.append_common_bypass_rules(family, "nat", "BOX_EXTERNAL")?;
        self.apply_ignored_external_interfaces(family, "nat", "BOX_EXTERNAL")?;
        self.apply_external_loopback_rule(family, "nat", "BOX_EXTERNAL", ProxyAction::Redirect)?;
        self.apply_external_ap_rules(family, "nat", "BOX_EXTERNAL", ProxyAction::Redirect)?;
        self.finish_external_chain(family, "nat", "BOX_EXTERNAL", "PREROUTING")
    }

    fn setup_redirect_local_chain(&self, family: Family, context: &RuleContext) -> Result<()> {
        self.setup_local_chain_common(family, "nat", "BOX_LOCAL", context)?;
        self.apply_redirect_reply_bypass_rules(family, "BOX_LOCAL")?;
        self.append_cnip_force_proxy_local_rules(
            family,
            "nat",
            "BOX_LOCAL",
            ProxyAction::Redirect,
            context,
        )?;
        self.append_common_bypass_rules(family, "nat", "BOX_LOCAL")?;
        self.apply_local_proxy_rules(family, "nat", "BOX_LOCAL", ProxyAction::Redirect, context)?;
        self.finish_local_chain(family, "nat", "BOX_LOCAL", "OUTPUT")
    }

    fn setup_tproxy_external_chain(
        &self,
        family: Family,
        _context: &RuleContext,
        capabilities: &Capabilities,
    ) -> Result<()> {
        if self.tproxy_performance_chain_enabled(capabilities) {
            return self.setup_tproxy_perf_external_chain(family);
        }

        self.setup_external_chain_common(family, "mangle", "BOX_EXTERNAL")?;
        self.apply_tproxy_reply_bypass_rules(family, "BOX_EXTERNAL")?;
        self.apply_mangle_dns_rules(family, "BOX_EXTERNAL", ProxyAction::Tproxy)?;
        self.apply_tproxy_ipv6_fakeip_rules(family, "BOX_EXTERNAL", ProxyAction::Tproxy)?;
        self.append_common_bypass_rules(family, "mangle", "BOX_EXTERNAL")?;
        self.apply_ignored_external_interfaces(family, "mangle", "BOX_EXTERNAL")?;
        self.apply_external_loopback_rule(family, "mangle", "BOX_EXTERNAL", ProxyAction::Tproxy)?;
        self.apply_external_ap_rules(family, "mangle", "BOX_EXTERNAL", ProxyAction::Tproxy)?;
        self.finish_external_chain(family, "mangle", "BOX_EXTERNAL", "PREROUTING")
    }

    fn setup_tproxy_local_chain(
        &self,
        family: Family,
        context: &RuleContext,
        capabilities: &Capabilities,
    ) -> Result<()> {
        if self.tproxy_performance_chain_enabled(capabilities) {
            return self.setup_tproxy_perf_local_chain(family, context);
        }

        self.setup_local_chain_common(family, "mangle", "BOX_LOCAL", context)?;
        self.apply_tproxy_reply_bypass_rules(family, "BOX_LOCAL")?;
        self.apply_mangle_dns_rules(family, "BOX_LOCAL", ProxyAction::Mark)?;
        self.apply_tproxy_ipv6_fakeip_rules(family, "BOX_LOCAL", ProxyAction::Mark)?;
        self.append_cnip_force_proxy_local_rules(
            family,
            "mangle",
            "BOX_LOCAL",
            ProxyAction::Mark,
            context,
        )?;
        self.append_common_bypass_rules(family, "mangle", "BOX_LOCAL")?;
        self.apply_local_proxy_rules(family, "mangle", "BOX_LOCAL", ProxyAction::Mark, context)?;
        self.finish_local_chain(family, "mangle", "BOX_LOCAL", "OUTPUT")
    }

    fn setup_tproxy_perf_external_chain(&self, family: Family) -> Result<()> {
        let ip_chain = tproxy_perf_pre_ip_chain();
        let if_chain = tproxy_perf_pre_if_chain();

        self.setup_external_chain_common(family, "mangle", "BOX_EXTERNAL")?;
        self.setup_perf_dest_chain(family, "mangle", ip_chain)?;
        self.setup_perf_pre_if_chain(family, "mangle", if_chain)?;

        self.apply_tproxy_reply_bypass_rules(family, "BOX_EXTERNAL")?;
        self.apply_mangle_dns_rules(family, "BOX_EXTERNAL", ProxyAction::Tproxy)?;
        self.apply_tproxy_ipv6_fakeip_rules(family, "BOX_EXTERNAL", ProxyAction::Tproxy)?;
        self.add_perf_chain_jumps(family, "mangle", "BOX_EXTERNAL", &[ip_chain, if_chain])?;
        self.append_tproxy_perf_connmark_rules(family, "BOX_EXTERNAL")?;

        if self.config.network_mode != "enhance" && self.config.proxy_tcp {
            self.append_tproxy_dispatch_rule(
                family,
                "BOX_EXTERNAL",
                vec![
                    "-p".into(),
                    "tcp".into(),
                    "-m".into(),
                    "connmark".into(),
                    "--mark".into(),
                    FWMARK.into(),
                ],
            )?;
        }
        if self.config.proxy_udp {
            self.append_tproxy_dispatch_rule(
                family,
                "BOX_EXTERNAL",
                vec![
                    "-p".into(),
                    "udp".into(),
                    "-m".into(),
                    "connmark".into(),
                    "--mark".into(),
                    FWMARK.into(),
                ],
            )?;
        }

        self.finish_external_chain(family, "mangle", "BOX_EXTERNAL", "PREROUTING")
    }

    fn setup_tproxy_perf_local_chain(&self, family: Family, context: &RuleContext) -> Result<()> {
        let ip_chain = tproxy_perf_out_ip_chain();
        let app_chain = tproxy_perf_out_app_chain();

        self.setup_local_chain_common(family, "mangle", "BOX_LOCAL", context)?;
        self.setup_perf_dest_chain(family, "mangle", ip_chain)?;
        self.setup_perf_out_app_chain(family, "mangle", app_chain, context)?;

        self.apply_tproxy_reply_bypass_rules(family, "BOX_LOCAL")?;
        self.apply_tproxy_ipv6_fakeip_rules(family, "BOX_LOCAL", ProxyAction::Mark)?;
        self.append_cnip_force_proxy_local_rules(
            family,
            "mangle",
            "BOX_LOCAL",
            ProxyAction::Mark,
            context,
        )?;
        self.add_perf_chain_jumps(family, "mangle", "BOX_LOCAL", &[ip_chain, app_chain])?;
        self.apply_mangle_dns_rules(family, "BOX_LOCAL", ProxyAction::Mark)?;
        self.append_tproxy_perf_connmark_rules(family, "BOX_LOCAL")?;

        if self.config.network_mode != "enhance" && self.config.proxy_tcp {
            self.ensure_rule_append(
                family,
                "mangle",
                "BOX_LOCAL",
                &[
                    "-p",
                    "tcp",
                    "-m",
                    "connmark",
                    "--mark",
                    FWMARK,
                    "-j",
                    "MARK",
                    "--set-xmark",
                    FWMARK,
                ],
            )?;
        }
        if self.config.proxy_udp {
            self.ensure_rule_append(
                family,
                "mangle",
                "BOX_LOCAL",
                &[
                    "-p",
                    "udp",
                    "-m",
                    "connmark",
                    "--mark",
                    FWMARK,
                    "-j",
                    "MARK",
                    "--set-xmark",
                    FWMARK,
                ],
            )?;
        }

        self.finish_local_chain(family, "mangle", "BOX_LOCAL", "OUTPUT")
    }

    fn setup_external_chain_common(&self, family: Family, table: &str, chain: &str) -> Result<()> {
        self.ensure_chain(family, table, chain)
    }

    fn setup_local_chain_common(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        context: &RuleContext,
    ) -> Result<()> {
        self.ensure_chain(family, table, chain)?;
        if !self.add_core_bypass_rule(family, table, chain, "-I", context) {
            self.ensure_rule_insert(
                family,
                table,
                chain,
                &["-m", "mark", "--mark", FWMARK, "-j", "RETURN"],
            );
            if family == Family::V4 {
                logger::warn_key(self.config, LogKey::CoreBypassFallback, &[]);
            }
        }
        Ok(())
    }

    fn finish_external_chain(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        parent: &str,
    ) -> Result<()> {
        self.ensure_jump(family, table, parent, chain)
    }

    fn finish_local_chain(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        parent: &str,
    ) -> Result<()> {
        self.ensure_jump(family, table, parent, chain)
    }

    fn cleanup_external_chain_common(
        &self,
        family: Family,
        table: &str,
        chain: &str,
        parent: &str,
    ) {
        self.del_jump(family, table, parent, chain);
        self.cleanup_chain_fast(family, table, chain);
    }

    fn cleanup_local_chain_common(&self, family: Family, table: &str, chain: &str, parent: &str) {
        self.del_jump(family, table, parent, chain);
        self.cleanup_chain_fast(family, table, chain);
        self.cleanup_chain_fast(family, table, local_ip_chain(family));
    }

    fn append_common_bypass_rules(&self, family: Family, table: &str, chain: &str) -> Result<()> {
        self.ensure_local_ip_chain(family, table)?;

        for subnet in self.bypass_subnets(family) {
            self.ensure_rule_append_owned(
                family,
                table,
                chain,
                vec!["-d".into(), subnet, "-j".into(), "RETURN".into()],
            )?;
        }

        if let Some(mut args) = self.cnip_match_args(family, chain, Vec::new()) {
            args.extend(["-j".into(), "RETURN".into()]);
            self.ensure_rule_append_owned(family, table, chain, args)?;
        }

        self.ensure_rule_append(family, table, chain, &["-j", local_ip_chain(family)])
    }

    fn apply_redirect_reply_bypass_rules(&self, family: Family, chain: &str) -> Result<()> {
        if !self.performance_conntrack_enabled() {
            return Ok(());
        }
        self.ensure_rule_append(
            family,
            "nat",
            chain,
            &["-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN"],
        )
    }

    fn apply_tproxy_reply_bypass_rules(&self, family: Family, chain: &str) -> Result<()> {
        if !self.performance_conntrack_enabled() {
            return Ok(());
        }
        self.ensure_rule_append(
            family,
            "mangle",
            chain,
            &["-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN"],
        )
    }
}
