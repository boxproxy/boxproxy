use crate::config::Config;
use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const STDOUT_LOG_LINE_ENV: &str = "BOXCTL_STDOUT_LOG_LINE";

mod args;
mod catalog;
mod time;

pub(crate) use time::timestamp;

#[derive(Clone, Copy, Debug)]
enum Lang {
    En,
    ZhCn,
}

#[derive(Clone, Debug)]
pub struct LogArg {
    key: &'static str,
    en: String,
    zh: String,
}

#[derive(Clone, Copy, Debug)]
pub enum LogKey {
    StartupBegin,
    StartupCompleted,
    StartupFailed,
    StopBegin,
    StopCompleted,
    RestartBegin,
    StatusSummary,
    CoreConfigRead,
    CoreConfigSyncDisabled,
    CoreConfigSyncUnsupported,
    CoreConfigSyncBegin,
    CoreConfigSyncUpdated,
    CoreConfigSyncNoChange,
    ServiceStart,
    ServiceStartFailed,
    ServiceExitedAfterStart,
    ServiceAlreadyRunningStopOld,
    ServiceCommand,
    ServiceStarted,
    ServiceStop,
    ServiceNotRunning,
    ServiceStatus,
    ServiceRunning,
    ServiceNotRunningPlain,
    ServicePreviewNotStarted,
    ServiceSendSigterm,
    ServiceStopped,
    ServiceForceStopAfterSigterm,
    DirectoryChecked,
    CoreCheck,
    CorePermissionsUpToDate,
    CorePermissionsChecked,
    CorePermissionsFailed,
    ConfigCheck,
    ConfigCheckNoCheck,
    ConfigCheckCacheHit,
    ConfigCheckPassed,
    ConfigCheckFailed,
    WifiMonitorStopped,
    WifiMonitorRestarted,
    WifiPending,
    WifiPolicyApplied,
    WifiPolicyFailed,
    RuntimeConfigReadFailed,
    LocalIpLoopUpdateFailed,
    NetworkRecalcFailed,
    LocalIpLoopRefreshed,
    Ipv6SystemModeRefreshed,
    ResourceDisabled,
    ResourceApplied,
    ResourcePartiallyFailed,
    InboundRulesApplied,
    InboundRulesClearing,
    InboundRulesCleared,
    RuleModeCreating,
    RuleTunCreating,
    FamilyRulesCreated,
    FamilyRuleFailed,
    FamilyRulesSkipped,
    Ip6NatUnavailable,
    Ipv6DnsFallbackApplied,
    CoreBypassFallback,
    PerformanceAddrtypeFallback,
    DnsCoreBypassFailed,
    ProxyModeInvalid,
    HotspotWhitelistEmpty,
    QuicBlockRuleFailed,
    TunCoreBypassFailed,
    RuleContext,
    PerformanceModeDisabled,
    PerformanceModeEnabled,
    VendorFirewallCleanup,
    CnipSkipDisabled,
    CnipSkipEbpf,
    CnipModeSkipIpset,
    CnipIpsetUnavailable,
    CnipIpsetRefreshed,
    CnipEbpfRefreshed,
    CnipFileMissing,
    CnipUnchanged,
    CnipImported,
    CnipKeepIpset,
    CnipEbpfLoaded,
    EbpfUnsupported,
    EbpfMapHotUpdated,
    EbpfMapHotUpdateFailed,
    TunDeviceDetected,
    TunDeviceMissing,
    IptablesInsertRuleFailed,
    CommandFailure,
}

pub fn arg(key: &'static str, value: impl ToString) -> LogArg {
    let value = value.to_string();
    LogArg {
        key,
        en: value.clone(),
        zh: value,
    }
}

pub fn arg_i18n(key: &'static str, en: impl ToString, zh: impl ToString) -> LogArg {
    LogArg {
        key,
        en: en.to_string(),
        zh: zh.to_string(),
    }
}

pub use args::*;

pub fn debug_key(config: &Config, key: LogKey, args: &[LogArg]) {
    write_key(config, "Debug", key, args, &config.box_log);
}

pub fn info_key(config: &Config, key: LogKey, args: &[LogArg]) {
    write_key(config, "Info", key, args, &config.box_log);
}

pub fn warn_key(config: &Config, key: LogKey, args: &[LogArg]) {
    write_key(config, "Warn", key, args, &config.box_log);
}

pub fn error_key(config: &Config, key: LogKey, args: &[LogArg]) {
    write_key(config, "Error", key, args, &config.box_log);
}

pub fn net_info_key(config: &Config, key: LogKey, args: &[LogArg]) {
    write_key(config, "Info", key, args, &net_log_path(config));
}

pub(crate) fn console_error(message: impl AsRef<str>) {
    let message = message.as_ref().trim();
    if stdout_log_line_enabled() {
        eprintln!("{} [Error] {}", timestamp(), message);
    } else {
        eprintln!("Error: {message}");
    }
}

pub(crate) fn log_paths(base: &Path) -> Vec<PathBuf> {
    vec![base.to_path_buf()]
}

pub(crate) fn net_log_path(config: &Config) -> PathBuf {
    config.paths.run.join("net.log")
}

fn write_key(config: &Config, level: &str, key: LogKey, args: &[LogArg], base: &Path) {
    let now = timestamp();
    let selected = render(key, args, lang_from_config(config));
    let selected_line = format!("{now} [{level}] {selected}");
    write_console(level, &selected_line, &selected);
    write_line(base, &selected_line);
}

fn write_console(level: &str, line: &str, message: &str) {
    let console_line = if stdout_log_line_enabled() {
        line
    } else {
        message
    };
    match level {
        "Error" => eprintln!("{console_line}"),
        _ => println!("{console_line}"),
    }
}

fn log_handles() -> &'static Mutex<HashMap<PathBuf, File>> {
    static HANDLES: OnceLock<Mutex<HashMap<PathBuf, File>>> = OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn write_line(path: &Path, line: &str) {
    let mut record = String::with_capacity(line.len() + 1);
    record.push_str(line);
    record.push('\n');

    let mut handles = match log_handles().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    if !handles.contains_key(path) {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(file) => {
                handles.insert(path.to_path_buf(), file);
            }
            Err(_) => return,
        }
    }

    if let Some(file) = handles.get_mut(path) {
        if file.write_all(record.as_bytes()).is_err() {
            handles.remove(path);
        }
    }
}

fn render(key: LogKey, args: &[LogArg], lang: Lang) -> String {
    let mut text = catalog::template(key, lang).to_string();
    for arg in args {
        let placeholder = format!("{{{}}}", arg.key);
        text = text.replace(&placeholder, arg.value(lang));
    }
    text
}

impl LogArg {
    fn value(&self, lang: Lang) -> &str {
        match lang {
            Lang::En => &self.en,
            Lang::ZhCn => &self.zh,
        }
    }

    pub(crate) fn en_value(&self) -> &str {
        &self.en
    }

    pub(crate) fn zh_value(&self) -> &str {
        &self.zh
    }
}

fn lang_from_config(config: &Config) -> Lang {
    if config.log_language == "en" {
        Lang::En
    } else {
        Lang::ZhCn
    }
}

fn display_value(value: &str) -> &str {
    if value.trim().is_empty() {
        "-"
    } else {
        value.trim()
    }
}

fn performance_reason_list_en(reasons: &[PerformanceFallbackReason]) -> String {
    reasons
        .iter()
        .map(|reason| match reason {
            PerformanceFallbackReason::MissingConntrack => "missing conntrack",
            PerformanceFallbackReason::MissingConnmark => "missing connmark",
            PerformanceFallbackReason::MissingConnmarkTarget => "missing CONNMARK",
            PerformanceFallbackReason::MissingSocketTransparent => "missing socket transparent",
            PerformanceFallbackReason::UdpNotEnabled => "UDP not enabled",
            PerformanceFallbackReason::ConditionsNotMet => "conditions not met",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn performance_reason_list_zh(reasons: &[PerformanceFallbackReason]) -> String {
    reasons
        .iter()
        .map(|reason| match reason {
            PerformanceFallbackReason::MissingConntrack => "缺少 conntrack",
            PerformanceFallbackReason::MissingConnmark => "缺少 connmark",
            PerformanceFallbackReason::MissingConnmarkTarget => "缺少 CONNMARK",
            PerformanceFallbackReason::MissingSocketTransparent => "缺少 socket transparent",
            PerformanceFallbackReason::UdpNotEnabled => "UDP 未启用",
            PerformanceFallbackReason::ConditionsNotMet => "条件未满足",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn uid_fallback_en(fallback: PerformanceUidFallback) -> &'static str {
    match fallback {
        PerformanceUidFallback::BpfMatchUnavailable => "iptables bpf match unavailable",
        PerformanceUidFallback::BoxbpfMissing => "boxbpf not found",
        PerformanceUidFallback::Ipv4ProgramMissing => "IPv4 program not loaded",
        PerformanceUidFallback::Ipv6ProgramMissing => "IPv6 program not loaded",
    }
}

fn uid_fallback_zh(fallback: PerformanceUidFallback) -> &'static str {
    match fallback {
        PerformanceUidFallback::BpfMatchUnavailable => "iptables bpf 匹配不可用",
        PerformanceUidFallback::BoxbpfMissing => "boxbpf 不存在",
        PerformanceUidFallback::Ipv4ProgramMissing => "IPv4 程序未加载",
        PerformanceUidFallback::Ipv6ProgramMissing => "IPv6 程序未加载",
    }
}

fn stdout_log_line_enabled() -> bool {
    env::var_os(STDOUT_LOG_LINE_ENV).is_some()
}
