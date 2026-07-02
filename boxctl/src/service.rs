use crate::config::Config;
use crate::core_config;
use crate::exec::{Runner, SIGKILL, SIGTERM};
use crate::logger;
use crate::resource;
use crate::Result;
use logger::{arg, LogKey};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};
mod command;
mod config_check;
mod permissions;
mod process;
mod stamp;
use command::*;
use config_check::*;
use permissions::*;
use process::*;
use stamp::*;

const STOP_WAIT_TOTAL_MS: u64 = 1500;
const STOP_POLL_MIN_MS: u64 = 10;
const STOP_POLL_MAX_MS: u64 = 100;
const STARTUP_PROBE_DELAY_MS: u64 = 300;

pub fn start(config: &Config, runner: &Runner) -> Result<()> {
    match start_inner(config, runner) {
        Ok(()) => Ok(()),
        Err(err) => {
            logger::error_key(config, LogKey::ServiceStartFailed, &[arg("error", &err)]);
            Err(err)
        }
    }
}

fn start_inner(config: &Config, runner: &Runner) -> Result<()> {
    ensure_dirs(config)?;
    validate_core(config)?;
    clear_run_log(config)?;

    logger::info_key(
        config,
        LogKey::ServiceStart,
        &[
            arg("core", &config.bin_name),
            arg("workdir", config.core_dir().display()),
            arg("config", config.config_path().display()),
        ],
    );

    let running = running_core_pids(config);
    if !running.is_empty() {
        logger::warn_key(
            config,
            LogKey::ServiceAlreadyRunningStopOld,
            &[arg("core", &config.bin_name)],
        );
        stop_pids(config, runner, running)?;
    }

    prepare_permissions(config, runner)?;
    core_config::preload_rule_sets(config)?;
    run_config_check(config, runner)?;

    let envs = core_env(config);
    let (program, args) = core_run_command(config);
    logger::debug_key(
        config,
        LogKey::ServiceCommand,
        &[arg(
            "command",
            format!(
                "{} {}",
                program,
                args.iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        )],
    );

    let (uid, gid) = parse_user_group(&config.box_user_group)?;
    let pid =
        runner.spawn_to_file_with_env_as(&program, &args, &config.bin_log, &envs, uid, gid)?;
    let Some(pid) = pid else {
        logger::info_key(
            config,
            LogKey::ServicePreviewNotStarted,
            &[arg("core", &config.bin_name)],
        );
        return Ok(());
    };

    if !runner.dry_run() {
        fs::write(&config.box_pid, pid.to_string())
            .map_err(|err| format!("write PID {} failed: {err}", config.box_pid.display()))?;
    }

    if !runner.dry_run() {
        thread::sleep(Duration::from_millis(STARTUP_PROBE_DELAY_MS));
        if !pid_matches_core(config, &pid.to_string()) {
            let _ = remove_pid(config);
            let detail = read_log_tail(&config.bin_log);
            let detail = if detail.is_empty() {
                "-"
            } else {
                detail.as_str()
            };
            logger::error_key(
                config,
                LogKey::ServiceExitedAfterStart,
                &[arg("core", &config.bin_name), arg("detail", detail)],
            );
            return Err(format!(
                "core {} exited immediately after start",
                config.bin_name
            ));
        }
    }

    logger::info_key(
        config,
        LogKey::ServiceStarted,
        &[arg("core", &config.bin_name), arg("pid", pid)],
    );
    resource::apply(config, pid)?;
    Ok(())
}

fn read_log_tail(path: &Path) -> String {
    let Ok(text) = fs::read_to_string(path) else {
        return String::new();
    };
    let mut tail: Vec<&str> = text
        .lines()
        .rev()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(3)
        .collect();
    tail.reverse();
    tail.join(" | ")
}

pub fn stop(config: &Config, runner: &Runner) -> Result<()> {
    logger::warn_key(
        config,
        LogKey::ServiceStop,
        &[
            arg("core", &config.bin_name),
            arg("pid_file", config.box_pid.display()),
        ],
    );

    let running = running_core_pids(config);
    if running.is_empty() {
        remove_pid(config)?;
        logger::warn_key(
            config,
            LogKey::ServiceNotRunning,
            &[arg("core", &config.bin_name)],
        );
        return Ok(());
    }

    stop_pids(config, runner, running)
}

pub fn status(config: &Config, _runner: &Runner) -> Result<()> {
    logger::info_key(
        config,
        LogKey::ServiceStatus,
        &[
            arg("core", &config.bin_name),
            arg("pid_file", config.box_pid.display()),
        ],
    );

    if let Some(pid) = pid_from_file_if_core(config) {
        logger::debug_key(
            config,
            LogKey::ServiceRunning,
            &[arg("core", &config.bin_name), arg("pid", pid)],
        );
        return Ok(());
    }

    let pids = running_core_pids(config)
        .into_iter()
        .map(|(bin, pid)| format!("{bin}:{pid}"))
        .collect::<Vec<_>>();
    if pids.is_empty() {
        logger::warn_key(
            config,
            LogKey::ServiceNotRunningPlain,
            &[arg("core", &config.bin_name)],
        );
    } else {
        logger::debug_key(
            config,
            LogKey::ServiceRunning,
            &[arg("core", &config.bin_name), arg("pid", pids.join(" "))],
        );
    }
    Ok(())
}

pub fn is_running(config: &Config, _runner: &Runner) -> bool {
    current_core_pid(config, _runner).is_some()
}

pub fn current_core_pid(config: &Config, _runner: &Runner) -> Option<u32> {
    pid_from_file_if_core(config).and_then(|pid| pid.parse::<u32>().ok())
}

fn ensure_dirs(config: &Config) -> Result<()> {
    for path in [&config.paths.run, &config.paths.state] {
        fs::create_dir_all(path)
            .map_err(|err| format!("create directory {} failed: {err}", path.display()))?;
        logger::debug_key(
            config,
            LogKey::DirectoryChecked,
            &[arg("path", path.display())],
        );
    }
    Ok(())
}

fn clear_run_log(config: &Config) -> Result<()> {
    for path in logger::log_paths(&config.box_log) {
        fs::write(&path, "")
            .map_err(|err| format!("clear log {} failed: {err}", path.display()))?;
    }
    for path in logger::log_paths(&logger::net_log_path(config)) {
        fs::write(&path, "")
            .map_err(|err| format!("clear log {} failed: {err}", path.display()))?;
    }
    Ok(())
}

fn validate_core(config: &Config) -> Result<()> {
    logger::debug_key(
        config,
        LogKey::CoreCheck,
        &[
            arg("bin", config.bin_path.display()),
            arg("config", config.config_path().display()),
        ],
    );

    match config.bin_name.as_str() {
        "mihomo" | "sing-box" | "xray" | "v2fly" | "hysteria" => {}
        other => return Err(format!("unknown core: {other}")),
    }

    if !config.bin_path.exists() {
        return Err(format!("core not detected: {}", config.bin_path.display()));
    }
    if config.config_name.trim().is_empty() {
        return Err("config file not selected".to_string());
    }
    if !config.config_path().is_file() {
        return Err(format!(
            "config file not detected: {}",
            config.config_path().display()
        ));
    }
    Ok(())
}
