use crate::config::Config;
use crate::core_config;
use crate::exec::Runner;
use crate::{logger, monitor, rules, service, wifi, Result};
use logger::{arg, LogKey};
use std::thread;

pub fn up(config: &Config, runner: &Runner) -> Result<()> {
    logger::info_key(config, LogKey::StartupBegin, &logger::startup_args(config));
    if let Err(err) = core_config::sync(config) {
        log_startup_failed(config, &err);
        return Err(err);
    }

    let (service_result, rules_result) = thread::scope(|scope| {
        let rules_handle = scope.spawn(|| rules::apply(config, runner));
        let service_result = service::start(config, runner);
        let rules_result = join_result(rules_handle.join(), "inbound rules thread panicked");
        (service_result, rules_result)
    });

    if let Err(err) = service_result {
        let _ = rules::clear(config, runner);
        log_startup_failed(config, &err);
        return Err(err);
    }
    if let Err(err) = rules_result {
        log_startup_failed(config, &err);
        return Err(err);
    }
    if let Err(err) = monitor::run(config, runner) {
        log_startup_failed(config, &err);
        return Err(err);
    }
    logger::info_key(config, LogKey::StartupCompleted, &[]);
    Ok(())
}

pub fn boot(config: &Config, runner: &Runner) -> Result<()> {
    if config.wifi_network_control_enabled {
        wifi::apply(config, runner)?;
        monitor::run(config, runner)?;
        return Ok(());
    }

    up(config, runner)
}

pub fn down(config: &Config, runner: &Runner) -> Result<()> {
    logger::warn_key(
        config,
        LogKey::StopBegin,
        &[
            arg("core", &config.bin_name),
            arg("mode", &config.network_mode),
        ],
    );

    let (rules_result, service_result) = thread::scope(|scope| {
        let service_handle = scope.spawn(|| service::stop(config, runner));
        let rules_result = rules::clear(config, runner);
        let service_result = join_result(service_handle.join(), "service stop thread panicked");
        (rules_result, service_result)
    });

    rules_result?;
    service_result?;
    monitor::run(config, runner)?;
    logger::warn_key(config, LogKey::StopCompleted, &[]);
    Ok(())
}

pub fn restart(config: &Config, runner: &Runner) -> Result<()> {
    logger::warn_key(
        config,
        LogKey::RestartBegin,
        &[
            arg("core", &config.bin_name),
            arg("mode", &config.network_mode),
        ],
    );
    down(config, runner)?;
    up(config, runner)
}

pub fn status(config: &Config, runner: &Runner) -> Result<()> {
    logger::info_key(
        config,
        LogKey::StatusSummary,
        &[
            arg("core", &config.bin_name),
            arg("mode", &config.network_mode),
            arg("tun", &config.tun_device),
            arg("tproxy", &config.tproxy_port),
            arg("redir", &config.redir_port),
            arg(
                "dns",
                format!("{}:{}", config.dns_hijack_mode, config.mihomo_dns_port),
            ),
            logger::enabled_arg("performance", config.performance_mode),
        ],
    );
    logger::info_key(
        config,
        LogKey::CoreConfigRead,
        &logger::core_config_args(config),
    );
    service::status(config, runner)
}

fn join_result(joined: std::thread::Result<Result<()>>, message: &str) -> Result<()> {
    match joined {
        Ok(result) => result,
        Err(_) => Err(message.to_string()),
    }
}

fn log_startup_failed(config: &Config, error: &str) {
    logger::error_key(config, LogKey::StartupFailed, &[arg("error", error)]);
}
