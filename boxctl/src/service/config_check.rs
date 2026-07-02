use super::*;

pub(super) fn run_config_check(config: &Config, runner: &Runner) -> Result<()> {
    let (program, args) = core_check_command(config);
    if program.is_empty() {
        logger::debug_key(
            config,
            LogKey::ConfigCheckNoCheck,
            &[arg("core", &config.bin_name)],
        );
        return Ok(());
    }

    if config_check_stamp_matches(config) {
        logger::debug_key(
            config,
            LogKey::ConfigCheckCacheHit,
            &[arg("config", config.service_config_path().display())],
        );
        return Ok(());
    }

    logger::info_key(
        config,
        LogKey::ConfigCheck,
        &[arg("core", &config.bin_name)],
    );
    if runner.dry_run() {
        runner.preview(&program, &args);
        return Ok(());
    }

    let output = runner.run(&program, &args)?;
    let mut log = String::new();
    if !output.stdout.is_empty() {
        log.push_str(&output.stdout);
        log.push('\n');
    }
    if !output.stderr.is_empty() {
        log.push_str(&output.stderr);
        log.push('\n');
    }
    fs::write(&config.bin_log, log)
        .map_err(|err| format!("write log {} failed: {err}", config.bin_log.display()))?;

    if output.ok {
        save_config_check_stamp(config)?;
        logger::info_key(
            config,
            LogKey::ConfigCheckPassed,
            &[arg("core", &config.bin_name)],
        );
        Ok(())
    } else {
        logger::error_key(
            config,
            LogKey::ConfigCheckFailed,
            &[
                arg("core", &config.bin_name),
                config_check_failure_detail(config, &output),
            ],
        );
        Err(format!(
            "{} config check failed, see {}",
            config.bin_name,
            config.bin_log.display()
        ))
    }
}

pub(super) fn config_check_stamp_matches(config: &Config) -> bool {
    let Some(stamp) = config_check_stamp(config) else {
        return false;
    };
    fs::read_to_string(config_check_stamp_path(config))
        .map(|saved| saved == stamp)
        .unwrap_or(false)
}

pub(super) fn save_config_check_stamp(config: &Config) -> Result<()> {
    let Some(stamp) = config_check_stamp(config) else {
        return Ok(());
    };
    fs::write(config_check_stamp_path(config), stamp)
        .map_err(|err| format!("write config check stamp failed: {err}"))
}

pub(super) fn config_check_stamp(config: &Config) -> Option<String> {
    Some(format!(
        "core={}\nconfig={}\nmode={}\n",
        file_stamp(&config.bin_path)?,
        file_stamp(&config.service_config_path())?,
        config.network_mode
    ))
}

pub(super) fn config_check_stamp_path(config: &Config) -> PathBuf {
    config
        .paths
        .state
        .join(format!("{}.config-check.stamp", config.bin_name))
}

fn config_check_failure_detail(config: &Config, output: &crate::exec::Output) -> logger::LogArg {
    let mut parts = Vec::new();
    if !output.stderr.trim().is_empty() {
        parts.push(format!("stderr: {}", compact_log_text(&output.stderr)));
    }
    if !output.stdout.trim().is_empty() {
        parts.push(format!("stdout: {}", compact_log_text(&output.stdout)));
    }
    let log_path = config.bin_log.display();
    if parts.is_empty() {
        return logger::arg_i18n(
            "detail",
            format!("no output, see {log_path}"),
            format!("无输出, 见 {log_path}"),
        );
    }
    let joined = parts.join(", ");
    logger::arg_i18n(
        "detail",
        format!("{joined}, see {log_path}"),
        format!("{joined}, 见 {log_path}"),
    )
}

fn compact_log_text(text: &str) -> String {
    const MAX_LEN: usize = 240;
    let compact = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= MAX_LEN {
        return compact;
    }
    let mut shortened = compact.chars().take(MAX_LEN).collect::<String>();
    shortened.push_str("...");
    shortened
}
