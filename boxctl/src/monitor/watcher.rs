use super::*;

pub(super) fn monitor_worker_requested() -> bool {
    env::var_os(MONITOR_WORKER_ENV).is_some()
}

pub(super) fn monitor_worker(config: &Config, runner: &Runner) -> Result<()> {
    let Some(_lock) = acquire_monitor_lock(config)? else {
        return Ok(());
    };

    if !monitor_required(config, runner) {
        return Ok(());
    }

    loop {
        match run_ip_monitor_once(config, runner) {
            Ok(()) => {}
            Err(err) => {
                let live_config = load_live_config(config);
                logger::warn_key(
                    &live_config,
                    LogKey::WifiMonitorRestarted,
                    &[arg("error", err)],
                )
            }
        }
        let live_config = load_live_config(config);
        if !monitor_required(&live_config, runner) {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(2));
    }
}

pub(super) fn monitor_required(config: &Config, runner: &Runner) -> bool {
    if config.wifi_network_control_enabled {
        return true;
    }

    service::is_running(config, runner) && config.network_mode != "tun"
}

pub(super) fn monitor_worker_running(config: &Config) -> bool {
    let path = monitor_lock_path(config);
    if let Some(pid) = read_monitor_pid(&path) {
        if monitor_pid_matches(pid) {
            return true;
        }
        let _ = fs::remove_file(path);
    }
    false
}

pub(super) fn stop_monitor_worker(config: &Config, runner: &Runner) -> Result<()> {
    let path = monitor_lock_path(config);
    let Some(pid) = read_monitor_pid(&path) else {
        return Ok(());
    };

    if !monitor_pid_matches(pid) {
        let _ = fs::remove_file(path);
        return Ok(());
    }

    logger::info_key(config, LogKey::WifiMonitorStopped, &[]);
    signal_monitor_process_group(runner, pid, SIGTERM);
    for _ in 0..20 {
        if !monitor_pid_matches(pid) {
            let _ = fs::remove_file(&path);
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    signal_monitor_process_group(runner, pid, SIGKILL);
    let _ = fs::remove_file(path);
    Ok(())
}

fn signal_monitor_process_group(runner: &Runner, pid: u32, sig: i32) {
    #[cfg(unix)]
    {
        if let Ok(pid_num) = i32::try_from(pid) {
            runner.signal(-pid_num, sig);
            runner.signal(pid_num, sig);
        }
    }
    #[cfg(not(unix))]
    {
        if let Ok(pid_num) = i32::try_from(pid) {
            runner.signal(pid_num, sig);
        }
    }
}

pub(super) fn spawn_monitor_worker(config: &Config) -> Result<()> {
    let exe = env::current_exe().unwrap_or_else(|_| config.paths.bin.join("boxctl"));
    let mut command = Command::new(exe);
    command
        .arg("--db")
        .arg(config.paths.db.as_os_str())
        .arg("monitor")
        .env(MONITOR_WORKER_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(unix)]
    unsafe {
        command.pre_exec(|| {
            if setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    command
        .spawn()
        .map_err(|err| format!("start Wi-Fi monitor failed: {err}"))?;
    Ok(())
}

pub(super) fn handle_network_change(
    live_config: &Config,
    runner: &Runner,
    iface_cache: &mut Option<String>,
) -> Result<()> {
    let observation = current_observation_cached(runner, iface_cache);
    let state_changed = !wifi_state_matches(live_config, &observation);

    if state_changed {
        let result = apply_network_control_policy(live_config, runner, observation)?;
        if result.handled {
            save_wifi_state(live_config, &result.observation);
        }
    }

    if let Err(err) = refresh_local_ip_rules_if_running(live_config, runner) {
        logger::warn_key(
            live_config,
            LogKey::LocalIpLoopUpdateFailed,
            &[arg("error", err)],
        );
    }
    Ok(())
}

pub(super) fn load_live_config(config: &Config) -> Config {
    Config::load(config.paths.clone(), ConfigOverrides::default()).unwrap_or_else(|err| {
        logger::warn_key(
            config,
            LogKey::RuntimeConfigReadFailed,
            &[arg("error", err)],
        );
        config.clone()
    })
}
