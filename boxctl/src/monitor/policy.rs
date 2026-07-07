use super::*;

pub(super) fn apply_network_control_policy(
    config: &Config,
    runner: &Runner,
    mut observation: WifiObservation,
) -> Result<NetworkPolicyResult> {
    if !config.wifi_network_control_enabled {
        return Ok(NetworkPolicyResult {
            observation,
            handled: true,
        });
    }

    if observation.connected {
        refresh_connected_ip(runner, &mut observation);
        if observation.ip.is_none() {
            control_log_key(
                config,
                LogKey::WifiPending,
                &[observation_arg(&observation)],
            );
            return Ok(NetworkPolicyResult {
                observation,
                handled: false,
            });
        }
    }

    let should_enable = should_enable_service(config, &observation);
    let action = if should_enable {
        start_service_if_needed(config, runner)
    } else {
        stop_service_if_needed(config, runner)
    };

    match action {
        Ok(action) => control_log_key(
            config,
            LogKey::WifiPolicyApplied,
            &[
                observation_arg(&observation),
                policy_arg(should_enable),
                action_arg(action),
            ],
        ),
        Err(err) => {
            control_log_key(
                config,
                LogKey::WifiPolicyFailed,
                &[
                    observation_arg(&observation),
                    policy_arg(should_enable),
                    arg("error", &err),
                ],
            );
            return Err(err);
        }
    }

    Ok(NetworkPolicyResult {
        observation,
        handled: true,
    })
}

pub(super) fn refresh_connected_ip(runner: &Runner, observation: &mut WifiObservation) {
    if observation.ip.is_some() {
        return;
    }

    for attempt in 1..WIFI_IP_RETRIES {
        thread::sleep(Duration::from_millis(WIFI_IP_RETRY_DELAY_MS));
        observation.ip = get_wifi_ip(runner, &observation.iface);
        if observation.ip.is_some() || attempt + 1 >= WIFI_IP_RETRIES {
            break;
        }
    }
}

pub(super) fn run_ip_monitor_once(config: &Config, runner: &Runner) -> Result<()> {
    let mut child = Command::new("ip")
        .args(["monitor", "link", "address", "route"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("start ip monitor failed: {err}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "cannot read ip monitor output".to_string())?;
    let (tx, rx) = mpsc::channel::<()>();
    let reader_handle = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            let read = match reader.read_line(&mut line) {
                Ok(read) => read,
                Err(_) => break,
            };
            if read == 0 {
                break;
            }
            if !line.trim().is_empty() && tx.send(()).is_err() {
                break;
            }
        }
    });

    let mut live = LiveConfigCache::new();
    let mut iface_cache: Option<String> = None;

    reconcile_network_state(config, runner, &mut live, &mut iface_cache);

    while rx.recv().is_ok() {
        wait_for_network_event_quiet(&rx);
        reconcile_network_state(config, runner, &mut live, &mut iface_cache);
    }

    let _ = child.kill();
    let status = child
        .wait()
        .map_err(|err| format!("wait for ip monitor exit failed: {err}"))?;
    let _ = reader_handle.join();
    if !status.success() {
        return Err(format!("ip monitor exited: {status}"));
    }
    Ok(())
}

fn reconcile_network_state(
    config: &Config,
    runner: &Runner,
    live: &mut LiveConfigCache,
    iface_cache: &mut Option<String>,
) {
    let live_config = live.get(config);
    if let Err(err) = handle_network_change(live_config, runner, iface_cache) {
        logger::warn_key(
            live_config,
            LogKey::NetworkRecalcFailed,
            &[arg("error", err)],
        );
    }
}

const LIVE_CONFIG_TTL: Duration = Duration::from_secs(5);

struct LiveConfigCache {
    cached: Option<Config>,
    loaded_at: Option<Instant>,
}

impl LiveConfigCache {
    fn new() -> Self {
        Self {
            cached: None,
            loaded_at: None,
        }
    }

    fn get(&mut self, base: &Config) -> &Config {
        let fresh = self
            .loaded_at
            .map(|at| at.elapsed() < LIVE_CONFIG_TTL)
            .unwrap_or(false);
        if !fresh {
            self.cached = Some(load_live_config(base));
            self.loaded_at = Some(Instant::now());
        }
        self.cached.as_ref().unwrap()
    }
}

pub(super) fn wait_for_network_event_quiet(rx: &mpsc::Receiver<()>) {
    let started = Instant::now();
    let quiet = Duration::from_millis(WIFI_EVENT_DEBOUNCE_MS);
    let max_wait = Duration::from_millis(WIFI_EVENT_MAX_DEBOUNCE_MS);
    loop {
        match rx.recv_timeout(quiet) {
            Ok(()) if started.elapsed() < max_wait => continue,
            Ok(()) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

pub(super) fn start_service_if_needed(config: &Config, runner: &Runner) -> Result<ServiceAction> {
    if service::is_running(config, runner) {
        return Ok(ServiceAction::AlreadyRunning);
    }

    run_boxctl_service_command(config, "up")?;
    Ok(ServiceAction::Started)
}

pub(super) fn stop_service_if_needed(config: &Config, runner: &Runner) -> Result<ServiceAction> {
    if !service::is_running(config, runner) {
        return Ok(ServiceAction::AlreadyStopped);
    }

    run_boxctl_service_command(config, "down")?;
    Ok(ServiceAction::Stopped)
}

fn run_boxctl_service_command(config: &Config, action: &str) -> Result<()> {
    let exe = env::current_exe().unwrap_or_else(|_| config.paths.bin.join("boxctl"));
    let status = Command::new(&exe)
        .arg("--db")
        .arg(config.paths.db.as_os_str())
        .arg(action)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("execute {} {action} failed: {err}", exe.display()))?;
    if !status.success() {
        return Err(format!(
            "execute {} {action} exited: {status}",
            exe.display()
        ));
    }
    Ok(())
}

pub(super) fn refresh_local_ip_rules_if_running(config: &Config, runner: &Runner) -> Result<()> {
    if !service::is_running(config, runner) {
        return Ok(());
    }
    rules::refresh_local_ip_rules(config, runner)
}

pub(super) fn should_enable_service(config: &Config, observation: &WifiObservation) -> bool {
    if !observation.connected {
        return config.wifi_use_on_disconnect;
    }

    if !config.wifi_use_on_connect {
        return false;
    }

    if !config.wifi_enable_ssid_matching {
        return true;
    }

    let matched = if !config.wifi_bssids.is_empty() && observation.bssid != "unknown" {
        contains_exact(&config.wifi_bssids, &observation.bssid)
    } else if !config.wifi_ssids.is_empty() {
        contains_exact(&config.wifi_ssids, &observation.ssid)
    } else {
        false
    };

    if matched {
        config.wifi_list_mode == "whitelist"
    } else {
        config.wifi_list_mode != "whitelist"
    }
}

pub(super) fn observation_arg(observation: &WifiObservation) -> logger::LogArg {
    logger::wifi_observation_arg(
        "observation",
        observation.connected,
        &observation.ssid,
        &observation.bssid,
        &observation.iface,
        observation.ip.as_deref(),
    )
}

pub(super) fn policy_arg(enabled: bool) -> logger::LogArg {
    logger::wifi_policy_arg("policy", enabled)
}

pub(super) fn action_arg(action: ServiceAction) -> logger::LogArg {
    logger::wifi_action_arg("action", action.log_id())
}
