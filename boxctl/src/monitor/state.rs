use super::*;

pub(super) fn save_wifi_state(config: &Config, observation: &WifiObservation) {
    let _ = fs::create_dir_all(&config.paths.state);
    let _ = fs::write(
        config.paths.state.join("last_wifi_state"),
        wifi_state_key(observation),
    );
}

pub(super) fn wifi_state_matches(config: &Config, observation: &WifiObservation) -> bool {
    fs::read_to_string(config.paths.state.join("last_wifi_state"))
        .ok()
        .map(|value| value.trim() == wifi_state_key(observation))
        .unwrap_or(false)
}

pub(super) fn wifi_state_key(observation: &WifiObservation) -> String {
    format!(
        "connected={}|ssid={}|bssid={}|ip={}",
        observation.connected,
        observation.ssid,
        observation.bssid,
        observation.ip.as_deref().unwrap_or("")
    )
}

pub(super) fn control_log_key(config: &Config, key: LogKey, args: &[logger::LogArg]) {
    if !config.wifi_enable_log {
        return;
    }
    logger::net_info_key(config, key, args);
}
