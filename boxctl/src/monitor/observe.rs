use super::*;

pub(super) fn current_observation(runner: &Runner) -> WifiObservation {
    observe_with_iface(runner, &mut None)
}

pub(super) fn current_observation_cached(
    runner: &Runner,
    iface_cache: &mut Option<String>,
) -> WifiObservation {
    observe_with_iface(runner, iface_cache)
}

fn observe_with_iface(runner: &Runner, iface_cache: &mut Option<String>) -> WifiObservation {
    let wifi_status = run_output(runner, "cmd", &["wifi", "status"]);
    let iface = resolve_wifi_iface(runner, wifi_status.as_deref(), iface_cache);
    let ssid = get_current_ssid(runner, &iface, wifi_status.as_deref());
    let bssid = get_current_bssid(runner, &iface, wifi_status.as_deref());
    let connected = if wifi_status.is_some() {
        wifi_status_connected(wifi_status.as_deref(), &ssid, &bssid)
    } else {
        wifi_iface_has_address(runner, &iface)
    };
    let ip = if connected {
        get_wifi_ip(runner, &iface)
    } else {
        None
    };

    WifiObservation {
        connected,
        ssid,
        bssid,
        iface,
        ip,
    }
}

fn resolve_wifi_iface(
    runner: &Runner,
    wifi_status: Option<&str>,
    iface_cache: &mut Option<String>,
) -> String {
    if let Some(cached) = iface_cache.as_deref() {
        if runner.run_ok("ip", &["link", "show", cached]) {
            return cached.to_string();
        }
    }

    let iface = get_wifi_iface(runner, wifi_status);
    *iface_cache = Some(iface.clone());
    iface
}

pub(super) fn get_wifi_iface(runner: &Runner, wifi_status: Option<&str>) -> String {
    if let Some(iface) = wifi_status.and_then(parse_client_mode_iface) {
        if runner.run_ok("ip", &["link", "show", iface.as_str()]) {
            return iface;
        }
    }

    if let Some(iface) =
        run_output(runner, "getprop", &["wifi.interface"]).map(|value| value.trim().to_string())
    {
        if is_wifi_iface_name(&iface) && runner.run_ok("ip", &["link", "show", iface.as_str()]) {
            return iface;
        }
    }

    if let Some(text) = run_output(runner, "ip", &["link"]) {
        for line in text.lines() {
            let trimmed = line.trim();
            let Some((_, right)) = trimmed.split_once(": ") else {
                continue;
            };
            if right.starts_with("wlan") || right.starts_with("swlan") {
                let iface = right
                    .split_whitespace()
                    .next()
                    .unwrap_or("wlan0")
                    .trim_end_matches(':')
                    .split('@')
                    .next()
                    .unwrap_or("wlan0");
                if !iface.is_empty() && runner.run_ok("ip", &["link", "show", iface]) {
                    return iface.to_string();
                }
            }
        }
    }

    if let Some(text) = run_output(runner, "ip", &["route"]) {
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.first() == Some(&"default") {
                for (index, part) in parts.iter().enumerate() {
                    if *part == "dev" {
                        if let Some(iface) = parts.get(index + 1) {
                            if is_wifi_iface_name(iface)
                                && runner.run_ok("ip", &["link", "show", *iface])
                            {
                                return (*iface).to_string();
                            }
                        }
                    }
                }
            }
        }
    }

    "wlan0".to_string()
}

pub(super) fn wifi_iface_has_address(runner: &Runner, iface: &str) -> bool {
    run_output(runner, "ip", &["addr", "show", iface])
        .map(|text| {
            text.lines().any(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("inet ")
                    || (trimmed.starts_with("inet6 ") && trimmed.contains(" scope global"))
            })
        })
        .unwrap_or(false)
}

pub(super) fn get_current_ssid(runner: &Runner, iface: &str, wifi_status: Option<&str>) -> String {
    let mut ssid = wifi_status.and_then(|text| parse_quoted_label(text, "SSID"));

    if option_empty_or(ssid.as_deref(), |value| value == "<unknown ssid>") {
        ssid = run_output(runner, "iw", &["dev", iface, "link"]).and_then(|text| {
            extract_after_prefix(&text, "SSID:").map(|value| {
                value
                    .trim_matches('"')
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
        });
    }

    if option_empty_or(ssid.as_deref(), |value| value == "<unknown ssid>") {
        ssid = run_output(runner, "iwconfig", &[iface]).and_then(|text| {
            extract_after_prefix(&text, "ESSID:").map(|value| {
                value
                    .trim_matches('"')
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
        });
    }

    match ssid.map(|value| value.trim().to_string()) {
        Some(value) if !value.is_empty() && value != "off/any" => value,
        _ => "unknown".to_string(),
    }
}

pub(super) fn get_current_bssid(runner: &Runner, iface: &str, wifi_status: Option<&str>) -> String {
    let mut bssid = wifi_status.and_then(parse_bssid_label);

    if option_empty_or(bssid.as_deref(), |value| value == "<none>") {
        bssid = run_output(runner, "iw", &["dev", iface, "link"])
            .and_then(|text| extract_connected_to(&text));
    }

    if option_empty_or(bssid.as_deref(), |value| value == "Not-Associated") {
        bssid = run_output(runner, "iwconfig", &[iface])
            .and_then(|text| extract_after_prefix(&text, "Access Point:"));
    }

    match bssid.map(normalize_bssid) {
        Some(value) if !value.is_empty() && value != "00:00:00:00:00:00" => value,
        _ => "unknown".to_string(),
    }
}

pub(super) fn get_wifi_ip(runner: &Runner, iface: &str) -> Option<String> {
    run_output(runner, "ip", &["addr", "show", iface]).and_then(|text| extract_ipv4(&text))
}

pub(super) fn run_output(runner: &Runner, program: &str, args: &[&str]) -> Option<String> {
    // `Runner::run` accepts `&[impl AsRef<str>]`, so the `&[&str]` goes straight
    // through with no intermediate `Vec<String>` allocation on this per-event path.
    runner
        .run(program, args)
        .ok()
        .and_then(|output| {
            let stdout = output.stdout.trim().to_string();
            if stdout.is_empty() {
                None
            } else {
                Some(stdout)
            }
        })
        .filter(|text| !text.trim().is_empty())
}

pub(super) fn parse_client_mode_iface(text: &str) -> Option<String> {
    for line in text.lines() {
        let Some((_, rest)) = line.split_once("iface=") else {
            continue;
        };
        let iface = rest
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
            .collect::<String>();
        if is_wifi_iface_name(&iface) {
            return Some(iface);
        }
    }
    None
}

pub(super) fn is_wifi_iface_name(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && (trimmed.starts_with("wlan")
            || trimmed.starts_with("swlan")
            || trimmed.starts_with("wifi"))
}

pub(super) fn wifi_status_connected(text: Option<&str>, ssid: &str, bssid: &str) -> bool {
    let Some(text) = text else {
        return false;
    };
    let has_identity = is_valid_ssid(ssid) || is_valid_bssid(bssid);
    if !has_identity {
        return false;
    }
    text.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("Wifi is connected to ")
            || trimmed.contains("Supplicant state: COMPLETED")
    })
}

pub(super) fn parse_quoted_label(text: &str, label: &str) -> Option<String> {
    let prefix = format!("{label}: \"");
    for line in text.lines() {
        let Some((_, rest)) = line.split_once(&prefix) else {
            continue;
        };
        if let Some(value) = rest.split('"').next() {
            if is_valid_ssid(value) {
                return Some(value.to_string());
            }
        }
    }
    None
}

pub(super) fn parse_bssid_label(text: &str) -> Option<String> {
    for line in text.lines() {
        let Some((_, rest)) = line.split_once("BSSID:") else {
            continue;
        };
        let value: String = rest
            .trim_start()
            .chars()
            .take_while(|ch| ch.is_ascii_hexdigit() || *ch == ':')
            .collect();
        if is_valid_bssid(&value) {
            return Some(value);
        }
    }
    None
}

pub(super) fn is_valid_ssid(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty() && trimmed != "<unknown ssid>" && trimmed != "unknown"
}

pub(super) fn is_valid_bssid(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed != "<none>"
        && trimmed != "unknown"
        && trimmed != "00:00:00:00:00:00"
}

pub(super) fn extract_connected_to(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Connected to ") {
            return Some(rest.split_whitespace().next()?.to_string());
        }
    }
    None
}

pub(super) fn extract_after_prefix(text: &str, prefix: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.split_once(prefix).map(|(_, right)| right.trim()) {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

pub(super) fn extract_ipv4(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            return Some(
                rest.split_whitespace()
                    .next()?
                    .split('/')
                    .next()?
                    .to_string(),
            );
        }
    }
    None
}

pub(super) fn normalize_bssid(raw: String) -> String {
    raw.split_whitespace()
        .next()
        .unwrap_or("")
        .split('(')
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase()
}

pub(super) fn contains_exact(values: &[String], needle: &str) -> bool {
    values.iter().any(|value| value == needle)
}

pub(super) fn option_empty_or(value: Option<&str>, predicate: impl FnOnce(&str) -> bool) -> bool {
    match value {
        Some(value) => predicate(value),
        None => true,
    }
}
