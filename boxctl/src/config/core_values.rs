use std::fs;
use std::path::Path;

use jsonc_parser::ParseOptions;

#[derive(Default)]
pub(super) struct CoreConfigValues {
    pub(super) read_status: String,
    pub(super) mihomo_dns_port: Option<String>,
    pub(super) tun_device: Option<String>,
    pub(super) fake_ip_range: Option<String>,
    pub(super) fake_ip6_range: Option<String>,
}

impl CoreConfigValues {
    pub(super) fn read(bin_name: &str, network_mode: &str, config_path: &Path) -> Self {
        let text = match fs::read_to_string(config_path) {
            Ok(text) => text,
            Err(err) => {
                return Self {
                    read_status: format!("read failed: {err}"),
                    ..Self::default()
                };
            }
        };
        match bin_name {
            "mihomo" => Self::read_mihomo(&text, network_mode),
            "sing-box" => Self::read_sing_box(&text, network_mode),
            _ => Self {
                read_status: format!("{bin_name} does not support automatic parsing"),
                ..Self::default()
            },
        }
    }

    fn read_mihomo(text: &str, network_mode: &str) -> Self {
        let values: serde_yaml::Value = serde_yaml::from_str(&text).unwrap();
        Self {
            read_status: "read mihomo config".to_string(),
            mihomo_dns_port: values.get("dns").unwrap().get("listen").and_then(|v| {
                v.as_str()
                    .unwrap()
                    .split_once(':')
                    .and_then(|v| Some(v.1.to_string()))
            }),
            tun_device: if matches!(network_mode, "tun" | "mixed") {
                values.get("tun").and_then(|v| {
                    v.get("device")
                        .map_or_else(|| None, |v| Some(v.as_str().unwrap().to_string()))
                })
            } else {
                None
            },
            fake_ip_range: values
                .get("dns")
                .unwrap()
                .get("fake-ip-range")
                .and_then(|v| Some(v.as_str().unwrap().to_string())),
            fake_ip6_range: values
                .get("dns")
                .unwrap()
                .get("fake-ip-range6")
                .and_then(|v| Some(v.as_str().unwrap().to_string())),
        }
    }

    fn read_sing_box(text: &str, network_mode: &str) -> Self {
        let values: serde_json::Value =
            jsonc_parser::parse_to_serde_value(&text, &ParseOptions::default()).unwrap();
        Self {
            read_status: "read sing-box config".to_string(),
            mihomo_dns_port: None,
            tun_device: if matches!(network_mode, "tun" | "mixed") {
                values
                    .get("inbounds")
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|v| v.get("interface_name").is_some())
                    .and_then(|v| {
                        v.get("interface_name")
                            .and_then(|v| Some(v.as_str().unwrap().to_string()))
                    })

                // json_string_value(text, "interface_name").filter(|value| !value.is_empty())
            } else {
                None
            },
            fake_ip_range: values
                .get("dns")
                .unwrap()
                .get("servers")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v.get("inet4_range").is_some())
                .and_then(|v| {
                    v.get("inet4_range")
                        .and_then(|v| Some(v.as_str().unwrap().to_string()))
                }),
            fake_ip6_range: values
                .get("dns")
                .unwrap()
                .get("servers")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v.get("inet6_range").is_some())
                .and_then(|v| {
                    v.get("inet6_range")
                        .and_then(|v| Some(v.as_str().unwrap().to_string()))
                }),
        }
    }
}

pub(super) fn value_source(
    override_value: &Option<String>,
    db_value: &Option<String>,
    core_value: &Option<String>,
    default_value: &str,
    applicable: bool,
    prefer_db: bool,
) -> &'static str {
    if override_value
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        return "CLI";
    }
    if core_value
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        return "core config";
    }
    if prefer_db
        && db_value
            .as_deref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    {
        return "App config";
    }
    if !applicable {
        return "not applicable";
    }
    if !default_value.trim().is_empty() {
        return "default";
    }
    "unset"
}

pub(super) fn non_empty_value(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

pub(super) fn default_mihomo_dns_port(bin_name: &str) -> String {
    if bin_name == "mihomo" {
        "1053".to_string()
    } else {
        String::new()
    }
}

pub(super) fn default_tun_device(bin_name: &str, network_mode: &str) -> String {
    if !matches!(network_mode, "tun" | "mixed") {
        return String::new();
    }
    match bin_name {
        "mihomo" => "meta".to_string(),
        "sing-box" => "sing".to_string(),
        _ => String::new(),
    }
}

pub(super) fn default_fake_ip_range(bin_name: &str) -> String {
    if bin_name == "mihomo" {
        "198.18.0.1/16".to_string()
    } else {
        String::new()
    }
}

pub(super) fn default_fake_ip6_range(bin_name: &str) -> String {
    if bin_name == "mihomo" {
        "fc00::/18".to_string()
    } else {
        String::new()
    }
}
