use crate::Result;
use rusqlite::Connection;
use std::path::Path;
mod read;
mod schema;
use read::*;
use schema::*;

#[derive(Clone, Debug)]
pub struct RuntimeData {
    pub log_language: String,
    pub core_name: String,
    pub mode: String,
    pub proxy_mode: String,
    pub auto_sync_config: bool,
    pub performance_mode: bool,
    pub clean_vendor_firewall: bool,
    pub ipv6_mode: String,
    pub config_name: String,
    pub tproxy_port: String,
    pub redir_port: String,
    pub quic: String,
    pub mihomo_dns_forward: String,
    pub mihomo_dns_port: String,
    pub proxy_tcp: bool,
    pub proxy_udp: bool,
    pub dns_hijack_tcp: bool,
    pub dns_hijack_udp: bool,
    pub dns_hijack_mode: String,
    pub cgroup_memcg: bool,
    pub memcg_limit: String,
    pub taskset_cpu: bool,
    pub allow_cpu: String,
    pub cgroup_blkio: bool,
    pub weight: String,
    pub bypass_cn: bool,
    pub cnip_mode: String,
    pub bypass_cn_v4: bool,
    pub bypass_cn_v6: bool,
    pub cn_ip_file: String,
    pub cn_ipv6_file: String,
    pub tun_device: String,
    pub fake_ip_range: String,
    pub fake_ip6_range: String,
    pub selected_uids: Vec<String>,
    pub gid_list: Vec<String>,
    pub cnip_force_uids: Vec<String>,
    pub wifi_network_control_enabled: bool,
    pub wifi_use_on_disconnect: bool,
    pub wifi_use_on_connect: bool,
    pub wifi_enable_ssid_matching: bool,
    pub wifi_enable_log: bool,
    pub wifi_list_mode: String,
    pub wifi_ssids: Vec<String>,
    pub wifi_bssids: Vec<String>,
    pub hotspot_ap_interfaces: Vec<String>,
    pub blocked_interfaces: Vec<String>,
    pub mac_filter: bool,
    pub mac_mode: String,
    pub macs_list: Vec<String>,
    pub intranet_cidrs4: Vec<String>,
    pub intranet_cidrs6: Vec<String>,
}

pub fn load_runtime_data(db_path: &Path) -> Result<RuntimeData> {
    let conn = Connection::open(db_path)
        .map_err(|err| format!("open database {} failed: {err}", db_path.display()))?;
    ensure_schema(&conn)?;
    let mut profile = load_profile(&conn)?;
    profile.log_language = read_app_setting(&conn, "app_language", "en");
    profile.selected_uids = read_uid_list(&conn, "app_selection", "uid");
    profile.gid_list = read_string_list(&conn, "app_gid_list", "value")?
        .into_iter()
        .filter(|value| value.chars().all(|ch| ch.is_ascii_digit()))
        .collect();
    profile.cnip_force_uids = read_uid_list(&conn, "cnip_force_uids", "uid");
    profile.wifi_network_control_enabled = read_wifi_flag(
        &conn,
        "wifi_match_settings",
        "network_control_enabled",
        false,
    )?;
    profile.wifi_use_on_disconnect =
        read_wifi_flag(&conn, "wifi_match_settings", "use_on_wifi_disconnect", true)?;
    profile.wifi_use_on_connect =
        read_wifi_flag(&conn, "wifi_match_settings", "use_on_wifi_connect", true)?;
    profile.wifi_enable_ssid_matching =
        read_wifi_flag(&conn, "wifi_match_settings", "enable_ssid_matching", false)?;
    profile.wifi_enable_log = read_wifi_flag(
        &conn,
        "wifi_match_settings",
        "enable_network_control_log",
        true,
    )?;
    profile.wifi_list_mode =
        read_wifi_text(&conn, "wifi_match_settings", "list_mode", "blacklist")?;
    profile.wifi_ssids = read_string_list(&conn, "wifi_match_ssids", "value")?;
    profile.wifi_bssids = read_string_list(&conn, "wifi_match_bssids", "value")?;
    profile.hotspot_ap_interfaces = read_string_list(&conn, "hotspot_ap_interfaces", "value")?;
    profile.blocked_interfaces = read_string_list(&conn, "blocked_interfaces", "value")?;
    profile.mac_filter = read_wifi_flag(&conn, "hotspot_settings", "mac_filter", false)?;
    profile.mac_mode = read_wifi_text(&conn, "hotspot_settings", "mac_mode", "blacklist")?;
    profile.macs_list = read_string_list(&conn, "hotspot_macs", "value")?;
    profile.intranet_cidrs4 = read_string_list(&conn, "intranet_ipv4_cidrs", "value")?;
    profile.intranet_cidrs6 = read_string_list(&conn, "intranet_ipv6_cidrs", "value")?;
    Ok(profile)
}
