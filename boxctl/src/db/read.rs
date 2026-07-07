use super::*;

pub(super) fn load_profile(conn: &Connection) -> Result<RuntimeData> {
    let row = conn
        .query_row(
            "SELECT
                core_name, mode, proxy_mode, auto_sync_config, performance_mode,
                clean_vendor_firewall, ipv6_mode,
                config_name, tproxy_port, redir_port, quic, mihomo_dns_forward,
                mihomo_dns_port,
                proxy_tcp, proxy_udp, dns_hijack_tcp, dns_hijack_udp, dns_hijack_mode,
                cgroup_memcg, memcg_limit, taskset_cpu, allow_cpu, cgroup_blkio, weight,
                bypass_cn, tun_device, fake_ip_range, fake_ip6_range,
                cn.bypass_ipv4, cn.bypass_ipv6, cn.ipv4_file, cn.ipv6_file,
                cn.cnip_mode
             FROM runtime_profile
             LEFT JOIN cnip_settings cn ON cn.id = 1
             WHERE runtime_profile.id = 1",
            [],
            |row| {
                Ok(RuntimeData {
                    log_language: "en".to_string(),
                    core_name: row.get(0)?,
                    mode: row.get(1)?,
                    proxy_mode: row.get(2)?,
                    auto_sync_config: row.get::<_, i64>(3)? != 0,
                    performance_mode: row.get::<_, i64>(4)? != 0,
                    clean_vendor_firewall: row.get::<_, i64>(5)? != 0,
                    ipv6_mode: normalize_ipv6_mode(row.get::<_, Option<String>>(6)?.as_deref()),
                    config_name: row.get(7)?,
                    tproxy_port: row.get(8)?,
                    redir_port: row.get(9)?,
                    quic: row.get(10)?,
                    mihomo_dns_forward: row.get(11)?,
                    mihomo_dns_port: row.get(12)?,
                    proxy_tcp: row.get::<_, i64>(13)? != 0,
                    proxy_udp: row.get::<_, i64>(14)? != 0,
                    dns_hijack_tcp: row.get::<_, i64>(15)? != 0,
                    dns_hijack_udp: row.get::<_, i64>(16)? != 0,
                    dns_hijack_mode: row.get(17)?,
                    cgroup_memcg: row.get::<_, i64>(18)? != 0,
                    memcg_limit: row.get(19)?,
                    taskset_cpu: row.get::<_, i64>(20)? != 0,
                    allow_cpu: row.get(21)?,
                    cgroup_blkio: row.get::<_, i64>(22)? != 0,
                    weight: row.get(23)?,
                    bypass_cn: row.get::<_, i64>(24)? != 0,
                    tun_device: row.get(25)?,
                    fake_ip_range: row.get(26)?,
                    fake_ip6_range: row.get(27)?,
                    bypass_cn_v4: row.get::<_, i64>(28)? != 0,
                    bypass_cn_v6: row.get::<_, i64>(29)? != 0,
                    cn_ip_file: row.get(30)?,
                    cn_ipv6_file: row.get(31)?,
                    cnip_mode: normalize_cnip_mode(row.get::<_, Option<String>>(32)?.as_deref()),
                    selected_uids: Vec::new(),
                    gid_list: Vec::new(),
                    cnip_force_uids: Vec::new(),
                    wifi_network_control_enabled: false,
                    wifi_use_on_disconnect: true,
                    wifi_use_on_connect: true,
                    wifi_enable_ssid_matching: false,
                    wifi_enable_log: true,
                    wifi_list_mode: "blacklist".to_string(),
                    wifi_ssids: Vec::new(),
                    wifi_bssids: Vec::new(),
                    hotspot_ap_interfaces: Vec::new(),
                    blocked_interfaces: Vec::new(),
                    mac_filter: false,
                    mac_mode: "blacklist".to_string(),
                    macs_list: Vec::new(),
                    intranet_cidrs4: Vec::new(),
                    intranet_cidrs6: Vec::new(),
                })
            },
        )
        .map_err(|err| format!("read database config failed: {err}"))?;
    Ok(row)
}

pub(super) fn read_app_setting(conn: &Connection, key: &str, default: &str) -> String {
    conn.query_row(
        "SELECT value FROM app_settings WHERE key = ?1",
        [key],
        |row| row.get::<_, String>(0),
    )
    .ok()
    .map(|value| normalize_app_language(&value))
    .unwrap_or_else(|| default.to_string())
}

pub(super) fn read_uid_list(conn: &Connection, table: &str, column: &str) -> Vec<String> {
    let sql = format!("SELECT {column} FROM {table} ORDER BY {column}");
    let mut stmt = match conn.prepare(&sql) {
        Ok(stmt) => stmt,
        Err(_) => return Vec::new(),
    };
    let rows = match stmt.query_map([], |row| {
        let value: i64 = row.get(0)?;
        Ok(value.to_string())
    }) {
        Ok(rows) => rows,
        Err(_) => return Vec::new(),
    };

    let mut values: Vec<String> = rows.filter_map(|row| row.ok()).collect();
    values.sort();
    values.dedup();
    values
}

pub(super) fn read_wifi_flag(
    conn: &Connection,
    table: &str,
    column: &str,
    default: bool,
) -> Result<bool> {
    let sql = format!("SELECT {column} FROM {table} WHERE id = 1");
    let value: Option<i64> = conn.query_row(&sql, [], |row| row.get(0)).ok();
    Ok(value.map(|value| value != 0).unwrap_or(default))
}

pub(super) fn read_wifi_text(
    conn: &Connection,
    table: &str,
    column: &str,
    default: &str,
) -> Result<String> {
    let sql = format!("SELECT {column} FROM {table} WHERE id = 1");
    let value: Option<String> = conn.query_row(&sql, [], |row| row.get(0)).ok();
    Ok(value.unwrap_or_else(|| default.to_string()))
}

pub(super) fn read_string_list(
    conn: &Connection,
    table: &str,
    column: &str,
) -> Result<Vec<String>> {
    let sql = format!("SELECT {column} FROM {table} ORDER BY id");
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| format!("read {table} failed: {err}"))?;
    let rows = stmt
        .query_map([], |row| {
            let value: String = row.get(0)?;
            Ok(value)
        })
        .map_err(|err| format!("read {table} failed: {err}"))?;

    let mut values = Vec::new();
    for value in rows.filter_map(|row| row.ok()) {
        let value = value.trim().to_string();
        if !value.is_empty() && !values.iter().any(|item| item == &value) {
            values.push(value);
        }
    }
    Ok(values)
}

pub(super) fn normalize_app_language(value: &str) -> String {
    if value.trim().eq_ignore_ascii_case("en") {
        "en".to_string()
    } else {
        "zh-CN".to_string()
    }
}

pub(super) fn normalize_ipv6_mode(value: Option<&str>) -> String {
    match value
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "enable" | "enabled" | "true" | "1" => "enable".to_string(),
        "disable" | "disabled" | "system_disable" | "off" => "disable".to_string(),
        "bypass" | "bypassed" | "false" | "0" => "bypass".to_string(),
        _ => "enable".to_string(),
    }
}

pub(super) fn normalize_cnip_mode(value: Option<&str>) -> String {
    match value
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "ebpf" => "ebpf".to_string(),
        _ => "ipset".to_string(),
    }
}
