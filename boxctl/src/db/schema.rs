use super::*;

const SCHEMA_VERSION: i64 = 1;

pub(super) fn ensure_schema(conn: &Connection) -> Result<()> {
    let current: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|err| format!("read database schema version failed: {err}"))?;
    if current < SCHEMA_VERSION {
        migrate_schema(conn)?;

        conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))
            .map_err(|err| format!("update database schema version failed: {err}"))?;
    }

    ensure_additive_schema(conn)
}

fn migrate_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS runtime_profile (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            core_name TEXT NOT NULL,
            mode TEXT NOT NULL,
            proxy_mode TEXT NOT NULL,
            auto_sync_config INTEGER NOT NULL,
            performance_mode INTEGER NOT NULL,
            clean_vendor_firewall INTEGER NOT NULL DEFAULT 0,
            ipv6_mode TEXT NOT NULL DEFAULT 'enable',
            config_name TEXT NOT NULL,
            tproxy_port TEXT NOT NULL,
            redir_port TEXT NOT NULL,
            quic TEXT NOT NULL,
            mihomo_dns_forward TEXT NOT NULL,
            mihomo_dns_port TEXT NOT NULL,
            proxy_tcp INTEGER NOT NULL,
            proxy_udp INTEGER NOT NULL,
            dns_hijack_tcp INTEGER NOT NULL,
            dns_hijack_udp INTEGER NOT NULL,
            dns_hijack_mode TEXT NOT NULL,
            cgroup_memcg INTEGER NOT NULL,
            memcg_limit TEXT NOT NULL,
            taskset_cpu INTEGER NOT NULL DEFAULT 0,
            allow_cpu TEXT NOT NULL,
            cgroup_blkio INTEGER NOT NULL,
            weight TEXT NOT NULL,
            bypass_cn INTEGER NOT NULL,
            tun_device TEXT NOT NULL,
            fake_ip_range TEXT NOT NULL,
            fake_ip6_range TEXT NOT NULL,
            boot_auto_start INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS app_selection (
            uid INTEGER PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS app_gid_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cnip_force_uids (
            uid INTEGER PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS cnip_settings (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            bypass_cnip INTEGER NOT NULL,
            cnip_mode TEXT NOT NULL DEFAULT 'ipset',
            bypass_ipv4 INTEGER NOT NULL,
            bypass_ipv6 INTEGER NOT NULL,
            ipv4_file TEXT NOT NULL,
            ipv4_url TEXT NOT NULL,
            ipv6_file TEXT NOT NULL,
            ipv6_url TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS wifi_match_settings (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            network_control_enabled INTEGER NOT NULL,
            use_on_wifi_disconnect INTEGER NOT NULL,
            use_on_wifi_connect INTEGER NOT NULL,
            enable_ssid_matching INTEGER NOT NULL,
            enable_network_control_log INTEGER NOT NULL,
            list_mode TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS wifi_match_ssids (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS wifi_match_bssids (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS hotspot_settings (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            mac_filter INTEGER NOT NULL,
            mac_mode TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS hotspot_ap_interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS blocked_interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS hotspot_macs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS intranet_bypass_settings (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            initialized INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS intranet_ipv4_cidrs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS intranet_ipv6_cidrs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL
        );
        "#,
    )
    .map_err(|err| format!("initialize database schema failed: {err}"))?;
    ensure_additive_schema(conn)
}

fn ensure_additive_schema(conn: &Connection) -> Result<()> {
    ensure_column(
        conn,
        "runtime_profile",
        "boot_auto_start",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        conn,
        "runtime_profile",
        "clean_vendor_firewall",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        conn,
        "runtime_profile",
        "ipv6_mode",
        "TEXT NOT NULL DEFAULT 'enable'",
    )?;
    ensure_column(
        conn,
        "runtime_profile",
        "taskset_cpu",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        conn,
        "cnip_settings",
        "cnip_mode",
        "TEXT NOT NULL DEFAULT 'ipset'",
    )?;
    Ok(())
}

pub(super) fn ensure_column(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<()> {
    if column_exists(conn, table, column)? {
        return Ok(());
    }

    let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
    conn.execute(&sql, [])
        .map_err(|err| format!("update {table}.{column} failed: {err}"))?;
    Ok(())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let pragma = format!("PRAGMA table_info({table})");
    let mut stmt = conn
        .prepare(&pragma)
        .map_err(|err| format!("read {table} schema failed: {err}"))?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|err| format!("read {table} schema failed: {err}"))?;

    for item in columns {
        if item
            .map_err(|err| format!("read {table} schema failed: {err}"))?
            .eq_ignore_ascii_case(column)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
