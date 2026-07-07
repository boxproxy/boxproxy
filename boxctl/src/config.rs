use crate::db;
use crate::Result;
use std::env;
use std::path::{Path, PathBuf};

mod core_values;
use core_values::*;

#[derive(Clone, Debug)]
pub struct BoxPaths {
    pub home: PathBuf,
    pub run: PathBuf,
    pub state: PathBuf,
    pub bin: PathBuf,
    pub db: PathBuf,
}

#[derive(Clone, Debug, Default)]
pub struct ConfigOverrides {
    pub bin_name: Option<String>,
    pub bin_path: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub auto_sync_config: Option<bool>,
    pub network_mode: Option<String>,
    pub proxy_mode: Option<String>,
    pub tproxy_port: Option<String>,
    pub redir_port: Option<String>,
    pub ipv6_mode: Option<String>,
    pub proxy_tcp: Option<bool>,
    pub proxy_udp: Option<bool>,
    pub dns_hijack_tcp: Option<bool>,
    pub dns_hijack_udp: Option<bool>,
    pub dns_hijack_mode: Option<String>,
    pub mihomo_dns_forward: Option<String>,
    pub mihomo_dns_port: Option<String>,
    pub quic: Option<String>,
    pub performance_mode: Option<bool>,
    pub clean_vendor_firewall: Option<bool>,
    pub cgroup_memcg: Option<bool>,
    pub memcg_limit: Option<String>,
    pub taskset_cpu: Option<bool>,
    pub allow_cpu: Option<String>,
    pub cgroup_blkio: Option<bool>,
    pub weight: Option<String>,
    pub bypass_cn_ip: Option<bool>,
    pub bypass_cn_ip_v4: Option<bool>,
    pub bypass_cn_ip_v6: Option<bool>,
    pub cn_ip_file: Option<PathBuf>,
    pub cn_ipv6_file: Option<PathBuf>,
    pub db_path: Option<PathBuf>,
    pub tun_device: Option<String>,
    pub fake_ip_range: Option<String>,
    pub fake_ip6_range: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub paths: BoxPaths,
    pub log_language: String,
    pub box_pid: PathBuf,
    pub box_log: PathBuf,
    pub box_user_group: String,
    pub bin_name: String,
    pub bin_list: Vec<String>,
    pub bin_path: PathBuf,
    pub bpf_matcher_path: PathBuf,
    pub bin_log: PathBuf,
    pub auto_sync_config: bool,
    pub network_mode: String,
    pub proxy_mode: String,
    pub tproxy_port: String,
    pub redir_port: String,
    pub ipv6_mode: String,
    pub ipv6: bool,
    pub proxy_tcp: bool,
    pub proxy_udp: bool,
    pub dns_hijack_tcp: bool,
    pub dns_hijack_udp: bool,
    pub dns_hijack_mode: String,
    pub mihomo_dns_forward: String,
    pub mihomo_dns_port: String,
    pub quic: String,
    pub performance_mode: bool,
    pub clean_vendor_firewall: bool,
    pub cgroup_memcg: bool,
    pub memcg_limit: String,
    pub taskset_cpu: bool,
    pub allow_cpu: String,
    pub cgroup_blkio: bool,
    pub weight: String,
    pub bypass_cn_ip: bool,
    pub cnip_mode: String,
    pub bypass_cn_ip_v4: bool,
    pub bypass_cn_ip_v6: bool,
    pub cn_ip_file: PathBuf,
    pub cn_ipv6_file: PathBuf,
    pub selected_uids: Vec<String>,
    pub cnip_force_uids: Vec<String>,
    pub wifi_network_control_enabled: bool,
    pub wifi_use_on_disconnect: bool,
    pub wifi_use_on_connect: bool,
    pub wifi_enable_ssid_matching: bool,
    pub wifi_enable_log: bool,
    pub wifi_list_mode: String,
    pub wifi_ssids: Vec<String>,
    pub wifi_bssids: Vec<String>,
    pub tun_device: String,
    pub fake_ip_range: String,
    pub fake_ip6_range: String,
    pub core_config_sources: CoreConfigSources,
    pub tun_force_proxy_cidrs: Vec<String>,
    pub tun_force_proxy_cidrs6: Vec<String>,
    pub gid_list: Vec<String>,
    pub hotspot_ap_interfaces: Vec<String>,
    pub blocked_interfaces: Vec<String>,
    pub mac_filter: bool,
    pub mac_mode: String,
    pub macs_list: Vec<String>,
    pub intranet_cidrs4: Vec<String>,
    pub intranet_cidrs6: Vec<String>,
    pub config_name: String,
    pub config_path: PathBuf,
}

impl BoxPaths {
    pub fn new(home_arg: Option<String>, db_arg: Option<PathBuf>) -> Result<Self> {
        let home_str = home_arg
            .or_else(|| env::var("BOX_HOME").ok())
            .or_else(|| {
                db_arg.as_ref().and_then(|path| {
                    path.parent()
                        .map(|parent| parent.to_string_lossy().to_string())
                })
            })
            .or_else(infer_home_from_current_exe)
            .unwrap_or_else(|| "/data/user/0/com.boxproxy.box/files/box".to_string());
        let home = PathBuf::from(home_str);
        let db = db_arg.unwrap_or_else(|| home.join("box.db"));
        Ok(Self {
            run: home.join("run"),
            state: home.join("run").join("state"),
            bin: home.join("bin"),
            home,
            db,
        })
    }
}

impl Config {
    pub fn load(paths: BoxPaths, overrides: ConfigOverrides) -> Result<Self> {
        let db_data = db::load_runtime_data(&paths.db)?;
        let auto_sync_config = overrides
            .auto_sync_config
            .unwrap_or(db_data.auto_sync_config);
        let bin_name = overrides
            .bin_name
            .clone()
            .unwrap_or_else(|| db_data.core_name.clone());
        let db_config_name = db_data.config_name.trim().to_string();
        let (config_name, config_path) = match overrides.config_path.clone() {
            Some(path) => {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default()
                    .to_string();
                (name, path)
            }
            None => {
                let path = paths.home.join(&bin_name).join(&db_config_name);
                (db_config_name, path)
            }
        };
        let network_mode = overrides
            .network_mode
            .clone()
            .unwrap_or_else(|| db_data.mode.clone());
        let core_values = CoreConfigValues::read(&bin_name, &network_mode, &config_path);
        let default_mihomo_dns_port = default_mihomo_dns_port(&bin_name);
        let default_tun_device = default_tun_device(&bin_name, &network_mode);
        let default_fake_ip_range = default_fake_ip_range(&bin_name);
        let default_fake_ip6_range = default_fake_ip6_range(&bin_name);
        let db_mihomo_dns_port = non_empty_value(&db_data.mihomo_dns_port);
        let db_tun_device = non_empty_value(&db_data.tun_device);
        let db_fake_ip_range = non_empty_value(&db_data.fake_ip_range);
        let db_fake_ip6_range = non_empty_value(&db_data.fake_ip6_range);
        let sources = CoreConfigSources {
            read_status: core_values.read_status.clone(),
            mihomo_dns_port: value_source(
                &overrides.mihomo_dns_port,
                &db_mihomo_dns_port,
                &core_values.mihomo_dns_port,
                &default_mihomo_dns_port,
                bin_name == "mihomo",
                auto_sync_config,
            ),
            tun_device: value_source(
                &overrides.tun_device,
                &db_tun_device,
                &core_values.tun_device,
                &default_tun_device,
                matches!(network_mode.as_str(), "tun" | "mixed"),
                auto_sync_config,
            ),
            fake_ip_range: value_source(
                &overrides.fake_ip_range,
                &db_fake_ip_range,
                &core_values.fake_ip_range,
                &default_fake_ip_range,
                matches!(bin_name.as_str(), "mihomo" | "sing-box"),
                auto_sync_config,
            ),
            fake_ip6_range: value_source(
                &overrides.fake_ip6_range,
                &db_fake_ip6_range,
                &core_values.fake_ip6_range,
                &default_fake_ip6_range,
                matches!(bin_name.as_str(), "mihomo" | "sing-box"),
                auto_sync_config,
            ),
        };

        let performance_mode = overrides
            .performance_mode
            .unwrap_or(db_data.performance_mode);
        let cnip_mode = normalize_cnip_mode(&db_data.cnip_mode);
        let config = Self {
            paths: paths.clone(),
            log_language: normalize_log_language(&db_data.log_language),
            box_pid: paths.run.join("box.pid"),
            box_log: paths.run.join("runs.log"),
            box_user_group: "root:net_admin".to_string(),
            bin_name: bin_name.clone(),
            bin_list: ["mihomo", "sing-box", "xray", "v2fly", "hysteria"]
                .iter()
                .map(|value| value.to_string())
                .collect(),
            bin_path: overrides
                .bin_path
                .clone()
                .unwrap_or_else(|| paths.bin.join(&bin_name)),
            bpf_matcher_path: paths.bin.join("boxbpf"),
            bin_log: paths.run.join(format!("{bin_name}.log")),
            auto_sync_config,
            network_mode,
            proxy_mode: overrides
                .proxy_mode
                .clone()
                .unwrap_or_else(|| db_data.proxy_mode.clone()),
            tproxy_port: overrides
                .tproxy_port
                .clone()
                .unwrap_or_else(|| db_data.tproxy_port.clone()),
            redir_port: overrides
                .redir_port
                .clone()
                .unwrap_or_else(|| db_data.redir_port.clone()),
            ipv6_mode: normalize_ipv6_mode(
                overrides.ipv6_mode.as_deref().unwrap_or(&db_data.ipv6_mode),
            ),
            ipv6: normalize_ipv6_mode(overrides.ipv6_mode.as_deref().unwrap_or(&db_data.ipv6_mode))
                == "enable",
            proxy_tcp: overrides.proxy_tcp.unwrap_or(db_data.proxy_tcp),
            proxy_udp: overrides.proxy_udp.unwrap_or(db_data.proxy_udp),
            dns_hijack_tcp: overrides.dns_hijack_tcp.unwrap_or(db_data.dns_hijack_tcp),
            dns_hijack_udp: overrides.dns_hijack_udp.unwrap_or(db_data.dns_hijack_udp),
            dns_hijack_mode: overrides
                .dns_hijack_mode
                .clone()
                .unwrap_or_else(|| db_data.dns_hijack_mode.clone()),
            mihomo_dns_forward: overrides
                .mihomo_dns_forward
                .clone()
                .unwrap_or_else(|| db_data.mihomo_dns_forward.clone()),
            mihomo_dns_port: overrides
                .mihomo_dns_port
                .clone()
                .or_else(|| {
                    if auto_sync_config {
                        db_mihomo_dns_port
                            .clone()
                            .or_else(|| core_values.mihomo_dns_port.clone())
                    } else {
                        core_values.mihomo_dns_port.clone()
                    }
                })
                .unwrap_or(default_mihomo_dns_port),
            quic: overrides
                .quic
                .clone()
                .unwrap_or_else(|| db_data.quic.clone()),
            performance_mode,
            clean_vendor_firewall: overrides
                .clean_vendor_firewall
                .unwrap_or(db_data.clean_vendor_firewall),
            cgroup_memcg: overrides.cgroup_memcg.unwrap_or(db_data.cgroup_memcg),
            memcg_limit: overrides
                .memcg_limit
                .clone()
                .unwrap_or_else(|| db_data.memcg_limit.clone()),
            taskset_cpu: overrides.taskset_cpu.unwrap_or(db_data.taskset_cpu),
            allow_cpu: overrides
                .allow_cpu
                .clone()
                .unwrap_or_else(|| db_data.allow_cpu.clone()),
            cgroup_blkio: overrides.cgroup_blkio.unwrap_or(db_data.cgroup_blkio),
            weight: overrides
                .weight
                .clone()
                .unwrap_or_else(|| db_data.weight.clone()),
            bypass_cn_ip: overrides.bypass_cn_ip.unwrap_or(db_data.bypass_cn),
            cnip_mode,
            bypass_cn_ip_v4: overrides.bypass_cn_ip_v4.unwrap_or(db_data.bypass_cn_v4),
            bypass_cn_ip_v6: overrides.bypass_cn_ip_v6.unwrap_or(db_data.bypass_cn_v6),
            cn_ip_file: overrides
                .cn_ip_file
                .clone()
                .unwrap_or_else(|| PathBuf::from(db_data.cn_ip_file.clone())),
            cn_ipv6_file: overrides
                .cn_ipv6_file
                .clone()
                .unwrap_or_else(|| PathBuf::from(db_data.cn_ipv6_file.clone())),
            selected_uids: db_data.selected_uids,
            gid_list: db_data.gid_list,
            cnip_force_uids: db_data.cnip_force_uids,
            wifi_network_control_enabled: db_data.wifi_network_control_enabled,
            wifi_use_on_disconnect: db_data.wifi_use_on_disconnect,
            wifi_use_on_connect: db_data.wifi_use_on_connect,
            wifi_enable_ssid_matching: db_data.wifi_enable_ssid_matching,
            wifi_enable_log: db_data.wifi_enable_log,
            wifi_list_mode: db_data.wifi_list_mode,
            wifi_ssids: db_data.wifi_ssids,
            wifi_bssids: db_data.wifi_bssids,
            tun_device: overrides
                .tun_device
                .clone()
                .or_else(|| {
                    if auto_sync_config {
                        db_tun_device
                            .clone()
                            .or_else(|| core_values.tun_device.clone())
                    } else {
                        core_values.tun_device.clone()
                    }
                })
                .unwrap_or(default_tun_device),
            fake_ip_range: overrides
                .fake_ip_range
                .clone()
                .or_else(|| {
                    if auto_sync_config {
                        db_fake_ip_range
                            .clone()
                            .or_else(|| core_values.fake_ip_range.clone())
                    } else {
                        core_values.fake_ip_range.clone()
                    }
                })
                .unwrap_or(default_fake_ip_range),
            fake_ip6_range: overrides
                .fake_ip6_range
                .clone()
                .or_else(|| {
                    if auto_sync_config {
                        db_fake_ip6_range
                            .clone()
                            .or_else(|| core_values.fake_ip6_range.clone())
                    } else {
                        core_values.fake_ip6_range.clone()
                    }
                })
                .unwrap_or(default_fake_ip6_range),
            core_config_sources: sources,
            tun_force_proxy_cidrs: Vec::new(),
            tun_force_proxy_cidrs6: Vec::new(),
            hotspot_ap_interfaces: db_data.hotspot_ap_interfaces,
            blocked_interfaces: db_data.blocked_interfaces,
            mac_filter: db_data.mac_filter,
            mac_mode: db_data.mac_mode,
            macs_list: db_data.macs_list,
            intranet_cidrs4: db_data.intranet_cidrs4,
            intranet_cidrs6: db_data.intranet_cidrs6,
            config_name,
            config_path,
        };

        Ok(config)
    }

    pub fn core_dir(&self) -> PathBuf {
        self.paths.home.join(&self.bin_name)
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }
}

#[derive(Clone, Debug)]
pub struct CoreConfigSources {
    pub read_status: String,
    pub mihomo_dns_port: &'static str,
    pub tun_device: &'static str,
    pub fake_ip_range: &'static str,
    pub fake_ip6_range: &'static str,
}

fn infer_home_from_current_exe() -> Option<String> {
    let exe = env::current_exe().ok()?;
    let bin_dir = exe.parent()?;
    if bin_dir.file_name()?.to_str()? != "bin" {
        return None;
    }
    Some(bin_dir.parent()?.to_string_lossy().to_string())
}

fn normalize_log_language(value: &str) -> String {
    if value.trim().eq_ignore_ascii_case("en") {
        "en".to_string()
    } else {
        "zh-CN".to_string()
    }
}

pub fn normalize_ipv6_mode(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "enable" | "enabled" | "true" | "1" => "enable".to_string(),
        "disable" | "disabled" | "system_disable" | "off" => "disable".to_string(),
        _ => "bypass".to_string(),
    }
}

pub fn normalize_cnip_mode(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "ebpf" => "ebpf".to_string(),
        _ => "ipset".to_string(),
    }
}
