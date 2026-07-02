use super::*;

pub(super) fn core_check_command(config: &Config) -> (String, Vec<String>) {
    let bin = config.bin_path.to_string_lossy().to_string();
    let dir = config.core_dir().to_string_lossy().to_string();
    let file = config.service_config_path().to_string_lossy().to_string();

    match config.bin_name.as_str() {
        "mihomo" => (bin, vec!["-t".into(), "-d".into(), dir, "-f".into(), file]),
        "sing-box" => (
            bin,
            vec!["check".into(), "-c".into(), file, "-D".into(), dir],
        ),
        "xray" => (bin, vec!["-test".into(), "-confdir".into(), dir]),
        "v2fly" => (bin, vec!["test".into(), "-d".into(), dir]),
        "hysteria" => (String::new(), Vec::new()),
        _ => (String::new(), Vec::new()),
    }
}

pub(super) fn core_run_command(config: &Config) -> (String, Vec<String>) {
    let mut args = Vec::new();
    let dir = config.core_dir().to_string_lossy().to_string();
    let file = config.service_config_path().to_string_lossy().to_string();
    let bin = config.bin_path.to_string_lossy().to_string();

    match config.bin_name.as_str() {
        "mihomo" => args.extend(["-d".into(), dir, "-f".into(), file]),
        "sing-box" => args.extend(["run".into(), "-c".into(), file, "-D".into(), dir]),
        "xray" => args.extend(["run".into(), "-confdir".into(), dir]),
        "v2fly" => args.extend(["run".into(), "-d".into(), dir]),
        "hysteria" => args.extend(["-c".into(), file]),
        _ => {}
    }

    (bin, args)
}

pub(super) fn core_env(config: &Config) -> Vec<(&'static str, String)> {
    let asset_dir = config.core_dir().to_string_lossy().to_string();
    match config.bin_name.as_str() {
        "xray" => vec![("XRAY_LOCATION_ASSET", asset_dir)],
        "v2fly" => vec![("V2RAY_LOCATION_ASSET", asset_dir)],
        _ => Vec::new(),
    }
}
