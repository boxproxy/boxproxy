use super::*;

pub(super) fn core_check_command(config: &Config) -> (String, Vec<String>) {
    let bin = config.bin_path.to_string_lossy().to_string();
    let dir = config.core_dir().to_string_lossy().to_string();
    let file = config.config_path().to_string_lossy().to_string();

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
    let file = config.config_path().to_string_lossy().to_string();
    let bin = config.bin_path.to_string_lossy().to_string();

    match config.bin_name.as_str() {
        "mihomo" => args.extend(["-d".into(), dir, "-f".into(), file]),
        "sing-box" => args.extend(["run".into(), "-c".into(), file, "-D".into(), dir]),
        "xray" => args.extend(["run".into(), "-confdir".into(), dir]),
        "v2fly" => args.extend(["run".into(), "-d".into(), dir]),
        "hysteria" => args.extend(["-c".into(), file]),
        _ => {}
    }

    if config.taskset_cpu {
        match taskset_mask_arg(config) {
            Ok(mask) => {
                let mut taskset_args = vec![mask, bin];
                taskset_args.extend(args);
                return (taskset_program(), taskset_args);
            }
            Err(err) => {
                eprintln!("[core_run_command] taskset fallback: {err}");
            }
        }
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

fn taskset_program() -> String {
    for path in [
        "/system/bin/taskset",
        "/vendor/bin/taskset",
        "/system/xbin/taskset",
        "/bin/taskset",
        "/usr/bin/taskset",
    ] {
        if std::path::Path::new(path).is_file() {
            return path.to_string();
        }
    }
    "taskset".to_string()
}

fn taskset_mask_arg(config: &Config) -> Result<String> {
    let cores = if config.allow_cpu.trim().is_empty() {
        detect_cpu_range().ok_or_else(|| "detect CPU cores failed".to_string())?
    } else {
        config.allow_cpu.trim().to_string()
    };
    cpu_list_to_taskset_mask(&cores)
}

fn detect_cpu_range() -> Option<String> {
    let count = std::thread::available_parallelism().ok()?.get();
    if count == 0 {
        None
    } else {
        Some(format!("0-{}", count - 1))
    }
}

fn cpu_list_to_taskset_mask(list: &str) -> Result<String> {
    let mut mask = 0_u128;
    let mut any = false;

    for item in list.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (start, end) = if let Some((start, end)) = item.split_once('-') {
            let start = parse_cpu_index(start)?;
            let end = parse_cpu_index(end)?;
            if start > end {
                return Err(format!("invalid CPU range: {item}"));
            }
            (start, end)
        } else {
            let cpu = parse_cpu_index(item)?;
            (cpu, cpu)
        };

        for cpu in start..=end {
            let bit = 1_u128
                .checked_shl(cpu)
                .ok_or_else(|| format!("CPU index out of taskset mask range: {cpu}"))?;
            mask |= bit;
            any = true;
        }
    }

    if !any {
        return Err("empty CPU list".to_string());
    }
    Ok(format!("{mask:x}"))
}

fn parse_cpu_index(value: &str) -> Result<u32> {
    let value = value.trim();
    if value.is_empty() {
        return Err("empty CPU index".to_string());
    }
    value
        .parse::<u32>()
        .map_err(|_| format!("invalid CPU index: {value}"))
}
