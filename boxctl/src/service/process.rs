use super::*;

pub(super) fn stop_pids(
    config: &Config,
    runner: &Runner,
    pids: Vec<(String, String)>,
) -> Result<()> {
    for (bin, pid) in &pids {
        logger::debug_key(
            config,
            LogKey::ServiceSendSigterm,
            &[arg("core", bin), arg("pid", pid)],
        );
        if let Ok(pid_num) = pid.parse::<i32>() {
            runner.signal(pid_num, SIGTERM);
        }
    }

    let deadline = Instant::now() + Duration::from_millis(STOP_WAIT_TOTAL_MS);
    let mut interval = STOP_POLL_MIN_MS;
    loop {
        if running_core_pids(config).is_empty() {
            remove_pid(config)?;
            logger::warn_key(
                config,
                LogKey::ServiceStopped,
                &[arg("core", &config.bin_name)],
            );
            return Ok(());
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(interval));
        interval = (interval * 2).min(STOP_POLL_MAX_MS);
    }

    let alive = running_core_pids(config);
    if !alive.is_empty() {
        logger::warn_key(config, LogKey::ServiceForceStopAfterSigterm, &[]);
        for (_, pid) in alive {
            if let Ok(pid_num) = pid.parse::<i32>() {
                runner.signal(pid_num, SIGKILL);
            }
        }
    }

    remove_pid(config)?;
    logger::warn_key(
        config,
        LogKey::ServiceStopped,
        &[arg("core", &config.bin_name)],
    );
    Ok(())
}

pub(super) fn running_core_pids(config: &Config) -> Vec<(String, String)> {
    let mut seen = BTreeSet::new();
    let mut pids = Vec::new();

    if let Some(pid) = pid_from_file_if_core(config) {
        seen.insert(pid.clone());
        pids.push((config.bin_name.clone(), pid));
    }

    let names: BTreeSet<&str> = config.bin_list.iter().map(String::as_str).collect();
    for (bin, pid) in scan_core_pids(&names) {
        if seen.insert(pid.clone()) {
            pids.push((bin, pid));
        }
    }

    pids
}

fn scan_core_pids(names: &BTreeSet<&str>) -> Vec<(String, String)> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };

    let mut found = Vec::new();
    for entry in entries.filter_map(|entry| entry.ok()) {
        let Ok(pid) = entry.file_name().into_string() else {
            continue;
        };
        if pid.is_empty() || !pid.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        if let Some(bin) = core_bin_for_pid(&pid, names) {
            found.push((bin, pid));
        }
    }
    found
}

/// Return which known core name a PID belongs to, if any.
fn core_bin_for_pid(pid: &str, names: &BTreeSet<&str>) -> Option<String> {
    let proc_dir = Path::new("/proc").join(pid);
    if !proc_dir.is_dir() {
        return None;
    }

    if let Ok(comm) = fs::read_to_string(proc_dir.join("comm")) {
        let comm = comm.trim();
        if names.contains(comm) {
            return Some(comm.to_string());
        }
    }

    let cmdline = fs::read(proc_dir.join("cmdline")).ok()?;
    let first_arg = cmdline
        .split(|byte| *byte == 0)
        .find(|part| !part.is_empty())?;
    let first_arg = String::from_utf8_lossy(first_arg);
    let first_name = Path::new(first_arg.as_ref())
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if names.contains(first_name) {
        Some(first_name.to_string())
    } else {
        None
    }
}

pub(super) fn pid_from_file_if_core(config: &Config) -> Option<String> {
    let text = fs::read_to_string(&config.box_pid).ok()?;
    let pid = text.trim();
    if pid.is_empty() || !pid.chars().all(|ch| ch.is_ascii_digit()) {
        let _ = remove_pid(config);
        return None;
    }

    if !pid_matches_core(config, pid) {
        let _ = remove_pid(config);
        return None;
    }

    Some(pid.to_string())
}

pub(super) fn pid_matches_core(config: &Config, pid: &str) -> bool {
    pid_matches_bin(&config.bin_name, pid)
}

pub(super) fn pid_matches_bin(bin_name: &str, pid: &str) -> bool {
    if pid.is_empty() || !pid.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }

    let proc_dir = Path::new("/proc").join(pid);
    if !proc_dir.is_dir() {
        return false;
    }

    if let Ok(comm) = fs::read_to_string(proc_dir.join("comm")) {
        if comm.trim() == bin_name {
            return true;
        }
    }

    let Ok(cmdline) = fs::read(proc_dir.join("cmdline")) else {
        return false;
    };
    let args = cmdline
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).to_string())
        .collect::<Vec<_>>();
    let Some(first_arg) = args.first() else {
        return false;
    };
    let first_name = Path::new(first_arg)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    first_name == bin_name
}

pub(super) fn remove_pid(config: &Config) -> Result<()> {
    if config.box_pid.exists() {
        fs::remove_file(&config.box_pid)
            .map_err(|err| format!("delete PID {} failed: {err}", config.box_pid.display()))?;
    }
    Ok(())
}
