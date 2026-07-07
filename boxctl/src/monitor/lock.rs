use super::*;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

#[cfg(unix)]
unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}

#[cfg(unix)]
const LOCK_EX: i32 = 2;
#[cfg(unix)]
const LOCK_NB: i32 = 4;

pub(super) fn acquire_monitor_lock(config: &Config) -> Result<Option<MonitorLock>> {
    let path = monitor_lock_path(config);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create monitor lock directory {} failed: {err}",
                parent.display()
            )
        })?;
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|err| format!("open monitor lock {} failed: {err}", path.display()))?;

    if !try_lock_exclusive(&file) {
        return Ok(None);
    }

    file.set_len(0)
        .map_err(|err| format!("reset monitor lock {} failed: {err}", path.display()))?;
    {
        let mut handle = &file;
        writeln!(handle, "{}", process::id())
            .map_err(|err| format!("write monitor lock {} failed: {err}", path.display()))?;
    }

    Ok(Some(MonitorLock { _file: file }))
}

#[cfg(unix)]
fn try_lock_exclusive(file: &fs::File) -> bool {
    unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) == 0 }
}

#[cfg(not(unix))]
fn try_lock_exclusive(_file: &fs::File) -> bool {
    true
}

pub(super) fn monitor_lock_path(config: &Config) -> PathBuf {
    config.paths.state.join("network_monitor.pid")
}

pub(super) fn read_monitor_pid(path: &PathBuf) -> Option<u32> {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse::<u32>().ok())
}

pub(super) fn pid_is_alive(pid: u32) -> bool {
    fs::metadata(format!("/proc/{pid}")).is_ok()
}

pub(super) fn monitor_pid_matches(pid: u32) -> bool {
    if !pid_is_alive(pid) {
        return false;
    }

    match fs::read(format!("/proc/{pid}/environ")) {
        Ok(environ) => {
            let marker = format!("{MONITOR_WORKER_ENV}=1");
            environ
                .split(|byte| *byte == 0)
                .any(|entry| entry == marker.as_bytes())
        }
        Err(_) => cmdline_looks_like_monitor(pid),
    }
}

fn cmdline_looks_like_monitor(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/cmdline"))
        .ok()
        .map(|cmdline| {
            let normalized = cmdline.replace('\0', " ");
            normalized.contains("boxctl") && normalized.contains("monitor")
        })
        .unwrap_or(false)
}

pub(super) struct MonitorLock {
    _file: fs::File,
}
