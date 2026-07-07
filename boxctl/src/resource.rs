use crate::config::Config;
use crate::exec::Runner;
use crate::logger;
use crate::service;
use crate::Result;
use logger::{arg, LogKey};
use std::fs;
use std::path::{Path, PathBuf};

pub fn apply_current(config: &Config, runner: &Runner) -> Result<()> {
    let pid = current_pid(config, runner)?;
    apply(config, runner, pid)
}

pub fn apply(config: &Config, _runner: &Runner, pid: u32) -> Result<()> {
    let mut any_enabled = false;
    let mut applied = Vec::new();
    let mut failed = Vec::new();

    if config.cgroup_memcg {
        any_enabled = true;
        match apply_memcg(config, pid) {
            Ok(detail) => applied.push(format!("memory {detail}")),
            Err(err) => failed.push(format!("memory {err}")),
        }
    }
    if config.cgroup_blkio {
        any_enabled = true;
        match apply_blkio(config, pid) {
            Ok(detail) => applied.push(format!("blkio {detail}")),
            Err(err) => failed.push(format!("blkio {err}")),
        }
    }

    if !any_enabled {
        logger::debug_key(config, LogKey::ResourceDisabled, &[]);
        return Ok(());
    }

    let applied_text = if applied.is_empty() {
        "none".to_string()
    } else {
        applied.join("; ")
    };
    if failed.is_empty() {
        logger::info_key(
            config,
            LogKey::ResourceApplied,
            &[arg("pid", pid), arg("applied", applied_text)],
        );
    } else {
        logger::warn_key(
            config,
            LogKey::ResourcePartiallyFailed,
            &[
                arg("pid", pid),
                arg("applied", applied_text),
                arg("failed", failed.join("; ")),
            ],
        );
    }

    Ok(())
}

fn current_pid(config: &Config, runner: &Runner) -> Result<u32> {
    if let Some(pid) = service::current_core_pid(config, runner) {
        return Ok(pid);
    }
    Err(format!("service is not running: {}", config.bin_name))
}

fn apply_memcg(config: &Config, pid: u32) -> Result<String> {
    let limit = parse_size(&config.memcg_limit)
        .ok_or_else(|| format!("invalid memory limit: {}", config.memcg_limit))?;
    let root =
        find_cgroup_mount("memory").ok_or_else(|| "memory cgroup path not found".to_string())?;
    let target = ensure_target_dir(&root, &["box", config.bin_name.as_str()])?;
    write_value(&target.join("memory.limit_in_bytes"), &limit.to_string())?;
    write_pid(&target, pid)?;
    Ok(format!(
        "-> {}, limit {}",
        target.display(),
        human_size(limit)
    ))
}

fn apply_blkio(config: &Config, pid: u32) -> Result<String> {
    let root =
        find_cgroup_mount("blkio").ok_or_else(|| "blkio cgroup path not found".to_string())?;
    let target = ensure_target_dir(&root, &["box", "foreground", "top-app"])?;
    let weight = config.weight.trim();
    let weight = if weight.is_empty() { "900" } else { weight };
    if target.file_name().and_then(|name| name.to_str()) == Some("box") {
        write_value(&target.join("blkio.weight"), weight)?;
    }
    write_pid(&target, pid)?;
    Ok(format!("-> {}, weight {}", target.display(), weight))
}

fn find_cgroup_mount(controller: &str) -> Option<PathBuf> {
    let mounts = fs::read_to_string("/proc/mounts")
        .or_else(|_| fs::read_to_string("/proc/self/mounts"))
        .ok()?;
    for line in mounts.lines() {
        let mut parts = line.split_whitespace();
        let _source = parts.next();
        let mount_point = parts.next()?;
        let fs_type = parts.next()?;
        let options = parts.next().unwrap_or_default();
        if fs_type == "cgroup" && options.split(',').any(|item| item == controller) {
            return Some(PathBuf::from(unescape_mount_path(mount_point)));
        }
    }
    None
}

fn ensure_target_dir(root: &Path, candidates: &[&str]) -> Result<PathBuf> {
    for (index, name) in candidates.iter().enumerate() {
        let target = root.join(name);
        if target.is_dir() {
            return Ok(target);
        }
        if index == 0 && fs::create_dir_all(&target).is_ok() && target.is_dir() {
            return Ok(target);
        }
    }
    Err(format!("cgroup target unavailable: {}", root.display()))
}

fn write_value(path: &Path, value: &str) -> Result<()> {
    fs::write(path, format!("{value}\n"))
        .map_err(|err| format!("write {} failed: {err}", path.display()))
}

fn write_pid(target: &Path, pid: u32) -> Result<()> {
    write_value(&target.join("cgroup.procs"), &pid.to_string())
}

fn parse_size(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (number, multiplier) = match value.chars().last()? {
        'k' | 'K' => (&value[..value.len() - 1], 1024_u64),
        'm' | 'M' => (&value[..value.len() - 1], 1024_u64 * 1024),
        'g' | 'G' => (&value[..value.len() - 1], 1024_u64 * 1024 * 1024),
        ch if ch.is_ascii_digit() => (value, 1),
        _ => return None,
    };
    number.trim().parse::<u64>().ok()?.checked_mul(multiplier)
}

fn human_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GiB", bytes as f64 / 1024_f64 / 1024_f64 / 1024_f64)
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MiB", bytes as f64 / 1024_f64 / 1024_f64)
    } else if bytes >= 1024 {
        format!("{:.2} KiB", bytes as f64 / 1024_f64)
    } else {
        format!("{bytes} B")
    }
}

fn unescape_mount_path(path: &str) -> String {
    path.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}
