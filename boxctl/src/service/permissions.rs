use super::*;

pub(super) fn prepare_permissions(config: &Config, runner: &Runner) -> Result<()> {
    if permission_stamp_matches(config) {
        logger::debug_key(
            config,
            LogKey::CorePermissionsUpToDate,
            &[arg("path", config.bin_path.display())],
        );
        return Ok(());
    }

    let bin_path = config.bin_path.to_string_lossy().to_string();
    if runner.dry_run() {
        runner.run_ignore("chown", &[config.box_user_group.clone(), bin_path.clone()]);
        runner.run_ignore("chmod", &["6755".to_string(), bin_path]);
        return Ok(());
    }

    let chown_ok = runner.run_ok("chown", &[config.box_user_group.clone(), bin_path.clone()]);
    let chmod_ok = runner.run_ok("chmod", &["6755".to_string(), bin_path]);
    if chown_ok && chmod_ok {
        save_permission_stamp(config)?;
        logger::debug_key(
            config,
            LogKey::CorePermissionsChecked,
            &[arg("path", config.bin_path.display())],
        );
    } else {
        let failed = match (chown_ok, chmod_ok) {
            (false, false) => "chown+chmod",
            (false, true) => "chown",
            _ => "chmod",
        };
        logger::warn_key(
            config,
            LogKey::CorePermissionsFailed,
            &[
                arg("path", config.bin_path.display()),
                arg("failed", failed),
            ],
        );
    }
    Ok(())
}

pub(super) fn parse_user_group(value: &str) -> Result<(u32, u32)> {
    let mut parts = value.splitn(2, ':');
    let user = parts.next().unwrap_or_default();
    let group = parts.next().unwrap_or(user);
    let uid = resolve_user_or_group(user).ok_or_else(|| format!("unknown run user: {user}"))?;
    let gid = resolve_user_or_group(group).ok_or_else(|| format!("unknown run group: {group}"))?;
    Ok((uid, gid))
}

pub(super) fn resolve_user_or_group(value: &str) -> Option<u32> {
    match value.trim() {
        "0" | "root" => Some(0),
        "system" => Some(1000),
        "vpn" => Some(1016),
        "shell" => Some(2000),
        "inet" => Some(3003),
        "net_raw" => Some(3004),
        "net_admin" => Some(3005),
        raw => raw.parse::<u32>().ok(),
    }
}

pub(super) fn permission_stamp_matches(config: &Config) -> bool {
    let Some(stamp) = permission_stamp(config) else {
        return false;
    };
    fs::read_to_string(permission_stamp_path(config))
        .map(|saved| saved == stamp)
        .unwrap_or(false)
}

pub(super) fn save_permission_stamp(config: &Config) -> Result<()> {
    let Some(stamp) = permission_stamp(config) else {
        return Ok(());
    };
    fs::write(permission_stamp_path(config), stamp)
        .map_err(|err| format!("write permission stamp failed: {err}"))
}

pub(super) fn permission_stamp(config: &Config) -> Option<String> {
    Some(format!(
        "{}\n{}\n",
        config.box_user_group,
        file_stamp(&config.bin_path)?
    ))
}

pub(super) fn permission_stamp_path(config: &Config) -> PathBuf {
    config
        .paths
        .state
        .join(format!("{}.permission.stamp", config.bin_name))
}
