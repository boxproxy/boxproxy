use super::*;

pub(super) fn split_user_group(value: &str) -> (&str, &str) {
    value.split_once(':').unwrap_or(("root", "net_admin"))
}

pub(super) fn normalized_list(values: &[String]) -> Vec<String> {
    let mut values: Vec<String> = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    values.sort();
    values.dedup();
    values
}

pub(super) fn normalize_cidr(family: Family, value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    match family {
        Family::V4 => normalize_ipv4_cidr(value),
        Family::V6 => normalize_ipv6_cidr(value),
    }
    .or_else(|| Some(value.to_string()))
}

pub(super) fn normalize_ipv4_cidr(value: &str) -> Option<String> {
    let (addr, prefix) = value.split_once('/')?;
    let addr: Ipv4Addr = addr.parse().ok()?;
    let prefix: u32 = prefix.parse().ok()?;
    if prefix > 32 {
        return None;
    }

    let raw = u32::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Some(format!("{}/{}", Ipv4Addr::from(raw & mask), prefix))
}

pub(super) fn normalize_ipv6_cidr(value: &str) -> Option<String> {
    let (addr, prefix) = value.split_once('/')?;
    let addr: Ipv6Addr = addr.parse().ok()?;
    let prefix: u32 = prefix.parse().ok()?;
    if prefix > 128 {
        return None;
    }

    let raw = u128::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    Some(format!("{}/{}", Ipv6Addr::from(raw & mask), prefix))
}

pub(super) fn ensure_empty_file(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create directory {} failed: {err}", parent.display()))?;
    }
    fs::write(path, "").map_err(|err| format!("create empty file {} failed: {err}", path.display()))
}

pub(super) fn write_lines_file(path: &Path, lines: &[String]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create directory {} failed: {err}", parent.display()))?;
    }
    let mut text = String::new();
    for line in lines {
        let value = line.trim();
        if value.is_empty() {
            continue;
        }
        text.push_str(value);
        text.push('\n');
    }
    fs::write(path, text).map_err(|err| format!("write file {} failed: {err}", path.display()))
}

pub(super) fn require_file(path: &Path, label: &str) -> Result<PathBuf> {
    if path.is_file() {
        Ok(path.to_path_buf())
    } else {
        Err(format!("{label} file not found: {}", path.display()))
    }
}

pub(super) fn find_proc_pid_by_name(name: &str) -> Option<String> {
    fs::read_dir("/proc")
        .ok()?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .find(|pid| proc_pid_matches_name(pid, name))
}

pub(super) fn proc_pid_matches_name(pid: &str, name: &str) -> bool {
    if pid.is_empty() || !pid.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    let proc_dir = Path::new("/proc").join(pid);
    if !proc_dir.is_dir() {
        return false;
    }
    if fs::read_to_string(proc_dir.join("comm"))
        .map(|comm| comm.trim() == name)
        .unwrap_or(false)
    {
        return true;
    }
    let Ok(cmdline) = fs::read(proc_dir.join("cmdline")) else {
        return false;
    };
    let Some(first) = cmdline
        .split(|byte| *byte == 0)
        .find(|part| !part.is_empty())
    else {
        return false;
    };
    Path::new(&String::from_utf8_lossy(first).to_string())
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value == name)
        .unwrap_or(false)
}

pub(super) fn proc_status_first_value(status: &str, key: &str) -> Option<String> {
    status.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?;
        rest.split_whitespace()
            .next()
            .map(|value| value.to_string())
    })
}

pub(super) fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

pub(super) fn ip_args(family: Family, args: &[&str]) -> Vec<String> {
    let mut full = Vec::new();
    if family == Family::V6 {
        full.push("-6".to_string());
    }
    full.extend(args.iter().map(|value| (*value).to_string()));
    full
}

pub(super) fn family_label(family: Family) -> &'static str {
    match family {
        Family::V4 => "IPv4",
        Family::V6 => "IPv6",
    }
}

pub(super) fn family_arg(family: Family) -> logger::LogArg {
    logger::family_arg("family", family_label(family))
}

pub(super) fn dns_target_arg(kind: DnsNatKind) -> logger::LogArg {
    match kind {
        DnsNatKind::Hijack => logger::dns_nat_target_arg("target", "hijack"),
        DnsNatKind::Forward => logger::dns_nat_target_arg("target", "forward"),
    }
}

pub(super) fn iptables_cmd(family: Family) -> &'static str {
    match family {
        Family::V4 => "iptables",
        Family::V6 => "ip6tables",
    }
}

pub(super) fn restore_cmd(family: Family) -> &'static str {
    match family {
        Family::V4 => "iptables-restore",
        Family::V6 => "ip6tables-restore",
    }
}

pub(super) fn local_ip_chain(family: Family) -> &'static str {
    match family {
        Family::V4 => "LOCAL_IP_V4",
        Family::V6 => "LOCAL_IP_V6",
    }
}

pub(super) fn cnip_set_name(family: Family) -> &'static str {
    match family {
        Family::V4 => "cnip",
        Family::V6 => "cnip6",
    }
}

pub(super) fn cnip_ebpf_pin_path(family: Family, chain: &str) -> &'static str {
    match (family, cnip_match_uses_prerouting_program(chain)) {
        (Family::V4, true) => EBPF_PRE4,
        (Family::V6, true) => EBPF_PRE6,
        (Family::V4, false) => EBPF_OUT4,
        (Family::V6, false) => EBPF_OUT6,
    }
}

pub(super) fn cnip_force_ebpf_pin_path(family: Family) -> &'static str {
    match family {
        Family::V4 => EBPF_FORCE_OUT4,
        Family::V6 => EBPF_FORCE_OUT6,
    }
}

pub(super) fn app_uid_ebpf_pin_path(family: Family) -> &'static str {
    match family {
        Family::V4 => EBPF_APP_OUT4,
        Family::V6 => EBPF_APP_OUT6,
    }
}

pub(super) fn cnip_match_uses_prerouting_program(chain: &str) -> bool {
    matches!(
        chain,
        "BOX_EXTERNAL" | "BOX_TUN_BYPASS_PRE" | "BOX_TUN_BYPASS6_PRE"
    ) || chain.contains("_PRE_")
        || chain.ends_with("_PRE")
}

pub(super) fn loopback_addr(family: Family) -> &'static str {
    match family {
        Family::V4 => "127.0.0.1",
        Family::V6 => "::1",
    }
}

pub(super) fn tun_pre_chain(family: Family) -> &'static str {
    match family {
        Family::V4 => "BOX_TUN_BYPASS_PRE",
        Family::V6 => "BOX_TUN_BYPASS6_PRE",
    }
}

pub(super) fn tun_out_chain(family: Family) -> &'static str {
    match family {
        Family::V4 => "BOX_TUN_BYPASS_OUT",
        Family::V6 => "BOX_TUN_BYPASS6_OUT",
    }
}

pub(super) fn dns_pre_chain(family: Family, kind: DnsNatKind) -> &'static str {
    match (family, kind) {
        (Family::V4, DnsNatKind::Hijack) => "NAT_DNS_HIJACK",
        (Family::V6, DnsNatKind::Hijack) => "NAT_DNS_HIJACK6",
        (Family::V4, DnsNatKind::Forward) => "NAT_DNS_FORWARD",
        (Family::V6, DnsNatKind::Forward) => "NAT_DNS_FORWARD6",
    }
}

pub(super) fn dns_out_chain(family: Family, kind: DnsNatKind) -> &'static str {
    match (family, kind) {
        (Family::V4, DnsNatKind::Hijack) => "NAT_DNS_HIJACK_OUT",
        (Family::V6, DnsNatKind::Hijack) => "NAT_DNS_HIJACK6_OUT",
        (Family::V4, DnsNatKind::Forward) => "NAT_DNS_FORWARD_OUT",
        (Family::V6, DnsNatKind::Forward) => "NAT_DNS_FORWARD6_OUT",
    }
}

pub(super) fn is_box_custom_chain(chain: &str) -> bool {
    chain.starts_with("BOX_")
        || chain.starts_with("AP_")
        || matches!(
            chain,
            "DIVERT"
                | "LOCAL_IP_V4"
                | "LOCAL_IP_V6"
                | "NAT_DNS_HIJACK"
                | "NAT_DNS_HIJACK6"
                | "NAT_DNS_HIJACK_OUT"
                | "NAT_DNS_HIJACK6_OUT"
                | "NAT_DNS_FORWARD"
                | "NAT_DNS_FORWARD6"
                | "NAT_DNS_FORWARD_OUT"
                | "NAT_DNS_FORWARD6_OUT"
                | "MIHOMO_DNS_EXTERNAL"
                | "MIHOMO_DNS_LOCAL"
        )
}

pub(super) fn is_box_rule_line(line: &str) -> bool {
    line.split_whitespace().any(is_box_custom_chain)
}

pub(super) fn core_bypass_variants(context: &RuleContext) -> Vec<Vec<String>> {
    vec![
        vec![
            "-m".into(),
            "owner".into(),
            "--uid-owner".into(),
            context.box_uid.clone(),
            "--gid-owner".into(),
            context.box_gid.clone(),
            "-j".into(),
            "RETURN".into(),
        ],
        vec![
            "-m".into(),
            "owner".into(),
            "--uid-owner".into(),
            context.box_uid.clone(),
            "-j".into(),
            "RETURN".into(),
        ],
        vec![
            "-m".into(),
            "owner".into(),
            "--gid-owner".into(),
            context.box_gid.clone(),
            "-j".into(),
            "RETURN".into(),
        ],
    ]
}

pub(super) fn owner_match_variants(
    context: &RuleContext,
    dest_flag: &str,
    dest: &str,
    port: &str,
) -> Vec<Vec<String>> {
    vec![
        vec![
            dest_flag.into(),
            dest.into(),
            "-p".into(),
            "tcp".into(),
            "-m".into(),
            "owner".into(),
            "--uid-owner".into(),
            context.box_uid.clone(),
            "--gid-owner".into(),
            context.box_gid.clone(),
            "-m".into(),
            "tcp".into(),
            "--dport".into(),
            port.into(),
            "-j".into(),
            "REJECT".into(),
        ],
        vec![
            dest_flag.into(),
            dest.into(),
            "-p".into(),
            "tcp".into(),
            "-m".into(),
            "owner".into(),
            "--uid-owner".into(),
            context.box_uid.clone(),
            "-m".into(),
            "tcp".into(),
            "--dport".into(),
            port.into(),
            "-j".into(),
            "REJECT".into(),
        ],
        vec![
            dest_flag.into(),
            dest.into(),
            "-p".into(),
            "tcp".into(),
            "-m".into(),
            "owner".into(),
            "--gid-owner".into(),
            context.box_gid.clone(),
            "-m".into(),
            "tcp".into(),
            "--dport".into(),
            port.into(),
            "-j".into(),
            "REJECT".into(),
        ],
    ]
}

pub(super) fn mode_needs_local_ip_mangle(mode: &str) -> bool {
    matches!(mode, "tproxy" | "enhance")
}

pub(super) fn mode_needs_local_ip_nat(mode: &str) -> bool {
    matches!(mode, "redirect" | "mixed" | "enhance")
}

pub(super) fn valid_macs(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| is_valid_mac(value))
        .collect()
}

pub(super) fn is_valid_mac(value: &str) -> bool {
    let parts: Vec<&str> = value.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|part| part.len() == 2 && part.chars().all(|ch| ch.is_ascii_hexdigit()))
}

pub(super) fn redirect_perf_chains() -> [&'static str; 4] {
    [
        "BOX_RD_PRE_IP",
        "BOX_RD_PRE_IF",
        "BOX_RD_OUT_IP",
        "BOX_RD_OUT_APP",
    ]
}

pub(super) fn tproxy_perf_chains() -> [&'static str; 4] {
    [
        "BOX_TP_PRE_IP",
        "BOX_TP_PRE_IF",
        "BOX_TP_OUT_IP",
        "BOX_TP_OUT_APP",
    ]
}

pub(super) fn tproxy_perf_pre_ip_chain() -> &'static str {
    "BOX_TP_PRE_IP"
}

pub(super) fn tproxy_perf_pre_if_chain() -> &'static str {
    "BOX_TP_PRE_IF"
}

pub(super) fn tproxy_perf_out_ip_chain() -> &'static str {
    "BOX_TP_OUT_IP"
}

pub(super) fn tproxy_perf_out_app_chain() -> &'static str {
    "BOX_TP_OUT_APP"
}

pub(super) fn parse_ip_addr_subnets(text: &str, family: Family, tun_device: &str) -> Vec<String> {
    let mut iface = String::new();
    let mut subnets = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if !line.starts_with(' ') && trimmed.contains(": ") {
            let mut parts = trimmed.split_whitespace();
            let _index = parts.next();
            if let Some(name) = parts.next() {
                iface = name
                    .trim_end_matches(':')
                    .split('@')
                    .next()
                    .unwrap_or(name)
                    .to_string();
            }
            continue;
        }
        if iface == tun_device {
            continue;
        }
        if iface == "lo" {
            continue;
        }

        match family {
            Family::V4 => {
                if let Some(rest) = trimmed.strip_prefix("inet ") {
                    if let Some(cidr) = rest.split_whitespace().next() {
                        subnets.push(cidr.to_string());
                    }
                }
            }
            Family::V6 => {
                if let Some(rest) = trimmed.strip_prefix("inet6 ") {
                    if !trimmed.contains("scope global")
                        || trimmed.contains(" tentative")
                        || trimmed.contains(" dadfailed")
                    {
                        continue;
                    }
                    if let Some(cidr) = rest.split_whitespace().next() {
                        if !cidr.starts_with("fe80") && !cidr.starts_with("::1") {
                            subnets.push(cidr.to_string());
                        }
                    }
                }
            }
        }
    }

    subnets
}

pub(super) fn parse_ip_o_addr_cidrs(text: &str, family: Family, tun_device: &str) -> Vec<String> {
    let mut cidrs = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let iface = parts[1].split('@').next().unwrap_or(parts[1]);
        if iface == tun_device {
            continue;
        }
        let proto = match family {
            Family::V4 => "inet",
            Family::V6 => "inet6",
        };
        let Some(index) = parts.iter().position(|part| *part == proto) else {
            continue;
        };
        let Some(cidr) = parts.get(index + 1) else {
            continue;
        };
        if family == Family::V4 && cidr.starts_with("127.") {
            continue;
        }
        if family == Family::V6 && cidr.to_ascii_lowercase().starts_with("fd00") {
            continue;
        }
        cidrs.push((*cidr).to_string());
    }
    cidrs
}

pub(super) fn fwmark_match_values(mark: &str) -> Vec<String> {
    let mut values = vec![mark.to_string()];
    if let Some((value, mask)) = mark.split_once('/') {
        if let (Ok(value), Ok(mask)) = (value.parse::<u64>(), mask.parse::<u64>()) {
            values.push(format!("0x{value:x}/0x{mask:x}"));
        }
    } else if let Ok(value) = mark.parse::<u64>() {
        values.push(format!("0x{value:x}"));
    }
    values
}

pub(super) fn ipset_source_stamp(source: &Path) -> Option<String> {
    let metadata = fs::metadata(source).ok()?;
    let len = metadata.len();
    let modified = metadata.modified().ok()?;
    let modified = modified.duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(format!("{len}:{modified}"))
}

pub(super) fn command_failure_message(program: &str, args: &[String], output: &Output) -> String {
    let details = if output.stderr.is_empty() {
        output.stdout.as_str()
    } else {
        output.stderr.as_str()
    };
    if details.is_empty() {
        format!(
            "{} execution failed",
            crate::exec::shell_join(program, args)
        )
    } else {
        format!(
            "{} execution failed: {details}",
            crate::exec::shell_join(program, args)
        )
    }
}

pub(super) fn empty_dash(value: &str) -> &str {
    if value.trim().is_empty() {
        "-"
    } else {
        value
    }
}

pub(super) fn join_display_cidrs(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(", ")
    }
}
