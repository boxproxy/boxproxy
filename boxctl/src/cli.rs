use crate::config::ConfigOverrides;
use crate::Result;
use std::path::PathBuf;
use std::process;

#[derive(Debug)]
pub(crate) enum Command {
    Up,
    Boot,
    Down,
    Restart,
    Status,
    Service(ServiceCommand),
    Mode(ModeCommand),
    Config(ConfigCommand),
    Resource(ResourceCommand),
    Cnip(CnipCommand),
    Monitor,
    MonitorStop,
    Wifi(WifiCommand),
}

#[derive(Debug)]
pub(crate) enum ServiceCommand {
    Start,
    Stop,
    Restart,
    Status,
}

#[derive(Debug)]
pub(crate) enum ModeCommand {
    Apply,
    Clear,
    Renew,
}

#[derive(Debug)]
pub(crate) enum ConfigCommand {
    Sync,
}

#[derive(Debug)]
pub(crate) enum ResourceCommand {
    Apply,
}

#[derive(Debug)]
pub(crate) enum CnipCommand {
    Reload,
}

#[derive(Debug)]
pub(crate) enum WifiCommand {
    Apply,
}

#[derive(Debug)]
pub(crate) struct Cli {
    pub(crate) home: Option<String>,
    pub(crate) dry_run: bool,
    pub(crate) verbose: bool,
    pub(crate) overrides: ConfigOverrides,
    pub(crate) command: Command,
}

pub(crate) fn parse_args(args: Vec<String>) -> Result<Cli> {
    let mut home = None;
    let mut dry_run = false;
    let mut verbose = false;
    let mut overrides = ConfigOverrides::default();
    let mut rest = Vec::new();
    let mut i = 0;

    while i < args.len() {
        // Normalize `--flag=value` into a key plus an inline value up front, so a
        // single set of `--flag` arms handles both `--flag value` and
        // `--flag=value` uniformly (the previous duplicated `=` arms covered only
        // some flags). Positional args (no leading `--`) are never split.
        let (key, inline) = match args[i].split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => (flag, Some(value.to_string())),
            _ => (args[i].as_str(), None),
        };
        let inline = inline.as_deref();

        match key {
            "--home" => home = Some(value_for(key, inline, &args, &mut i)?),
            "--dry-run" => dry_run = true,
            "--verbose" | "-v" => verbose = true,
            "--db" | "--db-path" => {
                overrides.db_path = Some(PathBuf::from(value_for(key, inline, &args, &mut i)?));
            }
            "--core" | "--bin" => {
                overrides.bin_name = Some(value_for(key, inline, &args, &mut i)?);
            }
            "--bin-path" => {
                overrides.bin_path = Some(PathBuf::from(value_for(key, inline, &args, &mut i)?));
            }
            "--config" | "--config-path" => {
                overrides.config_path = Some(PathBuf::from(value_for(key, inline, &args, &mut i)?));
            }
            "--mode" => {
                overrides.network_mode =
                    Some(normalize_mode(&value_for(key, inline, &args, &mut i)?)?);
            }
            "--proxy-mode" => {
                overrides.proxy_mode = Some(value_for(key, inline, &args, &mut i)?);
            }
            "--tproxy-port" => {
                overrides.tproxy_port = Some(value_for(key, inline, &args, &mut i)?);
            }
            "--redir-port" => {
                overrides.redir_port = Some(value_for(key, inline, &args, &mut i)?);
            }
            "--tun-device" => {
                overrides.tun_device = Some(value_for(key, inline, &args, &mut i)?);
            }
            "--dns-mode" => {
                overrides.dns_hijack_mode = Some(value_for(key, inline, &args, &mut i)?);
            }
            "--dns-port" => {
                overrides.mihomo_dns_port = Some(value_for(key, inline, &args, &mut i)?);
            }
            "--dns-forward" => {
                overrides.mihomo_dns_forward = Some(value_for(key, inline, &args, &mut i)?);
            }
            "--ipv6" => overrides.ipv6_mode = Some("enable".to_string()),
            "--no-ipv6" => overrides.ipv6_mode = Some("bypass".to_string()),
            "--ipv6-mode" => {
                overrides.ipv6_mode = Some(normalize_ipv6_mode(&value_for(
                    key, inline, &args, &mut i,
                )?)?);
            }
            "--tcp" => overrides.proxy_tcp = Some(true),
            "--no-tcp" => overrides.proxy_tcp = Some(false),
            "--udp" => overrides.proxy_udp = Some(true),
            "--no-udp" => overrides.proxy_udp = Some(false),
            "--dns-tcp" => overrides.dns_hijack_tcp = Some(true),
            "--no-dns-tcp" => overrides.dns_hijack_tcp = Some(false),
            "--dns-udp" => overrides.dns_hijack_udp = Some(true),
            "--no-dns-udp" => overrides.dns_hijack_udp = Some(false),
            "--quic" => overrides.quic = Some("enable".to_string()),
            "--no-quic" => overrides.quic = Some("disable".to_string()),
            "--memcg" => overrides.cgroup_memcg = Some(true),
            "--no-memcg" => overrides.cgroup_memcg = Some(false),
            "--memcg-limit" => {
                overrides.memcg_limit = Some(value_for(key, inline, &args, &mut i)?);
            }
            "--cpuset" => overrides.cgroup_cpuset = Some(true),
            "--no-cpuset" => overrides.cgroup_cpuset = Some(false),
            "--allow-cpu" => {
                overrides.allow_cpu = Some(value_for(key, inline, &args, &mut i)?);
            }
            "--blkio" => overrides.cgroup_blkio = Some(true),
            "--no-blkio" => overrides.cgroup_blkio = Some(false),
            "--io-weight" | "--weight" => {
                overrides.weight = Some(value_for(key, inline, &args, &mut i)?);
            }
            "--bypass-cn" => {
                overrides.bypass_cn_ip = Some(true);
                overrides.bypass_cn_ip_v4 = Some(true);
                overrides.bypass_cn_ip_v6 = Some(true);
            }
            "--no-bypass-cn" => {
                overrides.bypass_cn_ip = Some(false);
                overrides.bypass_cn_ip_v4 = Some(false);
                overrides.bypass_cn_ip_v6 = Some(false);
            }
            "--bypass-cn-v4" => {
                overrides.bypass_cn_ip = Some(true);
                overrides.bypass_cn_ip_v4 = Some(true);
            }
            "--bypass-cn-v6" => {
                overrides.bypass_cn_ip = Some(true);
                overrides.bypass_cn_ip_v6 = Some(true);
            }
            "--cn-ip-file" => {
                overrides.cn_ip_file = Some(PathBuf::from(value_for(key, inline, &args, &mut i)?));
            }
            "--cn-ipv6-file" => {
                overrides.cn_ipv6_file =
                    Some(PathBuf::from(value_for(key, inline, &args, &mut i)?));
            }
            "--fake-ip-range" => {
                overrides.fake_ip_range = Some(value_for(key, inline, &args, &mut i)?);
            }
            "--fake-ip6-range" => {
                overrides.fake_ip6_range = Some(value_for(key, inline, &args, &mut i)?);
            }
            "--sing-rule-set-preload" => overrides.sing_rule_set_preload = Some(true),
            "--no-sing-rule-set-preload" => overrides.sing_rule_set_preload = Some(false),
            "--sing-rule-set-refresh" => overrides.sing_rule_set_preload_refresh = Some(true),
            "--no-sing-rule-set-refresh" => overrides.sing_rule_set_preload_refresh = Some(false),
            "--sing-rule-set-dir" => {
                overrides.sing_rule_set_preload_dir =
                    Some(PathBuf::from(value_for(key, inline, &args, &mut i)?));
            }
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            "--version" | "-V" => {
                print_version();
                process::exit(0);
            }
            _ => rest.push(args[i].clone()),
        }
        i += 1;
    }

    if rest.is_empty() {
        print_usage();
        return Err("missing command".to_string());
    }

    let command = parse_command(&rest, &mut overrides)?;

    Ok(Cli {
        home,
        dry_run,
        verbose,
        overrides,
        command,
    })
}

fn parse_command(rest: &[String], overrides: &mut ConfigOverrides) -> Result<Command> {
    if rest.first().map(String::as_str) == Some("monitor") {
        return match rest {
            [cmd] if cmd == "monitor" => Ok(Command::Monitor),
            [cmd, action] if cmd == "monitor" && action == "stop" => Ok(Command::MonitorStop),
            _ => {
                print_usage();
                Err(format!("unknown command: {}", rest.join(" ")))
            }
        };
    }

    match rest {
        [cmd] => match cmd.as_str() {
            "up" => Ok(Command::Up),
            "boot" => Ok(Command::Boot),
            "down" => Ok(Command::Down),
            "restart" => Ok(Command::Restart),
            "status" => Ok(Command::Status),
            other => {
                print_usage();
                Err(format!("unknown command: {other}"))
            }
        },
        [group, action] => match (group.as_str(), action.as_str()) {
            ("service", "start") => Ok(Command::Service(ServiceCommand::Start)),
            ("service", "stop") => Ok(Command::Service(ServiceCommand::Stop)),
            ("service", "restart") => Ok(Command::Service(ServiceCommand::Restart)),
            ("service", "status") => Ok(Command::Service(ServiceCommand::Status)),
            ("mode", "apply") => Ok(Command::Mode(ModeCommand::Apply)),
            ("mode", "clear") => Ok(Command::Mode(ModeCommand::Clear)),
            ("mode", "renew") => Ok(Command::Mode(ModeCommand::Renew)),
            ("config", "sync") => Ok(Command::Config(ConfigCommand::Sync)),
            ("resource", "apply") => Ok(Command::Resource(ResourceCommand::Apply)),
            ("cnip", "reload") => Ok(Command::Cnip(CnipCommand::Reload)),
            ("wifi", "apply") => Ok(Command::Wifi(WifiCommand::Apply)),
            ("up", mode) => {
                set_mode_override(overrides, mode)?;
                Ok(Command::Up)
            }
            ("restart", mode) => {
                set_mode_override(overrides, mode)?;
                Ok(Command::Restart)
            }
            _ => {
                print_usage();
                Err(format!("unknown command: {}", rest.join(" ")))
            }
        },
        [group, action, mode] => match (group.as_str(), action.as_str()) {
            ("mode", "apply") => {
                set_mode_override(overrides, mode)?;
                Ok(Command::Mode(ModeCommand::Apply))
            }
            ("mode", "renew") => {
                set_mode_override(overrides, mode)?;
                Ok(Command::Mode(ModeCommand::Renew))
            }
            _ => {
                print_usage();
                Err(format!("unknown command: {}", rest.join(" ")))
            }
        },
        _ => {
            print_usage();
            Err(format!("unknown command: {}", rest.join(" ")))
        }
    }
}

/// Resolve a value flag: prefer the inline `--flag=value` form, otherwise
/// consume the next argument (advancing `i` past it).
fn value_for(flag: &str, inline: Option<&str>, args: &[String], i: &mut usize) -> Result<String> {
    if let Some(value) = inline {
        return Ok(value.to_string());
    }
    *i += 1;
    take_value(args, *i, flag)
}

fn take_value(args: &[String], index: usize, flag: &str) -> Result<String> {
    args.get(index)
        .filter(|value| !value.starts_with("--"))
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn set_mode_override(overrides: &mut ConfigOverrides, value: &str) -> Result<()> {
    let mode = normalize_mode(value)?;
    if let Some(current) = &overrides.network_mode {
        if current != &mode {
            return Err(format!(
                "network mode specified twice: {current} and {mode}"
            ));
        }
    }
    overrides.network_mode = Some(mode);
    Ok(())
}

fn normalize_mode(value: &str) -> Result<String> {
    match value {
        "tun" | "tproxy" | "redirect" | "mixed" | "enhance" => Ok(value.to_string()),
        other => Err(format!("unknown network mode: {other}")),
    }
}

fn normalize_ipv6_mode(value: &str) -> Result<String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "enable" | "enabled" | "true" | "1" => Ok("enable".to_string()),
        "bypass" | "bypassed" | "false" | "0" => Ok("bypass".to_string()),
        "disable" | "disabled" | "system_disable" | "off" => Ok("disable".to_string()),
        other => Err(format!("unknown IPv6 mode: {other}")),
    }
}

fn print_usage() {
    eprintln!(
        "Usage:
  boxctl [options] up [tun|tproxy|redirect|mixed|enhance]
  boxctl [options] boot
  boxctl [options] down
  boxctl [options] restart [tun|tproxy|redirect|mixed|enhance]
  boxctl [options] status
  boxctl [options] service start|stop|restart|status
  boxctl [options] mode apply [tun|tproxy|redirect|mixed|enhance]
  boxctl [options] mode clear
  boxctl [options] mode renew [tun|tproxy|redirect|mixed|enhance]
  boxctl [options] config sync
  boxctl [options] resource apply
  boxctl [options] cnip reload
  boxctl [options] wifi apply
  boxctl [options] monitor
  boxctl [options] monitor stop

Options:
  --home PATH              Box work directory, inferred from boxctl bin directory by default
  --db PATH                Database path, defaults to box.db under the work directory
  --core NAME              Core name, read from database by default
  --config PATH            Core config file
  --mode MODE              Network mode
  --tun-device NAME        TUN device name
  --tproxy-port PORT       TPROXY port
  --redir-port PORT        REDIRECT port
  --dns-mode MODE          DNS hijack mode: tproxy|redirect|disable
  --dns-port PORT          DNS forward port
  --ipv6                   Enable IPv6 proxying
  --no-ipv6                Bypass IPv6
  --ipv6-mode MODE         IPv6 mode: enable|bypass|disable
  --sing-rule-set-preload  Preload sing-box remote rule sets before start
  --sing-rule-set-refresh  Refresh cached sing-box rule sets before start
  --sing-rule-set-dir PATH Directory for preloaded sing-box rule sets
  --memcg                  Enable memory limit
  --memcg-limit LIMIT      Memory limit, for example 100M
  --cpuset                 Enable CPU assignment
  --allow-cpu LIST         Allowed CPU cores, for example 0-7
  --blkio                  Enable disk I/O weight
  --io-weight VALUE        I/O weight, default 900
  --bypass-cn              Enable CNIP bypass
  --dry-run                Preview commands only
  --version                Show version"
    );
}

pub(crate) fn print_version() {
    let build_time = option_env!("BOXCTL_BUILD_TIME").unwrap_or("unknown");
    println!("boxctl {} ({build_time})", env!("CARGO_PKG_VERSION"));
}
