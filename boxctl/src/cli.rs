use crate::config::ConfigOverrides;
use crate::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
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

#[derive(Debug, Parser)]
#[command(
    name = "boxctl",
    about = "Control BoxProxy runtime service and routing rules",
    disable_version_flag = true,
    arg_required_else_help = true,
    subcommand_required = true
)]
struct RawCli {
    #[command(flatten)]
    options: RawOptions,

    #[command(subcommand)]
    command: RawCommand,
}

#[derive(Debug, Args)]
struct RawOptions {
    #[arg(long, value_name = "PATH", help = "Box work directory")]
    home: Option<String>,

    #[arg(long, help = "Preview commands only")]
    dry_run: bool,

    #[arg(short, long, help = "Print commands before running them")]
    verbose: bool,

    #[arg(
        long = "db",
        alias = "db-path",
        value_name = "PATH",
        help = "Runtime database path"
    )]
    db_path: Option<PathBuf>,

    #[arg(long = "core", alias = "bin", value_name = "NAME", help = "Core name")]
    bin_name: Option<String>,

    #[arg(long, value_name = "PATH", help = "Core binary path")]
    bin_path: Option<PathBuf>,

    #[arg(
        long = "config",
        alias = "config-path",
        value_name = "PATH",
        help = "Core config file"
    )]
    config_path: Option<PathBuf>,

    #[arg(long, value_enum, value_name = "MODE", help = "Network mode")]
    mode: Option<NetworkMode>,

    #[arg(long, value_name = "MODE", help = "Proxy handling mode")]
    proxy_mode: Option<String>,

    #[arg(long, value_name = "PORT", help = "TPROXY port")]
    tproxy_port: Option<String>,

    #[arg(long, value_name = "PORT", help = "REDIRECT port")]
    redir_port: Option<String>,

    #[arg(long, value_name = "NAME", help = "TUN device name")]
    tun_device: Option<String>,

    #[arg(long, value_name = "MODE", help = "DNS hijack mode")]
    dns_mode: Option<String>,

    #[arg(long, value_name = "PORT", help = "Mihomo DNS forward port")]
    dns_port: Option<String>,

    #[arg(long, value_name = "MODE", help = "Mihomo DNS forward mode")]
    dns_forward: Option<String>,

    #[arg(long, conflicts_with = "no_ipv6", help = "Enable IPv6 proxying")]
    ipv6: bool,

    #[arg(long, conflicts_with = "ipv6", help = "Bypass IPv6 traffic")]
    no_ipv6: bool,

    #[arg(long, value_enum, value_name = "MODE", help = "IPv6 mode")]
    ipv6_mode: Option<Ipv6Mode>,

    #[arg(long, conflicts_with = "no_tcp", help = "Enable TCP proxying")]
    tcp: bool,

    #[arg(long, conflicts_with = "tcp", help = "Disable TCP proxying")]
    no_tcp: bool,

    #[arg(long, conflicts_with = "no_udp", help = "Enable UDP proxying")]
    udp: bool,

    #[arg(long, conflicts_with = "udp", help = "Disable UDP proxying")]
    no_udp: bool,

    #[arg(long, conflicts_with = "no_dns_tcp", help = "Enable TCP DNS hijacking")]
    dns_tcp: bool,

    #[arg(long, conflicts_with = "dns_tcp", help = "Disable TCP DNS hijacking")]
    no_dns_tcp: bool,

    #[arg(long, conflicts_with = "no_dns_udp", help = "Enable UDP DNS hijacking")]
    dns_udp: bool,

    #[arg(long, conflicts_with = "dns_udp", help = "Disable UDP DNS hijacking")]
    no_dns_udp: bool,

    #[arg(long, conflicts_with = "no_quic", help = "Enable QUIC")]
    quic: bool,

    #[arg(long, conflicts_with = "quic", help = "Disable QUIC")]
    no_quic: bool,

    #[arg(long, conflicts_with = "no_memcg", help = "Enable memory limit")]
    memcg: bool,

    #[arg(long, conflicts_with = "memcg", help = "Disable memory limit")]
    no_memcg: bool,

    #[arg(long, value_name = "LIMIT", help = "Memory limit, for example 100M")]
    memcg_limit: Option<String>,

    #[arg(
        long = "taskset",
        conflicts_with = "no_taskset",
        help = "Enable CPU assignment with taskset"
    )]
    taskset: bool,

    #[arg(
        long = "no-taskset",
        conflicts_with = "taskset",
        help = "Disable CPU assignment"
    )]
    no_taskset: bool,

    #[arg(long, value_name = "LIST", help = "Allowed CPU cores, for example 0-7")]
    allow_cpu: Option<String>,

    #[arg(long, conflicts_with = "no_blkio", help = "Enable disk I/O weight")]
    blkio: bool,

    #[arg(long, conflicts_with = "blkio", help = "Disable disk I/O weight")]
    no_blkio: bool,

    #[arg(
        long = "io-weight",
        alias = "weight",
        value_name = "VALUE",
        help = "Disk I/O weight"
    )]
    weight: Option<String>,

    #[arg(long, conflicts_with = "no_bypass_cn", help = "Enable CNIP bypass")]
    bypass_cn: bool,

    #[arg(
        long,
        conflicts_with_all = ["bypass_cn", "bypass_cn_v4", "bypass_cn_v6"],
        help = "Disable CNIP bypass"
    )]
    no_bypass_cn: bool,

    #[arg(
        long,
        conflicts_with = "no_bypass_cn",
        help = "Enable IPv4 CNIP bypass"
    )]
    bypass_cn_v4: bool,

    #[arg(
        long,
        conflicts_with = "no_bypass_cn",
        help = "Enable IPv6 CNIP bypass"
    )]
    bypass_cn_v6: bool,

    #[arg(long, value_name = "PATH", help = "IPv4 CNIP CIDR file")]
    cn_ip_file: Option<PathBuf>,

    #[arg(long, value_name = "PATH", help = "IPv6 CNIP CIDR file")]
    cn_ipv6_file: Option<PathBuf>,

    #[arg(long, value_name = "CIDR", help = "Fake-IP IPv4 range")]
    fake_ip_range: Option<String>,

    #[arg(long, value_name = "CIDR", help = "Fake-IP IPv6 range")]
    fake_ip6_range: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum NetworkMode {
    Tun,
    Tproxy,
    Redirect,
    Mixed,
    Enhance,
}

impl NetworkMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tun => "tun",
            Self::Tproxy => "tproxy",
            Self::Redirect => "redirect",
            Self::Mixed => "mixed",
            Self::Enhance => "enhance",
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum Ipv6Mode {
    #[value(alias = "enabled", alias = "true", alias = "1")]
    Enable,
    #[value(alias = "bypassed", alias = "false", alias = "0")]
    Bypass,
    #[value(alias = "disabled", alias = "system_disable", alias = "off")]
    Disable,
}

impl Ipv6Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Enable => "enable",
            Self::Bypass => "bypass",
            Self::Disable => "disable",
        }
    }
}

#[derive(Debug, Subcommand)]
#[command(rename_all = "kebab-case")]
enum RawCommand {
    Up {
        #[arg(value_enum, value_name = "MODE")]
        run_mode: Option<NetworkMode>,
    },
    Boot,
    Down,
    Restart {
        #[arg(value_enum, value_name = "MODE")]
        run_mode: Option<NetworkMode>,
    },
    Status,
    Service {
        #[command(subcommand)]
        command: RawServiceCommand,
    },
    Mode {
        #[command(subcommand)]
        command: RawModeCommand,
    },
    Config {
        #[command(subcommand)]
        command: RawConfigCommand,
    },
    Resource {
        #[command(subcommand)]
        command: RawResourceCommand,
    },
    Cnip {
        #[command(subcommand)]
        command: RawCnipCommand,
    },
    Monitor {
        #[command(subcommand)]
        command: Option<RawMonitorCommand>,
    },
    Wifi {
        #[command(subcommand)]
        command: RawWifiCommand,
    },
}

#[derive(Debug, Subcommand)]
#[command(rename_all = "kebab-case")]
enum RawServiceCommand {
    Start,
    Stop,
    Restart,
    Status,
}

#[derive(Debug, Subcommand)]
#[command(rename_all = "kebab-case")]
enum RawModeCommand {
    Apply {
        #[arg(value_enum, value_name = "MODE")]
        run_mode: Option<NetworkMode>,
    },
    Clear,
    Renew {
        #[arg(value_enum, value_name = "MODE")]
        run_mode: Option<NetworkMode>,
    },
}

#[derive(Debug, Subcommand)]
#[command(rename_all = "kebab-case")]
enum RawConfigCommand {
    Sync,
}

#[derive(Debug, Subcommand)]
#[command(rename_all = "kebab-case")]
enum RawResourceCommand {
    Apply,
}

#[derive(Debug, Subcommand)]
#[command(rename_all = "kebab-case")]
enum RawCnipCommand {
    Reload,
}

#[derive(Debug, Subcommand)]
#[command(rename_all = "kebab-case")]
enum RawMonitorCommand {
    Stop,
}

#[derive(Debug, Subcommand)]
#[command(rename_all = "kebab-case")]
enum RawWifiCommand {
    Apply,
}

pub(crate) fn parse_args(args: Vec<String>) -> Result<Cli> {
    let raw = match RawCli::try_parse_from(std::iter::once("boxctl".to_string()).chain(args)) {
        Ok(raw) => raw,
        Err(error) => match error.kind() {
            clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                let _ = error.print();
                process::exit(0);
            }
            _ => return Err(error.to_string()),
        },
    };

    raw.into_cli()
}

impl RawCli {
    fn into_cli(self) -> Result<Cli> {
        let mut overrides = self.options.into_overrides();
        let command = self.command.into_command(&mut overrides)?;
        Ok(Cli {
            home: self.options.home,
            dry_run: self.options.dry_run,
            verbose: self.options.verbose,
            overrides,
            command,
        })
    }
}

impl RawOptions {
    fn into_overrides(&self) -> ConfigOverrides {
        let mut overrides = ConfigOverrides::default();
        overrides.db_path = self.db_path.clone();
        overrides.bin_name = self.bin_name.clone();
        overrides.bin_path = self.bin_path.clone();
        overrides.config_path = self.config_path.clone();
        overrides.network_mode = self.mode.map(|mode| mode.as_str().to_string());
        overrides.proxy_mode = self.proxy_mode.clone();
        overrides.tproxy_port = self.tproxy_port.clone();
        overrides.redir_port = self.redir_port.clone();
        overrides.tun_device = self.tun_device.clone();
        overrides.dns_hijack_mode = self.dns_mode.clone();
        overrides.mihomo_dns_port = self.dns_port.clone();
        overrides.mihomo_dns_forward = self.dns_forward.clone();
        overrides.ipv6_mode = self.ipv6_mode.map(|mode| mode.as_str().to_string());
        set_flag(&mut overrides.ipv6_mode, self.ipv6, "enable");
        set_flag(&mut overrides.ipv6_mode, self.no_ipv6, "bypass");
        set_bool(&mut overrides.proxy_tcp, self.tcp, true);
        set_bool(&mut overrides.proxy_tcp, self.no_tcp, false);
        set_bool(&mut overrides.proxy_udp, self.udp, true);
        set_bool(&mut overrides.proxy_udp, self.no_udp, false);
        set_bool(&mut overrides.dns_hijack_tcp, self.dns_tcp, true);
        set_bool(&mut overrides.dns_hijack_tcp, self.no_dns_tcp, false);
        set_bool(&mut overrides.dns_hijack_udp, self.dns_udp, true);
        set_bool(&mut overrides.dns_hijack_udp, self.no_dns_udp, false);
        set_flag(&mut overrides.quic, self.quic, "enable");
        set_flag(&mut overrides.quic, self.no_quic, "disable");
        set_bool(&mut overrides.cgroup_memcg, self.memcg, true);
        set_bool(&mut overrides.cgroup_memcg, self.no_memcg, false);
        overrides.memcg_limit = self.memcg_limit.clone();
        set_bool(&mut overrides.taskset_cpu, self.taskset, true);
        set_bool(&mut overrides.taskset_cpu, self.no_taskset, false);
        overrides.allow_cpu = self.allow_cpu.clone();
        set_bool(&mut overrides.cgroup_blkio, self.blkio, true);
        set_bool(&mut overrides.cgroup_blkio, self.no_blkio, false);
        overrides.weight = self.weight.clone();
        if self.bypass_cn {
            overrides.bypass_cn_ip = Some(true);
            overrides.bypass_cn_ip_v4 = Some(true);
            overrides.bypass_cn_ip_v6 = Some(true);
        }
        if self.no_bypass_cn {
            overrides.bypass_cn_ip = Some(false);
            overrides.bypass_cn_ip_v4 = Some(false);
            overrides.bypass_cn_ip_v6 = Some(false);
        }
        if self.bypass_cn_v4 {
            overrides.bypass_cn_ip = Some(true);
            overrides.bypass_cn_ip_v4 = Some(true);
        }
        if self.bypass_cn_v6 {
            overrides.bypass_cn_ip = Some(true);
            overrides.bypass_cn_ip_v6 = Some(true);
        }
        overrides.cn_ip_file = self.cn_ip_file.clone();
        overrides.cn_ipv6_file = self.cn_ipv6_file.clone();
        overrides.fake_ip_range = self.fake_ip_range.clone();
        overrides.fake_ip6_range = self.fake_ip6_range.clone();
        overrides
    }
}

impl RawCommand {
    fn into_command(self, overrides: &mut ConfigOverrides) -> Result<Command> {
        Ok(match self {
            Self::Up { run_mode } => {
                set_mode_override(overrides, run_mode)?;
                Command::Up
            }
            Self::Boot => Command::Boot,
            Self::Down => Command::Down,
            Self::Restart { run_mode } => {
                set_mode_override(overrides, run_mode)?;
                Command::Restart
            }
            Self::Status => Command::Status,
            Self::Service { command } => Command::Service(command.into()),
            Self::Mode { command } => command.into_command(overrides)?,
            Self::Config { command } => Command::Config(command.into()),
            Self::Resource { command } => Command::Resource(command.into()),
            Self::Cnip { command } => Command::Cnip(command.into()),
            Self::Monitor { command } => match command {
                Some(RawMonitorCommand::Stop) => Command::MonitorStop,
                None => Command::Monitor,
            },
            Self::Wifi { command } => Command::Wifi(command.into()),
        })
    }
}

impl RawModeCommand {
    fn into_command(self, overrides: &mut ConfigOverrides) -> Result<Command> {
        Ok(match self {
            Self::Apply { run_mode } => {
                set_mode_override(overrides, run_mode)?;
                Command::Mode(ModeCommand::Apply)
            }
            Self::Clear => Command::Mode(ModeCommand::Clear),
            Self::Renew { run_mode } => {
                set_mode_override(overrides, run_mode)?;
                Command::Mode(ModeCommand::Renew)
            }
        })
    }
}

impl From<RawServiceCommand> for ServiceCommand {
    fn from(value: RawServiceCommand) -> Self {
        match value {
            RawServiceCommand::Start => Self::Start,
            RawServiceCommand::Stop => Self::Stop,
            RawServiceCommand::Restart => Self::Restart,
            RawServiceCommand::Status => Self::Status,
        }
    }
}

impl From<RawConfigCommand> for ConfigCommand {
    fn from(value: RawConfigCommand) -> Self {
        match value {
            RawConfigCommand::Sync => Self::Sync,
        }
    }
}

impl From<RawResourceCommand> for ResourceCommand {
    fn from(value: RawResourceCommand) -> Self {
        match value {
            RawResourceCommand::Apply => Self::Apply,
        }
    }
}

impl From<RawCnipCommand> for CnipCommand {
    fn from(value: RawCnipCommand) -> Self {
        match value {
            RawCnipCommand::Reload => Self::Reload,
        }
    }
}

impl From<RawWifiCommand> for WifiCommand {
    fn from(value: RawWifiCommand) -> Self {
        match value {
            RawWifiCommand::Apply => Self::Apply,
        }
    }
}

fn set_mode_override(overrides: &mut ConfigOverrides, mode: Option<NetworkMode>) -> Result<()> {
    let Some(mode) = mode else {
        return Ok(());
    };
    let mode = mode.as_str().to_string();
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

fn set_bool(target: &mut Option<bool>, enabled: bool, value: bool) {
    if enabled {
        *target = Some(value);
    }
}

fn set_flag(target: &mut Option<String>, enabled: bool, value: &str) {
    if enabled {
        *target = Some(value.to_string());
    }
}

pub(crate) fn print_version() {
    let build_time = option_env!("BOXCTL_BUILD_TIME").unwrap_or("unknown");
    println!("boxctl {} ({build_time})", env!("CARGO_PKG_VERSION"));
}
