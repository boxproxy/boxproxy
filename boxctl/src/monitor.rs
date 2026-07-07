use crate::config::{Config, ConfigOverrides};
use crate::exec::{Runner, SIGKILL, SIGTERM};
use crate::logger;
use crate::rules;
use crate::service;
use crate::Result;
use logger::{arg, LogKey};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{self, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
mod lock;
mod observe;
mod policy;
mod state;
mod watcher;
use lock::*;
use observe::*;
use policy::*;
use state::*;
use watcher::*;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[cfg(unix)]
unsafe extern "C" {
    fn setsid() -> i32;
}

const WIFI_IP_RETRIES: usize = 3;
const WIFI_IP_RETRY_DELAY_MS: u64 = 500;
const WIFI_EVENT_DEBOUNCE_MS: u64 = 600;
const WIFI_EVENT_MAX_DEBOUNCE_MS: u64 = 2000;
const MONITOR_WORKER_ENV: &str = "BOXCTL_MONITOR_WORKER";

#[derive(Clone, Debug)]
struct WifiObservation {
    connected: bool,
    ssid: String,
    bssid: String,
    iface: String,
    ip: Option<String>,
}

#[derive(Clone, Copy, Debug)]
enum ServiceAction {
    AlreadyRunning,
    Started,
    AlreadyStopped,
    Stopped,
}

impl ServiceAction {
    fn log_id(self) -> &'static str {
        match self {
            Self::AlreadyRunning => "already_running",
            Self::Started => "started",
            Self::AlreadyStopped => "already_stopped",
            Self::Stopped => "stopped",
        }
    }
}

struct NetworkPolicyResult {
    observation: WifiObservation,
    handled: bool,
}

pub fn apply_wifi_policy(config: &Config, runner: &Runner) -> Result<()> {
    let observation = current_observation(runner);
    let result = apply_network_control_policy(config, runner, observation)?;
    if result.handled {
        save_wifi_state(config, &result.observation);
    }
    Ok(())
}

pub fn run(config: &Config, runner: &Runner) -> Result<()> {
    if monitor_worker_requested() {
        return if monitor_required(config, runner) {
            monitor_worker(config, runner)
        } else {
            Ok(())
        };
    }

    if !monitor_required(config, runner) {
        return stop_monitor_worker(config, runner);
    }

    if monitor_worker_running(config) {
        return Ok(());
    }

    spawn_monitor_worker(config)?;
    Ok(())
}

pub fn stop(config: &Config, runner: &Runner) -> Result<()> {
    if monitor_required(config, runner) || monitor_worker_requested() {
        return Ok(());
    }

    stop_monitor_worker(config, runner)
}
