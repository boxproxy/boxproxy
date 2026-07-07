use crate::config::Config;
use crate::exec::Runner;
use crate::monitor;
use crate::Result;

pub fn apply(config: &Config, runner: &Runner) -> Result<()> {
    monitor::apply_wifi_policy(config, runner)
}
