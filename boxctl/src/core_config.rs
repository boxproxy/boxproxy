use crate::config::Config;
use crate::{logger, Result};
use jsonc_parser::cst::{CstArray, CstInputValue, CstNode, CstObject, CstRootNode};
use jsonc_parser::{parse_to_serde_value, ParseOptions};
use logger::{arg, LogKey};
use serde_json::{Map, Value};
use std::fs;

mod common;
mod mihomo;
mod rule_set_preload;
mod sing_box;
mod util;
use common::*;
use mihomo::sync_mihomo;
use rule_set_preload::preload_sing_box_rule_sets;
use sing_box::sync_sing_box;
use util::*;

const MANAGED_TUN_BEGIN: &str = "# boxctl managed tun begin";
const MANAGED_TUN_END: &str = "# boxctl managed tun end";

pub fn sync(config: &Config) -> Result<()> {
    if !config.auto_sync_config {
        logger::info_key(config, LogKey::CoreConfigSyncDisabled, &[]);
        return Ok(());
    }

    match config.bin_name.as_str() {
        "mihomo" => sync_mihomo(config),
        "sing-box" => sync_sing_box(config),
        "xray" | "v2fly" | "hysteria" => {
            logger::warn_key(
                config,
                LogKey::CoreConfigSyncUnsupported,
                &[arg("core", &config.bin_name)],
            );
            Ok(())
        }
        other => Err(format!("unknown core: {other}")),
    }
}

pub fn preload_rule_sets(config: &Config) -> Result<()> {
    match config.bin_name.as_str() {
        "sing-box" => preload_sing_box_rule_sets(config),
        _ => Ok(()),
    }
}
