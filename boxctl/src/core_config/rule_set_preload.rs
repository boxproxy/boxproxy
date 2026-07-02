use super::*;
use std::path::{Path, PathBuf};
use std::time::Duration;

const USER_AGENT: &str = concat!("boxctl/", env!("CARGO_PKG_VERSION"));
const MAX_RULE_SET_BYTES: u64 = 50 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
struct RemoteRuleSet {
    index: usize,
    tag: String,
    url: String,
    format: String,
}

pub(super) fn preload_sing_box_rule_sets(config: &Config) -> Result<()> {
    if !config.sing_rule_set_preload {
        remove_prepared_config(config)?;
        return Ok(());
    }

    let path = config.config_path();
    let text = fs::read_to_string(path)
        .map_err(|err| format!("read sing-box config {} failed: {err}", path.display()))?;
    let value: Value = parse_to_serde_value::<Value>(&text, &ParseOptions::default())
        .map_err(|err| format!("parse sing-box config {} failed: {err}", path.display()))?;
    let rule_sets = collect_remote_rule_sets(&value);
    if rule_sets.is_empty() {
        remove_prepared_config(config)?;
        return Ok(());
    }

    fs::create_dir_all(&config.sing_rule_set_preload_dir).map_err(|err| {
        format!(
            "create rule-set cache directory {} failed: {err}",
            config.sing_rule_set_preload_dir.display()
        )
    })?;
    if let Some(parent) = config.sing_rule_set_prepared_config.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create prepared config directory failed: {err}"))?;
    }

    logger::info_key(
        config,
        LogKey::RuleSetPreloadBegin,
        &[
            arg("count", rule_sets.len()),
            arg("dir", config.sing_rule_set_preload_dir.display()),
        ],
    );

    let agent = http_agent();
    let root = CstRootNode::parse(&text, &ParseOptions::default()).map_err(|err| {
        format!(
            "parse sing-box config structure {} failed: {err}",
            path.display()
        )
    })?;
    for rule_set in &rule_sets {
        let local_path = rule_set_local_path(config, rule_set);
        let downloaded = ensure_rule_set_file(config, &agent, rule_set, &local_path)?;
        rewrite_rule_set_to_local(&root, rule_set.index, &local_path)?;
        if downloaded {
            logger::info_key(
                config,
                LogKey::RuleSetPreloadDownloaded,
                &[
                    arg("tag", rule_set_label(rule_set)),
                    arg("path", local_path.display()),
                ],
            );
        } else {
            logger::debug_key(
                config,
                LogKey::RuleSetPreloadCached,
                &[
                    arg("tag", rule_set_label(rule_set)),
                    arg("path", local_path.display()),
                ],
            );
        }
    }

    fs::write(&config.sing_rule_set_prepared_config, root.to_string()).map_err(|err| {
        format!(
            "write prepared sing-box config {} failed: {err}",
            config.sing_rule_set_prepared_config.display()
        )
    })?;
    logger::info_key(
        config,
        LogKey::RuleSetPreloadPrepared,
        &[arg(
            "config",
            config.sing_rule_set_prepared_config.display(),
        )],
    );
    Ok(())
}

fn remove_prepared_config(config: &Config) -> Result<()> {
    match fs::remove_file(&config.sing_rule_set_prepared_config) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "remove prepared sing-box config {} failed: {err}",
            config.sing_rule_set_prepared_config.display()
        )),
    }
}

fn collect_remote_rule_sets(value: &Value) -> Vec<RemoteRuleSet> {
    value
        .as_object()
        .and_then(|root| root.get("route"))
        .and_then(Value::as_object)
        .and_then(|route| route.get("rule_set"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .enumerate()
                .filter_map(|(index, item)| {
                    let object = item.as_object()?;
                    let rule_type = object.get("type")?.as_str()?;
                    if rule_type != "remote" {
                        return None;
                    }
                    let url = object.get("url")?.as_str()?.trim();
                    if url.is_empty() {
                        return None;
                    }
                    Some(RemoteRuleSet {
                        index,
                        tag: object
                            .get("tag")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .trim()
                            .to_string(),
                        url: url.to_string(),
                        format: object
                            .get("format")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .trim()
                            .to_ascii_lowercase(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn http_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .timeout_resolve(Some(Duration::from_secs(8)))
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_recv_body(Some(Duration::from_secs(20)))
        .max_redirects(5)
        .build()
        .into()
}

fn ensure_rule_set_file(
    config: &Config,
    agent: &ureq::Agent,
    rule_set: &RemoteRuleSet,
    path: &Path,
) -> Result<bool> {
    if path.is_file() && !config.sing_rule_set_preload_refresh {
        return Ok(false);
    }

    match download_rule_set(agent, &rule_set.url, path) {
        Ok(()) => Ok(true),
        Err(err) if path.is_file() => {
            logger::warn_key(
                config,
                LogKey::RuleSetPreloadCacheFallback,
                &[arg("tag", rule_set_label(rule_set)), arg("error", err)],
            );
            Ok(false)
        }
        Err(err) => Err(format!(
            "download sing-box rule-set {} failed: {err}",
            rule_set_label(rule_set)
        )),
    }
}

fn download_rule_set(agent: &ureq::Agent, url: &str, path: &Path) -> Result<()> {
    let mut response = agent
        .get(url)
        .header("User-Agent", USER_AGENT)
        .call()
        .map_err(|err| format!("GET {url}: {err}"))?;
    let bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_RULE_SET_BYTES)
        .read_to_vec()
        .map_err(|err| format!("read {url}: {err}"))?;
    if bytes.is_empty() {
        return Err(format!("GET {url}: empty body"));
    }

    let tmp = temp_download_path(path);
    fs::write(&tmp, bytes)
        .map_err(|err| format!("write temporary rule-set {} failed: {err}", tmp.display()))?;
    replace_file(&tmp, path)
}

fn replace_file(tmp: &Path, target: &Path) -> Result<()> {
    match fs::rename(tmp, target) {
        Ok(()) => Ok(()),
        Err(_) => {
            fs::copy(tmp, target).map_err(|err| {
                format!(
                    "replace rule-set {} with {} failed: {err}",
                    target.display(),
                    tmp.display()
                )
            })?;
            fs::remove_file(tmp).map_err(|err| {
                format!("remove temporary rule-set {} failed: {err}", tmp.display())
            })?;
            Ok(())
        }
    }
}

fn rewrite_rule_set_to_local(root: &CstRootNode, index: usize, local_path: &Path) -> Result<()> {
    let route = root.object_value_or_set().object_value_or_set("route");
    let rule_sets = route.array_value_or_set("rule_set");
    let node = rule_sets
        .elements()
        .get(index)
        .cloned()
        .ok_or_else(|| format!("remote rule-set index {index} not found"))?;
    let object = node
        .as_object()
        .ok_or_else(|| format!("remote rule-set index {index} is not an object"))?;

    set_cst_prop(&object, "type", CstInputValue::from("local"));
    set_cst_prop(
        &object,
        "path",
        CstInputValue::from(local_path.to_string_lossy().to_string()),
    );
    for key in ["url", "download_detour", "http_client", "update_interval"] {
        if let Some(prop) = object.get(key) {
            prop.remove();
        }
    }
    Ok(())
}

fn rule_set_local_path(config: &Config, rule_set: &RemoteRuleSet) -> PathBuf {
    config
        .sing_rule_set_preload_dir
        .join(rule_set_file_name(rule_set))
}

fn rule_set_file_name(rule_set: &RemoteRuleSet) -> String {
    let label = if rule_set.tag.is_empty() {
        format!("rule-set-{}", rule_set.index)
    } else {
        safe_file_name(&rule_set.tag)
    };
    format!(
        "{:03}_{}.{}",
        rule_set.index,
        label,
        rule_set_file_ext(rule_set)
    )
}

fn rule_set_file_ext(rule_set: &RemoteRuleSet) -> &'static str {
    let url_path = rule_set
        .url
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if url_path.ends_with(".json") || rule_set.format == "source" {
        "json"
    } else {
        "srs"
    }
}

fn safe_file_name(value: &str) -> String {
    let mut name = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    while name.contains("..") {
        name = name.replace("..", ".");
    }
    name = name.trim_matches(['.', '_', '-']).to_string();
    if name.is_empty() {
        "rule-set".to_string()
    } else {
        name.chars().take(80).collect()
    }
}

fn temp_download_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("rule-set");
    path.with_file_name(format!(".{file_name}.tmp"))
}

fn rule_set_label(rule_set: &RemoteRuleSet) -> String {
    if rule_set.tag.is_empty() {
        format!("#{}", rule_set.index)
    } else {
        rule_set.tag.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_remote_rule_sets_only() {
        let text = r#"
        {
          "route": {
            "rule_set": [
              { "type": "remote", "tag": "Discord/Site", "format": "binary", "url": "https://example.com/a.srs" },
              { "type": "local", "tag": "Local", "path": "local.srs" },
              { "type": "remote", "tag": "NoUrl" }
            ]
          }
        }
        "#;
        let value: Value = parse_to_serde_value(text, &ParseOptions::default()).unwrap();
        let entries = collect_remote_rule_sets(&value);
        assert_eq!(
            entries,
            vec![RemoteRuleSet {
                index: 0,
                tag: "Discord/Site".to_string(),
                url: "https://example.com/a.srs".to_string(),
                format: "binary".to_string(),
            }]
        );
    }

    #[test]
    fn rewrites_remote_rule_set_to_local() {
        let text = r#"
        {
          "route": {
            "rule_set": [
              {
                "type": "remote",
                "tag": "Discord-Site",
                "format": "binary",
                "url": "https://example.com/Discord.srs",
                "download_detour": "proxy",
                "update_interval": "1d"
              }
            ]
          }
        }
        "#;
        let root = CstRootNode::parse(text, &ParseOptions::default()).unwrap();
        rewrite_rule_set_to_local(&root, 0, Path::new("/data/box/rule-set/Discord.srs")).unwrap();
        let output = root.to_string();
        let value: Value = parse_to_serde_value(&output, &ParseOptions::default()).unwrap();
        let rule_set = &value["route"]["rule_set"][0];
        assert_eq!(rule_set["type"], "local");
        assert_eq!(rule_set["path"], "/data/box/rule-set/Discord.srs");
        assert!(rule_set.get("url").is_none());
        assert!(rule_set.get("download_detour").is_none());
        assert!(rule_set.get("update_interval").is_none());
    }
}
