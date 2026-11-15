//! Imported routing rule lists: parsing another client's list, keeping it on
//! disk, and answering which rule a destination meets.
//!
//! The parser turns a list into this app's own rule grammar (the one the Block
//! and Direct boxes in Advanced take, and that both engines read): plain names,
//! hosts-file lines, addresses and CIDRs, and Clash classical lines, alone or
//! inside a rule-provider payload. Nothing is fetched and nothing is guessed: a
//! line that cannot be translated is counted under the reason it was left out.
//!
//! Lists live as files in the app's data directory, not in the profile. The
//! profile travels over IPC on every save; a list can be thousands of lines.
//! The engines read the enabled lists from here when a connection starts.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;

// shortcut: rules are rendered inline into both engines' configs; a list past
// this belongs in a mihomo rule-provider file, the upgrade if lists grow.
pub const MAX_ENTRIES: usize = 5_000;
/// Across every enabled list.
pub const MAX_TOTAL: usize = 10_000;
/// Checked before the file is read, so a wrong pick cannot fill memory.
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

const HOSTS_SINK: [&str; 4] = ["0.0.0.0", "127.0.0.1", "::", "::1"];
const ESSENTIAL_PORTS: [u16; 3] = [53, 80, 443];

/// What an imported list does with the destinations it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Block,
    Direct,
}

/// Why a line was left out. Counted, never hidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Ignored {
    /// A rule type with no equivalent here.
    Unsupported,
    /// geosite and geoip other than `private` need a database this build does not ship.
    NeedsDatabase,
    /// Wide enough to take everything, or the ports everything uses: in a direct
    /// list it would send the whole machine around the tunnel, in a block list
    /// it would cut the connection off.
    TooBroad,
    Duplicate,
    OverLimit,
}

#[derive(Debug, Default)]
pub struct Report {
    pub accepted: Vec<String>,
    pub ignored: BTreeMap<Ignored, usize>,
}

pub fn parse(text: &str) -> Report {
    let mut report = Report::default();
    let mut seen = std::collections::HashSet::new();
    for raw in text.lines() {
        let Some(line) = clean(raw) else { continue };
        match translate(&line) {
            Ok(rule) if seen.contains(&rule) => *report.ignored.entry(Ignored::Duplicate).or_default() += 1,
            Ok(_) if report.accepted.len() >= MAX_ENTRIES => {
                *report.ignored.entry(Ignored::OverLimit).or_default() += 1
            }
            Ok(rule) => {
                seen.insert(rule.clone());
                report.accepted.push(rule);
            }
            Err(reason) => *report.ignored.entry(reason).or_default() += 1,
        }
    }
    report
}

/// A rule line without list markup, or None for blanks, notes and headers.
fn clean(raw: &str) -> Option<String> {
    let mut line = raw.split(" #").next().unwrap_or("").trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with("//") || line.starts_with('!') {
        return None;
    }
    if line.ends_with(':') && !line.contains(',') {
        return None; // `payload:` and other YAML keys
    }
    if let Some(rest) = line.strip_prefix("- ") {
        line = rest.trim();
    }
    for quote in ['\'', '"'] {
        if line.len() >= 2 && line.starts_with(quote) && line.ends_with(quote) {
            line = line[1..line.len() - 1].trim();
        }
    }
    (!line.is_empty()).then(|| line.to_string())
}

fn translate(line: &str) -> Result<String, Ignored> {
    // A hosts file: "0.0.0.0 ads.example.com".
    let words: Vec<&str> = line.split_whitespace().collect();
    if words.len() >= 2 && HOSTS_SINK.contains(&words[0]) {
        return name(words[1]);
    }
    if line.contains(',') {
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        return classical(&fields);
    }
    if let Some(result) = address(line) {
        return result;
    }
    let (kind, value) = match line.split_once(':') {
        Some((kind, value)) => (kind.to_ascii_lowercase(), value.trim()),
        None => (String::new(), ""),
    };
    match kind.as_str() {
        "domain" | "suffix" => name(value),
        "full" | "exact" => exact(value),
        "keyword" => keyword(value),
        "regexp" | "regex" => regex(value),
        "ip" | "cidr" => address(value).unwrap_or(Err(Ignored::Unsupported)),
        "port" => port(value),
        "geosite" | "geoip" => geo(value),
        "" if line.eq_ignore_ascii_case("private") => Ok("private".into()),
        "" => name(line),
        _ => Err(Ignored::Unsupported),
    }
}

fn classical(fields: &[&str]) -> Result<String, Ignored> {
    let value = fields.get(1).copied().unwrap_or("");
    match fields[0].to_ascii_uppercase().as_str() {
        "DOMAIN-SUFFIX" => name(value),
        "DOMAIN" => exact(value),
        "DOMAIN-KEYWORD" => keyword(value),
        "DOMAIN-REGEX" => regex(value),
        "IP-CIDR" | "IP-CIDR6" => address(value).unwrap_or(Err(Ignored::Unsupported)),
        "DST-PORT" => port(value),
        "GEOSITE" | "GEOIP" => geo(value),
        _ => Err(Ignored::Unsupported),
    }
}

fn valid_domain(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    labels.iter().enumerate().all(|(index, label)| {
        let last = index == labels.len() - 1;
        let bytes = label.as_bytes();
        let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || (!last && b == b'_');
        !label.is_empty()
            && label.len() <= 63
            && edge(bytes[0])
            && edge(bytes[bytes.len() - 1])
            && bytes.iter().all(|b| edge(*b) || *b == b'-' || (!last && *b == b'_'))
    })
}

fn name(value: &str) -> Result<String, Ignored> {
    let lower = value.to_ascii_lowercase();
    let host = lower.trim_end_matches('.');
    let host = host.strip_prefix("+.").or_else(|| host.strip_prefix("*.")).or_else(|| host.strip_prefix('.')).unwrap_or(host);
    if valid_domain(host) { Ok(host.to_string()) } else { Err(Ignored::Unsupported) }
}

fn exact(value: &str) -> Result<String, Ignored> {
    let lower = value.to_ascii_lowercase();
    let host = lower.trim_end_matches('.');
    if valid_domain(host) { Ok(format!("full:{host}")) } else { Err(Ignored::Unsupported) }
}

fn keyword(value: &str) -> Result<String, Ignored> {
    if value.trim().is_empty() || value.contains(char::is_whitespace) || !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_') {
        return Err(Ignored::Unsupported);
    }
    // Two letters is inside half the names on the internet.
    if value.chars().count() < 3 {
        return Err(Ignored::TooBroad);
    }
    Ok(format!("keyword:{}", value.to_ascii_lowercase()))
}

fn regex(value: &str) -> Result<String, Ignored> {
    // Both engines split a list on `,` and `;`, and mihomo's rules are unquoted
    // YAML, so only patterns that survive both are taken.
    let safe = !value.is_empty()
        && value.chars().all(|c| c.is_ascii_alphanumeric() || ".^$*+?()[]|\\-".contains(c));
    if !safe {
        return Err(Ignored::Unsupported);
    }
    let Ok(pattern) = regex::Regex::new(value) else { return Err(Ignored::Unsupported) };
    // A pattern that takes two unrelated names takes anything.
    if pattern.is_match("zq7.example") && pattern.is_match("www.wikipedia.org") {
        return Err(Ignored::TooBroad);
    }
    Ok(format!("regexp:{value}"))
}

fn port(value: &str) -> Result<String, Ignored> {
    let parts: Vec<Option<u16>> = value.split('-').map(|part| part.trim().parse().ok()).collect();
    let (low, high) = match parts.as_slice() {
        [Some(one)] => (*one, *one),
        [Some(low), Some(high)] => (*low, *high),
        _ => return Err(Ignored::Unsupported),
    };
    if low == 0 || high < low {
        return Err(Ignored::Unsupported);
    }
    if ESSENTIAL_PORTS.iter().any(|port| (low..=high).contains(port)) {
        return Err(Ignored::TooBroad);
    }
    Ok(if low == high { format!("port:{low}") } else { format!("port:{low}-{high}") })
}

fn geo(value: &str) -> Result<String, Ignored> {
    if value.eq_ignore_ascii_case("private") || value.eq_ignore_ascii_case("lan") {
        Ok("private".into())
    } else {
        Err(Ignored::NeedsDatabase)
    }
}

/// An address or a CIDR as `cidr:`, or None for anything that is not one.
fn address(value: &str) -> Option<Result<String, Ignored>> {
    let (host, prefix) = match value.split_once('/') {
        Some((host, prefix)) => (host, Some(prefix)),
        None => (value, None),
    };
    let ip: IpAddr = host.parse().ok()?;
    let bits = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        None => bits,
        Some(text) => match text.parse::<u8>() {
            Ok(prefix) if prefix <= bits => prefix,
            _ => return Some(Err(Ignored::Unsupported)),
        },
    };
    // Shorter than a /8 or a /16 is a continent, not a service.
    if prefix < if ip.is_ipv4() { 8 } else { 16 } {
        return Some(Err(Ignored::TooBroad));
    }
    Some(Ok(format!("cidr:{ip}/{prefix}")))
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// One imported list as the user sees it. Its rules live in a file beside the index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleList {
    pub id: String,
    pub name: String,
    pub action: RuleAction,
    pub imported_at: u64,
    pub count: usize,
    pub enabled: bool,
}

/// Every read-modify-write of the index, in one process, one at a time.
static STORE: Mutex<()> = Mutex::new(());

fn directory(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|error| format!("no application data directory: {error}"))?
        .join("rule-lists"))
}

fn rules_path(directory: &Path, id: &str) -> Result<PathBuf, String> {
    // The id names a file, so it is held to what this module generates.
    if id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(directory.join(format!("{id}.txt")))
    } else {
        Err("Unknown rule list".into())
    }
}

pub fn lists_in(directory: &Path) -> Vec<RuleList> {
    let Ok(text) = std::fs::read_to_string(directory.join("index.json")) else { return Vec::new() };
    let lists: Vec<RuleList> = serde_json::from_str(&text).unwrap_or_default();
    lists
        .into_iter()
        .filter(|list| rules_path(directory, &list.id).is_ok_and(|path| path.is_file()))
        .collect()
}

fn enabled_total(lists: &[RuleList]) -> usize {
    lists.iter().filter(|list| list.enabled).map(|list| list.count).sum()
}

fn write_atomically(target: &Path, text: &str) -> Result<(), String> {
    let partial = target.with_extension("part");
    std::fs::write(&partial, text).map_err(|error| format!("cannot save the rule list: {error}"))?;
    std::fs::rename(&partial, target).map_err(|error| format!("cannot save the rule list: {error}"))
}

fn save(directory: &Path, lists: &[RuleList]) -> Result<(), String> {
    std::fs::create_dir_all(directory).map_err(|error| format!("cannot prepare the rule lists: {error}"))?;
    let text = serde_json::to_string(lists).map_err(|error| error.to_string())?;
    write_atomically(&directory.join("index.json"), &text)
}

/// Saves `entries` as a new enabled list, or refuses past [`MAX_TOTAL`].
pub fn add_in(directory: &Path, name: &str, action: RuleAction, entries: &[String], now: u64) -> Result<RuleList, String> {
    let _guard = STORE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut lists = lists_in(directory);
    if entries.is_empty() {
        return Err("The file held no rule this app can use".into());
    }
    if enabled_total(&lists) + entries.len() > MAX_TOTAL {
        return Err(format!("Turned on, the lists would hold more than {MAX_TOTAL} rules. Turn one off or delete it first."));
    }
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| error.to_string())?;
    let id: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let list = RuleList { id, name: name.chars().take(80).collect(), action, imported_at: now, count: entries.len(), enabled: true };
    std::fs::create_dir_all(directory).map_err(|error| format!("cannot prepare the rule lists: {error}"))?;
    write_atomically(&rules_path(directory, &list.id)?, &entries.join("\n"))?;
    lists.push(list.clone());
    save(directory, &lists)?;
    Ok(list)
}

pub fn set_enabled_in(directory: &Path, id: &str, enabled: bool) -> Result<(), String> {
    let _guard = STORE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut lists = lists_in(directory);
    let total = enabled_total(&lists);
    let target = lists.iter_mut().find(|list| list.id == id).ok_or("Unknown rule list")?;
    if enabled && !target.enabled && total + target.count > MAX_TOTAL {
        return Err(format!("Turned on, the lists would hold more than {MAX_TOTAL} rules. Turn one off first."));
    }
    target.enabled = enabled;
    save(directory, &lists)
}

pub fn delete_in(directory: &Path, id: &str) -> Result<(), String> {
    let _guard = STORE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = rules_path(directory, id)?;
    let lists: Vec<RuleList> = lists_in(directory).into_iter().filter(|list| list.id != id).collect();
    save(directory, &lists)?;
    let _ = std::fs::remove_file(path);
    Ok(())
}

/// Every enabled rule for `action`, one per line.
pub fn active_in(directory: &Path, action: RuleAction) -> String {
    lists_in(directory)
        .iter()
        .filter(|list| list.enabled && list.action == action)
        .filter_map(|list| std::fs::read_to_string(rules_path(directory, &list.id).ok()?).ok())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The enabled imported rules for `action`, or nothing when the store cannot be found.
pub fn active(app: &AppHandle, action: RuleAction) -> String {
    directory(app).map(|directory| active_in(&directory, action)).unwrap_or_default()
}

/// The user's own rules, then the imported ones.
pub fn join(own: &str, imported: &str) -> String {
    [own.trim(), imported.trim()].into_iter().filter(|part| !part.is_empty()).collect::<Vec<_>>().join("\n")
}

// ---------------------------------------------------------------------------
// Matching, worked out here from the rules alone: no DNS
// ---------------------------------------------------------------------------

const PRIVATE: [&str; 9] = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8",
    "100.64.0.0/10", "fc00::/7", "fe80::/10", "::1/128",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleMatch {
    /// None is the tunnel.
    pub action: Option<RuleAction>,
    pub rule: Option<String>,
}

fn rule_lines(raw: &str) -> impl Iterator<Item = &str> {
    raw.split(['\n', ',', ';']).map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#'))
}

/// Block first, then direct, as both engines order them. Port rules need a
/// port, which a name alone does not have, so they never match here.
pub fn match_destination(destination: &str, block: &str, direct: &str) -> RuleMatch {
    let lower = destination.trim().to_ascii_lowercase();
    let target = lower.trim_end_matches('.');
    if !target.is_empty() {
        for (action, list) in [(RuleAction::Block, block), (RuleAction::Direct, direct)] {
            if let Some(rule) = rule_lines(list).find(|rule| matches(rule, target)) {
                return RuleMatch { action: Some(action), rule: Some(rule.to_string()) };
            }
        }
    }
    RuleMatch { action: None, rule: None }
}

/// The kind prefix and the value of one rule in our grammar.
fn split_rule(rule: &str) -> (String, &str) {
    match rule.split_once(':') {
        Some((kind, value)) if !kind.contains('.') && !kind.contains('/') && kind.chars().all(|c| c.is_ascii_alphabetic()) => {
            (kind.trim().to_ascii_lowercase(), value.trim())
        }
        _ => (String::new(), rule.trim()),
    }
}

fn matches(rule: &str, target: &str) -> bool {
    let (kind, value) = split_rule(rule);
    let value_lower = value.to_ascii_lowercase();
    let address: Option<IpAddr> = target.trim_start_matches('[').trim_end_matches(']').parse().ok();
    match kind.as_str() {
        "domain" | "suffix" => address.is_none() && suffix(&value_lower, target),
        "full" | "exact" => address.is_none() && target == value_lower,
        "keyword" => address.is_none() && !value_lower.is_empty() && target.contains(&value_lower),
        "regexp" | "regex" => address.is_none() && regex::Regex::new(value).is_ok_and(|pattern| pattern.is_match(target)),
        "ip" | "cidr" => address.is_some_and(|address| in_net(&value_lower, address)),
        "geoip" | "geosite" => value_lower == "private" && is_private(target, address),
        "" if value_lower == "private" => is_private(target, address),
        "" if value_lower.contains('/') => address.is_some_and(|address| in_net(&value_lower, address)),
        "" => address.is_none() && suffix(&value_lower, target),
        _ => false,
    }
}

fn suffix(value: &str, target: &str) -> bool {
    !value.is_empty() && (target == value || target.strip_suffix(value).is_some_and(|rest| rest.ends_with('.')))
}

fn is_private(target: &str, address: Option<IpAddr>) -> bool {
    target == "localhost" || address.is_some_and(|address| PRIVATE.iter().any(|net| in_net(net, address)))
}

fn in_net(cidr: &str, address: IpAddr) -> bool {
    let (host, prefix) = cidr.split_once('/').unwrap_or((cidr, ""));
    let Ok(network) = host.parse::<IpAddr>() else { return false };
    let bits: u32 = if network.is_ipv4() { 32 } else { 128 };
    let prefix = if prefix.is_empty() { bits } else { match prefix.parse::<u32>() { Ok(p) if p <= bits => p, _ => return false } };
    let mask = |p: u32, width: u32| -> u128 { if p == 0 { 0 } else { u128::MAX << (width - p) } };
    match (network, address) {
        (IpAddr::V4(net), IpAddr::V4(addr)) => {
            let m = mask(prefix, 32) as u32;
            (u32::from(net) & m) == (u32::from(addr) & m)
        }
        (IpAddr::V6(net), IpAddr::V6(addr)) => {
            let m = mask(prefix, 128);
            (u128::from(net) & m) == (u128::from(addr) & m)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// mihomo
// ---------------------------------------------------------------------------

/// One rule in our grammar as mihomo rules, or none if it is neither.
///
/// Address rules carry `no-resolve` so a name is never looked up merely to test
/// it against a block: that lookup would leave the tunnel and name the
/// destination to whoever is watching.
pub fn mihomo_rules(pattern: &str, action: &str) -> Vec<String> {
    let entry = pattern.trim();
    if entry.is_empty() || entry.starts_with('#') {
        return Vec::new();
    }
    let (kind, value) = split_rule(entry);
    // The rules are unquoted YAML: anything that could end the scalar is dropped.
    if value.is_empty() || value.chars().any(|c| c.is_whitespace() || "#'\"{}`".contains(c)) {
        return Vec::new();
    }
    let cidr = |value: &str| {
        let family = if value.contains(':') { "IP-CIDR6" } else { "IP-CIDR" };
        vec![format!("{family},{value},{action},no-resolve")]
    };
    match kind.as_str() {
        "domain" | "suffix" => vec![format!("DOMAIN-SUFFIX,{value},{action}")],
        "full" | "exact" => vec![format!("DOMAIN,{value},{action}")],
        "keyword" => vec![format!("DOMAIN-KEYWORD,{value},{action}")],
        "regexp" | "regex" => vec![format!("DOMAIN-REGEX,{value},{action}")],
        "ip" | "cidr" => cidr(value),
        "port" => vec![format!("DST-PORT,{value},{action}")],
        "geoip" | "geosite" if value.eq_ignore_ascii_case("private") => private_rules(action),
        "" if value.eq_ignore_ascii_case("private") => private_rules(action),
        "" if value.contains('/') => cidr(value),
        "" => vec![format!("DOMAIN-SUFFIX,{value},{action}")],
        _ => Vec::new(),
    }
}

/// `private`, spelled out: GEOIP,PRIVATE wants a database this build does not ship.
fn private_rules(action: &str) -> Vec<String> {
    let mut rules = vec![format!("DOMAIN,localhost,{action}")];
    for range in [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8",
        "100.64.0.0/10", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "0.0.0.0/32",
        "255.255.255.255/32", "::1/128", "::/128", "fc00::/7", "fe80::/10",
    ] {
        let family = if range.contains(':') { "IP-CIDR6" } else { "IP-CIDR" };
        rules.push(format!("{family},{range},{action},no-resolve"));
    }
    rules
}

/// mihomo rules for the user's own and the imported rules: refusals first, so a
/// blocked destination cannot also match a direct rule further down.
pub fn mihomo_section(block: &str, direct: &str) -> String {
    let mut out = String::new();
    for (list, action) in [(block, "REJECT"), (direct, "DIRECT")] {
        for pattern in rule_lines(list) {
            for rule in mihomo_rules(pattern, action) {
                out.push_str("  - ");
                out.push_str(&rule);
                out.push('\n');
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportOutcome {
    pub cancelled: bool,
    pub list: Option<RuleList>,
    pub accepted: usize,
    pub ignored: BTreeMap<Ignored, usize>,
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Reads a picked file, refusing one too large to be a rule list.
fn read_limited(path: &Path) -> Result<String, String> {
    let size = std::fs::metadata(path).map_err(|error| format!("cannot read that file: {error}"))?.len();
    if size > MAX_FILE_BYTES {
        return Err("That file is larger than 2 MB, too large for a rule list".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|error| format!("cannot read that file: {error}"))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err("That file is larger than 2 MB, too large for a rule list".into());
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[tauri::command]
pub fn rule_lists(app: AppHandle) -> Result<Vec<RuleList>, String> {
    Ok(lists_in(&directory(&app)?))
}

/// Picks a local file and saves what it holds as a new list. Local files only:
/// a list fetched from a URL is a list someone else can change under you.
#[tauri::command]
pub async fn rule_list_import(app: AppHandle, action: RuleAction) -> Result<ImportOutcome, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let picked = app
            .dialog()
            .file()
            .add_filter("Rule list", &["txt", "list", "conf", "yaml", "yml", "hosts"])
            .add_filter("All files", &["*"])
            .blocking_pick_file();
        let Some(picked) = picked else {
            return Ok(ImportOutcome { cancelled: true, list: None, accepted: 0, ignored: BTreeMap::new() });
        };
        let path = picked.into_path().map_err(|_| "that file cannot be read".to_string())?;
        let report = parse(&read_limited(&path)?);
        let name = path.file_stem().map(|stem| stem.to_string_lossy().into_owned()).unwrap_or_else(|| "list".into());
        let list = if report.accepted.is_empty() {
            None
        } else {
            Some(add_in(&directory(&app)?, &name, action, &report.accepted, now_seconds())?)
        };
        Ok(ImportOutcome { cancelled: false, list, accepted: report.accepted.len(), ignored: report.ignored })
    })
    .await
    .map_err(|error| format!("the import did not finish: {error}"))?
}

#[tauri::command]
pub fn rule_list_set_enabled(app: AppHandle, id: String, enabled: bool) -> Result<(), String> {
    set_enabled_in(&directory(&app)?, &id, enabled)
}

#[tauri::command]
pub fn rule_list_delete(app: AppHandle, id: String) -> Result<(), String> {
    delete_in(&directory(&app)?, &id)
}

/// Which rule `destination` meets among the user's own and the enabled lists.
#[tauri::command]
pub fn rule_match(app: AppHandle, destination: String, block: String, direct: String) -> RuleMatch {
    let block = join(&block, &active(&app, RuleAction::Block));
    let direct = join(&direct, &active(&app, RuleAction::Direct));
    match_destination(&destination, &block, &direct)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted(text: &str) -> Vec<String> {
        parse(text).accepted
    }

    #[test]
    fn every_supported_format_becomes_our_grammar() {
        let text = "\
# comment
payload:
  - '+.ads.example.com'
  - \"*.track.example\"
.lead.example
plain.example.
0.0.0.0 hosts.example
127.0.0.1 local-sink.example
10.20.0.0/16
2001:db8::/32
DOMAIN-SUFFIX,suffix.example
DOMAIN,exact.example
DOMAIN-KEYWORD,tracker
DOMAIN-REGEX,^ad[0-9]+\\.example$
IP-CIDR,203.0.113.0/24,no-resolve
IP-CIDR6,2001:db8:1::/48
DST-PORT,6881-6889
GEOIP,private
full:full.example
keyword:beacon
port:8443
private
";
        assert_eq!(
            accepted(text),
            [
                "ads.example.com", "track.example", "lead.example", "plain.example", "hosts.example",
                "local-sink.example", "cidr:10.20.0.0/16", "cidr:2001:db8::/32", "suffix.example",
                "full:exact.example", "keyword:tracker", "regexp:^ad[0-9]+\\.example$",
                "cidr:203.0.113.0/24", "cidr:2001:db8:1::/48", "port:6881-6889", "private",
                "full:full.example", "keyword:beacon", "port:8443", "private",
            ]
            .into_iter()
            .filter({
                let mut seen = std::collections::HashSet::new();
                move |rule| seen.insert(*rule)
            })
            .collect::<Vec<_>>()
        );
        assert_eq!(parse(text).ignored.get(&Ignored::Duplicate), Some(&1));
    }

    #[test]
    fn every_line_left_out_is_counted_with_its_reason() {
        let report = parse(
            "PROCESS-NAME,chrome.exe\nGEOSITE,netflix\nGEOIP,cn\n1.0.0.0/7\n2001::/15\nDST-PORT,443\nDST-PORT,50-60\nport:1-65535\nkeyword:ab\nDOMAIN-REGEX,.*\nDOMAIN-REGEX,a{2}\nregexp:^(a\nex ample\nsame.example\nsame.example\n",
        );
        assert!(report.accepted == ["same.example"], "{:?}", report.accepted);
        assert_eq!(report.ignored[&Ignored::Unsupported], 4, "{:?}", report.ignored);
        assert_eq!(report.ignored[&Ignored::NeedsDatabase], 2);
        assert_eq!(report.ignored[&Ignored::TooBroad], 7);
        assert_eq!(report.ignored[&Ignored::Duplicate], 1);
    }

    #[test]
    fn a_list_is_capped_and_the_rest_counted() {
        let text: String = (0..MAX_ENTRIES + 7).map(|i| format!("host{i}.example\n")).collect();
        let report = parse(&text);
        assert_eq!(report.accepted.len(), MAX_ENTRIES);
        assert_eq!(report.ignored[&Ignored::OverLimit], 7);
    }

    #[test]
    fn matching_is_block_then_direct_then_the_tunnel_with_no_lookup() {
        let block = "keyword:ads, cidr:203.0.113.0/24";
        let direct = "example.ir;full:exact.example\nprivate\nregexp:^cdn[0-9]\\.example$";
        let check = |destination: &str, action: Option<RuleAction>, rule: Option<&str>| {
            assert_eq!(match_destination(destination, block, direct), RuleMatch { action, rule: rule.map(String::from) }, "{destination}");
        };
        check("ads.example.ir", Some(RuleAction::Block), Some("keyword:ads"));
        check("www.example.ir.", Some(RuleAction::Direct), Some("example.ir"));
        check("notexample.ir", None, None);
        check("exact.example", Some(RuleAction::Direct), Some("full:exact.example"));
        check("www.exact.example", None, None);
        check("203.0.113.9", Some(RuleAction::Block), Some("cidr:203.0.113.0/24"));
        check("192.168.1.1", Some(RuleAction::Direct), Some("private"));
        check("localhost", Some(RuleAction::Direct), Some("private"));
        check("cdn7.example", Some(RuleAction::Direct), Some("regexp:^cdn[0-9]\\.example$"));
        check("wikipedia.org", None, None);
    }

    #[test]
    fn mihomo_gets_refusals_first_and_addresses_unresolved() {
        let section = mihomo_section("keyword:ads\nport:6881", "example.ir\ncidr:2001:db8::/32\nprivate\nbad value");
        let lines: Vec<&str> = section.lines().collect();
        assert_eq!(lines[0], "  - DOMAIN-KEYWORD,ads,REJECT");
        assert_eq!(lines[1], "  - DST-PORT,6881,REJECT");
        assert_eq!(lines[2], "  - DOMAIN-SUFFIX,example.ir,DIRECT");
        assert_eq!(lines[3], "  - IP-CIDR6,2001:db8::/32,DIRECT,no-resolve");
        assert!(section.contains("  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve\n"));
        assert!(!section.contains("bad"));
    }

    #[test]
    fn lists_are_stored_capped_toggled_and_deleted() {
        let directory = std::env::temp_dir().join(format!("whiteaesther-rule-lists-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let first = add_in(&directory, "ads", RuleAction::Block, &["a.example".into(), "b.example".into()], 1).unwrap();
        let second = add_in(&directory, "local", RuleAction::Direct, &["c.example".into()], 2).unwrap();
        assert_eq!(lists_in(&directory), [first.clone(), second.clone()]);
        assert_eq!(active_in(&directory, RuleAction::Block), "a.example\nb.example");
        set_enabled_in(&directory, &first.id, false).unwrap();
        assert_eq!(active_in(&directory, RuleAction::Block), "");
        let big: Vec<String> = (0..MAX_TOTAL).map(|i| format!("h{i}.example")).collect();
        assert!(add_in(&directory, "big", RuleAction::Block, &big, 3).is_err(), "past the total");
        let fits: Vec<String> = big[..MAX_TOTAL - 1].to_vec();
        let filler = add_in(&directory, "fits", RuleAction::Block, &fits, 4).unwrap();
        assert!(set_enabled_in(&directory, &first.id, true).is_err(), "re-enabling would pass the total");
        delete_in(&directory, &filler.id).unwrap();
        set_enabled_in(&directory, &first.id, true).unwrap();
        assert!(delete_in(&directory, "../index").is_err(), "ids name files and are held to hex");
        delete_in(&directory, &second.id).unwrap();
        assert_eq!(lists_in(&directory), [first]);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
