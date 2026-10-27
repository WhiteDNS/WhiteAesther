//! Syntax checks shared by profile storage, scanner and session startup.
//! BoringSSL itself checks cipher/group names through the core's offline check.
use crate::core_supervisor::CoreProfile;

#[cfg(test)]
mod parity_tests {
    use super::*;
    #[test]
    fn a_profile_round_trip_preserves_every_extended_tls_setting() {
        let mut profile = CoreProfile::default();
        profile.tls.masque_sni = Some("example.com".into());
        profile.tls.api_host = Some("example.com".into());
        profile.tls.api_sni = Some("example.com".into());
        profile.tls.tls13_ciphers = Some("example.com".into());
        profile.tls.tls_key_shares = Some("example.com".into());
        profile.tls.tls_sigalgs = Some("example.com".into());
        profile.tls.tls_cert_compression = Some("example.com".into());
        profile.tls.tls_alps = Some("example.com".into());
        profile.tls.tls_trust_anchors = Some("example.com".into());
        profile.tls.tls_server_padding = Some("example.com".into());
        profile.tls.enable_grease_sigalgs = true;
        profile.tls.enable_ech_grease = true;
        profile.tls.disable_ocsp_stapling = true;
        profile.tls.disable_sct = true;
        profile.tls.disable_session_ticket = true;
        profile.tls.disable_extension_permutation = true;
        profile.fragment_client_hello = true;
        profile.hello_shape = "records".into();
        profile.fragment_sni = false;
        let json = serde_json::to_value(&profile).unwrap();
        let restored: CoreProfile = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(profile.tls, restored.tls);
        assert_eq!(restored.hello_shape, "records");
        assert!(!restored.fragment_sni);
        let args = restored.tls_args();
        assert!(args.iter().any(|v| v == "--masque-sni"));
        assert!(args.iter().any(|v| v == "--api-host"));
        assert!(args.iter().any(|v| v == "--api-sni"));
        assert!(args.iter().any(|v| v == "--tls13-ciphers"));
        assert!(args.iter().any(|v| v == "--tls-key-shares"));
        assert!(args.iter().any(|v| v == "--tls-sigalgs"));
        assert!(args.iter().any(|v| v == "--tls-cert-compression"));
        assert!(args.iter().any(|v| v == "--tls-alps"));
        assert!(args.iter().any(|v| v == "--tls-trust-anchors"));
        assert!(args.iter().any(|v| v == "--tls-server-padding"));
        assert!(args.iter().any(|v| v == "--enable-grease-sigalgs"));
        assert!(args.iter().any(|v| v == "--enable-ech-grease"));
        assert!(args.iter().any(|v| v == "--disable-ocsp-stapling"));
        assert!(args.iter().any(|v| v == "--disable-sct"));
        assert!(args.iter().any(|v| v == "--disable-session-ticket"));
        assert!(args.iter().any(|v| v == "--disable-extension-permutation"));
        assert!(args.windows(2).any(|v| v == ["--hello-shape", "records"]));
        assert!(args.windows(2).any(|v| v == ["--fragment-sni", "false"]));
    }
    #[test]
    fn legacy_profiles_remain_readable_and_runtime_contract_rejects_missing_features() {
        let profile: CoreProfile =
            serde_json::from_str(r#"{"protocol":"masque","fragmentClientHello":true}"#).unwrap();
        assert!(profile.fragment_client_hello);
        assert!(profile.fragment_sni);
        assert!(profile.hello_shape.is_empty());
        let expected: serde_json::Value =
            serde_json::from_str(include_str!("../../core-source.json")).unwrap();
        let mut cap = serde_json::json!({"schema":1,"version":expected["version"],"revision":expected["revision"],"patchset":expected["patchset"],
            "commands":expected["requiredCommands"],"features":expected["requiredFeatures"]});
        assert!(validate_contract(&cap).is_ok());
        cap["features"] = serde_json::json!([]);
        assert!(validate_contract(&cap).is_err());
    }
}

pub(crate) fn validate_contract(value: &serde_json::Value) -> Result<(), String> {
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("../../core-source.json")).expect("valid core manifest");
    for key in ["version", "revision", "patchset"] {
        if value[key] != expected[key] {
            return Err(format!("The selected Aether core has an incompatible {key}; clear Core executable to use the bundled core."));
        }
    }
    if value["schema"] != 1 {
        return Err("Unsupported Aether capability schema".into());
    }
    for (actual, required) in [
        ("commands", "requiredCommands"),
        ("features", "requiredFeatures"),
    ] {
        for item in expected[required]
            .as_array()
            .ok_or("Incomplete bundled core contract")?
        {
            if !value[actual]
                .as_array()
                .is_some_and(|items| items.contains(item))
            {
                return Err(format!(
                    "The selected core is missing {}. Use the bundled Aether core.",
                    item.as_str().unwrap_or("a required feature")
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn check_runtime_core(path: &Path) -> Result<(), String> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static VERIFIED: OnceLock<
        Mutex<HashMap<std::path::PathBuf, (u64, Option<std::time::SystemTime>)>>,
    > = OnceLock::new();
    let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
    let stamp = (metadata.len(), metadata.modified().ok());
    let cache = VERIFIED.get_or_init(|| Mutex::new(HashMap::new()));
    if cache
        .lock()
        .ok()
        .is_some_and(|c| c.get(path) == Some(&stamp))
    {
        return Ok(());
    }
    let mut command = Command::new(path);
    clear_inherited(&mut command);
    command
        .arg("--desktop-capabilities")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    crate::core_supervisor::hide_console(&mut command);
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let stdout = child.stdout.take().ok_or("Cannot read core capabilities")?;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take(65536).read_to_end(&mut bytes);
        let _ = tx.send(bytes);
    });
    let output = rx.recv_timeout(Duration::from_secs(10));
    let _ = child.kill();
    let _ = child.wait();
    let bytes = output.map_err(|_| "The selected core did not answer its capability check")?;
    let value = serde_json::from_slice(&bytes)
        .map_err(|_| "The selected core does not support desktop capability checks")?;
    validate_contract(&value)?;
    if let Ok(mut cache) = cache.lock() {
        cache.insert(path.to_path_buf(), stamp);
    }
    Ok(())
}

/// Shared Android 2.4 handshake controls, flattened into the saved desktop profile.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct TlsOverrides {
    pub masque_sni: Option<String>,
    pub api_host: Option<String>,
    pub api_sni: Option<String>,
    pub tls13_ciphers: Option<String>,
    pub tls_key_shares: Option<String>,
    pub tls_sigalgs: Option<String>,
    pub tls_cert_compression: Option<String>,
    pub tls_alps: Option<String>,
    pub tls_trust_anchors: Option<String>,
    pub tls_server_padding: Option<String>,
    pub enable_grease_sigalgs: bool,
    pub enable_ech_grease: bool,
    pub disable_ocsp_stapling: bool,
    pub disable_sct: bool,
    pub disable_session_ticket: bool,
    pub disable_extension_permutation: bool,
}

impl TlsOverrides {
    pub fn args(&self) -> Vec<String> {
        let mut args = Vec::new();
        for (flag, value) in [
            ("--masque-sni", &self.masque_sni),
            ("--api-host", &self.api_host),
            ("--api-sni", &self.api_sni),
            ("--tls13-ciphers", &self.tls13_ciphers),
            ("--tls-key-shares", &self.tls_key_shares),
            ("--tls-sigalgs", &self.tls_sigalgs),
            ("--tls-cert-compression", &self.tls_cert_compression),
            ("--tls-alps", &self.tls_alps),
            ("--tls-trust-anchors", &self.tls_trust_anchors),
            ("--tls-server-padding", &self.tls_server_padding),
        ] {
            if let Some(value) = value.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
                args.extend([flag.to_string(), value.to_string()]);
            }
        }
        for (flag, enabled) in [
            ("--enable-grease-sigalgs", self.enable_grease_sigalgs),
            ("--enable-ech-grease", self.enable_ech_grease),
            ("--disable-ocsp-stapling", self.disable_ocsp_stapling),
            ("--disable-sct", self.disable_sct),
            ("--disable-session-ticket", self.disable_session_ticket),
            (
                "--disable-extension-permutation",
                self.disable_extension_permutation,
            ),
        ] {
            if enabled {
                args.push(flag.into());
            }
        }
        args
    }

    pub fn validate(&self) -> Result<(), String> {
        for (flag, value) in [
            ("masque-sni", &self.masque_sni),
            ("api-host", &self.api_host),
            ("api-sni", &self.api_sni),
            ("tls13-ciphers", &self.tls13_ciphers),
            ("tls-key-shares", &self.tls_key_shares),
            ("tls-sigalgs", &self.tls_sigalgs),
            ("tls-cert-compression", &self.tls_cert_compression),
            ("tls-alps", &self.tls_alps),
            ("tls-trust-anchors", &self.tls_trust_anchors),
            ("tls-server-padding", &self.tls_server_padding),
        ] {
            if value
                .as_deref()
                .is_some_and(|v| v.len() > 4096 || v.chars().any(char::is_control))
            {
                return Err(format!(
                    "{flag} must be at most 4096 characters without control characters"
                ));
            }
        }
        for (label, value) in [
            ("MASQUE SNI", &self.masque_sni),
            ("API host", &self.api_host),
            ("API SNI", &self.api_sni),
        ] {
            if let Some(value) = value.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
                if value.parse::<IpAddr>().is_ok() || !domain(value) {
                    return Err(format!("{label} must be a domain name"));
                }
            }
        }
        Ok(())
    }
}
use std::{
    io::Read,
    net::IpAddr,
    path::Path,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

/// Ask the exact engine that will run to validate BoringSSL names and ECH data.
/// This command cannot register, look up DNS or open a listener.
pub(crate) fn check_with_core(path: &Path, profile: &CoreProfile) -> Result<(), String> {
    let mut command = Command::new(path);
    clear_inherited(&mut command);
    command
        .arg("--check-options")
        .args(profile.tls_args())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    crate::core_supervisor::hide_console(&mut command);
    let mut child = command
        .spawn()
        .map_err(|e| format!("Cannot validate TLS settings: {e}"))?;
    let output = child.stdout.take().expect("piped output");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = output.take(65_536).read_to_end(&mut bytes);
        let _ = tx.send(bytes);
    });
    let result = rx.recv_timeout(Duration::from_secs(10));
    let _ = child.kill();
    let _ = child.wait();
    let output =
        result.map_err(|_| "The core did not finish validating TLS settings".to_string())?;
    let value: serde_json::Value = serde_json::from_slice(&output).map_err(|_| {
        "This core cannot validate the new settings; use the bundled Aether core".to_string()
    })?;
    if value["ok"] == true {
        Ok(())
    } else {
        Err(value["error"]
            .as_str()
            .unwrap_or("Invalid TLS/ECH settings")
            .to_string())
    }
}

pub(crate) fn clear_inherited(command: &mut Command) {
    for key in [
        "AETHER_PROTOCOL",
        "AETHER_SCAN",
        "AETHER_IP",
        "AETHER_SOCKS",
        "AETHER_HTTP_PROXY",
        "AETHER_MASQUE_HTTP2",
        "AETHER_PEER",
        "AETHER_WG_PEER",
        "AETHER_MASQUE_H2_PEER",
        "AETHER_DNS",
        "AETHER_QUICK_RECONNECT",
        "AETHER_MASQUE_NO_DATA_CHECK",
        "AETHER_WG_NO_DATA_CHECK",
        "AETHER_SCAN_BUDGET_MS",
        "AETHER_PROVISION_ONLY",
        "AETHER_TEST_ENDPOINT",
        "AETHER_SCAN_ONLY",
        "AETHER_SCAN_LIMIT",
        "AETHER_EXPORT_IDENTITY",
        "AETHER_IMPORT_IDENTITY",
        "AETHER_ECH",
        "AETHER_ECH_DNS",
        "AETHER_ECH_DOMAIN",
        "AETHER_TLS_CIPHERS",
        "AETHER_TLS_GROUPS",
        "AETHER_DISABLE_GREASE",
        "AETHER_ENROLL_ADDRESS",
        "AETHER_API_ADDRESS",
        "AETHER_API_HOST",
        "AETHER_API_SNI",
        "AETHER_MASQUE_H2_FRAGMENT",
        "AETHER_MASQUE_H2_FRAGMENT_SIZE",
        "AETHER_MASQUE_H2_FRAGMENT_DELAY",
        "AETHER_HELLO_SHAPE",
        "AETHER_MASQUE_SNI",
        "AETHER_API_HOST",
        "AETHER_API_SNI",
        "AETHER_TLS13_CIPHERS",
        "AETHER_TLS_KEY_SHARES",
        "AETHER_TLS_SIGALGS",
        "AETHER_TLS_CERT_COMPRESSION",
        "AETHER_TLS_ALPS",
        "AETHER_TLS_TRUST_ANCHORS",
        "AETHER_TLS_SERVER_PADDING",
        "AETHER_ENABLE_GREASE_SIGALGS",
        "AETHER_ENABLE_ECH_GREASE",
        "AETHER_DISABLE_OCSP_STAPLING",
        "AETHER_DISABLE_SCT",
        "AETHER_DISABLE_SESSION_TICKET",
        "AETHER_DISABLE_EXTENSION_PERMUTATION",
        "AETHER_MASQUE_H2_FRAGMENT_SNI",
    ] {
        command.env_remove(key);
    }
}

fn domain(value: &str) -> bool {
    let value = value.trim_end_matches('.');
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

fn address(value: &str, default_port: u16) -> bool {
    if value.parse::<IpAddr>().is_ok() {
        return true;
    }
    let Ok(url) = tauri::Url::parse(&format!("https://{value}")) else {
        return false;
    };
    url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/"
        && url.port().unwrap_or(default_port) > 0
        && url.host_str().is_some_and(|host| {
            host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() || domain(host)
        })
        && !value.contains('/')
        && !value.ends_with(':')
}

pub(crate) fn validate(profile: &CoreProfile) -> Result<(), String> {
    profile.tls.validate()?;
    if !matches!(profile.hello_shape.as_str(), "" | "records" | "compact") {
        return Err("ClientHello shape must be empty, records or compact".into());
    }
    for (label, value) in [
        ("TLS groups", &profile.tls_groups),
        ("TLS 1.2 ciphers", &profile.tls_ciphers),
        ("ECH configuration", &profile.ech),
        ("ECH resolver", &profile.ech_resolver),
        ("ECH domain", &profile.ech_domain),
        ("WARP registration address", &profile.enroll_address),
    ] {
        if value
            .as_deref()
            .is_some_and(|v| v.chars().any(char::is_control))
        {
            return Err(format!("{label} must not contain control characters"));
        }
    }
    for (label, value) in [
        ("TLS groups", &profile.tls_groups),
        ("TLS 1.2 ciphers", &profile.tls_ciphers),
    ] {
        if value.as_deref().is_some_and(|v| v.contains(',')) {
            return Err(format!(
                "{label} use ':' as the separator, for example X25519:P-256"
            ));
        }
    }
    if let Some(value) = profile
        .enroll_address
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        if !address(value, 443) {
            return Err(
                "WARP registration address must be a host/IP with an optional port (default 443)"
                    .into(),
            );
        }
    }
    // Off retains the saved override text, but does not activate or validate it.
    let ech = profile.ech.as_deref().unwrap_or("").trim();
    if ech.contains("://") {
        return Err("ECH configuration expects auto, off or a Base64 ECHConfigList. Put the resolver URL in ECH resolver.".into());
    }
    if ech.eq_ignore_ascii_case("off") {
        return Ok(());
    }
    if let Some(value) = profile
        .ech_domain
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        if !domain(value) || value.parse::<IpAddr>().is_ok() {
            return Err("ECH key domain must be a domain name".into());
        }
    }
    if let Some(value) = profile
        .ech_resolver
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        let mut pieces = value.split('@');
        let Ok(url) = tauri::Url::parse(pieces.next().unwrap_or("")) else {
            return Err("ECH resolver must use udp://, tcp:// or https://".into());
        };
        let scheme = url.scheme();
        if !matches!(scheme, "udp" | "tcp" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.port() == Some(0)
        {
            return Err(
                "ECH resolver must be a valid udp://IP, tcp://IP or https:// DoH URL".into(),
            );
        }
        if scheme != "https"
            && (url
                .host_str()
                .unwrap()
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_err()
                || !matches!(url.path(), "" | "/")
                || url.query().is_some()
                || value.contains('@'))
        {
            return Err("UDP/TCP ECH resolvers require a numeric IP and optional port; DoH can use a hostname".into());
        }
        let mut seen = std::collections::HashSet::new();
        for piece in pieces {
            let Some((key, host)) = piece.split_once('=') else {
                return Err("ECH DoH overrides use @address=host and @sni=name".into());
            };
            if !seen.insert(key)
                || !matches!(key, "address" | "sni")
                || !(domain(host)
                    || key == "address" && host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok())
            {
                return Err("Invalid ECH DoH address/SNI override".into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_resolvers_registration_and_saved_inactive_overrides() {
        let mut p = CoreProfile {
            ech: Some("auto".into()),
            ..Default::default()
        };
        for value in [
            "udp://1.1.1.1",
            "tcp://[2606:4700:4700::1111]:53",
            "https://resolver.example/dns-query@address=1.1.1.1@sni=resolver.example",
        ] {
            p.ech_resolver = Some(value.into());
            assert!(validate(&p).is_ok(), "{value}");
        }
        for value in [
            "udp://resolver.example",
            "ftp://1.1.1.1",
            "tcp://1.1.1.1:0",
            "https://user:secret@example.com/dns-query",
        ] {
            p.ech_resolver = Some(value.into());
            assert!(validate(&p).is_err(), "{value}");
        }
        p.ech = Some("off".into());
        assert!(validate(&p).is_ok());
        for value in [
            "registration.example",
            "203.0.113.10:443",
            "[2001:db8::1]:443",
            "2001:db8::1",
        ] {
            p.enroll_address = Some(value.into());
            assert!(validate(&p).is_ok(), "{value}");
        }
        for value in [
            "https://registration.example",
            "registration.example/path",
            "203.0.113.10:0",
            "host:",
        ] {
            p.enroll_address = Some(value.into());
            assert!(validate(&p).is_err(), "{value}");
        }
    }
}
