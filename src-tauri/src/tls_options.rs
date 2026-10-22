//! Syntax checks shared by profile storage, scanner and session startup.
//! BoringSSL itself checks cipher/group names through the core's offline check.
use crate::core_supervisor::CoreProfile;
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
        "This core cannot validate the new settings; use the bundled Aether 2.3 core".to_string()
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
        "AETHER_ECH",
        "AETHER_ECH_DNS",
        "AETHER_ECH_DOMAIN",
        "AETHER_TLS_CIPHERS",
        "AETHER_TLS_GROUPS",
        "AETHER_DISABLE_GREASE",
        "AETHER_ENROLL_ADDRESS",
        "AETHER_MASQUE_H2_FRAGMENT",
        "AETHER_MASQUE_H2_FRAGMENT_SIZE",
        "AETHER_MASQUE_H2_FRAGMENT_DELAY",
        "AETHER_HELLO_SHAPE",
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
