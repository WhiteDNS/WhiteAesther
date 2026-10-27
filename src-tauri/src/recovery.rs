//! Android v1.15 connection recipes, shared by racing, reconnects and discovery.
use crate::core_supervisor::CoreProfile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineRecipe {
    pub protocol: String,
    pub masque_transport: String,
    pub fragment_client_hello: bool,
    pub hello_shape: String,
    pub fragment_size: String,
    pub fragment_delay: String,
    pub fragment_sni: bool,
    pub ech: Option<String>,
    pub ip_family: String,
    pub scan_mode: String,
}

impl EngineRecipe {
    pub fn from_profile(p: &CoreProfile) -> Self {
        Self {
            protocol: p.protocol.clone(),
            masque_transport: p.masque_transport.clone(),
            fragment_client_hello: p.fragment_client_hello,
            hello_shape: p.hello_shape.clone(),
            fragment_size: p.fragment_size.clone(),
            fragment_delay: p.fragment_delay.clone(),
            fragment_sni: p.fragment_sni,
            ech: p.ech.clone(),
            ip_family: p.ip_family.clone(),
            scan_mode: p.scan_mode.clone(),
        }
    }

    pub fn apply(&self, p: &CoreProfile) -> CoreProfile {
        let mut p = p.clone();
        p.protocol = self.protocol.clone();
        p.masque_transport = self.masque_transport.clone();
        p.fragment_client_hello = self.fragment_client_hello;
        p.hello_shape = self.hello_shape.clone();
        p.fragment_size = self.fragment_size.clone();
        p.fragment_delay = self.fragment_delay.clone();
        p.fragment_sni = self.fragment_sni;
        p.ech = self.ech.clone();
        p.ip_family = self.ip_family.clone();
        p.scan_mode = self.scan_mode.clone();
        p
    }

    pub fn label(&self) -> String {
        let transport = if self.protocol == "masque" {
            self.masque_transport.as_str()
        } else {
            &self.protocol
        };
        let mut label = format!("aether {transport}");
        if self.fragment_client_hello && self.masque_transport == "h2" {
            label.push_str(if self.hello_shape.is_empty() {
                "+fragment"
            } else {
                "+"
            });
            if !self.hello_shape.is_empty() {
                label.push_str(&self.hello_shape);
            }
        }
        if self
            .ech
            .as_deref()
            .is_some_and(|v| !v.is_empty() && !v.eq_ignore_ascii_case("off"))
        {
            label.push_str("+ech");
        }
        if self.ip_family == "v6" {
            label.push_str("+ipv6");
        }
        label
    }

    pub fn budget(&self) -> Duration {
        Duration::from_secs(match self.protocol.as_str() {
            "wom" => 120,
            "mim" => 180,
            "masque" if self.scan_mode == "turbo" => 45,
            "masque" => 180,
            _ => 300,
        })
    }
}

/// Settings that invalidate a previously proven recipe. Credentials are hashed,
/// never persisted in route memory. Endpoint address is a hint, not policy.
pub fn context(p: &CoreProfile) -> String {
    let encoded = serde_json::json!({
        "protocol": p.protocol, "tls": p.tls, "groups": p.tls_groups,
        "ciphers": p.tls_ciphers, "grease": p.disable_grease, "ech": p.ech,
        "echDns": p.ech_resolver, "echDomain": p.ech_domain, "apiAddress": p.enroll_address,
        "upstream": p.upstream_proxy, "team": p.team, "ip": p.ip_family,
        "fragmentSize": p.fragment_size, "fragmentDelay": p.fragment_delay,
        "fragmentSni": p.fragment_sni, "fragment":p.fragment_client_hello, "shape": p.hello_shape, "noize": p.noize,
    }).to_string();
    format!("{:x}", Sha256::digest(encoded.as_bytes()))
}

/// Quick framings, record shaping, tactics, IPv6, WOM, deep H2 and MIM.
/// Explicit ECH-off and IPv4-only remain strict. The configured recipe gets
/// its own first attempt when it differs from the ordinary quick recipes.
pub fn recipes(
    p: &CoreProfile,
    remembered: Option<&EngineRecipe>,
    failure: Option<&str>,
) -> Vec<EngineRecipe> {
    let mut result = Vec::new();
    let mut add = |candidate: CoreProfile| {
        let recipe = EngineRecipe::from_profile(&candidate);
        if !result.contains(&recipe) {
            result.push(recipe);
        }
    };
    let mut base = p.clone();
    base.endpoint_mode = "automatic".into();
    if !matches!(base.scan_mode.as_str(), "turbo" | "balanced") {
        base.scan_mode = "balanced".into();
    }
    if base.protocol != "masque"
        || base.fragment_client_hello
        || !base.hello_shape.is_empty()
        || base.ech_setting().is_some()
    {
        let mut configured = base.clone();
        configured.scan_mode = "turbo".into();
        add(configured);
    }
    let mut h2 = base.clone();
    h2.protocol = "masque".into();
    h2.masque_transport = "h2".into();
    h2.scan_mode = "turbo".into();
    h2.fragment_client_hello = false;
    h2.hello_shape.clear();
    let mut h3 = h2.clone();
    h3.masque_transport = "h3".into();
    if p.masque_transport == "h3" {
        add(h3.clone());
        add(h2.clone());
    } else {
        add(h2.clone());
        add(h3.clone());
    }
    let mut records = h2.clone();
    records.fragment_client_hello = true;
    records.hello_shape = "records".into();
    add(records);
    let mut fragmented = h2.clone();
    fragmented.fragment_client_hello = true;
    add(fragmented);
    if !p
        .ech
        .as_deref()
        .is_some_and(|v| v.eq_ignore_ascii_case("off"))
    {
        let mut encrypted = h2.clone();
        encrypted.ech = Some(p.ech_setting().unwrap_or("auto").into());
        add(encrypted.clone());
        encrypted.masque_transport = "h3".into();
        add(encrypted);
    }
    let mut compact = h2.clone();
    compact.fragment_client_hello = true;
    compact.hello_shape = "compact".into();
    add(compact);
    if p.ip_family != "v4" {
        let mut ipv6 = h2.clone();
        ipv6.ip_family = "v6".into();
        add(ipv6);
    }
    let mut wom = h2.clone();
    wom.protocol = "wom".into();
    add(wom);
    let mut full = h2.clone();
    full.scan_mode = "balanced".into();
    add(full);
    let mut mim = h2;
    mim.protocol = "mim".into();
    add(mim);
    if let Some(recipe) = remembered {
        if result.contains(recipe) {
            result.retain(|r| r != recipe);
            result.insert(0, recipe.clone());
        }
    }
    if let Some(failure) = failure {
        let lower = failure.to_ascii_lowercase();
        let wanted = if lower.contains("ech") {
            result
                .iter()
                .position(|r| r.ech.as_deref().is_some_and(|v| v != "off"))
        } else if lower.contains("unrecognised name") || lower.contains("unrecognized name") {
            result.iter().position(|r| r.fragment_client_hello)
        } else {
            None
        };
        if let Some(index) = wanted {
            let recipe = result.remove(index);
            result.insert(0, recipe);
        }
    }
    result
}

pub fn conclusive_identity_error(reason: &str) -> bool {
    let reason = reason.to_ascii_lowercase();
    [
        "registration on hold",
        "registration is on hold",
        "rate limited",
        "rate-limited",
        "429",
        "identity refused",
        "identity has been refused",
        "registration budget",
        "retry-after",
    ]
    .iter()
    .any(|needle| reason.contains(needle))
}

/// Android's one-minute floor, doubling for consecutive fast failures, capped
/// at eight minutes. Successful or full-duration rounds do not sleep again.
pub fn pause_after_round(elapsed: Duration, fast_rounds: u32) -> Duration {
    if fast_rounds == 0 {
        return Duration::ZERO;
    }
    Duration::from_secs(60u64 << fast_rounds.saturating_sub(1).min(3)).saturating_sub(elapsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_android_recovery_tactic_is_reachable_and_bounded() {
        let p = CoreProfile::default();
        let all = recipes(&p, None, None);
        for name in [
            "aether h2",
            "aether h3",
            "aether h2+records",
            "aether h2+compact",
            "aether h2+fragment",
            "aether h2+ech",
            "aether h3+ech",
            "aether h2+ipv6",
            "aether wom",
            "aether mim",
        ] {
            assert!(all.iter().any(|r| r.label() == name), "{name}");
        }
        assert!(all.iter().any(|r| r.scan_mode == "balanced"));
        assert!(all.iter().all(|r| r.budget() <= Duration::from_secs(300)));
    }
    #[test]
    fn ipv4_and_ech_off_are_not_overridden() {
        let p = CoreProfile {
            ip_family: "v4".into(),
            ech: Some("off".into()),
            ..Default::default()
        };
        assert!(recipes(&p, None, None)
            .iter()
            .all(|r| r.ip_family == "v4" && r.ech.as_deref() == Some("off")));
    }
    #[test]
    fn only_one_method_working_still_produces_its_exact_recipe() {
        let p = CoreProfile::default();
        for working in [
            "aether h2+records",
            "aether h2+compact",
            "aether h3+ech",
            "aether h2+ipv6",
            "aether wom",
        ] {
            let selected = recipes(&p, None, None)
                .into_iter()
                .find(|r| r.label() == working)
                .unwrap();
            assert_eq!(EngineRecipe::from_profile(&selected.apply(&p)), selected);
            assert_eq!(recipes(&p, Some(&selected), None)[0], selected);
        }
    }
    #[test]
    fn changed_tls_and_upstream_invalidate_proofs_without_storing_secrets() {
        let p = CoreProfile::default();
        let mut q = p.clone();
        q.tls.masque_sni = Some("example.com".into());
        assert_ne!(context(&p), context(&q));
        q = p.clone();
        q.upstream_proxy = "socks5://user:secret@127.0.0.1:1234".into();
        assert_ne!(context(&p), context(&q));
        assert!(!context(&q).contains("secret"));
    }
    #[test]
    fn fast_round_backoff_matches_android() {
        assert_eq!(
            pause_after_round(Duration::from_secs(10), 1),
            Duration::from_secs(50)
        );
        assert_eq!(
            pause_after_round(Duration::from_secs(10), 9),
            Duration::from_secs(470)
        );
        assert_eq!(
            pause_after_round(Duration::from_secs(80), 1),
            Duration::ZERO
        );
    }
}
