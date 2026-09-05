//! What gets us out of the network, and what the routing engine needs to know
//! about it.
//!
//! Aether is one way out; Psiphon and Tor are others. They have nothing in
//! common internally -- one is a Cloudflare MASQUE tunnel, one finds its own
//! path, one builds a circuit through three relays -- but they end in the same
//! place: a SOCKS5 listener on loopback that mihomo routes the interface into.
//!
//! That listener is all [`chain`](crate::chain) ever needed. What it *also*
//! needs, and used to have as three constants naming Aether, is everything
//! about the carrier that changes the config it renders:
//!
//! - the **name** the proxy takes in the YAML, because every node's
//!   `dialer-proxy` points at it,
//! - the **process** it runs as, because under full tunnel the default route
//!   goes into the TUN device and the carrier's own packets have to be let out
//!   of it, and
//! - whether it carries **datagrams**, because a proxy declared as carrying UDP
//!   that cannot swallows every one -- which is experienced as DNS and QUIC
//!   hanging while TCP works, the hardest shape of broken to recognise.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

/// Which way out the user has chosen.
///
/// Serialised into the profile, so the names are a stored format: renaming one
/// silently moves everybody who chose it back to the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CarrierKind {
    /// The Aether engine: Cloudflare MASQUE or WireGuard.
    #[default]
    Aether,
    /// Psiphon, which finds its own way out and picks its own exit country.
    Psiphon,
    /// Tor, through three relays and optionally a bridge.
    Tor,
}

impl CarrierKind {
    /// The name this carrier's proxy takes in the rendered config.
    ///
    /// Every node's `dialer-proxy` and every provider's `proxy` names it, and
    /// the catch-all falls back to it when there is no exit chain -- so it has
    /// to be stable within a run and distinct between carriers, which is the
    /// whole reason it is no longer the constant `"aether"`.
    pub fn proxy_name(self) -> &'static str {
        match self {
            Self::Aether => "aether",
            Self::Psiphon => "psiphon",
            Self::Tor => "tor",
        }
    }

    /// The executable this carrier runs as, for the rule that keeps its own
    /// packets out of the device they would otherwise be fed back into.
    ///
    /// Matched on the process rather than the address deliberately: see the
    /// rule this feeds in [`crate::chain`]. Getting it wrong under full tunnel
    /// is not a degraded connection, it is total silent loss -- the carrier's
    /// packets are handed back to the carrier that produced them, including the
    /// ones that would have explained why.
    pub fn process_name(self) -> &'static str {
        match self {
            Self::Aether => {
                if cfg!(windows) {
                    "aether.exe"
                } else {
                    "aether"
                }
            }
            Self::Psiphon => {
                if cfg!(windows) {
                    "psiphon-tunnel-core.exe"
                } else {
                    "psiphon-tunnel-core"
                }
            }
            Self::Tor => {
                if cfg!(windows) {
                    "tor.exe"
                } else {
                    "tor"
                }
            }
        }
    }

    /// Whether this carrier can carry datagrams at all.
    ///
    /// Tor cannot: it is a TCP-only transport, and nothing configures that
    /// away. Declaring the proxy `udp: true` anyway produces a carrier that
    /// swallows every datagram -- DNS and QUIC hang rather than failing, and
    /// neither falls back because nothing told them to. Refused, a resolver
    /// retries over TCP and a browser drops off QUIC, both within a round trip.
    pub fn carries_udp(self) -> bool {
        match self {
            Self::Aether | Self::Psiphon => true,
            Self::Tor => false,
        }
    }

    /// What to call this on screen, and in a log line a person reads.
    pub fn label(self) -> &'static str {
        match self {
            Self::Aether => "Aether",
            Self::Psiphon => "Psiphon",
            Self::Tor => "Tor",
        }
    }
}

/// A carrier that is up, and everything the routing engine needs about it.
///
/// Built by whichever supervisor is running and handed to
/// [`crate::chain::ChainRequest`]. Deliberately not the supervisor itself: the
/// chain has no business reading state it cannot act on, and this is the whole
/// of what it can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Carrier {
    pub kind: CarrierKind,
    /// The SOCKS5 listener everything is routed into.
    pub socks: SocketAddr,
    /// The gateway this carrier is connected to, when it has a single one.
    ///
    /// Only Aether does. It is exempted from the TUN device by address as a
    /// second line of defence behind the process rule, for a platform where
    /// process matching is unavailable. Psiphon and Tor have no one address to
    /// name -- the process rule carries it alone there, which is what it was
    /// already doing everywhere.
    pub endpoint: Option<IpAddr>,
    /// Whether a QUIC handshake fits through this carrier.
    ///
    /// Narrower than [`CarrierKind::carries_udp`] and not the same question. A
    /// MASQUE tunnel carries datagrams perfectly well and still cannot carry
    /// QUIC: hysteria2 needs 1308 bytes and Cloudflare's capsule carries 1306.
    /// So this is false for MASQUE and true for WireGuard, on the same carrier
    /// -- which is why it is measured per-connection here rather than declared
    /// per-kind above.
    pub carries_quic: bool,
}

impl Carrier {
    /// The name this carrier's proxy takes in the config.
    pub fn proxy_name(&self) -> &'static str {
        self.kind.proxy_name()
    }

    /// The executable to exempt from the TUN device.
    pub fn process_name(&self) -> &'static str {
        self.kind.process_name()
    }

    /// Whether to declare the proxy as carrying datagrams.
    ///
    /// A carrier that cannot carry QUIC can still carry ordinary UDP, so this
    /// follows the kind and not `carries_quic`.
    pub fn carries_udp(&self) -> bool {
        self.kind.carries_udp()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_is_the_one_carrier_that_carries_no_datagrams() {
        // Declared rather than discovered. A proxy that claims UDP and swallows
        // it is experienced as DNS and QUIC hanging while TCP works, which is
        // the hardest shape of broken to recognise.
        assert!(!CarrierKind::Tor.carries_udp());
        assert!(CarrierKind::Aether.carries_udp());
        assert!(CarrierKind::Psiphon.carries_udp());
    }

    #[test]
    fn every_carrier_has_a_distinct_name_and_process() {
        // Two carriers sharing a proxy name would render a config where one
        // node's dialer-proxy silently points at the other carrier; two sharing
        // a process name would exempt the wrong executable from the TUN device.
        let kinds = [CarrierKind::Aether, CarrierKind::Psiphon, CarrierKind::Tor];
        for (index, one) in kinds.iter().enumerate() {
            for other in &kinds[index + 1..] {
                assert_ne!(one.proxy_name(), other.proxy_name());
                assert_ne!(one.process_name(), other.process_name());
            }
        }
    }

    #[test]
    fn the_stored_names_are_a_format_and_do_not_drift() {
        // Serialised into the profile. A rename moves everyone who chose that
        // carrier silently back to the default at the next load.
        for (kind, stored) in [
            (CarrierKind::Aether, "\"aether\""),
            (CarrierKind::Psiphon, "\"psiphon\""),
            (CarrierKind::Tor, "\"tor\""),
        ] {
            assert_eq!(serde_json::to_string(&kind).unwrap(), stored);
            assert_eq!(serde_json::from_str::<CarrierKind>(stored).unwrap(), kind);
        }
    }

    #[test]
    fn a_profile_that_names_no_carrier_reads_as_aether() {
        // Every saved profile predates carriers. Defaulting to anything else
        // would move existing users onto a way out they never chose.
        assert_eq!(CarrierKind::default(), CarrierKind::Aether);
    }

    #[test]
    fn carrying_datagrams_and_carrying_quic_are_different_questions() {
        // MASQUE carries UDP perfectly well and still cannot carry QUIC:
        // hysteria2 needs 1308 bytes and Cloudflare's capsule carries 1306.
        let masque = Carrier {
            kind: CarrierKind::Aether,
            socks: "127.0.0.1:1819".parse().unwrap(),
            endpoint: None,
            carries_quic: false,
        };
        assert!(masque.carries_udp(), "the tunnel carries datagrams");
        assert!(!masque.carries_quic, "but not a QUIC handshake");
    }
}
