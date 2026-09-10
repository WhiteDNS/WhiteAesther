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
    /// Declaring a proxy `udp: true` when it cannot produces a carrier that
    /// swallows every datagram -- DNS and QUIC hang rather than failing, and
    /// neither falls back because nothing told them to. Refused, a resolver
    /// retries over TCP and a browser drops off QUIC, both within a round trip.
    ///
    /// Tor cannot, by design: it is a TCP-only transport and nothing configures
    /// that away.
    ///
    /// **Psiphon cannot either, which was measured rather than assumed.** Its
    /// SOCKS5 listener answers `UDP ASSOCIATE` with `0x07 COMMAND NOT
    /// SUPPORTED`, so mihomo has no way to relay a datagram through it. This
    /// shipped as `true` in 1.8.0 on the strength of a guess, and the cost was
    /// exactly the failure described above: under Psiphon, QUIC hung instead of
    /// falling back, which reads as "the internet is slow" rather than as
    /// anything to report.
    ///
    /// Only Aether carries datagrams, and even then not a QUIC handshake --
    /// see `Carrier::carries_quic`, which is a narrower question.
    pub fn carries_udp(self) -> bool {
        match self {
            Self::Aether => true,
            Self::Psiphon | Self::Tor => false,
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

/// An ordered pair of carriers, as the user chose them.
///
/// `first` is what leaves the local network; `second` decides the exit address.
/// `second: None` is the single-carrier case, which is every session that
/// existed before chaining -- so a profile written then reads as itself.
///
/// See `CARRIER-CHAINING.md` for what was measured about each ordering, and in
/// particular why `second: Some(Aether)` needs an identity that already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct CarrierChain {
    pub first: CarrierKind,
    pub second: Option<CarrierKind>,
}

// Part of this is read only by later steps of CARRIER-CHAINING.md: the
// sequential startup in step 2, and the two-selector screen in step 6. It lives
// with the type rather than being invented twice when those land.
#[allow(dead_code)]
impl CarrierChain {
    /// The carrier whose listener traffic is finally routed into.
    pub fn last(&self) -> CarrierKind {
        self.second.unwrap_or(self.first)
    }


    /// Every kind in the chain, in the order traffic travels.
    pub fn kinds(&self) -> Vec<CarrierKind> {
        match self.second {
            Some(second) => vec![self.first, second],
            None => vec![self.first],
        }
    }

    pub fn is_chained(&self) -> bool {
        self.second.is_some()
    }

    /// Whether this is the Aether engine on its own.
    ///
    /// The one case that takes the engine's own supervisor rather than the
    /// carrier path: it has a scan to run, transports to alternate and a
    /// gateway to re-pick, none of which the others have.
    pub fn is_lone_aether(&self) -> bool {
        self.first == CarrierKind::Aether && self.second.is_none()
    }

    /// What to call this chain on screen and in a log line.
    ///
    /// The arrow is the order traffic travels, which is the thing people get
    /// backwards. Naming only the exit would hide the hop that decides what the
    /// local network sees; naming only the first would hide where traffic comes
    /// out. Both, in order.
    pub fn label(&self) -> String {
        match self.second {
            Some(second) => format!("{} → {}", self.first.label(), second.label()),
            None => self.first.label().to_string(),
        }
    }

    /// Whether this chain contains a given carrier at any position.
    ///
    /// Settings belong to a carrier rather than to a position: an exit country
    /// is Psiphon's whether Psiphon is the first hop or the second.
    pub fn contains(&self, kind: CarrierKind) -> bool {
        self.kinds().contains(&kind)
    }

    /// Why this ordering cannot be run, when it cannot.
    ///
    /// Only the shapes that are wrong regardless of the network. Whether a
    /// given carrier can reach anything from here is a question for the
    /// attempt, not for validation.
    pub fn refusal(&self) -> Option<String> {
        let second = self.second?;
        if second == self.first {
            // Two hops of the same carrier buy nothing: the second would dial
            // its own servers through the first, doubling the latency to reach
            // the same network.
            return Some(format!(
                "{} cannot be chained to itself -- the second hop would reach the same network \
                 through the first, for twice the delay.",
                self.first.label()
            ));
        }
        None
    }
}

/// A chain that is up, ordered as traffic travels.
///
/// Built by the supervisor once every hop is carrying traffic, and handed to
/// [`crate::chain`] in place of a single `Carrier`. The accessors exist because
/// three of the four answers the routing engine needs are **not** the last
/// hop's answer, and reading them off one carrier is how a chain silently
/// becomes a single hop in the rendered config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningChain {
    hops: Vec<Carrier>,
}

#[allow(dead_code)]
impl RunningChain {
    /// One hop: the case that exists today.
    pub fn single(carrier: Carrier) -> Self {
        Self { hops: vec![carrier] }
    }

    /// Two hops, in the order traffic travels.
    pub fn pair(first: Carrier, second: Carrier) -> Self {
        Self { hops: vec![first, second] }
    }

    /// What mihomo dials: the last hop, because every earlier one is reached
    /// through it rather than by us.
    pub fn listener(&self) -> SocketAddr {
        self.hops.last().expect("a chain has at least one hop").socks
    }

    /// The carrier the exit address belongs to.
    pub fn last(&self) -> &Carrier {
        self.hops.last().expect("a chain has at least one hop")
    }

    /// Every process to keep out of the TUN device.
    ///
    /// All of them, not just the one that reaches the physical network.
    /// Strictly, only the first hop does -- later hops talk to it on loopback,
    /// which `auto-route` does not capture. Exempting all of them costs one
    /// rule each and covers the case that would otherwise be silent: a hop that
    /// makes one unexpected direct connection, and takes the whole connection
    /// down with no diagnosis at all.
    pub fn process_names(&self) -> Vec<&'static str> {
        self.hops.iter().map(Carrier::process_name).collect()
    }

    /// Whether datagrams survive the whole chain.
    ///
    /// The AND across hops, not the last hop's answer. Measured: Psiphon's
    /// SOCKS5 refuses `UDP ASSOCIATE` and Tor carries no datagrams at all, so
    /// one TCP-only hop makes the entire chain TCP-only however capable the
    /// others are.
    pub fn carries_udp(&self) -> bool {
        self.hops.iter().all(Carrier::carries_udp)
    }

    /// Whether a QUIC handshake fits through the whole chain. Same reasoning.
    pub fn carries_quic(&self) -> bool {
        self.hops.iter().all(|hop| hop.carries_quic)
    }

    /// The gateway to exempt from the TUN device by address.
    ///
    /// The **first** hop's, because it is the only one with a gateway on the
    /// real internet. Later hops reach the network through it, so their traffic
    /// never touches the physical interface and there is no address to name.
    pub fn endpoint(&self) -> Option<IpAddr> {
        self.hops.first().and_then(|hop| hop.endpoint)
    }

    /// Whether this is more than one hop, for the lines a person reads.
    pub fn is_chained(&self) -> bool {
        self.hops.len() > 1
    }
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
    fn only_aether_carries_datagrams() {
        // Declared rather than discovered. A proxy that claims UDP and swallows
        // it is experienced as DNS and QUIC hanging while TCP works, which is
        // the hardest shape of broken to recognise.
        //
        // Tor is TCP-only by design. Psiphon was measured: its SOCKS5 answers
        // `UDP ASSOCIATE` with 0x07 COMMAND NOT SUPPORTED. 1.8.0 claimed it
        // carried datagrams because nobody had asked it.
        assert!(CarrierKind::Aether.carries_udp());
        assert!(!CarrierKind::Psiphon.carries_udp());
        assert!(!CarrierKind::Tor.carries_udp());
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

    fn hop(kind: CarrierKind, port: u16, endpoint: Option<&str>, quic: bool) -> Carrier {
        Carrier {
            kind,
            socks: SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)),
            endpoint: endpoint.map(|value| value.parse().unwrap()),
            carries_quic: quic,
        }
    }

    #[test]
    fn a_chain_is_dialled_at_its_last_hop() {
        // Every earlier hop is reached through the last one rather than by us,
        // so the last listener is the only address mihomo has any business
        // dialling.
        let chain = RunningChain::pair(
            hop(CarrierKind::Aether, 1819, Some("162.159.198.2"), false),
            hop(CarrierKind::Psiphon, 64347, None, false),
        );
        assert_eq!(chain.listener().port(), 64347);
        assert_eq!(chain.last().kind, CarrierKind::Psiphon);
        assert!(chain.is_chained());
    }

    #[test]
    fn every_hop_stays_out_of_the_tun_device() {
        // Strictly only the first hop reaches the physical network. Exempting
        // all of them is deliberate: the failure this guards against is a hop
        // that makes one unexpected direct connection, and it is total and
        // silent -- the packets that would have explained it are the ones being
        // fed back.
        let chain = RunningChain::pair(
            hop(CarrierKind::Aether, 1819, None, false),
            hop(CarrierKind::Tor, 9150, None, false),
        );
        let names = chain.process_names();
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(names.contains(&CarrierKind::Aether.process_name()), "{names:?}");
        assert!(names.contains(&CarrierKind::Tor.process_name()), "{names:?}");
    }

    #[test]
    fn one_tcp_only_hop_makes_the_whole_chain_tcp_only() {
        // The AND, not the last hop's answer. Reading it off the last hop is
        // how a chain ending at Aether would claim to carry datagrams that a
        // Psiphon or Tor hop in front of it cannot pass -- and a proxy that
        // claims UDP and swallows it is experienced as hanging, not failing.
        let aether_then_tor = RunningChain::pair(
            hop(CarrierKind::Aether, 1819, None, true),
            hop(CarrierKind::Tor, 9150, None, false),
        );
        assert!(!aether_then_tor.carries_udp());
        assert!(!aether_then_tor.carries_quic());

        // And the reverse ordering, where the capable hop is last.
        let tor_then_aether = RunningChain::pair(
            hop(CarrierKind::Tor, 9150, None, false),
            hop(CarrierKind::Aether, 1819, None, true),
        );
        assert!(
            !tor_then_aether.carries_udp(),
            "a Tor hop in front cannot pass what Aether would carry"
        );
        assert!(!tor_then_aether.carries_quic());

        // Aether alone still carries datagrams.
        assert!(RunningChain::single(hop(CarrierKind::Aether, 1819, None, true)).carries_udp());
    }

    #[test]
    fn the_address_exemption_names_the_first_hops_gateway() {
        // The first hop is the only one with a gateway on the real internet.
        // Naming the last hop's would exempt an address nothing connects to,
        // and leave the one that matters captured.
        let chain = RunningChain::pair(
            hop(CarrierKind::Aether, 1819, Some("162.159.198.2"), false),
            hop(CarrierKind::Psiphon, 64347, None, false),
        );
        assert_eq!(chain.endpoint().map(|ip| ip.to_string()).as_deref(), Some("162.159.198.2"));

        // Psiphon and Tor have no single gateway, so a chain starting with one
        // has no address to name and relies on the process rule alone.
        let starts_with_psiphon = RunningChain::pair(
            hop(CarrierKind::Psiphon, 64347, None, false),
            hop(CarrierKind::Aether, 1819, Some("162.159.198.2"), false),
        );
        assert!(starts_with_psiphon.endpoint().is_none());
    }

    #[test]
    fn a_carrier_cannot_be_chained_to_itself() {
        // The second hop would dial the same network through the first, for
        // twice the delay and no change of exit.
        for kind in [CarrierKind::Aether, CarrierKind::Psiphon, CarrierKind::Tor] {
            let refusal = CarrierChain { first: kind, second: Some(kind) }
                .refusal()
                .expect("chaining a carrier to itself should be refused");
            assert!(refusal.contains(kind.label()), "{refusal}");
        }
    }

    #[test]
    fn every_ordering_of_two_different_carriers_is_allowed() {
        // All six, because all six were measured to work -- two of them only
        // with an Aether identity that already exists, which is a precondition
        // the supervisor checks rather than a shape this refuses.
        let kinds = [CarrierKind::Aether, CarrierKind::Psiphon, CarrierKind::Tor];
        let mut allowed = 0;
        for first in kinds {
            for second in kinds {
                if first == second {
                    continue;
                }
                let chain = CarrierChain { first, second: Some(second) };
                assert!(chain.refusal().is_none(), "{first:?} -> {second:?}");
                assert_eq!(chain.last(), second);
                assert_eq!(chain.kinds(), vec![first, second]);
                allowed += 1;
            }
        }
        assert_eq!(allowed, 6, "there are six orderings of three carriers taken two at a time");
    }

    #[test]
    fn a_profile_with_no_second_hop_is_the_single_carrier_case() {
        // Every session that exists today. A profile written before chaining
        // carries no `second`, and must read as exactly what it was.
        let stored = serde_json::json!({ "first": "psiphon" });
        let chain: CarrierChain = serde_json::from_value(stored).unwrap();
        assert_eq!(chain.first, CarrierKind::Psiphon);
        assert_eq!(chain.second, None);
        assert_eq!(chain.last(), CarrierKind::Psiphon);
        assert!(!chain.is_chained());
        assert!(chain.refusal().is_none());

        // And an entirely absent chain is Aether, as it always was.
        let empty: CarrierChain = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(empty.first, CarrierKind::Aether);
        assert_eq!(empty.second, None);
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
