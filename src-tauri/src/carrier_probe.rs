//! Whether a route actually carries traffic, judged by who answers.
//!
//! This is the question the "find one that works" search settles on, and it is
//! the hard part of that feature -- harder than running the attempts. A route
//! that finished its handshakes is not a route that carries traffic, and a
//! carrier that reports a listener and then carries nothing is the worst thing
//! a search can settle on: it looks like success on every screen and fails
//! everything the person tries next.
//!
//! ## Why the round-trip probe was not enough
//!
//! 1.9.1 settled it with [`crate::latency::round_trip_ms`]: a SOCKS5 CONNECT to
//! `1.1.1.1:80` and a byte back. That proves bytes move, and it is the right
//! measurement for the latency the screen shows. It is not proof of *who
//! answered*. It asks for a literal address over plain HTTP, so a transparent
//! interception on port 80 answers it just as promptly as Cloudflare does, and
//! the search declares that route the winner.
//!
//! The Android client learned this the expensive way and it cost two releases,
//! because every test passes on a network that answers honestly.
//!
//! So this asks a question only the real host can answer: a TLS handshake to a
//! **name**, resolved by the carrier, verified against a pinned set of public
//! roots. See [`crate::tls`] for the two rules that implements.
//!
//! ## Why more than one target
//!
//! Rejecting a working carrier is a real cost, not a safe default -- the point
//! of the whole feature is someone who cannot get out otherwise. A single
//! target makes the verdict depend on one operator being reachable from
//! whatever country the carrier happens to exit in. Two independent operators,
//! either of which is enough, keeps a confident "no" rare without weakening
//! what a "yes" means.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use tauri::State;

use crate::core_supervisor::CoreSupervisor;
use crate::tls::connect_verified;

/// Hosts that answer for themselves, run by unrelated operators.
///
/// Both are the web front of a public resolver: about as widely reachable as
/// anything on the internet, stable for years at a time, and not the sort of
/// address whose blocking would go unnoticed. Names, not addresses -- an
/// address would skip the lookup this exists to make the carrier perform.
const TARGETS: [&str; 2] = ["cloudflare-dns.com", "dns.google"];

/// Long enough for a Tor circuit to build and hand over.
///
/// The latency probe's five seconds is sized for a tunnel already carrying
/// traffic; this one runs the moment a route comes up, in front of a carrier
/// that may still be settling, and three relays deep in the slowest case.
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// Whether `socks` carries traffic to a host that proved who it is.
///
/// `Ok(())` means one target completed a verified TLS handshake and answered
/// over it. The error names the last thing that went wrong, which is what the
/// search shows beside the attempt it rules out.
pub(crate) fn carries_verified_traffic(socks: SocketAddr) -> Result<(), String> {
    carries_verified_traffic_unless(socks, &|| false)
}

/// The same question, abandoned early when `give_up` says to.
///
/// Checked between targets rather than during one. A blocking socket cannot be
/// interrupted from outside without non-blocking IO, and the timeout that would
/// make interruption prompt is the same timeout that decides whether a slow but
/// working route is judged dead -- which on a disrupted network is the error
/// that matters. So each target keeps its full patience, and the cancellation
/// costs at most one of them.
pub(crate) fn carries_verified_traffic_unless(
    socks: SocketAddr,
    give_up: &dyn Fn() -> bool,
) -> Result<(), String> {
    let mut last = String::from("no targets were tried");
    for host in TARGETS {
        if give_up() {
            return Err(last);
        }
        match ask(socks, host) {
            Ok(()) => return Ok(()),
            // Kept rather than returned: the next operator may be reachable
            // from wherever this carrier leaves the network.
            Err(error) => last = format!("{host}: {error}"),
        }
    }
    Err(last)
}

/// One target: connect through the carrier, prove the peer, exchange a byte.
fn ask(socks: SocketAddr, host: &str) -> Result<(), String> {
    let mut tls = connect_verified(Some(socks), host, 443, PROBE_TIMEOUT)?;

    // HEAD, so the answer is a header and there is nothing to download. Writing
    // it is also what drives the handshake to completion -- rustls defers that
    // until the first byte moves -- so a failure to authenticate `host` surfaces
    // here rather than being missed.
    let request = format!(
        "HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: WhiteAesther\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(request.as_bytes())
        .map_err(|error| format!("the handshake did not complete: {error}"))?;

    let mut first = [0u8; 1];
    // A connection that closes with nothing on it is a failed probe, not a fast
    // one -- the same trap the latency probe had to be taught.
    match tls.read(&mut first) {
        Ok(0) => Err("the connection closed without an answer".into()),
        Ok(_) => Ok(()),
        Err(error) => Err(format!("nothing came back: {error}")),
    }
}

/// Asks whether the live route carries verified traffic.
///
/// `Ok(None)` when there is nothing connected to ask about, which is ordinary
/// while a route is still coming up and is not a failure worth showing.
/// `Ok(Some(reason))` is a route that is up and did not pass.
#[tauri::command]
pub async fn probe_carrier(
    supervisor: State<'_, CoreSupervisor>,
) -> Result<Option<String>, String> {
    let Some(socks) = supervisor.connected_socks() else {
        return Ok(None);
    };
    let address: SocketAddr = socks
        .parse()
        .map_err(|_| format!("the proxy address {socks} cannot be parsed"))?;

    // Blocking sockets on the webview thread freeze the window; every other
    // command in this app learned that the hard way.
    tauri::async_runtime::spawn_blocking(move || match carries_verified_traffic(address) {
        Ok(()) => None,
        Err(reason) => Some(reason),
    })
    .await
    .map_err(|error| format!("the carrier probe did not finish: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

    #[test]
    fn a_listener_that_is_not_a_carrier_fails_rather_than_passing() {
        // Exactly the shape this module exists to catch: something that accepts
        // the connection -- so the port is open and a naive check is satisfied
        // -- and then carries nothing.
        //
        // Accepting and dropping rather than merely binding, so the SOCKS
        // handshake fails on a closed connection instead of sitting out the
        // probe timeout twice and adding half a minute to every test run.
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(TARGETS.len()) {
                drop(stream);
            }
        });
        let error = carries_verified_traffic(address).unwrap_err();
        // The last target's name is in the message, so the search can say which
        // question went unanswered rather than only that one did.
        assert!(error.starts_with(TARGETS[TARGETS.len() - 1]), "{error}");
    }

    #[test]
    fn every_target_is_a_name_and_not_an_address() {
        // An address would be resolved by nobody and would skip the lookup this
        // exists to make the carrier perform -- which is how the probe it
        // replaces could be answered by an interception.
        for host in TARGETS {
            assert!(host.parse::<std::net::IpAddr>().is_err(), "{host}");
            assert!(host.contains('.'), "{host}");
        }
    }
}
