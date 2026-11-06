//! Round-trip measurement through the live tunnel.
//!
//! The engine reports a latency figure exactly once, on the log line that
//! announces the selected gateway (`rtt 84.5ms`). That is a single number from
//! the moment of connecting, so it cannot answer the question the status screen
//! actually asks: is the route still good *now*.
//!
//! So we measure it ourselves. A SOCKS5 CONNECT through the local listener out
//! to a fixed address times the whole path — client, engine, MASQUE tunnel,
//! edge, and the TCP handshake at the far end. It is the same work a browser
//! does to open a connection, which is what makes it worth showing.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::State;

use crate::chain::Chain;
use crate::core_supervisor::CoreSupervisor;
use crate::http_bridge::socks5_connect;

/// A literal address, so the figure is the path and not a DNS lookup that would
/// swamp it. Cloudflare anycast on 443, which is up wherever the tunnel lands.
///
/// A routing rule that sends this address direct would measure the direct path
/// instead; that is a deliberate choice by whoever wrote the rule.
const TARGET_HOST: &str = "1.1.1.1";
/// A Cloudflare Worker cannot `connect()` to Cloudflare addresses, so through
/// the Worker carrier the round trip is timed to a host outside Cloudflare.
const WORKER_TARGET_HOST: &str = "www.google.com";
/// Port 80, because the probe now asks for a byte back and needs a server that
/// will answer in the clear. There is no TLS client in this crate, and nothing
/// here is secret -- it is a fixed request to a public resolver's web front.
const TARGET_PORT: u16 = 80;

/// Short on purpose. A probe that has not answered in this long has told us
/// what we needed to know, and holding the thread longer only delays the next
/// sample.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Times one round trip through the tunnel, in milliseconds.
///
/// Returns `Ok(None)` rather than an error when there is no tunnel to measure:
/// the caller polls this on a timer, and a disconnect is an ordinary outcome,
/// not a failure worth surfacing to the user.
#[tauri::command]
pub async fn probe_latency(
    app: tauri::AppHandle,
    supervisor: State<'_, CoreSupervisor>,
) -> Result<Option<f64>, String> {
    let Some(socks) = supervisor.connected_socks() else {
        return Ok(None);
    };
    let address: SocketAddr = socks
        .parse()
        .map_err(|_| format!("the proxy address {socks} cannot be parsed"))?;
    let worker = supervisor.carrier(&app).is_some_and(|carrier| carrier.kind == crate::carrier::CarrierKind::Worker);
    let host = if worker { WORKER_TARGET_HOST } else { TARGET_HOST };

    // Blocking sockets on the main thread freeze the window; every other command
    // in this app learned that the hard way.
    tauri::async_runtime::spawn_blocking(move || measure(address, host))
        .await
        .map_err(|error| format!("the latency probe did not finish: {error}"))
}

/// One round trip through the tunnel, for anything that needs to judge the
/// route rather than display it.
pub(crate) fn round_trip_ms(socks: SocketAddr) -> Option<f64> {
    measure(socks, TARGET_HOST)
}

/// Times a request and its first byte back, not just the handshake.
///
/// Timing the SOCKS5 CONNECT alone was measuring the wrong thing: opening a
/// connection through a congested tunnel stays fast, because the engine answers
/// as soon as the far end accepts. A gateway that had degraded to five seconds
/// a page still charted at thirty milliseconds, so the screen said the route was
/// healthy while nothing would load. Waiting for a byte to come back is the
/// cheapest measurement that moves when the experience does.
fn measure(socks: SocketAddr, host: &str) -> Option<f64> {
    let started = Instant::now();
    let mut stream = socks5_connect(socks, host, TARGET_PORT, PROBE_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(PROBE_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(PROBE_TIMEOUT)).ok()?;
    // HEAD, so the answer is a header and nothing is downloaded to time.
    let request = format!(
        "HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: WhiteAesther\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut first = [0u8; 1];
    // A closed connection with nothing on it is a failed probe, not a fast one.
    if stream.read(&mut first).ok()? == 0 {
        return None;
    }
    let elapsed = started.elapsed();
    drop(stream);
    Some(elapsed.as_secs_f64() * 1000.0)
}

/// How fast the tunnel actually carries bulk traffic.
const SPEED_HOST: &str = "speed.cloudflare.com";
const SPEED_BYTES: usize = 10_000_000;
/// Generous: a slow route still deserves a number rather than an error.
const SPEED_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpeedResult {
    /// Megabits per second, the unit connections are sold in.
    pub mbps: f64,
    pub bytes: usize,
    pub seconds: f64,
}

/// Downloads a fixed payload through the tunnel and reports the throughput.
///
/// Plain HTTP on purpose: this crate has no TLS client, and the endpoint serves
/// the same bytes either way. There is nothing secret in a stream of zeroes, and
/// the tunnel is carrying it regardless.
#[tauri::command]
pub async fn speed_test(supervisor: State<'_, CoreSupervisor>) -> Result<SpeedResult, String> {
    let socks = supervisor
        .connected_socks()
        .ok_or("connect first — there is no tunnel to measure")?;
    let address: SocketAddr = socks
        .parse()
        .map_err(|_| format!("the proxy address {socks} cannot be parsed"))?;

    tauri::async_runtime::spawn_blocking(move || download(address))
        .await
        .map_err(|error| format!("the speed test did not finish: {error}"))?
}

fn download(socks: SocketAddr) -> Result<SpeedResult, String> {
    let mut stream = socks5_connect(socks, SPEED_HOST, 80, SPEED_TIMEOUT)
        .map_err(|error| format!("the tunnel refused the connection: {error}"))?;
    stream
        .set_read_timeout(Some(SPEED_TIMEOUT))
        .map_err(|error| error.to_string())?;

    let request = format!(
        "GET /__down?bytes={SPEED_BYTES} HTTP/1.1\r\nHost: {SPEED_HOST}\r\n\
         User-Agent: WhiteAesther\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("could not send the request: {error}"))?;

    // Timed from the first byte, so the figure is transfer rate and not the
    // handshake that preceded it — the round-trip chart already covers that.
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_usize;
    let mut started: Option<Instant> = None;
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                started.get_or_insert_with(Instant::now);
                total += read;
            }
            Err(error) => return Err(format!("the transfer stopped early: {error}")),
        }
    }

    let elapsed = started.ok_or("the endpoint sent nothing back")?.elapsed();
    let seconds = elapsed.as_secs_f64().max(0.001);
    if total < SPEED_BYTES / 2 {
        return Err(format!(
            "only {total} of {SPEED_BYTES} bytes arrived before the connection closed"
        ));
    }
    Ok(SpeedResult {
        mbps: (total as f64 * 8.0) / seconds / 1_000_000.0,
        bytes: total,
        seconds,
    })
}

/// What the rest of the internet sees when this tunnel is up.
///
/// The screen has always shown the *edge* -- the Cloudflare gateway the tunnel
/// connects to -- which is not the same thing as the address a website reads,
/// and users reasonably read one as the other. This reports the address that
/// actually leaves.
const TRACE_HOST: &str = "www.cloudflare.com";
const TRACE_PATH: &str = "/cdn-cgi/trace";
const TRACE_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExitInfo {
    /// The address a website logs for this connection.
    pub ip: String,
    /// Two-letter country as Cloudflare geolocates that address.
    pub country: String,
    /// The datacentre the traffic left from, as a three-letter airport code.
    pub colo: String,
    /// Whether Cloudflare sees this connection as WARP at all.
    ///
    /// Only meaningful when `chained` is false. Through a second hop it is
    /// always off, because the last leg is the node's own connection and not a
    /// WARP one -- which is the point of the hop, not a fault.
    pub warp: bool,
    /// Whether an organisation's Zero Trust gateway is applying policy.
    pub gateway: bool,
    /// Whether this was read through the second hop rather than the tunnel.
    pub chained: bool,
}

/// Reads the exit address and country from wherever traffic actually leaves.
///
/// Follows the chain when there is one. Reading the tunnel regardless was the
/// bug this replaces: with a second hop carrying traffic, the card reported
/// Cloudflare's address while every application was leaving through the node --
/// the card contradicting the browser on the one question it exists to answer.
#[tauri::command]
pub async fn exit_info(
    supervisor: State<'_, CoreSupervisor>,
    chain: State<'_, Chain>,
) -> Result<ExitInfo, String> {
    let carrier = chain.address();
    let address: SocketAddr = match carrier {
        // mihomo's listener is a mixed one, so it answers SOCKS5 here exactly
        // as the tunnel does.
        Some(address) => address,
        None => {
            let socks = supervisor
                .connected_socks()
                .ok_or("connect first — there is nothing to look up")?;
            socks
                .parse()
                .map_err(|_| format!("the proxy address {socks} cannot be parsed"))?
        }
    };
    let chained = carrier.is_some();

    tauri::async_runtime::spawn_blocking(move || fetch_trace(address, chained))
        .await
        .map_err(|error| format!("the lookup did not finish: {error}"))?
}

fn fetch_trace(socks: SocketAddr, chained: bool) -> Result<ExitInfo, String> {
    // Plain HTTP on purpose: this crate has no TLS client, and the endpoint
    // answers over both. Nothing here is secret -- it is the address a website
    // would read anyway -- and it travels inside the tunnel regardless.
    let body = http_get(socks, TRACE_HOST, TRACE_PATH, TRACE_TIMEOUT)?;
    let field = |name: &str| {
        body.lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .map(str::trim)
            .map(str::to_string)
    };

    Ok(ExitInfo {
        ip: field("ip").ok_or("the reply carried no address")?,
        country: field("loc").unwrap_or_else(|| "??".into()),
        colo: field("colo").unwrap_or_default(),
        warp: field("warp").as_deref() == Some("on"),
        gateway: field("gateway").as_deref() == Some("on"),
        chained,
    })
}

/// A plain GET through the tunnel, returning the body.
fn http_get(socks: SocketAddr, host: &str, path: &str, timeout: Duration) -> Result<String, String> {
    let mut stream = socks5_connect(socks, host, 80, timeout)
        .map_err(|error| format!("the tunnel refused the connection: {error}"))?;
    stream.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    stream
        .write_all(
            format!(
                "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: WhiteAesther\r\n\
                 Connection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .map_err(|error| format!("could not send the request: {error}"))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|error| format!("the reply was cut short: {error}"))?;
    let text = String::from_utf8_lossy(&raw);
    // Headers and body are split by a blank line; only the body is wanted.
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .ok_or("the reply was not a complete HTTP response")?;
    Ok(body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trace_reply_is_read_into_its_fields() {
        // Verbatim shape of a cdn-cgi/trace body, which is line-oriented
        // key=value and not JSON.
        let body = "fl=129f135\nh=www.cloudflare.com\nip=104.28.51.7\nts=1787049464.000\n\
                    colo=FRA\nloc=DE\nwarp=on\ngateway=off\n";
        let field = |name: &str| {
            body.lines()
                .find_map(|line| line.strip_prefix(&format!("{name}=")))
                .map(str::trim)
                .map(str::to_string)
        };
        assert_eq!(field("ip").as_deref(), Some("104.28.51.7"));
        assert_eq!(field("loc").as_deref(), Some("DE"));
        assert_eq!(field("warp").as_deref(), Some("on"));
        // "gateway=off" must not be mistaken for the "gateway" prefix of
        // another key, and must read as false rather than missing.
        assert_eq!(field("gateway").as_deref(), Some("off"));
    }

    #[test]
    fn a_lookup_against_a_dead_listener_fails_rather_than_inventing_a_country() {
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(fetch_trace(dead, false).is_err());
    }

    #[test]
    fn a_download_from_a_dead_listener_fails_rather_than_reporting_zero() {
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(download(dead).is_err(), "a refused tunnel is not a 0 Mbps result");
    }

    #[test]
    fn a_probe_against_a_dead_listener_reports_nothing_rather_than_zero() {
        // Port 1 on loopback has nothing behind it, so the connect fails fast.
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert_eq!(measure(dead, TARGET_HOST), None, "a failed probe must not read as 0 ms");
    }
}
