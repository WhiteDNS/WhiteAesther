//! Asking Tor's circumvention service which bridges work in a given country.
//!
//! The one-tap fetch, and the only thing in this crate that speaks TLS.
//!
//! Two properties decide the whole design, and both are the reason this is not
//! simply a `fetch()` in the window:
//!
//! - **It has to go through whichever carrier is up.**
//!   `bridges.torproject.org` is blocked in most of the places its answer is
//!   wanted, so asking directly returns nothing and reads as the service being
//!   down. The webview cannot be pointed at a loopback SOCKS listener per
//!   request; this can.
//! - **It asks about the *user's* country, not the exit's.** There is no SIM to
//!   read one from on a desktop, so the caller passes what the person chose.
//!   Guessing from the current exit address would ask about whichever country
//!   the carrier happens to be leaving from, which is the one place the answer
//!   does not apply.

use std::{
    io::{Read, Write},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::http_bridge::socks5_connect;

const HOST: &str = "bridges.torproject.org";
const PATH: &str = "/moat/circumvention/settings";
const TIMEOUT: Duration = Duration::from_secs(45);

/// Bridge lines for `country`, fetched through `carrier` when one is up.
pub fn fetch_bridges(country: &str, carrier: Option<SocketAddr>) -> Result<Vec<String>, String> {
    let country = country.trim().to_ascii_lowercase();
    if country.len() != 2 || !country.chars().all(|c| c.is_ascii_lowercase()) {
        return Err("choose the country you are connecting from".into());
    }

    // Plain `{"country": "xx"}`, not the JSON-API envelope the older `/moat`
    // endpoints take. Measured: sending the envelope to this endpoint gets a
    // 200 with `{"settings":[],"country":"th"}` -- the country silently ignored
    // and filled in from the source address instead, which is the one thing
    // this request exists to override. An empty answer that looks like "no
    // bridges needed here" is exactly how that mistake hides.
    let body = serde_json::json!({ "country": country }).to_string();

    let response = post(&body, carrier)?;
    let parsed: serde_json::Value = serde_json::from_str(&response)
        .map_err(|error| format!("the bridge service sent something unreadable: {error}"))?;
    let lines = bridge_lines(&parsed);

    if lines.is_empty() {
        // A country the service has no answer for is not a failed request, and
        // reporting it as one sends someone to check their network instead of
        // trying another way in.
        return Err(format!(
            "Tor's bridge service had nothing for {}. Try the built-in bridges, or ask someone \
             to send you a bridge line.",
            country.to_uppercase()
        ));
    }
    Ok(lines)
}

/// Pulls every bridge line out of a moat reply.
///
/// Split out so it can be tested against a recorded answer: the shape is
/// `settings[].bridges.{type,bridge_strings[]}`, and a change to it would
/// otherwise only show up as an empty list in front of someone who needs one.
fn bridge_lines(parsed: &serde_json::Value) -> Vec<String> {
    let mut lines = Vec::new();
    let Some(settings) = parsed.get("settings").and_then(|value| value.as_array()) else {
        return lines;
    };
    for setting in settings {
        let Some(bridges) = setting.get("bridges") else {
            continue;
        };
        let transport = bridges
            .get("type")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let Some(list) = bridges.get("bridge_strings").and_then(|v| v.as_array()) else {
            continue;
        };
        for line in list.iter().filter_map(|value| value.as_str()) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Some transports answer with the type already on the line and some
            // do not. tor needs it exactly once: missing, the line is refused;
            // doubled, so is the whole file.
            if transport.is_empty() || line.split_whitespace().next() == Some(transport) {
                lines.push(line.to_string());
            } else {
                lines.push(format!("{transport} {line}"));
            }
        }
    }
    lines
}

/// One HTTPS POST, over a carrier's SOCKS listener when there is one.
fn post(body: &str, carrier: Option<SocketAddr>) -> Result<String, String> {
    let tcp = match carrier {
        // Domain-name addressing, so the name is resolved at the far end of the
        // carrier rather than here -- a lookup made locally would name the host
        // to the network this is trying to get around.
        Some(address) => socks5_connect(address, HOST, 443, TIMEOUT)
            .map_err(|error| format!("the carrier refused the connection: {error}"))?,
        None => {
            let stream = std::net::TcpStream::connect((HOST, 443))
                .map_err(|error| format!("cannot reach {HOST}: {error}"))?;
            stream
                .set_read_timeout(Some(TIMEOUT))
                .map_err(|error| error.to_string())?;
            stream
        }
    };
    tcp.set_read_timeout(Some(TIMEOUT))
        .map_err(|error| error.to_string())?;

    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = ServerName::try_from(HOST)
        .map_err(|error| format!("{HOST} is not a valid server name: {error}"))?;
    let connection = ClientConnection::new(Arc::new(config), server)
        .map_err(|error| format!("cannot start TLS: {error}"))?;
    let mut tls = StreamOwned::new(connection, tcp);

    let request = format!(
        "POST {PATH} HTTP/1.1\r\n\
         Host: {HOST}\r\n\
         User-Agent: WhiteAesther\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(request.as_bytes())
        .map_err(|error| format!("could not ask the bridge service: {error}"))?;

    let mut raw = Vec::new();
    // A clean close from the far side arrives as an error in some TLS stacks;
    // what matters is whether anything was read, so a short read with bytes in
    // hand is treated as the end of the reply rather than as a failure.
    if let Err(error) = tls.read_to_end(&mut raw) {
        if raw.is_empty() {
            return Err(format!("the bridge service did not answer: {error}"));
        }
    }

    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or("the bridge service sent an incomplete reply")?;
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        let status = head.lines().next().unwrap_or("(no status)");
        return Err(format!("the bridge service refused the request: {status}"));
    }
    Ok(decode_body(head, body))
}

/// Undoes chunked transfer encoding when the server used it.
///
/// `Connection: close` usually gets an unchunked reply, but the header is a
/// request and not a guarantee -- and a chunked body read as-is has hex length
/// markers scattered through it, which fails to parse as JSON in a way that
/// looks like the service returning nonsense.
fn decode_body(head: &str, body: &str) -> String {
    if !head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        return body.to_string();
    }
    let mut out = String::new();
    let mut rest = body;
    loop {
        let Some((size, remainder)) = rest.split_once("\r\n") else {
            break;
        };
        let Ok(length) = usize::from_str_radix(size.trim().split(';').next().unwrap_or("").trim(), 16)
        else {
            break;
        };
        if length == 0 || remainder.len() < length {
            break;
        }
        out.push_str(&remainder[..length]);
        rest = remainder[length..].trim_start_matches("\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_country_is_two_letters_or_the_request_is_refused() {
        for bad in ["", "irr", "1r", "I"] {
            assert!(fetch_bridges(bad, None).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn bridge_lines_are_pulled_out_of_a_moat_reply() {
        // The shape the service answers with, recorded rather than imagined.
        let reply = serde_json::json!({
            "settings": [
                { "bridges": { "type": "obfs4", "bridge_strings": [
                    "obfs4 1.2.3.4:443 FINGERPRINT cert=abc iat-mode=0"
                ] } },
                { "bridges": { "type": "webtunnel", "bridge_strings": [
                    "webtunnel 5.6.7.8:443 FINGERPRINT url=https://example.com/x"
                ] } }
            ]
        });
        let lines = bridge_lines(&reply);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].starts_with("obfs4 1.2.3.4"), "{lines:?}");
        assert!(lines[1].starts_with("webtunnel 5.6.7.8"), "{lines:?}");
    }

    #[test]
    fn a_transport_missing_from_the_line_is_put_back_exactly_once() {
        // tor needs the keyword once. Missing, the line is refused; doubled, so
        // is the whole torrc -- and the error names a line the user never
        // typed, because we wrote it.
        let reply = serde_json::json!({
            "settings": [
                { "bridges": { "type": "obfs4", "bridge_strings": ["1.2.3.4:443 FINGERPRINT cert=abc"] } }
            ]
        });
        let lines = bridge_lines(&reply);
        assert_eq!(lines, vec!["obfs4 1.2.3.4:443 FINGERPRINT cert=abc"]);

        let already = serde_json::json!({
            "settings": [
                { "bridges": { "type": "obfs4", "bridge_strings": ["obfs4 1.2.3.4:443 FINGERPRINT"] } }
            ]
        });
        assert_eq!(bridge_lines(&already), vec!["obfs4 1.2.3.4:443 FINGERPRINT"]);
    }

    #[test]
    fn an_answer_with_no_bridges_in_it_yields_nothing_rather_than_rubbish() {
        for empty in [
            serde_json::json!({}),
            serde_json::json!({ "settings": [] }),
            serde_json::json!({ "settings": [{ "bridges": { "type": "obfs4" } }] }),
            serde_json::json!({ "errors": [{ "detail": "no settings" }] }),
        ] {
            assert!(bridge_lines(&empty).is_empty(), "{empty}");
        }
    }

    #[test]
    fn a_chunked_body_is_reassembled() {
        // Connection: close usually avoids this, but the header is a request
        // and not a guarantee. Read as-is, the hex markers sit inside the JSON
        // and it fails to parse in a way that looks like the service being
        // broken.
        let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked";
        let body = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(decode_body(head, body), "hello world");
    }

    #[test]
    fn an_unchunked_body_is_left_alone() {
        let head = "HTTP/1.1 200 OK\r\nContent-Length: 11";
        assert_eq!(decode_body(head, "hello world"), "hello world");
    }
}

#[cfg(test)]
mod live {
    //! Ignored by default: it reaches the real service over the network.
    //! `cargo test --lib moat::live -- --ignored --nocapture`
    use super::*;

    #[test]
    #[ignore = "reaches bridges.torproject.org"]
    fn iran_gets_a_real_answer() {
        let lines = fetch_bridges("ir", None).expect("moat should answer for ir");
        println!("{} lines", lines.len());
        for line in &lines {
            println!("  {line}");
        }
        assert!(!lines.is_empty());
    }
}
