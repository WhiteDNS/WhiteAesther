//! Lets other devices on the same network use this machine's tunnel.
//!
//! The listeners the app already runs are on loopback, which is the right
//! default: a proxy reachable from the network is a proxy anyone on that
//! network can use. This opens a second door, deliberately, on request -- a
//! phone or a television that cannot run the app itself can be pointed at this
//! machine instead.
//!
//! One port speaks both HTTP and SOCKS5, because the devices people want to
//! share with are split between the two and asking which one a television wants
//! is not a question anybody can answer. The first byte says which it is:
//! SOCKS5 always opens with 0x05, and no HTTP method does.
//!
//! Whatever arrives is forwarded to whichever listener is currently carrying
//! traffic -- the second hop when one is running, the tunnel otherwise -- so a
//! device configured once keeps working when the chain is switched on or off.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::http_bridge::socks5_connect;

/// Long enough for a slow tunnel to answer, short enough that a wedged peer
/// does not hold a thread forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// A request line plus headers. Anything larger is not a proxy request.
const MAX_HEADER_BYTES: usize = 32 * 1024;

/// What the user asked for, kept in the profile so it survives a restart.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LanSettings {
    pub enabled: bool,
    /// The port other devices are pointed at.
    pub port: u16,
    /// Both empty means no sign-in, which is a real decision and not a default:
    /// see [`LanStatus::open`].
    pub username: String,
    pub password: String,
}

impl Default for LanSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            // 1080 is what a person expects a SOCKS proxy to be on, and this
            // port is typed into another device by hand.
            port: 1080,
            username: String::new(),
            password: String::new(),
        }
    }
}

impl LanSettings {
    /// The credentials to enforce, or `None` when the user chose to run open.
    ///
    /// A username without a password (or the reverse) is treated as no
    /// credentials rather than as a half-configured lock, because enforcing an
    /// empty password would be worse than not pretending to have one.
    pub fn credentials(&self) -> Option<(String, String)> {
        let user = self.username.trim();
        let password = self.password.trim();
        if user.is_empty() || password.is_empty() {
            return None;
        }
        Some((user.to_string(), password.to_string()))
    }
}

/// What the interface shows about the shared door.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LanStatus {
    pub running: bool,
    /// The address to type into the other device, e.g. `192.168.1.24:1080`.
    pub address: Option<String>,
    /// Running without credentials: anyone on this network can use the tunnel.
    pub open: bool,
}

impl LanStatus {
    pub fn stopped() -> Self {
        Self { running: false, address: None, open: false }
    }
}

/// The one door this process has open, if any.
///
/// Held as Tauri state so every path that changes what is carrying traffic can
/// point it at the new listener without threading a handle through them all.
#[derive(Default)]
pub struct LanDoor(Mutex<Option<LanShare>>);

impl LanDoor {
    pub fn status(&self) -> LanStatus {
        self.0
            .lock()
            .ok()
            .and_then(|held| held.as_ref().map(LanShare::status))
            .unwrap_or_else(LanStatus::stopped)
    }

    /// Opens the door, replacing any door already open.
    pub fn open(&self, carrier: SocketAddr, settings: &LanSettings) -> Result<LanStatus, String> {
        let share = start(carrier, settings).map_err(|error| match error.kind() {
            // The message a person can act on: the port is the one thing they
            // chose, and something else on the machine already has it.
            io::ErrorKind::AddrInUse => {
                format!("port {} is already in use; pick another", settings.port)
            }
            _ => format!("cannot share on port {}: {error}", settings.port),
        })?;
        let status = share.status();
        let mut held = self.0.lock().map_err(|_| "the sharing lock is poisoned")?;
        // The old door is dropped, and stopped, only once the new one is bound.
        *held = Some(share);
        Ok(status)
    }

    pub fn close(&self) {
        if let Ok(mut held) = self.0.lock() {
            held.take();
        }
    }

    /// Follows the listener that is now carrying traffic.
    pub fn retarget(&self, carrier: SocketAddr) {
        if let Ok(held) = self.0.lock() {
            if let Some(share) = held.as_ref() {
                share.retarget(carrier);
            }
        }
    }
}

pub struct LanShare {
    port: u16,
    stop: Arc<AtomicBool>,
    /// Where traffic is handed on. Held behind a lock rather than copied into
    /// each thread so switching the second hop on does not strand devices on
    /// the listener that was carrying traffic when they connected.
    carrier: Arc<Mutex<SocketAddr>>,
    open: bool,
}

impl LanShare {
    pub fn status(&self) -> LanStatus {
        LanStatus {
            running: true,
            address: Some(format!("{}:{}", local_address(), self.port)),
            open: self.open,
        }
    }

    /// Points the door at a different listener, in place.
    pub fn retarget(&self, carrier: SocketAddr) {
        if let Ok(mut held) = self.carrier.lock() {
            *held = carrier;
        }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        // Unblock the accept loop, which is parked in accept() rather than
        // polling a flag it cannot see.
        let _ = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, self.port)));
    }
}

impl Drop for LanShare {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Opens the door on every interface and forwards to `carrier`.
///
/// Binding `0.0.0.0` is the whole point and also the risk, so the caller is
/// expected to have told the user what it means. On Windows the first run
/// raises a firewall prompt; until it is accepted, the port is reachable from
/// this machine only.
pub fn start(
    carrier: SocketAddr,
    settings: &LanSettings,
) -> io::Result<LanShare> {
    let credentials = settings.credentials();
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, settings.port)))?;
    let port = listener.local_addr()?.port();
    let stop = Arc::new(AtomicBool::new(false));
    let carrier = Arc::new(Mutex::new(carrier));

    let accept_stop = stop.clone();
    let accept_carrier = carrier.clone();
    let accept_credentials = credentials.clone();
    thread::Builder::new()
        .name("whiteaesther-lan-share".into())
        .spawn(move || {
            for client in listener.incoming() {
                if accept_stop.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(client) = client else { continue };
                let carrier = accept_carrier.clone();
                let credentials = accept_credentials.clone();
                thread::spawn(move || {
                    let to = carrier.lock().map(|held| *held).ok();
                    if let Some(to) = to {
                        // A failed exchange closes that connection and nothing
                        // else.
                        let _ = serve(client, to, credentials.as_ref());
                    }
                });
            }
        })?;

    Ok(LanShare { port, stop, carrier, open: credentials.is_none() })
}

fn serve(mut client: TcpStream, carrier: SocketAddr, auth: Option<&(String, String)>) -> io::Result<()> {
    client.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;

    let mut first = [0_u8; 1];
    if client.read(&mut first)? == 0 {
        return Ok(());
    }
    if first[0] == 0x05 {
        return serve_socks5(client, carrier, auth);
    }
    serve_http(client, carrier, auth, first[0])
}

// ---------------------------------------------------------------------------
// SOCKS5
// ---------------------------------------------------------------------------

const SOCKS_NO_AUTH: u8 = 0x00;
const SOCKS_USER_PASS: u8 = 0x02;
const SOCKS_NO_ACCEPTABLE: u8 = 0xFF;

fn serve_socks5(
    mut client: TcpStream,
    carrier: SocketAddr,
    auth: Option<&(String, String)>,
) -> io::Result<()> {
    // The version byte has already been read.
    let mut count = [0_u8; 1];
    client.read_exact(&mut count)?;
    let mut methods = vec![0_u8; count[0] as usize];
    client.read_exact(&mut methods)?;

    let wanted = if auth.is_some() { SOCKS_USER_PASS } else { SOCKS_NO_AUTH };
    if !methods.contains(&wanted) {
        // Refused rather than downgraded: a client that will not sign in does
        // not get in because it asked nicely.
        client.write_all(&[0x05, SOCKS_NO_ACCEPTABLE])?;
        return Ok(());
    }
    client.write_all(&[0x05, wanted])?;

    if let Some((user, password)) = auth {
        if !socks5_sign_in(&mut client, user, password)? {
            return Ok(());
        }
    }

    let mut head = [0_u8; 4];
    client.read_exact(&mut head)?;
    if head[1] != 0x01 {
        // CONNECT only. BIND and UDP ASSOCIATE would need the carrier to offer
        // them too, and saying so is better than half-supporting them.
        return socks5_reply(&mut client, 0x07);
    }
    let host = match head[3] {
        0x01 => {
            let mut raw = [0_u8; 4];
            client.read_exact(&mut raw)?;
            Ipv4Addr::from(raw).to_string()
        }
        0x03 => {
            let mut length = [0_u8; 1];
            client.read_exact(&mut length)?;
            let mut name = vec![0_u8; length[0] as usize];
            client.read_exact(&mut name)?;
            String::from_utf8_lossy(&name).into_owned()
        }
        0x04 => {
            let mut raw = [0_u8; 16];
            client.read_exact(&mut raw)?;
            std::net::Ipv6Addr::from(raw).to_string()
        }
        _ => return socks5_reply(&mut client, 0x08),
    };
    let mut port = [0_u8; 2];
    client.read_exact(&mut port)?;
    let port = u16::from_be_bytes(port);

    let upstream = match socks5_connect(carrier, &host, port, HANDSHAKE_TIMEOUT) {
        Ok(upstream) => upstream,
        Err(_) => return socks5_reply(&mut client, 0x05),
    };
    socks5_reply(&mut client, 0x00)?;
    client.set_read_timeout(None)?;
    splice(client, upstream);
    Ok(())
}

/// RFC 1929. Returns whether the client got in.
fn socks5_sign_in(client: &mut TcpStream, user: &str, password: &str) -> io::Result<bool> {
    let mut version = [0_u8; 1];
    client.read_exact(&mut version)?;
    if version[0] != 0x01 {
        client.write_all(&[0x01, 0x01])?;
        return Ok(false);
    }
    let mut length = [0_u8; 1];
    client.read_exact(&mut length)?;
    let mut offered_user = vec![0_u8; length[0] as usize];
    client.read_exact(&mut offered_user)?;
    client.read_exact(&mut length)?;
    let mut offered_password = vec![0_u8; length[0] as usize];
    client.read_exact(&mut offered_password)?;

    let ok = offered_user == user.as_bytes() && offered_password == password.as_bytes();
    client.write_all(&[0x01, if ok { 0x00 } else { 0x01 }])?;
    Ok(ok)
}

fn socks5_reply(client: &mut TcpStream, code: u8) -> io::Result<()> {
    client.write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

fn serve_http(
    mut client: TcpStream,
    carrier: SocketAddr,
    auth: Option<&(String, String)>,
    first: u8,
) -> io::Result<()> {
    let mut reader = BufReader::new(client.try_clone()?);
    let mut request_line = String::from(first as char);
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let mut parts = request_line.split_whitespace();
    let (method, target) = match (parts.next(), parts.next()) {
        (Some(method), Some(target)) => (method.to_string(), target.to_string()),
        _ => return respond(&mut client, 400, "Bad Request"),
    };

    let mut headers = Vec::new();
    let mut total = request_line.len();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        total += line.len();
        if total > MAX_HEADER_BYTES {
            return respond(&mut client, 431, "Request Header Fields Too Large");
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        headers.push(line);
    }

    if let Some((user, password)) = auth {
        if !http_signed_in(&headers, user, password) {
            return respond_unauthorized(&mut client);
        }
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let Some((host, port)) = split_authority(&target, 443) else {
            return respond(&mut client, 400, "Bad Request");
        };
        let upstream = match socks5_connect(carrier, &host, port, HANDSHAKE_TIMEOUT) {
            Ok(upstream) => upstream,
            Err(_) => return respond(&mut client, 502, "Bad Gateway"),
        };
        client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
        client.set_read_timeout(None)?;
        splice(client, upstream);
        return Ok(());
    }

    let Some((host, port, path)) = split_absolute_uri(&target) else {
        return respond(&mut client, 400, "Bad Request");
    };
    let mut upstream = match socks5_connect(carrier, &host, port, HANDSHAKE_TIMEOUT) {
        Ok(upstream) => upstream,
        Err(_) => return respond(&mut client, 502, "Bad Gateway"),
    };

    let mut head = format!("{method} {path} HTTP/1.1\r\n");
    for header in &headers {
        // Hop-by-hop: meaningful to this proxy, not to the origin server. The
        // credentials especially must not travel on to the destination.
        let lowered = header.to_ascii_lowercase();
        if lowered.starts_with("proxy-connection:") || lowered.starts_with("proxy-authorization:") {
            continue;
        }
        head.push_str(header);
    }
    head.push_str("\r\n");
    upstream.write_all(head.as_bytes())?;

    let buffered = reader.buffer().to_vec();
    if !buffered.is_empty() {
        upstream.write_all(&buffered)?;
    }
    client.set_read_timeout(None)?;
    splice(client, upstream);
    Ok(())
}

/// Whether a `Proxy-Authorization: Basic` header carries these credentials.
fn http_signed_in(headers: &[String], user: &str, password: &str) -> bool {
    let expected = base64(format!("{user}:{password}").as_bytes());
    headers.iter().any(|header| {
        let Some((name, value)) = header.split_once(':') else {
            return false;
        };
        if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
            return false;
        }
        let value = value.trim();
        let Some(offered) = value
            .strip_prefix("Basic ")
            .or_else(|| value.strip_prefix("basic "))
        else {
            return false;
        };
        offered.trim() == expected
    })
}

fn respond(client: &mut TcpStream, code: u16, reason: &str) -> io::Result<()> {
    write!(client, "HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

fn respond_unauthorized(client: &mut TcpStream) -> io::Result<()> {
    write!(
        client,
        "HTTP/1.1 407 Proxy Authentication Required\r\n\
         Proxy-Authenticate: Basic realm=\"WhiteAesther\"\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n"
    )
}

/// Standard base64, no padding shortcuts. Small enough not to be worth a
/// dependency, and only ever fed a username and password.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let bits = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(ALPHABET[((bits >> (18 - index * 6)) & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// `host:port`, with IPv6 in brackets.
fn split_authority(target: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(port) => port.parse().ok()?,
            None => default_port,
        };
        return Some((host.to_string(), port));
    }
    match target.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Some((host.to_string(), port.parse().ok()?)),
        _ => Some((target.to_string(), default_port)),
    }
}

/// `http://host[:port]/path` into its parts, with the path in origin form.
fn split_absolute_uri(target: &str) -> Option<(String, u16, String)> {
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("HTTP://"))?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = split_authority(authority, 80)?;
    Some((host, port, path.to_string()))
}

/// Copies in both directions until either side closes.
fn splice(client: TcpStream, upstream: TcpStream) {
    let Ok(client_reader) = client.try_clone() else { return };
    let Ok(upstream_reader) = upstream.try_clone() else { return };

    let outbound = thread::spawn(move || {
        let mut from = client_reader;
        let mut to = upstream;
        let _ = io::copy(&mut from, &mut to);
        let _ = to.shutdown(std::net::Shutdown::Write);
    });

    let mut from = upstream_reader;
    let mut to = client;
    let _ = io::copy(&mut from, &mut to);
    let _ = to.shutdown(std::net::Shutdown::Write);
    let _ = outbound.join();
}

/// This machine's address on the local network.
///
/// Found by asking the routing table which source address it would use to reach
/// the internet, which is the one another device on the same network can reach.
/// Nothing is sent: a UDP socket that has only been connected has not spoken.
fn local_address() -> IpAddr {
    UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .and_then(|socket| {
            socket.connect((Ipv4Addr::new(1, 1, 1, 1), 80))?;
            socket.local_addr()
        })
        .map(|address| address.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn half_filled_credentials_do_not_pretend_to_be_a_lock() {
        // A username with no password is someone who started typing and stopped.
        // Enforcing it would accept an empty password as valid.
        let mut settings = LanSettings { enabled: true, port: 1080, ..LanSettings::default() };
        settings.username = "alex".into();
        assert!(settings.credentials().is_none());
        settings.password = "  ".into();
        assert!(settings.credentials().is_none());
        settings.password = "hunter2".into();
        assert_eq!(settings.credentials(), Some(("alex".into(), "hunter2".into())));
    }

    #[test]
    fn base64_matches_the_header_browsers_send() {
        // The values in RFC 7617 and the classic example, because a wrong
        // encoder would reject every correct password instead of failing loudly.
        assert_eq!(base64(b"Aladdin:open sesame"), "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        assert_eq!(base64(b"a"), "YQ==");
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(base64(b"abc"), "YWJj");
        assert_eq!(base64(b""), "");
    }

    #[test]
    fn the_right_credentials_get_in_and_nothing_else_does() {
        let header = |value: &str| vec![format!("Proxy-Authorization: {value}\r\n")];
        let ok = format!("Basic {}", base64(b"alex:hunter2"));
        assert!(http_signed_in(&header(&ok), "alex", "hunter2"));
        // Right user, wrong password.
        assert!(!http_signed_in(&header(&format!("Basic {}", base64(b"alex:wrong"))), "alex", "hunter2"));
        // No header at all, which is what the first request from a browser is.
        assert!(!http_signed_in(&[], "alex", "hunter2"));
        // A scheme we do not implement must not be waved through.
        assert!(!http_signed_in(&header("Bearer somethingelse"), "alex", "hunter2"));
    }

    #[test]
    fn the_door_binds_on_every_interface_not_just_loopback() {
        // The entire point of the feature. Binding loopback would look like it
        // worked from this machine and be unreachable from the phone.
        let carrier = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
        let settings = LanSettings { enabled: true, port: 0, ..LanSettings::default() };
        let share = start(carrier, &settings).expect("the door should open");
        let status = share.status();
        assert!(status.running);
        assert!(status.open, "no credentials were set, so it is open");
        share.stop();
    }

    /// A stand-in for whatever is carrying traffic: speaks just enough SOCKS5
    /// to accept one CONNECT, then echoes. Returns its address and a handle
    /// that yields the bytes it was asked to send onward.
    fn stub_carrier() -> (SocketAddr, std::sync::mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let tx = tx.clone();
                thread::spawn(move || {
                    let mut greeting = [0_u8; 2];
                    if stream.read_exact(&mut greeting).is_err() {
                        return;
                    }
                    let mut methods = vec![0_u8; greeting[1] as usize];
                    let _ = stream.read_exact(&mut methods);
                    let _ = stream.write_all(&[0x05, 0x00]);

                    let mut head = [0_u8; 4];
                    if stream.read_exact(&mut head).is_err() {
                        return;
                    }
                    match head[3] {
                        0x01 => {
                            let mut raw = [0_u8; 4];
                            let _ = stream.read_exact(&mut raw);
                        }
                        0x03 => {
                            let mut length = [0_u8; 1];
                            let _ = stream.read_exact(&mut length);
                            let mut name = vec![0_u8; length[0] as usize];
                            let _ = stream.read_exact(&mut name);
                        }
                        _ => {
                            let mut raw = [0_u8; 16];
                            let _ = stream.read_exact(&mut raw);
                        }
                    }
                    let mut port = [0_u8; 2];
                    let _ = stream.read_exact(&mut port);
                    let _ = stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

                    let mut buffer = [0_u8; 1024];
                    while let Ok(read) = stream.read(&mut buffer) {
                        if read == 0 {
                            break;
                        }
                        let _ = tx.send(buffer[..read].to_vec());
                        let _ = stream.write_all(&buffer[..read]);
                    }
                });
            }
        });
        (address, rx)
    }

    fn open_door(credentials: bool) -> (LanShare, std::sync::mpsc::Receiver<Vec<u8>>) {
        let (carrier, rx) = stub_carrier();
        let settings = LanSettings {
            enabled: true,
            port: 0,
            username: if credentials { "alex".into() } else { String::new() },
            password: if credentials { "hunter2".into() } else { String::new() },
        };
        (start(carrier, &settings).expect("the door should open"), rx)
    }

    #[test]
    fn a_signed_in_socks_client_reaches_the_carrier() {
        let (share, _rx) = open_door(true);
        let mut client =
            TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, share.port))).unwrap();
        client.write_all(&[0x05, 0x01, SOCKS_USER_PASS]).unwrap();
        let mut reply = [0_u8; 2];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [0x05, SOCKS_USER_PASS]);

        // RFC 1929: version, username, password.
        client.write_all(&[0x01, 4]).unwrap();
        client.write_all(b"alex").unwrap();
        client.write_all(&[7]).unwrap();
        client.write_all(b"hunter2").unwrap();
        let mut auth = [0_u8; 2];
        client.read_exact(&mut auth).unwrap();
        assert_eq!(auth, [0x01, 0x00], "the right password must be accepted");

        // CONNECT example.com:80, as a domain so the name is resolved beyond
        // the tunnel rather than here.
        client.write_all(&[0x05, 0x01, 0x00, 0x03, 11]).unwrap();
        client.write_all(b"example.com").unwrap();
        client.write_all(&80_u16.to_be_bytes()).unwrap();
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).unwrap();
        assert_eq!(response[1], 0x00, "the carrier accepted, so the client must be told so");

        client.write_all(b"hello").unwrap();
        let mut echoed = [0_u8; 5];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"hello", "bytes must travel both ways");
        share.stop();
    }

    #[test]
    fn a_wrong_password_does_not_get_through() {
        let (share, _rx) = open_door(true);
        let mut client =
            TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, share.port))).unwrap();
        client.write_all(&[0x05, 0x01, SOCKS_USER_PASS]).unwrap();
        let mut reply = [0_u8; 2];
        client.read_exact(&mut reply).unwrap();
        client.write_all(&[0x01, 4]).unwrap();
        client.write_all(b"alex").unwrap();
        client.write_all(&[5]).unwrap();
        client.write_all(b"wrong").unwrap();
        let mut auth = [0_u8; 2];
        client.read_exact(&mut auth).unwrap();
        assert_eq!(auth, [0x01, 0x01], "refused");
        // And the connection is over: no second guess at the password.
        let mut anything = [0_u8; 1];
        assert_eq!(client.read(&mut anything).unwrap_or(0), 0);
        share.stop();
    }

    #[test]
    fn an_http_request_arrives_at_the_carrier_in_origin_form() {
        // The first byte of the request line is read before the protocol is
        // known, so it has to be put back before the line is parsed. Getting
        // that wrong turns every GET into "ET".
        let (share, rx) = open_door(false);
        let mut client =
            TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, share.port))).unwrap();
        client
            .write_all(b"GET http://example.com/a?b=c HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        let forwarded = rx.recv_timeout(Duration::from_secs(5)).expect("the carrier should be dialled");
        let text = String::from_utf8_lossy(&forwarded);
        assert!(text.starts_with("GET /a?b=c HTTP/1.1\r\n"), "got: {text}");
        assert!(text.contains("Host: example.com"), "got: {text}");
        share.stop();
    }

    #[test]
    fn an_http_connect_tunnel_carries_bytes_once_established() {
        let (share, _rx) = open_door(true);
        let mut client =
            TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, share.port))).unwrap();
        let credentials = base64(b"alex:hunter2");
        write!(
            client,
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {credentials}\r\n\r\n"
        )
        .unwrap();
        let mut header = [0_u8; 39];
        client.read_exact(&mut header).unwrap();
        assert!(
            String::from_utf8_lossy(&header).starts_with("HTTP/1.1 200"),
            "got: {}",
            String::from_utf8_lossy(&header)
        );
        client.write_all(b"hello").unwrap();
        let mut echoed = [0_u8; 5];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"hello");
        share.stop();
    }

    #[test]
    fn a_socks_client_that_will_not_sign_in_is_refused() {
        let carrier = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
        let settings = LanSettings {
            enabled: true,
            port: 0,
            username: "alex".into(),
            password: "hunter2".into(),
        };
        let share = start(carrier, &settings).expect("the door should open");
        assert!(!share.status().open, "credentials were set");

        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, share.port));
        let mut client = TcpStream::connect(address).expect("should accept");
        // "SOCKS5, and the only method I know is no authentication."
        client.write_all(&[0x05, 0x01, SOCKS_NO_AUTH]).unwrap();
        let mut reply = [0_u8; 2];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [0x05, SOCKS_NO_ACCEPTABLE]);
        share.stop();
    }

    #[test]
    fn an_http_client_without_credentials_is_told_to_authenticate() {
        let carrier = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
        let settings = LanSettings {
            enabled: true,
            port: 0,
            username: "alex".into(),
            password: "hunter2".into(),
        };
        let share = start(carrier, &settings).expect("the door should open");
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, share.port));
        let mut client = TcpStream::connect(address).expect("should accept");
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 407"), "got: {response}");
        assert!(response.contains("Proxy-Authenticate: Basic"), "got: {response}");
        share.stop();
    }
}

#[cfg(test)]
mod live_door {
    use super::*;

    /// Opens a real LAN door against a real carrier and holds it, so the whole
    /// path can be exercised from another machine (or another shell) with an
    /// ordinary client. The unit tests above prove the protocol handling
    /// against a stub; this is what proves the socket is reachable from off
    /// this host at all. Not part of the suite.
    #[test]
    #[ignore = "opens a port on every interface and holds it"]
    fn hold_a_live_door() {
        let carrier: SocketAddr = std::env::var("WHITEAESTHER_LAN_CARRIER")
            .expect("set WHITEAESTHER_LAN_CARRIER to a live SOCKS5 address")
            .parse()
            .expect("carrier must be host:port");
        let port: u16 = std::env::var("WHITEAESTHER_LAN_PORT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1080);
        let settings = LanSettings {
            enabled: true,
            port,
            username: std::env::var("WHITEAESTHER_LAN_USER").unwrap_or_default(),
            password: std::env::var("WHITEAESTHER_LAN_PASS").unwrap_or_default(),
        };
        let share = start(carrier, &settings).expect("the door should open");
        let status = share.status();
        println!(
            "door open at {} (sign-in required: {})",
            status.address.unwrap_or_default(),
            !status.open
        );
        std::thread::sleep(Duration::from_secs(
            std::env::var("WHITEAESTHER_LAN_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
        ));
        share.stop();
    }
}
