//! A TLS connection through a carrier, to a host that has to prove who it is.
//!
//! Two rules live here rather than in each caller, because they are the same
//! two rules every time and getting either wrong is invisible on a healthy
//! network:
//!
//! - **The carrier resolves the name, not this machine.** The address is handed
//!   to SOCKS5 as a domain name (`socks5_connect` writes address type `0x03`),
//!   so the lookup happens at the far end. A lookup made here would name the
//!   host to the very network the carrier exists to get around, and on a
//!   network whose resolver answers with the censor's address it would send the
//!   connection to the block page.
//!
//! - **Whoever answers has to present a certificate for the name we asked
//!   for.** A reply is not proof of anything: an interception answers too, and
//!   an HTTP status arrives just as promptly from a block page as from the real
//!   host. A certificate chaining to a public root, for that exact name, is
//!   something only the real host can present.
//!
//! The roots are `webpki-roots` and deliberately not the platform store: a
//! pinned set that travels with the build cannot be widened by a root somebody
//! added to this machine.

use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::http_bridge::socks5_connect;

/// A TLS stream whose peer has been authenticated as `host`.
pub(crate) type VerifiedStream = StreamOwned<ClientConnection, TcpStream>;

/// Opens a verified TLS connection to `host`, through `carrier` when there is
/// one and directly when there is not.
///
/// The handshake itself is deferred by rustls until the first read or write, so
/// a caller that needs the peer proved has to exchange at least one byte. Every
/// caller here does, and that is deliberate: a handshake nobody completed
/// proves nothing, and the byte also shows the route carries application data
/// rather than merely completing a negotiation.
pub(crate) fn connect_verified(
    carrier: Option<SocketAddr>,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<VerifiedStream, String> {
    let tcp = match carrier {
        Some(address) => socks5_connect(address, host, port, timeout)
            .map_err(|error| format!("the carrier refused the connection: {error}"))?,
        None => {
            let stream = TcpStream::connect((host, port))
                .map_err(|error| format!("cannot reach {host}: {error}"))?;
            stream
        }
    };
    tcp.set_read_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    tcp.set_write_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;

    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Owned, because the connection outlives the borrow of `host`.
    let server = ServerName::try_from(host)
        .map_err(|error| format!("{host} is not a valid server name: {error}"))?
        .to_owned();
    let connection = ClientConnection::new(Arc::new(config), server)
        .map_err(|error| format!("cannot start TLS: {error}"))?;
    Ok(StreamOwned::new(connection, tcp))
}
