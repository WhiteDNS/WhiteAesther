//! Registers the second device MASQUE-in-MASQUE needs, while the network still
//! works.
//!
//! `--mim` nests two MASQUE hops, and each hop is its own Cloudflare device. The
//! engine will provision the second one on demand -- `load_or_provision_masque`
//! against a sibling of the identity path -- so nothing is broken as such.
//!
//! The problem is *when* it does it. MASQUE-in-MASQUE exists for a network that
//! has learnt to recognise a single MASQUE hop and blocks it. On that network,
//! registering a device fails too: it is a request to Cloudflare's API from a
//! machine whose whole difficulty is that it cannot reach Cloudflare. So the
//! lane that exists for the hardest case is the lane guaranteed to lose there,
//! and it loses for a reason that has nothing to do with whether nested MASQUE
//! would have worked.
//!
//! The fix is to stop asking at the worst possible moment. Once a route is up
//! and carrying traffic, the network has just proved it can reach the outside;
//! that is when the second device is registered, once, in the background. It
//! then sits on disk waiting for the day it is needed.
//!
//! Every failure here is silent and simply tried again after the next
//! successful connect. This is preparation, not a feature anyone asked for, and
//! a person whose connection is working must never be shown an error about a
//! protocol they have not chosen.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use tauri::{AppHandle, Manager};

use crate::core_supervisor::{engine_command, resolve_core_path, CoreProfile, CoreSupervisor};

/// Long enough for a registration on a slow link, short enough that a failed
/// one is not a process sitting around for minutes. The run is killed the
/// instant the file appears, so this only bounds the failing case.
const WINDOW: Duration = Duration::from_secs(60);

/// How often to look for the file the engine writes when it has registered.
const POLL: Duration = Duration::from_millis(500);

/// One attempt per run of the app. The file on disk is the real guard -- this
/// only stops a second attempt while the first is still going, and stops a
/// network that cannot register being asked again every time a log line lands.
static ATTEMPTED: AtomicBool = AtomicBool::new(false);

/// Where the engine keeps the second MASQUE identity.
///
/// Derived the way the engine derives it: a sibling of the MASQUE identity
/// named `-secondary`. Spelled out here rather than guessed at, because being
/// wrong means registering a device on every single connect and never noticing.
fn secondary_path(config_dir: &std::path::Path) -> PathBuf {
    config_dir
        .join("identity")
        .join("aether-masque-secondary.toml")
}

/// Registers the second device if it is missing, in the background.
///
/// Called when a route has just proved it carries traffic. Returns at once;
/// everything happens on a thread of its own.
pub fn arm_in_background(app: &AppHandle, profile: &CoreProfile) {
    // Cheap checks first, on the caller's thread, because this is called from
    // the log path and most calls have nothing to do.
    if ATTEMPTED.load(Ordering::SeqCst) {
        return;
    }
    let Ok(config_dir) = app.path().app_config_dir() else {
        return;
    };
    if secondary_path(&config_dir).exists() {
        return;
    }
    if ATTEMPTED.swap(true, Ordering::SeqCst) {
        return;
    }

    let app = app.clone();
    let profile = profile.clone();
    thread::spawn(move || arm(&app, &profile, &config_dir));
}

fn arm(app: &AppHandle, profile: &CoreProfile, config_dir: &std::path::Path) {
    let supervisor = app.state::<CoreSupervisor>();
    let wanted = secondary_path(config_dir);

    // A whole nested tunnel is started to get one registration, because the
    // engine offers no way to ask for only that: `--mim` provisions the second
    // identity and then goes on to build with it. The run is killed the moment
    // the file lands, so what actually happens is a registration and a few
    // seconds of a tunnel nobody uses.
    let mut trial = profile.clone();
    trial.protocol = "mim".into();
    trial.auto_reconnect = false;
    // Its own listener. The session that triggered this is using the real one.
    let Ok(port) = free_port() else { return };
    trial.socks_address = format!("127.0.0.1:{port}");

    let Ok(core_path) = resolve_core_path(app, profile.core_path.as_deref()) else {
        return;
    };
    let Ok(mut command) = engine_command(app, &trial, &core_path) else {
        return;
    };
    let Ok(mut child) = command.spawn() else { return };

    let deadline = Instant::now() + WINDOW;
    let mut registered = false;
    while Instant::now() < deadline {
        if wanted.exists() {
            registered = true;
            break;
        }
        // A run that died has nothing left to wait for.
        if !matches!(child.try_wait(), Ok(None)) {
            break;
        }
        thread::sleep(POLL);
    }
    let _ = child.kill();
    let _ = child.wait();

    if registered {
        supervisor.log(
            "info",
            "registered the second device MASQUE-in-MASQUE needs, so it is ready on a network \
             that blocks a single hop"
                .into(),
        );
    } else {
        // Warn rather than error, and never surfaced as a failed action: the
        // connection the person is using is fine, and this is preparation for
        // one they have not asked for yet. Tried again after the next connect.
        supervisor.log(
            "warn",
            "could not register the second device MASQUE-in-MASQUE would need; it will be tried \
             again after a later connection"
                .into(),
        );
    }
}

fn free_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| error.to_string())?;
    let port = listener
        .local_addr()
        .map_err(|error| error.to_string())?
        .port();
    drop(listener);
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_second_identity_is_looked_for_where_the_engine_writes_it() {
        // Observed on disk after a `--mim` run: the engine derives this name
        // from the MASQUE identity path rather than the base one. Getting it
        // wrong means the file is never found, so a device is registered on
        // every connect for the life of the install and nobody notices.
        let path = secondary_path(std::path::Path::new("/config"));
        assert!(path.ends_with("identity/aether-masque-secondary.toml"), "{path:?}");
    }

    #[test]
    fn it_is_a_sibling_of_the_identity_the_engine_already_keeps() {
        let primary = std::path::Path::new("/config").join("identity").join("aether-masque.toml");
        let secondary = secondary_path(std::path::Path::new("/config"));
        assert_eq!(primary.parent(), secondary.parent());
    }
}
