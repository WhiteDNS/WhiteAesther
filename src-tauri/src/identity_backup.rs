//! Saving this install's identity to a file, and restoring one.
//!
//! Cloudflare limits how many devices one network can register. Uninstalling
//! throws the registration away, and after a few reinstalls the network can be
//! refused another -- which looks exactly like the app being broken. A backup
//! carries the registration across instead.
//!
//! The engine owns the format (`--export-identity`, `--import-identity`), so a
//! file saved by the Android client restores here and the other way round.
//! This side only chooses where the file goes, and never lets the contents
//! reach the webview: the file holds private keys, and the page has no reason
//! to see them.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::{DialogExt, FilePath};

use crate::core_supervisor::{hide_console_window, resolve_core_path, CoreProfile, CoreSupervisor};

/// The name offered when saving, the same as the Android client's.
const FILE_NAME: &str = "whiteaesther-identity.toml";

/// What happened, for the screen to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BackupOutcome {
    Saved,
    Restored,
    /// The picker was closed without choosing. Not an error.
    Cancelled,
}

/// Reads the engine's one-line JSON answer.
///
/// Anything that is not `ok: true` is the engine's own error, with the kind
/// prefix it puts on every message taken off: "other: there is no identity to
/// export yet" means something to a developer and nothing to anyone else.
fn answer_of(stdout: &str) -> Result<serde_json::Value, String> {
    let line = stdout
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .ok_or_else(|| "the engine did not answer".to_string())?;
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|_| "the engine's answer was not readable".to_string())?;
    if value.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
        return Ok(value);
    }
    let error = value
        .get("error")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("the engine refused");
    let error = error.strip_prefix("other: ").unwrap_or(error);
    // The first line only: a parse error goes on to draw the file's contents,
    // which is no place for a key.
    Err(error.lines().next().unwrap_or(error).trim().to_string())
}

/// Runs the engine once to answer an identity question.
fn ask_engine(app: &AppHandle, profile: &CoreProfile, question: &[&str]) -> Result<serde_json::Value, String> {
    let config_dir = app
        .path()
        .app_config_dir()
        .map_err(|error| format!("cannot resolve app config directory: {error}"))?;
    // The same base path every connect passes, so the engine finds the same
    // store and derives the same sibling files.
    let identity = config_dir.join("identity").join("aether.toml");
    let core_path = resolve_core_path(app, profile.core_path.as_deref())?;

    let mut command = Command::new(core_path);
    command
        .args(question)
        .arg("--config")
        .arg(&identity)
        .current_dir(&config_dir)
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    hide_console_window(&mut command);
    let output = command
        .output()
        .map_err(|error| format!("could not start the engine: {error}"))?;
    answer_of(&String::from_utf8_lossy(&output.stdout))
}

fn chosen_path(picked: Option<FilePath>) -> Result<Option<PathBuf>, String> {
    match picked {
        None => Ok(None),
        Some(path) => path
            .into_path()
            .map(Some)
            .map_err(|_| "that location cannot be written to".to_string()),
    }
}

/// Saves the identity to a file the user chooses.
///
/// The engine is asked first and the picker opened only once there is
/// something to save: opening it first and failing afterwards would leave an
/// empty file named as though it held an identity, which somebody might rely
/// on.
#[tauri::command]
pub async fn backup_identity(app: AppHandle, profile: CoreProfile) -> Result<BackupOutcome, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let answer = ask_engine(&app, &profile, &["--export-identity"])?;
        let payload = answer
            .get("payload")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "the engine's answer held no identity".to_string())?
            .to_string();

        let picked = app
            .dialog()
            .file()
            .set_file_name(FILE_NAME)
            .add_filter("WhiteAesther identity", &["toml"])
            .blocking_save_file();
        let Some(path) = chosen_path(picked)? else {
            return Ok(BackupOutcome::Cancelled);
        };
        write_private(&path, &payload)?;
        Ok(BackupOutcome::Saved)
    })
    .await
    .map_err(|error| format!("the backup did not finish: {error}"))?
}

/// Restores an identity from a file the user chooses.
///
/// Refused unless nothing is running. Swapping the identity under a session --
/// or under a search, whose trial engines read it too -- would leave an engine
/// carrying traffic for a device it no longer has the keys for, and the failure
/// would arrive long after the cause.
#[tauri::command]
pub async fn restore_identity(
    app: AppHandle,
    supervisor: State<'_, CoreSupervisor>,
    profile: CoreProfile,
) -> Result<BackupOutcome, String> {
    if !supervisor.is_idle() {
        return Err("Disconnect before importing an identity".into());
    }
    let supervisor = supervisor.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let picked = app
            .dialog()
            .file()
            .add_filter("WhiteAesther identity", &["toml"])
            .blocking_pick_file();
        let Some(path) = chosen_path(picked)? else {
            return Ok(BackupOutcome::Cancelled);
        };
        // Asked again: a connect may have started while the picker was open.
        if !supervisor.is_idle() {
            return Err("Disconnect before importing an identity".into());
        }
        let path = path.to_string_lossy().into_owned();
        ask_engine(&app, &profile, &["--import-identity", &path])?;
        supervisor.log("info", "restored the identity from a backup".into());
        Ok(BackupOutcome::Restored)
    })
    .await
    .map_err(|error| format!("the restore did not finish: {error}"))?
}

/// Writes the backup so only this user can read it, where the platform allows.
fn write_private(path: &Path, payload: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| format!("cannot write the backup: {error}"))?;
        file.write_all(payload.as_bytes())
            .map_err(|error| format!("cannot write the backup: {error}"))
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, payload).map_err(|error| format!("cannot write the backup: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each as the engine printed it, from `--export-identity` and
    // `--import-identity` run against a real install and an empty one.

    #[test]
    fn a_restore_that_worked_is_read_as_one() {
        assert!(answer_of("{\"ok\":true}\n").is_ok());
    }

    #[test]
    fn the_payload_comes_back_with_the_answer() {
        let answer = answer_of("{\"ok\":true,\"payload\":\"version = 2\\n\"}\n").unwrap();
        assert_eq!(answer["payload"], "version = 2\n");
    }

    #[test]
    fn a_refusal_reads_as_the_engine_said_it_without_the_kind() {
        assert_eq!(
            answer_of("{\"ok\":false,\"error\":\"other: there is no identity to export yet\"}\n"),
            Err("there is no identity to export yet".to_string())
        );
    }

    #[test]
    fn a_file_that_is_not_a_backup_is_named_without_repeating_its_contents() {
        let printed = "{\"ok\":false,\"error\":\"other: this is not a WhiteAesther identity file: TOML parse error at line 1, column 5\\n  |\\n1 | not a backup\\n  |     ^\\nkey with no value, expected `=`\\n\"}\n";
        let error = answer_of(printed).unwrap_err();
        assert!(error.starts_with("this is not a WhiteAesther identity file"), "{error}");
        assert!(!error.contains("not a backup\n"), "{error}");
        assert!(!error.contains('\n'), "{error}");
    }

    #[test]
    fn no_answer_at_all_is_an_error_not_a_success() {
        assert!(answer_of("").is_err());
        assert!(answer_of("Aether v2.0.0\n").is_err());
    }
}
