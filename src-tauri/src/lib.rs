mod chain;
mod core_supervisor;
mod elevation;
mod http_bridge;
mod iran_routes;
mod lan_share;
mod latency;
mod scanner;
mod system_proxy;

use chain::Chain;
use core_supervisor::CoreSupervisor;
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager,
};

/// The tray icon's id, used to create it and to take it away again.
///
/// Windows keeps showing a tray icon after the process that owns it is gone --
/// it only notices on the next hover -- so every path that ends this process
/// has to remove the icon itself. A build installed over a running copy is the
/// common way to collect a row of dead icons.
const TRAY_ID: &str = "whiteaesther";

/// Takes the tray icon away before the process goes.
///
/// Idempotent, and safe to call from every exit path: removing an icon that has
/// already gone does nothing.
fn remove_tray(app: &AppHandle) {
    app.remove_tray_by_id(TRAY_ID);
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ChainStatus {
    running: bool,
    /// Where applications and the system proxy point while the chain carries
    /// traffic. None means the tunnel is carrying it directly.
    address: Option<String>,
}

/// Whether the second hop is up, and what it is listening on.
#[tauri::command]
async fn chain_status(chain: tauri::State<'_, Chain>) -> Result<ChainStatus, String> {
    Ok(ChainStatus {
        running: chain.is_running(),
        address: chain.address().map(|value| value.to_string()),
    })
}

/// Every node the chain knows about, with the delay each last recorded.
#[tauri::command]
async fn chain_nodes(
    chain: tauri::State<'_, Chain>,
    supervisor: tauri::State<'_, CoreSupervisor>,
) -> Result<Vec<chain::ChainNode>, String> {
    // Which transport came up decides whether a QUIC node behind the tunnel can
    // work at all, and only the supervisor knows that.
    chain.nodes(supervisor.carries_quic())
}

/// Measures one node through the tunnel.
///
/// The same call answers "does this config work from here" and "how fast is
/// it", because the probe travels the node's own dialer-proxy: a number means
/// it is usable behind the tunnel, and nothing means it is not.
#[tauri::command]
async fn chain_test(
    chain: tauri::State<'_, Chain>,
    source: String,
    node: String,
) -> Result<Option<u32>, String> {
    chain.test(&source, &node)
}

#[tauri::command]
async fn chain_select(chain: tauri::State<'_, Chain>, node: String) -> Result<(), String> {
    chain.select(&node)
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn toggle_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        if window.is_visible().unwrap_or(false) {
            let _ = window.hide();
        } else {
            show_main_window(app);
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // Before anything else, so a second launch never reaches setup(). Its
        // proxy recovery would revert the settings the running copy applied,
        // and its window would report "Not connected" over a live tunnel.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            show_main_window(app);
        }))
        .plugin(tauri_plugin_opener::init())
        .manage(CoreSupervisor::new())
        .manage(Chain::new())
        .manage(lan_share::LanDoor::default())
        .setup(|app| {
            // A previous run that was killed rather than closed may have left
            // the system proxy pointing at a listener that is now gone, which
            // takes the machine off the network until it is put back.
            match system_proxy::recover(app.handle()) {
                Ok(true) => eprintln!("restored the system proxy left by an earlier run"),
                Ok(false) => {}
                Err(error) => eprintln!("could not restore the system proxy: {error}"),
            }

            // Full tunnel restarts this app elevated, and from then on the
            // desktop shortcut is at a lower integrity level than the copy it
            // is trying to wake. Windows blocks messages sent up that gradient,
            // so without this a click on the icon found the running copy and
            // silently failed to reach it.
            elevation::allow_launches_from_an_ordinary_user(&app.config().identifier);

            // One thread delivers logs and status to the window on a timer, so
            // the core's own progress never waits on the interface.
            core_supervisor::start_pump(app.handle().clone(), &app.state::<CoreSupervisor>());

            let open = MenuItem::with_id(app, "open", "Open WhiteAesther", true, None::<&str>)?;
            let connection = MenuItem::with_id(
                app,
                "toggle-connection",
                "Connect / Disconnect",
                true,
                None::<&str>,
            )?;
            let diagnostics =
                MenuItem::with_id(app, "diagnostics", "Open Diagnostics", true, None::<&str>)?;
            // Reachable with the window hidden, which is exactly the state
            // someone is in when the kill switch has blocked their traffic and
            // they are looking for the way out.
            let restore = MenuItem::with_id(
                app,
                "restore-proxy",
                "Restore system proxy",
                true,
                None::<&str>,
            )?;
            let hide = MenuItem::with_id(app, "hide", "Hide WhiteAesther", true, None::<&str>)?;
            let separator = PredefinedMenuItem::separator(app)?;
            let quit = MenuItem::with_id(app, "quit", "Quit WhiteAesther", true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[&open, &connection, &restore, &diagnostics, &hide, &separator, &quit],
            )?;
            let icon = app
                .default_window_icon()
                .cloned()
                .ok_or("application icon is unavailable")?;

            TrayIconBuilder::with_id(TRAY_ID)
                .icon(icon)
                .tooltip(format!("WhiteAesther {}", app.package_info().version))
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "open" => show_main_window(app),
                    "hide" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.hide();
                        }
                    }
                    "toggle-connection" => {
                        let _ = app.emit("tray-action", "toggle-connection");
                    }
                    "restore-proxy" => {
                        let _ = app.emit("tray-action", "restore-proxy");
                    }
                    "diagnostics" => {
                        show_main_window(app);
                        let _ = app.emit("tray-action", "open-diagnostics");
                    }
                    "quit" => {
                        app.state::<CoreSupervisor>().shutdown(app);
                        remove_tray(app);
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if matches!(
                        event,
                        TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        }
                    ) {
                        toggle_main_window(tray.app_handle());
                    }
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| match event {
            tauri::WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                let _ = window.hide();
            }
            tauri::WindowEvent::Destroyed => {
                let app = window.app_handle();
                app.state::<CoreSupervisor>().shutdown(app);
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            core_supervisor::runtime_info,
            core_supervisor::probe_core,
            core_supervisor::start_core,
            core_supervisor::stop_core,
            core_supervisor::core_status,
            core_supervisor::core_logs,
            core_supervisor::save_profile,
            core_supervisor::load_profile,
            core_supervisor::save_report,
            core_supervisor::set_system_proxy,
            core_supervisor::set_chain,
            core_supervisor::set_full_tunnel,
            core_supervisor::full_tunnel_is_permitted,
            core_supervisor::resuming_full_tunnel,
            core_supervisor::restart_as_administrator,
            core_supervisor::set_lan_share,
            core_supervisor::lan_share_status,
            scanner::scan_endpoints,
            scanner::test_endpoint,
            scanner::cancel_scan,
            latency::probe_latency,
            latency::speed_test,
            latency::exit_info,
            chain_status,
            chain_nodes,
            chain_test,
            chain_select,
        ])
        .build(tauri::generate_context!())
        .expect("error while running WhiteAesther")
        // prevent_close() above means WindowEvent::Destroyed never fires, so it was never a
        // cleanup path — Cmd+Q, Dock Quit and logout all exited here instead, orphaning a live
        // core (std::process::Child does not kill on drop). shutdown() is idempotent.
        // ponytail: cannot cover SIGKILL/OOM — that needs a pid file reaped at next launch.
        .run(|app, event| {
            match event {
                // Asked to go: an installer replacing this build, a logout, or
                // a quit from the dock. The icon has to be withdrawn while
                // there is still a process to withdraw it.
                tauri::RunEvent::ExitRequested { .. } => remove_tray(app),
                tauri::RunEvent::Exit => {
                    app.state::<CoreSupervisor>().shutdown(app);
                    remove_tray(app);
                }
                _ => {}
            }
        });
}
