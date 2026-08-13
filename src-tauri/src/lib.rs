mod core_supervisor;

use core_supervisor::CoreSupervisor;
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager,
};

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
        .plugin(tauri_plugin_opener::init())
        .manage(CoreSupervisor::new())
        .setup(|app| {
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
            let hide = MenuItem::with_id(app, "hide", "Hide WhiteAesther", true, None::<&str>)?;
            let separator = PredefinedMenuItem::separator(app)?;
            let quit = MenuItem::with_id(app, "quit", "Quit WhiteAesther", true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[&open, &connection, &diagnostics, &hide, &separator, &quit],
            )?;
            let icon = app
                .default_window_icon()
                .cloned()
                .ok_or("application icon is unavailable")?;

            TrayIconBuilder::with_id("whiteaesther")
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
                    "diagnostics" => {
                        show_main_window(app);
                        let _ = app.emit("tray-action", "open-diagnostics");
                    }
                    "quit" => {
                        app.state::<CoreSupervisor>().shutdown();
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
                window.state::<CoreSupervisor>().shutdown();
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
        ])
        .build(tauri::generate_context!())
        .expect("error while running WhiteAesther")
        // prevent_close() above means WindowEvent::Destroyed never fires, so it was never a
        // cleanup path — Cmd+Q, Dock Quit and logout all exited here instead, orphaning a live
        // core (std::process::Child does not kill on drop). shutdown() is idempotent.
        // ponytail: cannot cover SIGKILL/OOM — that needs a pid file reaped at next launch.
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                app.state::<CoreSupervisor>().shutdown();
            }
        });
}
