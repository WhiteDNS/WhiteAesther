//! The tray icon shows the connection state as a coloured dot in its corner.
//!
//! The dot is drawn onto the application icon at runtime rather than shipped as
//! one image per state, so the tray never drifts from the app icon.

use std::sync::atomic::{AtomicU8, Ordering};

use tauri::{image::Image, AppHandle};

use crate::core_supervisor::CoreSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Badge {
    Idle = 0,
    Working = 1,
    Connected = 2,
    Failed = 3,
    Blocked = 4,
}

/// What the tray shows now, so a snapshot that only moved the latency does not
/// redraw the icon. Starts as Idle: the icon is built plain.
static SHOWN: AtomicU8 = AtomicU8::new(Badge::Idle as u8);

fn badge_for(state: &str, blocking: bool) -> Badge {
    // Blocking outranks the state: the tunnel may be "reconnecting", but what
    // the person needs to know is that nothing is getting out.
    if blocking {
        return Badge::Blocked;
    }
    match state {
        "connected" => Badge::Connected,
        "starting" | "scanning" | "connecting" | "reconnecting" => Badge::Working,
        "error" => Badge::Failed,
        _ => Badge::Idle,
    }
}

fn colour(badge: Badge) -> Option<[u8; 3]> {
    match badge {
        Badge::Idle => None,
        Badge::Working => Some([0xEA, 0xB3, 0x08]),
        Badge::Connected => Some([0x22, 0xC5, 0x5E]),
        Badge::Failed => Some([0xEF, 0x44, 0x44]),
        Badge::Blocked => Some([0xF9, 0x73, 0x16]),
    }
}

fn label(badge: Badge) -> &'static str {
    match badge {
        Badge::Idle => "Not connected",
        Badge::Working => "Connecting…",
        Badge::Connected => "Connected",
        Badge::Failed => "Stopped",
        Badge::Blocked => "Traffic blocked",
    }
}

/// Paints a dot in the bottom-right corner of a straight-alpha RGBA image, with
/// a transparent gap around it so it reads on light and dark taskbars alike.
fn draw_badge(rgba: &mut [u8], width: u32, height: u32, rgb: [u8; 3]) {
    let size = width.min(height) as f32;
    let radius = size * 0.24;
    let gap = size * 0.07;
    let centre_x = width as f32 - radius - size * 0.01;
    let centre_y = height as f32 - radius - size * 0.01;
    let reach = radius + gap;

    let x0 = (centre_x - reach).floor().max(0.0) as u32;
    let y0 = (centre_y - reach).floor().max(0.0) as u32;
    for y in y0..height {
        for x in x0..width {
            let dx = x as f32 + 0.5 - centre_x;
            let dy = y as f32 + 0.5 - centre_y;
            let distance = (dx * dx + dy * dy).sqrt();
            let outer = (reach + 0.5 - distance).clamp(0.0, 1.0);
            if outer == 0.0 {
                continue;
            }
            let dot = (radius + 0.5 - distance).clamp(0.0, 1.0);
            let pixel = &mut rgba[((y * width + x) * 4) as usize..][..4];

            // Cut the gap out of the icon, then lay the dot over what is left.
            let under = pixel[3] as f32 / 255.0 * (1.0 - outer);
            let alpha = dot + under * (1.0 - dot);
            if alpha > 0.0 {
                for channel in 0..3 {
                    let mixed = rgb[channel] as f32 * dot + pixel[channel] as f32 * under * (1.0 - dot);
                    pixel[channel] = (mixed / alpha).round() as u8;
                }
            }
            pixel[3] = (alpha * 255.0).round() as u8;
        }
    }
}

/// Brings the tray icon and tooltip in line with the latest snapshot.
pub fn show(app: &AppHandle, snapshot: &CoreSnapshot) {
    let badge = badge_for(&snapshot.state, snapshot.blocking);
    if SHOWN.swap(badge as u8, Ordering::SeqCst) == badge as u8 {
        return;
    }
    let (Some(tray), Some(base)) = (app.tray_by_id(crate::TRAY_ID), app.default_window_icon()) else {
        // Not built yet: forget what was "shown" so the next snapshot tries again.
        SHOWN.store(Badge::Idle as u8, Ordering::SeqCst);
        return;
    };

    let mut rgba = base.rgba().to_vec();
    if let Some(rgb) = colour(badge) {
        draw_badge(&mut rgba, base.width(), base.height(), rgb);
    }
    let _ = tray.set_icon(Some(Image::new_owned(rgba, base.width(), base.height())));
    let _ = tray.set_tooltip(Some(format!(
        "WhiteAesther {} · {}",
        app.package_info().version,
        label(badge)
    )));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_supervisor_state_has_a_badge() {
        assert_eq!(badge_for("idle", false), Badge::Idle);
        for state in ["starting", "scanning", "connecting", "reconnecting"] {
            assert_eq!(badge_for(state, false), Badge::Working, "{state}");
        }
        assert_eq!(badge_for("connected", false), Badge::Connected);
        assert_eq!(badge_for("error", false), Badge::Failed);
        assert_eq!(badge_for("reconnecting", true), Badge::Blocked);
        assert_eq!(colour(Badge::Idle), None);
    }

    #[test]
    fn the_dot_sits_in_the_corner_behind_a_transparent_gap() {
        let (width, height) = (32u32, 32u32);
        let mut rgba = vec![255u8; (width * height * 4) as usize];
        draw_badge(&mut rgba, width, height, [0x22, 0xC5, 0x5E]);
        let at = |x: u32, y: u32| &rgba[((y * width + x) * 4) as usize..][..4];

        // The middle of the dot is the badge colour, fully opaque.
        assert_eq!(at(24, 24), &[0x22, 0xC5, 0x5E, 255]);
        // The far corner of the icon is untouched.
        assert_eq!(at(1, 1), &[255, 255, 255, 255]);
        // Just outside the dot, the icon is cut away.
        assert!(at(14, 24)[3] < 128, "gap alpha {}", at(14, 24)[3]);
    }
}
