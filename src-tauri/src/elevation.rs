//! Getting the permission a network device needs, without asking anyone to
//! right-click.
//!
//! Full tunnel creates a network adapter and installs a route, and neither is
//! something an ordinary user process may do. Until now the answer was "run it
//! as administrator", which is a thing to remember every single launch and a
//! thing most people will get wrong once and then not use the feature.
//!
//! So the app asks for itself: when full tunnel is switched on without the
//! permission to deliver it, it restarts itself elevated and comes back with
//! the switch already on. One prompt, in response to a thing the person just
//! asked for, which is when a prompt makes sense.
//!
//! This is deliberately not the end state. A service installed once would mean
//! no prompt at all, ever, and is the better answer for a machine someone uses
//! every day -- but it is a much larger thing to build and to be trusted with,
//! and this closes the gap in the meantime.

/// The argument the elevated copy is started with, so it knows to turn full
/// tunnel back on rather than coming up with it off.
pub const RESUME_FULL_TUNNEL: &str = "--resume-full-tunnel";

/// Whether this process may create a network adapter.
#[cfg(windows)]
pub fn is_elevated() -> bool {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0_u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Linux and macOS carry the permission on the binary or the service manager
/// rather than on the session, so there is nothing to ask for here. Reported as
/// already permitted so the caller goes ahead and lets the engine say whether
/// it worked -- which it checks anyway, because the engine does not exit when
/// it cannot create the device.
#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    true
}

/// Starts this same executable again, elevated, and reports whether the prompt
/// was accepted.
///
/// The caller is expected to end this process afterwards: two copies would fight
/// over the same listeners, and the single-instance guard would stop the new one
/// before it ever reached the point of creating a device.
#[cfg(windows)]
pub fn relaunch_elevated() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let exe = std::env::current_exe()
        .map_err(|error| format!("cannot find this application on disk: {error}"))?;

    let wide = |value: &std::ffi::OsStr| -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    };
    let verb: Vec<u16> = "runas\0".encode_utf16().collect();
    let file = wide(exe.as_os_str());
    let parameters: Vec<u16> = format!("{RESUME_FULL_TUNNEL}\0").encode_utf16().collect();

    // Returns a fake HINSTANCE; anything at or below 32 is an error, and the
    // one that matters is the person saying no to the prompt.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            parameters.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    let code = result as isize;
    match code {
        // SE_ERR_ACCESSDENIED. The prompt was refused, which is an answer and
        // not a fault: the caller says so plainly rather than reporting a
        // failure the person did not cause.
        5 => Err("permission was refused".into()),
        code if code <= 32 => Err(format!("could not restart with permission (code {code})")),
        _ => Ok(()),
    }
}

#[cfg(not(windows))]
pub fn relaunch_elevated() -> Result<(), String> {
    Err("this platform does not restart itself with permission".into())
}

/// Whether this copy was started by the one above, and should therefore switch
/// full tunnel back on once it is connected.
pub fn started_to_resume_full_tunnel() -> bool {
    std::env::args().any(|argument| argument == RESUME_FULL_TUNNEL)
}

/// Lets an ordinary launch reach a copy that is running elevated.
///
/// When full tunnel restarts the app with permission, everything after that is
/// running at a higher integrity level than the desktop shortcut that starts
/// it. Windows blocks messages sent up that gradient, and the single-instance
/// plugin signals the running copy with exactly such a message -- so clicking
/// the icon while the window was hidden did nothing at all: the second copy
/// found the first, could not reach it, and exited quietly.
///
/// The plugin's receiving window is a hidden one of its own, named after the
/// application identifier. Allowing that one message through is the documented
/// way to accept it from a lower-integrity sender, and it is the narrowest
/// thing that works: one message, on one window.
#[cfg(windows)]
pub fn allow_launches_from_an_ordinary_user(identifier: &str) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        ChangeWindowMessageFilterEx, FindWindowW, MSGFLT_ALLOW, WM_COPYDATA,
    };

    let class: Vec<u16> = std::ffi::OsStr::new(&format!("{identifier}-sic"))
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        // A null window name matches any window of the class, so this does not
        // depend on how the plugin spells the rest of the name.
        let hwnd = FindWindowW(class.as_ptr(), std::ptr::null());
        if hwnd.is_null() {
            return;
        }
        ChangeWindowMessageFilterEx(hwnd, WM_COPYDATA, MSGFLT_ALLOW, std::ptr::null_mut());
    }
}

#[cfg(not(windows))]
pub fn allow_launches_from_an_ordinary_user(_identifier: &str) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_resume_flag_is_recognised_only_when_it_is_actually_passed() {
        // The flag is what tells the elevated copy to finish what the
        // unelevated one started. Read from the real arguments, so a test can
        // only check the shape -- but a typo here would leave the restarted
        // copy sitting with the switch off and no sign why.
        assert_eq!(RESUME_FULL_TUNNEL, "--resume-full-tunnel");
        assert!(RESUME_FULL_TUNNEL.starts_with("--"));
        // A test binary is not started with it.
        assert!(!started_to_resume_full_tunnel());
    }

    #[cfg(windows)]
    #[test]
    fn asking_whether_we_are_elevated_answers_rather_than_failing() {
        // Whatever it returns, it must return: the caller uses this to decide
        // whether to prompt, and a panic here would take out the switch.
        let _ = is_elevated();
    }
}
