//! Turning terminal echo off around a secret prompt.
//!
//! Scoped deliberately narrowly: this module knows how to stop the terminal
//! from echoing what is typed on **the process's own stdin**, and nothing
//! else. It does not read, prompt, or open `/dev/tty`.
//!
//! Reading stays on stdin (`secret_cmd::read_hidden_line`) rather than moving
//! to the controlling terminal, which is what a `getpass(3)`-shaped crate
//! (`rpassword`, `console`) would do. Two properties depend on that:
//!
//! - **EOF is an aborted prompt, not an empty credential.** Every such crate
//!   turns end-of-input into `Ok("")`, which this code must distinguish from
//!   an operator answering an optional field with a bare newline — those have
//!   different outcomes (refuse vs. skip). See `read_hidden_line`.
//! - **`act login` under closed stdin must fail, not block.** It has no
//!   `is_terminal` gate, so a prompt bound to `/dev/tty` would read the
//!   developer's own terminal and hang the test suite instead of reporting
//!   EOF.
//!
//! So the terminal handling is here and the reading is not.

/// Restores the echo setting that was in place when it was taken.
///
/// Held across the read and dropped after it, so echo comes back on an early
/// return or a panic as well as on the normal path — the `stty -echo` /
/// `stty echo` subprocess pair this replaced restored it only when the read
/// returned normally, and left the operator's terminal mute otherwise.
pub(crate) struct EchoOff(imp::Restore);

impl Drop for EchoOff {
    fn drop(&mut self) {
        self.0.restore();
    }
}

/// Turns echo off on stdin for as long as the returned guard lives.
///
/// - `Ok(Some(guard))` — echo is off.
/// - `Ok(None)` — stdin is not a terminal, so there is no echo to turn off
///   and nothing to warn about. A piped or redirected secret was never going
///   to appear on screen.
/// - `Err(_)` — stdin *is* a terminal and echo could not be turned off. The
///   caller says so before it reads; it is the only case where what the
///   operator types next will be visible.
pub(crate) fn echo_off() -> std::io::Result<Option<EchoOff>> {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Ok(None);
    }
    imp::echo_off().map(|r| Some(EchoOff(r)))
}

#[cfg(unix)]
mod imp {
    use rustix::termios::{LocalModes, OptionalActions, Termios, tcgetattr, tcsetattr};

    pub(super) struct Restore(Termios);

    impl Restore {
        pub(super) fn restore(&self) {
            // Nothing useful to do if this fails: we are on a drop path, and
            // the process is about to hand the terminal back to the shell,
            // which resets it on the next prompt.
            let _ = tcsetattr(std::io::stdin(), OptionalActions::Now, &self.0);
        }
    }

    pub(super) fn echo_off() -> std::io::Result<Restore> {
        let stdin = std::io::stdin();
        let original = tcgetattr(&stdin)?;
        let mut quiet = original.clone();
        quiet.local_modes -= LocalModes::ECHO;
        // `Flush` (TCSAFLUSH), not `Now`: it discards input already typed
        // ahead of the prompt, so a keystroke buffered while echo was still
        // on cannot be read as part of the credential.
        tcsetattr(&stdin, OptionalActions::Flush, &quiet)?;
        Ok(Restore(original))
    }
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Console::{
        CONSOLE_MODE, ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE,
        SetConsoleMode,
    };

    pub(super) struct Restore {
        handle: HANDLE,
        mode: CONSOLE_MODE,
    }

    // `HANDLE` is a raw pointer, so the guard is not `Send`/`Sync` by
    // inference. It is only ever created and dropped on the thread that
    // prompts, and the console handle is process-wide, so the pointer is
    // valid for the guard's whole life.
    unsafe impl Send for Restore {}

    impl Restore {
        pub(super) fn restore(&self) {
            unsafe { SetConsoleMode(self.handle, self.mode) };
        }
    }

    pub(super) fn echo_off() -> std::io::Result<Restore> {
        // The process's own stdin handle, the same stream the read below
        // consumes — not `CONIN$`. Redirected stdin is already excluded by
        // the `is_terminal` check in `echo_off`.
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let mut mode: CONSOLE_MODE = 0;
        if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Restore { handle, mode })
    }
}

/// Neither termios nor the Windows console API: echo cannot be turned off,
/// and `echo_off` reports that as the error it is rather than pretending to
/// have succeeded.
#[cfg(not(any(unix, windows)))]
mod imp {
    pub(super) struct Restore;

    impl Restore {
        pub(super) fn restore(&self) {}
    }

    pub(super) fn echo_off() -> std::io::Result<Restore> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "no terminal-echo control on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The case that must not warn.** `cargo test` runs with stdin
    /// redirected, which is the same shape as `act secret set … < file` and
    /// as a CI pipeline. `echo_off` must report "nothing to do" rather than
    /// an error, because `secret_cmd` turns an error into a visible warning
    /// that the credential is about to be echoed — advice that would be
    /// false here, and alarming in a log.
    #[test]
    fn a_redirected_stdin_is_not_an_error_and_not_a_guard() {
        assert!(
            !std::io::IsTerminal::is_terminal(&std::io::stdin()),
            "this test asserts the non-terminal branch; it needs stdin redirected, \
             which is how the test harness runs it"
        );
        match echo_off() {
            Ok(None) => {}
            Ok(Some(_)) => panic!("a redirected stdin has no echo to turn off"),
            Err(e) => panic!("a redirected stdin is not a failure to report: {e}"),
        }
    }

    /// The guard exists to be dropped, so dropping it must be safe when
    /// there is nothing to restore — the `Ok(None)` path returns no guard,
    /// and this pins that the caller's `let _echo = …; drop` shape cannot
    /// touch the terminal in that case.
    #[test]
    fn no_guard_means_nothing_is_restored() {
        let guard = echo_off().expect("redirected stdin does not fail");
        assert!(guard.is_none());
        drop(guard);
    }

    /// **Echo is actually restored, asserted against the terminal state
    /// itself rather than against the guard's existence.**
    ///
    /// Needs a real terminal to read the `ECHO` bit back from, and the
    /// harness redirects stdin — so this opens the controlling terminal
    /// directly. Marked `#[ignore]` because most places this runs have no
    /// controlling terminal at all: CI, a container, and this workspace's
    /// own sandbox, where `/dev/tty` exists as a device node but opening it
    /// gives ENXIO.
    ///
    /// **Marked rather than silently skipped.** An early `return` on a
    /// missing terminal reports success while asserting nothing, which is
    /// the failure mode this suite has been bitten by before. `#[ignore]`
    /// says "not run" where a reader can see it. Run it on a real terminal
    /// with `cargo test -p act-cli --bin act -- --ignored on_a_real`.
    ///
    /// Unix-only: it reads `termios`, which is the thing being verified.
    ///
    /// It drives the same `tcgetattr`/`tcsetattr` pair `imp` does rather than
    /// calling `echo_off`, which is hard-wired to stdin. What it pins is that
    /// the save-and-restore shape actually returns the bit — the property the
    /// `Drop` guard exists for, and the one the old `stty` pair got wrong on
    /// the panic path.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs a controlling terminal: run with --ignored from a real tty"]
    fn on_a_real_terminal_echo_goes_off_and_comes_back() {
        use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};

        let tty = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
        {
            Ok(f) => f,
            Err(e) => panic!(
                "no controlling terminal ({e}). This test was asked for \
                 explicitly with --ignored, so it fails rather than passing \
                 without checking anything — run it from a real terminal."
            ),
        };
        let before = tcgetattr(&tty).expect("a controlling terminal has termios");
        assert!(
            before.local_modes.contains(LocalModes::ECHO),
            "expected a terminal with echo on to start from"
        );

        let mut off = before.clone();
        off.local_modes -= LocalModes::ECHO;
        tcsetattr(&tty, OptionalActions::Now, &off).expect("echo off");
        let while_off = tcgetattr(&tty)
            .unwrap()
            .local_modes
            .contains(LocalModes::ECHO);

        // Restored before asserting, so a failed assertion cannot leave the
        // developer's terminal mute.
        tcsetattr(&tty, OptionalActions::Now, &before).expect("restore");
        let after = tcgetattr(&tty)
            .unwrap()
            .local_modes
            .contains(LocalModes::ECHO);

        assert!(!while_off, "echo must actually be off between the calls");
        assert!(after, "restoring the saved termios must put echo back");
    }
}
