//! The command `exec` hands the credentials to: its environment, and its
//! signals and exit code while cf-sts waits to revoke.

use std::{ffi::OsString, io, process::ExitStatus};

use anyhow::{Context, Result, bail};
use tokio::process::{Child, Command};

use super::{Credentials, VARIABLES};

/// Returns `command` with the credentials in its environment, and every other
/// variable `exec` sets removed.
pub fn child(command: &[OsString], credentials: &Credentials) -> Result<Command> {
    let Some((program, args)) = command.split_first() else {
        bail!("no command to run");
    };
    let mut child = Command::new(program);
    child.args(args);
    for name in VARIABLES {
        child.env_remove(name);
    }
    child.envs(credentials.variables());
    Ok(child)
}

/// Runs `child` to the end and returns its exit code, handling `signals`
/// meanwhile. One that can't start is `127` if it isn't found and `126`
/// otherwise, as a shell has it.
pub async fn run_child(mut child: Command, signals: Signals) -> Result<u8> {
    let program = child.as_std().get_program().to_string_lossy().into_owned();
    let child = match child.spawn() {
        Ok(child) => child,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            crate::log::error(format!("{program}: command not found"));
            return Ok(127);
        }
        Err(err) => {
            crate::log::error(format!("{program}: {err}"));
            return Ok(126);
        }
    };
    let status = signals
        .wait(child)
        .await
        .context("waiting for the command failed")?;
    Ok(exit_code(status))
}

/// Returns the child's exit code, or `128 + n` if signal `n` killed it, as a
/// shell has it.
fn exit_code(status: ExitStatus) -> u8 {
    if let Some(code) = status.code() {
        return u8::try_from(code).unwrap_or(1);
    }
    #[cfg(unix)]
    if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&status) {
        return u8::try_from(128 + signal).unwrap_or(1);
    }
    1
}

/// Signals are those `exec` handles while the child runs. Listening replaces
/// their default action, which would kill `exec` before it revokes.
///
/// - `SIGINT` and `SIGQUIT` are ignored: the terminal sends them to the whole
///   foreground process group, so the child has them already. Forwarding them
///   would deliver them twice, and a second Ctrl-C makes tofu stop at once.
/// - `SIGTERM` and `SIGHUP` are sent to `exec` alone, and forwarded.
#[cfg(unix)]
pub struct Signals {
    interrupt: tokio::signal::unix::Signal,
    quit: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
    hangup: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl Signals {
    /// Starts handling the signals.
    pub fn listen() -> Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        let listen = |kind| signal(kind).context("can't handle signals");
        Ok(Self {
            interrupt: listen(SignalKind::interrupt())?,
            quit: listen(SignalKind::quit())?,
            terminate: listen(SignalKind::terminate())?,
            hangup: listen(SignalKind::hangup())?,
        })
    }

    async fn wait(mut self, mut child: Child) -> io::Result<ExitStatus> {
        let forward = |child: &Child, signal| {
            if let Some(pid) = child.id().and_then(|pid| i32::try_from(pid).ok()) {
                // SAFETY: kill(2) takes any pid and signal number, and the
                // child is ours and not yet reaped, so the pid is its.
                unsafe { libc::kill(pid, signal) };
            }
        };
        loop {
            tokio::select! {
                status = child.wait() => return status,
                _ = self.interrupt.recv() => {}
                _ = self.quit.recv() => {}
                _ = self.terminate.recv() => forward(&child, libc::SIGTERM),
                _ = self.hangup.recv() => forward(&child, libc::SIGHUP),
            }
        }
    }
}

/// On Windows, Ctrl-C reaches every process on the console: `exec` ignores it
/// and waits for the child.
#[cfg(not(unix))]
pub struct Signals;

#[cfg(not(unix))]
impl Signals {
    /// Starts handling the signals.
    pub fn listen() -> Result<Self> {
        Ok(Self)
    }

    async fn wait(self, mut child: Child) -> io::Result<ExitStatus> {
        loop {
            tokio::select! {
                status = child.wait() => return status,
                _ = tokio::signal::ctrl_c() => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, ffi::OsStr};

    use serde_json::json;

    use super::*;
    use crate::sts::credentials::tests::credentials;

    #[test]
    fn removes_what_the_profile_doesnt_grant() {
        let credentials = credentials(json!({ "access_token": null, "token_id": null })).unwrap();
        let command = child(&["true".into()], &credentials).unwrap();
        let env: HashMap<&OsStr, Option<&OsStr>> = command.as_std().get_envs().collect();
        // A token in the caller's shell can't stand in for the one the
        // profile doesn't grant.
        assert_eq!(env[OsStr::new("CLOUDFLARE_API_TOKEN")], None);
        assert_eq!(
            env[OsStr::new("CLOUDFLARE_R2_BUCKET")],
            Some(OsStr::new("org-terraform-state"))
        );
        assert_eq!(
            env[OsStr::new("CLOUDFLARE_R2_PREFIXES")],
            Some(OsStr::new("[\"github.com/example-org/app/\"]"))
        );
    }
}
