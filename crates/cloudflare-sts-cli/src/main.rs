//! `cloudflare-sts`: short-lived Cloudflare credentials from a cloudflare-sts broker, for
//! people and the agents working on their machines. CI has the action.
//!
//! - No secret on argv, stdout or stderr: the Cloudflare token and R2 keys
//!   reach the child's environment only.
//! - Nothing persists but the ID token, in the OS keychain.
//! - Nothing but `login` opens a browser or waits for a person, so an agent
//!   never hangs on it.

mod app;
mod log;
mod sts;

use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use crate::{
    app::{args::*, exec::*},
    sts::*,
};

/// The loopback port the identity provider redirects to: an Access for SaaS
/// app's redirect URI names it exactly.
const LOGIN_PORT: u16 = 8250;

fn main() -> ExitCode {
    let program = Program::parse();
    let parent = program.command.parent();
    log::set_level(match (parent.quiet, parent.verbose) {
        (true, _) => log::Level::Quiet,
        (_, true) => log::Level::Verbose,
        _ => log::Level::Normal,
    });

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to start");
    match runtime.and_then(|runtime| runtime.block_on(run(program))) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            log::error(format!("{err:#}"));
            ExitCode::FAILURE
        }
    }
}

/// Runs the command, and returns the exit code: `exec`'s is its command's.
async fn run(program: Program) -> Result<u8> {
    match program.command {
        ProgramCommand::Login(args) => {
            let store = Box::new(Keychain);
            let open = Box::new(|link: &str| Ok(open::that_detached(link)?));
            let mut command = LoginCommand {
                store,
                open,
                port: LOGIN_PORT,
            };
            command.execute(&args).await?;
            Ok(0)
        }
        ProgramCommand::Logout(args) => {
            let store = Box::new(Keychain);
            let mut command = LogoutCommand { store };
            command.execute(&args)?;
            Ok(0)
        }
        ProgramCommand::Whoami(args) => {
            let store = Box::new(Keychain);
            let writer = Box::new(std::io::stdout());
            let mut command = WhoamiCommand { store, writer };
            command.execute(&args).await?;
            Ok(0)
        }
        ProgramCommand::Exec(args) => {
            let store = Box::new(Keychain);
            let mut command = ExecCommand { store };
            command.execute(&args).await
        }
    }
}
