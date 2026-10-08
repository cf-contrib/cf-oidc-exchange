use std::{
    fmt::Display,
    sync::atomic::{AtomicU8, Ordering},
};

use console::style;

/// How much cloudflare-sts prints to stderr. stdout is the command's own: `whoami`'s
/// output, or the child's under `exec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Warnings and errors only.
    Quiet = 0,
    /// Also status lines.
    Normal = 1,
    /// Also details for debugging.
    Verbose = 2,
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Normal as u8);

/// Sets how much cloudflare-sts prints to stderr.
pub fn set_level(level: Level) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

/// Returns true if messages of `level` are printed.
fn enabled(level: Level) -> bool {
    LEVEL.load(Ordering::Relaxed) >= level as u8
}

/// Prints an error to stderr.
pub fn error(message: impl Display) {
    eprintln!(
        "cloudflare-sts: {} {message}",
        style("error:").red().bold().for_stderr()
    );
}

/// Prints a warning to stderr, even when quiet.
pub fn warn(message: impl Display) {
    eprintln!(
        "cloudflare-sts: {} {message}",
        style("warning:").yellow().bold().for_stderr()
    );
}

/// Prints what a person has to act on to stderr, even when quiet, such as the
/// sign-in link.
pub fn notice(message: impl Display) {
    eprintln!("cloudflare-sts: {message}");
}

/// Prints a status line to stderr, unless quiet. Worded as the action's, so a
/// run can be matched to the broker's audit log.
pub fn info(message: impl Display) {
    if enabled(Level::Normal) {
        eprintln!("cloudflare-sts: {message}");
    }
}

/// Prints a detail for debugging to stderr, if verbose. Never a secret.
pub fn debug(message: impl Display) {
    if enabled(Level::Verbose) {
        eprintln!(
            "{}",
            style(format!("cloudflare-sts: debug: {message}"))
                .dim()
                .for_stderr()
        );
    }
}
