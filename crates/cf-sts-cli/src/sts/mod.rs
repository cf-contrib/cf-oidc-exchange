//! cf-sts for people: the [`broker`] and its API, the stored login --
//! [`identity`] -- the sign-in it comes from -- [`oidc`] -- and the command
//! `exec` runs with the credentials -- [`process`].

mod broker;
mod identity;
mod oidc;
mod process;
#[cfg(test)]
pub mod stub;

pub use broker::*;
pub use identity::*;
pub use oidc::*;
pub use process::*;

/// An error with what to do about it on a line of its own:
/// `cf-sts: error: <message>` then `  hint: <hint>`.
pub fn hinted(message: impl std::fmt::Display, hint: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("{message}\n  hint: {hint}")
}
