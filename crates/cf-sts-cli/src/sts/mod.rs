//! cf-sts for people, by role: the parties the CLI talks to -- the [`broker`],
//! the identity [`provider`] people sign in at, and the [`redirect`] endpoint
//! the browser comes back to -- what the person holds -- one sign-in's
//! [`pkce`] secrets, the [`identity`] it ends in, and the [`keychain`] that
//! keeps it -- and what `exec` hands on: the [`credentials`] the broker grants,
//! to the [`child`] command.

mod broker;
mod child;
mod credentials;
mod identity;
mod keychain;
mod pkce;
mod provider;
mod redirect;
mod time;

#[cfg(test)]
pub mod stub;

pub use broker::*;
pub use child::*;
pub use credentials::*;
pub use identity::*;
pub use keychain::*;
pub use pkce::*;
pub use provider::*;
pub use redirect::*;
pub use time::*;

/// An error with what to do about it on a line of its own:
/// `cf-sts: error: <message>` then `  hint: <hint>`.
pub fn hinted(message: impl std::fmt::Display, hint: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("{message}\n  hint: {hint}")
}
