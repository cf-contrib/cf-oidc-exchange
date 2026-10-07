//! cf-sts for people, by domain: the [`broker`] and its API, [`login`] at an
//! identity provider, the stored [`session`] it ends in, and the [`process`]
//! `exec` runs with what the broker grants.

mod broker;
mod error;
mod login;
mod process;
mod session;

#[cfg(test)]
pub mod stub;

pub use broker::*;
pub use error::*;
pub use login::*;
pub use process::*;
pub use session::*;
