//! Errors a person can act on.

use std::fmt::Display;

/// Returns an error with what to do about it on a line of its own:
/// `cloudflare-sts: error: <message>` then `  hint: <hint>`.
pub fn hinted(message: impl Display, hint: impl Display) -> anyhow::Error {
    anyhow::anyhow!("{message}\n  hint: {hint}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn puts_the_hint_on_a_line_of_its_own() {
        let err = hinted(
            "not signed in to https://cloudflare-sts-api.example.com",
            "run 'cloudflare-sts login'",
        );
        assert_eq!(
            err.to_string(),
            "not signed in to https://cloudflare-sts-api.example.com\n  hint: run 'cloudflare-sts login'"
        );
    }
}
