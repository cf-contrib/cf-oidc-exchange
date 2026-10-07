//! Errors a person can act on.

use std::fmt::Display;

/// Returns an error with what to do about it on a line of its own:
/// `cf-sts: error: <message>` then `  hint: <hint>`.
pub fn hinted(message: impl Display, hint: impl Display) -> anyhow::Error {
    anyhow::anyhow!("{message}\n  hint: {hint}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn puts_the_hint_on_a_line_of_its_own() {
        let err = hinted(
            "not signed in to https://cf-sts.example.com",
            "run 'cf-sts login'",
        );
        assert_eq!(
            err.to_string(),
            "not signed in to https://cf-sts.example.com\n  hint: run 'cf-sts login'"
        );
    }
}
