//! Times, as the broker and the action show them.

use chrono::{DateTime, Utc};

/// Returns Unix seconds as the broker and the action show them, e.g.
/// `2026-09-28T12:15:00Z`.
pub fn rfc3339(seconds: i64) -> String {
    DateTime::<Utc>::from_timestamp(seconds, 0)
        .map(|at| at.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| seconds.to_string())
}

/// Returns how long until `exp`, roughly: `7h12m`, `5m`, `30s`.
pub fn until(exp: i64) -> String {
    let left = (exp - Utc::now().timestamp()).max(0);
    match (left / 3600, left % 3600 / 60) {
        (0, 0) => format!("{left}s"),
        (0, minutes) => format!("{minutes}m"),
        (hours, minutes) => format!("{hours}h{minutes}m"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_times_as_the_broker_does() {
        assert_eq!(rfc3339(1_790_597_700), "2026-09-28T12:15:00Z");
    }

    #[test]
    fn says_roughly_how_long_until() {
        let now = Utc::now().timestamp();
        assert_eq!(until(now + 30), "30s");
        assert_eq!(until(now + 5 * 60 + 30), "5m");
        assert!(until(now + 3 * 3600 + 120).starts_with("3h"));
        assert_eq!(until(now - 10), "0s");
    }
}
