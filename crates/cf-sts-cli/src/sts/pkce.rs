//! One sign-in's secrets: the PKCE verifier (RFC 7636), and the `state` and
//! `nonce` OpenID Connect checks the redirect and the ID token against.

use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

/// Authorization is what one sign-in sends the provider, and checks its ID
/// token against.
pub struct Authorization {
    pub client_id: String,
    pub redirect_uri: String,
    pub verifier: String,
    pub state: String,
    pub nonce: String,
}

impl Authorization {
    /// Returns a sign-in as `client_id`, redirected to `redirect_uri`, with a
    /// fresh PKCE verifier, state and nonce.
    pub fn new(client_id: &str, redirect_uri: &str) -> Result<Self> {
        Ok(Self {
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            verifier: random()?,
            state: random()?,
            nonce: random()?,
        })
    }
}

/// Returns 32 random bytes, base64url: a PKCE verifier (RFC 7636 §4.1), a
/// state or a nonce.
fn random() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|err| anyhow!("no randomness from the OS: {err}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Returns the PKCE `S256` challenge for `verifier` (RFC 7636 §4.2).
pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn makes_the_pkce_challenge_rfc_7636_does() {
        // RFC 7636, Appendix B.
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let verifier = random().unwrap();
        assert_eq!(verifier.len(), 43);
        assert_ne!(verifier, random().unwrap());
    }
}
