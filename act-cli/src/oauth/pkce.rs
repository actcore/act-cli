//! PKCE (RFC 7636), S256 only.
//!
//! `plain` is not implemented and will not be. RFC 7636 §4.2 permits it only
//! where the client cannot do SHA-256, which is not a situation this host can
//! be in, and a `plain` challenge is the verifier itself — so an attacker who
//! sees the authorization request can complete the exchange. Offering it as a
//! fallback would mean an authorization server that advertises both could
//! silently get the weaker one.

use anyhow::Result;

use super::{b64url, random_bytes};

/// A verifier and the challenge derived from it. The verifier never leaves the
/// host until the token exchange; the challenge is what travels in the
/// authorization request.
#[derive(Debug, Clone)]
pub struct Pkce {
    verifier: String,
    challenge: String,
}

impl Pkce {
    /// 32 bytes of entropy, base64url-encoded to 43 characters — the RFC's
    /// recommended length, and comfortably inside its 43..=128 range.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_verifier(b64url(&random_bytes::<32>()?)))
    }

    /// The challenge is `BASE64URL(SHA256(ASCII(verifier)))` (RFC 7636 §4.2).
    fn from_verifier(verifier: String) -> Self {
        use sha2::Digest;
        let digest = sha2::Sha256::digest(verifier.as_bytes());
        Self {
            challenge: b64url(&digest),
            verifier,
        }
    }

    /// Sent in the authorization request, alongside `code_challenge_method=S256`.
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// Sent in the token request. Proves this exchange belongs to the same
    /// client that made the authorization request.
    pub fn verifier(&self) -> &str {
        &self.verifier
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example from RFC 7636 Appendix B. A hand-rolled S256 that is
    /// subtly wrong — hashing the decoded bytes rather than the ASCII, or
    /// padding the base64 — produces a challenge every authorization server
    /// rejects, and the failure arrives as an opaque `invalid_grant` at the
    /// token endpoint, far from here.
    #[test]
    fn matches_the_rfc_7636_appendix_b_vector() {
        let p = Pkce::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string());
        assert_eq!(p.challenge(), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn a_generated_verifier_is_the_rfc_recommended_length() {
        let p = Pkce::generate().unwrap();
        assert_eq!(p.verifier().len(), 43, "32 bytes as unpadded base64url");
        assert!(
            p.verifier().len() >= 43 && p.verifier().len() <= 128,
            "RFC 7636 §4.1 length range"
        );
    }

    #[test]
    fn the_verifier_is_url_safe_and_unpadded() {
        // A `+`, `/` or `=` here travels through a URL and a form body; the
        // RFC's alphabet is what keeps both hops from re-encoding it.
        let p = Pkce::generate().unwrap();
        for s in [p.verifier(), p.challenge()] {
            assert!(
                s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "not url-safe: {s}"
            );
        }
    }

    #[test]
    fn two_generated_verifiers_differ() {
        // Cheap, but it is the difference between a CSPRNG and a constant, and
        // a constant verifier would make PKCE decorative.
        let a = Pkce::generate().unwrap();
        let b = Pkce::generate().unwrap();
        assert_ne!(a.verifier(), b.verifier());
        assert_ne!(a.challenge(), b.challenge());
    }

    #[test]
    fn the_challenge_is_not_the_verifier() {
        // What `plain` would have done, and the reason this module has no
        // `plain`: a challenge equal to the verifier hands the exchange to
        // whoever saw the authorization request.
        let p = Pkce::generate().unwrap();
        assert_ne!(p.challenge(), p.verifier());
    }
}
