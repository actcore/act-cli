//! The `iss` check (RFC 9207), applied before the code leaves the host.
//!
//! ## What it defends against
//!
//! The mix-up attack. A user with more than one authorization server — the
//! common case for anyone with a work and a personal account, or a host talking
//! to several upstreams — can be steered so that a code issued by server A
//! arrives at a callback the host believes belongs to server B, and the host
//! then presents A's code to B's token endpoint. Where B is attacker-controlled,
//! that hands over a live authorization code.
//!
//! RFC 9207 closes it by having the authorization response carry `iss`. The
//! check is worth nothing unless it happens **before** the code is transmitted,
//! which is why this is a pure function called at the callback rather than
//! error handling around a token request.

/// What the authorization server said about itself during discovery.
#[derive(Debug, Clone)]
pub struct Expected {
    /// The `issuer` from the server's own metadata, already validated against
    /// the URL it was fetched from.
    pub issuer: String,
    /// `authorization_response_iss_parameter_supported` (RFC 9207 §3). When
    /// true, an authorization response without `iss` is malformed.
    pub advertises_iss: bool,
}

/// Why a callback was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum IssError {
    /// The server advertised RFC 9207 and then omitted `iss`. Refusing is the
    /// whole point: accepting it would let an attacker strip the parameter and
    /// walk back to the unprotected behaviour.
    Missing { expected: String },
    /// A different issuer than the one this flow was started against.
    Mismatch { expected: String, got: String },
}

impl std::error::Error for IssError {}

impl std::fmt::Display for IssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssError::Missing { expected } => write!(
                f,
                "the authorization response carried no 'iss', but {expected} \
                 advertises RFC 9207 support — refusing to send the code, since \
                 a stripped 'iss' is what a mix-up attack looks like"
            ),
            IssError::Mismatch { expected, got } => write!(
                f,
                "the authorization response came from '{got}', not '{expected}' \
                 — refusing to send the code to a token endpoint it does not \
                 belong to"
            ),
        }
    }
}

/// The RFC 9207 / SEP-2468 table, as one decision.
///
/// | advertised | `iss` present | result |
/// |---|---|---|
/// | yes | yes, matching | accept |
/// | yes | yes, differing | reject — mismatch |
/// | yes | no | reject — missing |
/// | no | yes, matching | accept |
/// | no | yes, differing | reject — mismatch |
/// | no | no | accept |
///
/// The last row is the only concession, and it is forced: a server that does
/// not implement RFC 9207 cannot send the parameter, and refusing every such
/// server would make the flow unusable against most deployments today. The row
/// above it is where this is stricter than the RFC requires — an `iss` that
/// arrives unbidden and disagrees is still a mismatch, because there is no
/// reading of it under which sending the code is correct.
pub fn check(expected: &Expected, returned: Option<&str>) -> Result<(), IssError> {
    match returned {
        Some(got) if got == expected.issuer => Ok(()),
        Some(got) => Err(IssError::Mismatch {
            expected: expected.issuer.clone(),
            got: got.to_string(),
        }),
        None if expected.advertises_iss => Err(IssError::Missing {
            expected: expected.issuer.clone(),
        }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected(advertises: bool) -> Expected {
        Expected {
            issuer: "https://as.example.com".into(),
            advertises_iss: advertises,
        }
    }

    #[test]
    fn the_whole_table() {
        // Every row, named, so a rewrite that collapses two of them fails here
        // rather than in a penetration test.
        assert_eq!(
            check(&expected(true), Some("https://as.example.com")),
            Ok(())
        );
        assert_eq!(
            check(&expected(false), Some("https://as.example.com")),
            Ok(())
        );
        assert_eq!(check(&expected(false), None), Ok(()));

        assert_eq!(
            check(&expected(true), None),
            Err(IssError::Missing {
                expected: "https://as.example.com".into()
            })
        );
        for advertises in [true, false] {
            assert_eq!(
                check(&expected(advertises), Some("https://evil.example.com")),
                Err(IssError::Mismatch {
                    expected: "https://as.example.com".into(),
                    got: "https://evil.example.com".into()
                }),
                "a differing iss is a mismatch whether or not it was advertised"
            );
        }
    }

    #[test]
    fn comparison_is_exact_not_prefix_or_host() {
        // `https://as.example.com.evil.test` shares a prefix, and
        // `https://as.example.com/other` shares a host. Neither is the issuer,
        // and an implementation matching on either would accept a code from a
        // server the user never chose.
        for imposter in [
            "https://as.example.com.evil.test",
            "https://as.example.com/other",
            "https://as.example.com/",
            "http://as.example.com",
            "HTTPS://AS.EXAMPLE.COM",
        ] {
            assert!(
                check(&expected(true), Some(imposter)).is_err(),
                "{imposter} must not pass as the issuer"
            );
        }
    }

    #[test]
    fn the_error_says_what_it_refused_to_do() {
        let e = check(&expected(true), Some("https://evil.example.com")).unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("evil.example.com") && msg.contains("as.example.com"));
        assert!(
            msg.contains("refusing to send the code"),
            "an operator has to learn that nothing was transmitted: {msg}"
        );
    }
}
