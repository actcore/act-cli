//! Properties of the two matchers that decide whether a guest may touch a
//! file or reach a host.
//!
//! These are the crate's security boundary, and both carry a rule that is
//! easy to state and easy to get subtly wrong: the filesystem matcher allows
//! *reading* a directory that merely lies on the path to an allowed target
//! (WASI stats every intermediate directory), and the network matcher treats
//! `*.example.com` as a suffix with a dot boundary. The example-based tests
//! next to each module pin the cases someone thought of. These pin the
//! relationships that must hold for every input, which is where a rewrite of
//! either matcher would actually go wrong.
//!
//! Generators draw path segments and host labels from a small fixed
//! alphabet, deliberately: random text would almost always miss every
//! pattern and the properties would pass without ever exercising a match.

use act_policy::Decision;
use act_policy::fs_matcher::{FsAccess, FsMatcher};
use act_policy::grant::{FsAllow, FsConfig, PolicyMode};
use act_policy::net::{self, NetworkCheck, NetworkRule};
use act_types::FsMode;
use proptest::prelude::*;

// ── Filesystem ───────────────────────────────────────────────────────────

/// A short absolute path. Only `/`-rooted: `expand_pattern` resolves a
/// relative pattern against the process's current directory, which would
/// make these tests depend on where they were run from.
fn abs_path() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop::sample::select(vec!["a", "b", "c", "data", "tmp", "db.sqlite"]),
        1..4,
    )
    .prop_map(|segs| format!("/{}", segs.join("/")))
}

/// A path, a subtree (`/x/**`), or a single-level wildcard (`/x/*`) — the
/// three shapes an operator actually writes in a grant.
fn fs_glob() -> impl Strategy<Value = String> {
    abs_path().prop_flat_map(|p| {
        prop_oneof![
            Just(p.clone()),
            Just(format!("{p}/**")),
            Just(format!("{p}/*")),
        ]
    })
}

fn fs_allow() -> impl Strategy<Value = FsAllow> {
    (
        fs_glob(),
        prop::sample::select(vec![FsMode::Ro, FsMode::Rw]),
    )
        .prop_map(|(glob, mode)| FsAllow { glob, mode })
}

fn fs_config(mode: PolicyMode) -> impl Strategy<Value = FsConfig> {
    (
        proptest::collection::vec(fs_allow(), 0..4),
        proptest::collection::vec(fs_glob(), 0..3),
    )
        .prop_map(move |(allow, deny)| FsConfig { mode, allow, deny })
}

fn access() -> impl Strategy<Value = FsAccess> {
    prop::sample::select(vec![FsAccess::Read, FsAccess::Write])
}

proptest! {
    /// `Deny` short-circuits before any glob is consulted. A grant that
    /// somehow matched would still have to lose.
    #[test]
    fn deny_mode_denies_everything(
        cfg in fs_config(PolicyMode::Deny),
        path in abs_path(),
        acc in access(),
    ) {
        let m = FsMatcher::compile(&cfg).expect("compiles");
        prop_assert_eq!(m.decide(std::path::Path::new(&path), acc), Decision::Deny);
    }

    /// The mirror image: `Open` is the whole declared ceiling, and a deny
    /// entry inside it does not narrow it — narrowing is `allowlist`'s job.
    #[test]
    fn open_mode_allows_everything(
        cfg in fs_config(PolicyMode::Open),
        path in abs_path(),
        acc in access(),
    ) {
        let m = FsMatcher::compile(&cfg).expect("compiles");
        prop_assert_eq!(m.decide(std::path::Path::new(&path), acc), Decision::Allow);
    }

    /// Write access is never broader than read access.
    ///
    /// Two separate things have to hold for this: the write set is built
    /// from the `rw` entries only (a subset of the read set's), and
    /// ancestor traversal — the rule that opens intermediate directories —
    /// applies to reads alone. Wiring traversal into the write path, the
    /// obvious "fix" for a component that cannot create a file in a granted
    /// directory, breaks this and hands out write access to every parent
    /// directory up to `/`.
    #[test]
    fn write_never_exceeds_read(
        cfg in fs_config(PolicyMode::Allowlist),
        path in abs_path(),
    ) {
        let m = FsMatcher::compile(&cfg).expect("compiles");
        let p = std::path::Path::new(&path);
        if m.decide(p, FsAccess::Write) == Decision::Allow {
            prop_assert_eq!(m.decide(p, FsAccess::Read), Decision::Allow);
        }
    }

    /// Every allowed write is attributable to a rule the operator wrote.
    ///
    /// `which_allow` answers from the per-entry glob sets and knows nothing
    /// about ancestor traversal, so an allowed write it cannot attribute is
    /// a write that came from somewhere other than a grant. Read is
    /// deliberately not asserted this way: an allowed read *may* be
    /// unattributable, because traversal is exactly that case.
    #[test]
    fn an_allowed_write_always_names_a_rule(
        cfg in fs_config(PolicyMode::Allowlist),
        path in abs_path(),
    ) {
        let m = FsMatcher::compile(&cfg).expect("compiles");
        let p = std::path::Path::new(&path);
        if m.decide(p, FsAccess::Write) == Decision::Allow {
            prop_assert!(
                m.which_allow(p, FsAccess::Write).is_some(),
                "{} was allowed for write with no matching rule",
                path
            );
        }
    }

    /// A deny entry wins over any allow entry, for both access types.
    #[test]
    fn deny_entries_beat_allow_entries(
        cfg in fs_config(PolicyMode::Allowlist),
        path in abs_path(),
        acc in access(),
    ) {
        let denied = FsMatcher::compile(&FsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![],
            deny: cfg.deny.clone(),
        })
        .expect("compiles");
        let p = std::path::Path::new(&path);
        // `deny`-only config: anything it denies by rule (rather than by
        // falling through) must stay denied once the allow list is added.
        let deny_only_decision = denied.decide(p, acc);
        let m = FsMatcher::compile(&cfg).expect("compiles");
        if deny_only_decision == Decision::Deny && !cfg.deny.is_empty() {
            // Only meaningful where the deny list actually matched; a
            // fall-through `Deny` says nothing. Re-check by asking whether
            // an all-permitting allow list would still refuse.
            let permissive = FsMatcher::compile(&FsConfig {
                mode: PolicyMode::Allowlist,
                allow: vec![FsAllow { glob: "/**".into(), mode: FsMode::Rw }],
                deny: cfg.deny.clone(),
            })
            .expect("compiles");
            if permissive.decide(p, acc) == Decision::Deny {
                prop_assert_eq!(m.decide(p, acc), Decision::Deny);
            }
        }
    }

    /// `ask` is `allowlist` with `Allow` renamed to `Ask` — nothing else.
    ///
    /// The documented contract (`decide`'s comment, ACT's ask-by-default
    /// design) is that `ask` is *bounded by the ceiling*: it prompts where
    /// an allowlist would have permitted, and refuses without prompting
    /// everywhere else. Stated as an equivalence it also rules out the
    /// failure that would matter most — a target outside the ceiling
    /// reaching a human prompt, where a distracted yes grants what no grant
    /// ever declared.
    #[test]
    fn ask_is_allowlist_with_allow_renamed(
        cfg in fs_config(PolicyMode::Allowlist),
        path in abs_path(),
        acc in access(),
    ) {
        let allowlist = FsMatcher::compile(&cfg).expect("compiles");
        let ask = FsMatcher::compile(&FsConfig { mode: PolicyMode::Ask, ..cfg.clone() })
            .expect("compiles");
        let p = std::path::Path::new(&path);
        let expected = match allowlist.decide(p, acc) {
            Decision::Allow => Decision::Ask,
            other => other,
        };
        prop_assert_eq!(ask.decide(p, acc), expected);
    }

    /// Nothing is reachable through an empty allowlist. The traversal rule
    /// widens an existing grant; with no grant there is nothing to widen,
    /// and a matcher that returned `Allow` here would be opening `/`.
    #[test]
    fn an_empty_allowlist_reaches_nothing(path in abs_path(), acc in access()) {
        let m = FsMatcher::compile(&FsConfig {
            mode: PolicyMode::Allowlist,
            allow: vec![],
            deny: vec![],
        })
        .expect("compiles");
        prop_assert_eq!(m.decide(std::path::Path::new(&path), acc), Decision::Deny);
    }
}

// ── Network ──────────────────────────────────────────────────────────────

fn host() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop::sample::select(vec!["api", "www", "example", "com", "net", "evil"]),
        1..4,
    )
    .prop_map(|labels| labels.join("."))
}

fn host_pattern() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("*".to_string()),
        host(),
        host().prop_map(|h| format!("*.{h}"))
    ]
}

fn network_rule() -> impl Strategy<Value = NetworkRule> {
    (
        prop::option::of(host_pattern()),
        prop::option::of(proptest::collection::vec(
            prop::sample::select(vec![80u16, 443, 5432]),
            1..3,
        )),
    )
        .prop_map(|(host, ports)| NetworkRule {
            host,
            ports,
            cidr: None,
            except_ports: None,
        })
}

proptest! {
    /// `*` is the any-host wildcard, with no input it declines.
    #[test]
    fn star_matches_every_host(h in host()) {
        prop_assert!(net::host_matches("*", &h));
    }

    /// Host comparison is ASCII-case-insensitive on both sides — DNS names
    /// are, and a policy that were not would be bypassable by typing
    /// `API.Example.Com`.
    #[test]
    fn host_matching_ignores_case(pat in host_pattern(), h in host()) {
        let expected = net::host_matches(&pat, &h);
        prop_assert_eq!(net::host_matches(&pat.to_uppercase(), &h), expected);
        prop_assert_eq!(net::host_matches(&pat, &h.to_uppercase()), expected);
    }

    /// A `*.suffix` pattern matches on a label boundary, never on raw text.
    ///
    /// This is the classic suffix-matching hole: `*.example.com` written as
    /// `ends_with("example.com")` also accepts `notexample.com`, which an
    /// attacker registers. Any prefix glued straight onto the suffix must be
    /// rejected; the same prefix with a dot must be accepted.
    #[test]
    fn wildcard_suffix_matches_only_on_a_label_boundary(
        suffix in host(),
        prefix in prop::sample::select(vec!["evil", "not", "x"]),
    ) {
        let pattern = format!("*.{suffix}");
        // Bound to locals: `prop_assert!` stringifies the expression into its
        // own format string, so a `format!` written inline inside it cannot
        // capture from this scope.
        let glued = format!("{prefix}{suffix}");
        let separated = format!("{prefix}.{suffix}");
        prop_assert!(
            !net::host_matches(&pattern, &glued),
            "{} must not match {}",
            pattern,
            glued
        );
        prop_assert!(net::host_matches(&pattern, &separated));
        // The suffix itself is in scope: `*.example.com` covers `example.com`.
        prop_assert!(net::host_matches(&pattern, &suffix));
    }

    /// Same absorbing modes as the filesystem matcher, so the two dimensions
    /// cannot disagree about what a mode means.
    #[test]
    fn network_deny_and_open_modes_are_absorbing(
        allow in proptest::collection::vec(network_rule(), 0..3),
        deny in proptest::collection::vec(network_rule(), 0..3),
        h in host(),
        port in prop::sample::select(vec![80u16, 443, 5432, 9999]),
    ) {
        let check = NetworkCheck::new(&h, port);
        prop_assert_eq!(net::decide(PolicyMode::Deny, &allow, &deny, &check), Decision::Deny);
        prop_assert_eq!(net::decide(PolicyMode::Open, &allow, &deny, &check), Decision::Allow);
    }

    /// A matching deny rule wins no matter what the allow list says.
    #[test]
    fn a_matching_deny_rule_wins(
        allow in proptest::collection::vec(network_rule(), 0..3),
        deny_rule in network_rule(),
        h in host(),
        port in prop::sample::select(vec![80u16, 443, 5432]),
    ) {
        let check = NetworkCheck::new(&h, port);
        if net::rule_matches(&deny_rule, &check) {
            let deny = vec![deny_rule];
            prop_assert_eq!(
                net::decide(PolicyMode::Allowlist, &allow, &deny, &check),
                Decision::Deny
            );
            prop_assert_eq!(
                net::decide(PolicyMode::Ask, &allow, &deny, &check),
                Decision::Deny
            );
        }
    }

    /// As on the filesystem side: `ask` prompts exactly where an allowlist
    /// would have permitted, and refuses everywhere else without asking.
    #[test]
    fn network_ask_is_allowlist_with_allow_renamed(
        allow in proptest::collection::vec(network_rule(), 0..3),
        deny in proptest::collection::vec(network_rule(), 0..3),
        h in host(),
        port in prop::sample::select(vec![80u16, 443, 5432, 9999]),
    ) {
        let check = NetworkCheck::new(&h, port);
        let expected = match net::decide(PolicyMode::Allowlist, &allow, &deny, &check) {
            Decision::Allow => Decision::Ask,
            other => other,
        };
        prop_assert_eq!(net::decide(PolicyMode::Ask, &allow, &deny, &check), expected);
    }
}
