//! Shorthand constraints for `--allow` / `--deny`: what a provider tells the
//! CLI about its short form. The parsing itself lives with each provider.

/// What a provider tells `--help` (and the audit hint) about its shorthand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShorthandHelp {
    /// Short name accepted wherever the class id is (`fs` for `wasi:filesystem`).
    pub alias: Option<&'static str>,
    /// Grammar of the part after `=`, e.g. `<glob>[:ro|:rw]`. Empty when the
    /// class takes no constraint.
    pub syntax: &'static str,
    /// Complete example flag values, e.g. `fs=/data/**`.
    pub examples: &'static [&'static str],
    /// Placeholder used in the audit hint, e.g. `<path>`. Empty when the class
    /// takes no constraint.
    pub placeholder: &'static str,
}
