#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::too_many_arguments)]

use git_version::git_version;

pub mod aggregator;
pub mod binaries;
pub mod binary_utils;
pub mod cache;
pub mod config;
pub mod diagnostic;
pub mod metrics;
pub mod trace;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Operation {
    Put,
    Update,
}

/// Returns the git revision used to build this crate, using `git describe` if available, or the
/// environment variable `GIT_REVISION`. Returns `"unknown"` instead if neither is available.
pub fn git_revision() -> &'static str {
    let mut git_revision: &'static str = git_version!(fallback = "unknown");
    if git_revision == "unknown" {
        if let Some(value) = option_env!("GIT_REVISION") {
            git_revision = value;
        }
    }
    git_revision
}
