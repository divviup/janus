#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::too_many_arguments)]

pub mod aggregator;
pub mod binaries;
pub mod binary_utils;
pub mod cache;
pub mod config;
pub mod metrics;
pub mod trace;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Operation {
    Put,
    Update,
}
