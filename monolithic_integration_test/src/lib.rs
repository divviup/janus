//! This crate contains functionality useful for Janus integration tests.

use lazy_static::lazy_static;
use tokio::sync::Mutex;

pub mod daphne;
pub mod janus;

// lazy_static! {
//     pub static ref MUTEX: Mutex<()> = Mutex::new(());
// }
