//! Testing functionality that interacts with the testcontainers library.

use std::sync::{Arc, Mutex, Weak};
use testcontainers::clients::Cli;

/// Returns a container client, possibly shared with other callers to this function.
pub fn container_client() -> Arc<Cli> {
    // Once `Weak::new` is const in stable Rust, this should be replaced by a static variable
    // initialized to `Mutex::new(Weak::new())`. [https://github.com/rust-lang/rust/issues/95091]
    lazy_static::lazy_static! {
        static ref CONTAINER_CLIENT_MU: Mutex<Weak<Cli>> = Mutex::new(Weak::new());
    }

    let mut container_client = CONTAINER_CLIENT_MU.lock().unwrap();
    container_client.upgrade().unwrap_or_else(|| {
        let client = Arc::new(Cli::default());
        *container_client = Arc::downgrade(&client);
        client
    })
}
