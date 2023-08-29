//! Testing functionality that interacts with the testcontainers library.

use std::sync::{Arc, Mutex, OnceLock, Weak};
use testcontainers::clients::Cli;

/// Returns a container client, possibly shared with other callers to this function.
pub fn container_client() -> Arc<Cli> {
    // Once `Weak::new` is const in stable Rust, in version 1.73, this should be replaced by a
    // static variable initialized to `Mutex::new(Weak::new())`.
    static CONTAINER_CLIENT_MU: OnceLock<Mutex<Weak<Cli>>> = OnceLock::new();

    let mut container_client = CONTAINER_CLIENT_MU
        .get_or_init(|| Mutex::new(Weak::new()))
        .lock()
        .unwrap();
    container_client.upgrade().unwrap_or_else(|| {
        let client = Arc::new(Cli::default());
        *container_client = Arc::downgrade(&client);
        client
    })
}
