//! Provides a testcontainer image to allow container-based testing of Janus.

use lazy_static::lazy_static;
use regex::Regex;
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    sync::Mutex,
    thread,
};
use testcontainers::{core::WaitFor, Image};

// INTEROP_AGGREGATOR_IMAGE_BYTES / interop_aggregator.tar are created by this package's build.rs.
const INTEROP_AGGREGATOR_IMAGE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/interop_aggregator.tar"));
static INTEROP_AGGREGATOR_IMAGE_HASH: Mutex<Option<String>> = Mutex::new(None);

lazy_static! {
    static ref DOCKER_HASH_RE: Regex = Regex::new(r"sha256:([0-9a-f]{64})").unwrap();
}

/// Represents a Janus Aggregator as a testcontainer image.
#[non_exhaustive]
pub struct Aggregator {}

impl Default for Aggregator {
    fn default() -> Self {
        // One-time initialization step: load compiled image into docker, recording its image tag,
        // so that we can launch it later.
        let mut image_hash = INTEROP_AGGREGATOR_IMAGE_HASH.lock().unwrap();
        if image_hash.is_none() {
            let mut docker_load_child = Command::new("docker")
                .args(["load", "--quiet"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("Failed to execute `docker load` for interop aggregator");
            let mut child_stdin = docker_load_child.stdin.take().unwrap();
            let writer_handle = thread::spawn(move || {
                // We write in a separate thread as "writing more than a pipe buffer's
                // worth of input to stdin without also reading stdout and stderr at the
                // same time may cause a deadlock."
                child_stdin.write_all(INTEROP_AGGREGATOR_IMAGE_BYTES)
            });
            let mut child_stdout = docker_load_child.stdout.take().unwrap();
            let mut stdout = String::new();
            child_stdout
                .read_to_string(&mut stdout)
                .expect("Couldn't read interop aggregator image ID from docker");
            let caps = DOCKER_HASH_RE
                .captures(&stdout)
                .expect("Couldn't find image ID from `docker load` output");
            let hash = caps.get(1).unwrap().as_str().to_string();
            // The first `expect` catches panics, the second `expect` catches write errors.
            writer_handle
                .join()
                .expect("Couldn't write interop aggregator image to docker")
                .expect("Couldn't write interop aggregator image to docker");
            *image_hash = Some(hash);
        }

        Self {}
    }
}

impl Image for Aggregator {
    type Args = ();

    fn name(&self) -> String {
        // This works around a quirk in testconatiners: it will always generated the image name
        // it passes to Docker as "$NAME:$TAG". We want a string of the form "sha256:$HASH". So we
        // hardcode the name to be "sha256" and the tag to be the hash we want.
        "sha256".to_string()
    }

    fn tag(&self) -> String {
        INTEROP_AGGREGATOR_IMAGE_HASH
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone()
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        Vec::new()
    }
}
