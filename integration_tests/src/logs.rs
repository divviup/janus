//! Functionality for extracting logs from a containerized DAP actor.

use std::{convert::AsRef, path::Path};

pub trait CopyLogs {
    /// Copies log files out of the container's `/logs` directory and into the host filesystem for
    /// later analysis. Log files are written to a directory whose name is the container's ID,
    /// created under `destination`.
    fn logs<P: AsRef<Path>>(&self, destination: &P);
}
