//! Writing diagnostic files to disk.

use anyhow::Context;
use derivative::Derivative;
use janus_messages::{AggregationJobId, BatchId, ReportMetadata};
use std::{fmt::Debug, fs::File, io::Write, path::Path, time::SystemTime};
use uuid::Uuid;

/// Represents an illegal attempt to mutate an aggregation job.
#[derive(Derivative, Clone)]
#[derivative(Debug)]
pub struct AggregationJobInitForbiddenMutationEvent {
    /// The ID of the aggregation job.
    pub aggregation_job_id: AggregationJobId,

    /// The SHA-256 of the request that created the aggregation job.
    #[derivative(Debug(format_with = "fmt_hash_option"))]
    pub original_request_hash: Option<[u8; 32]>,

    /// The ordered report metadatas from the request that created the aggregation job.
    pub original_report_metadatas: Vec<ReportMetadata>,

    /// The batch ID in the original request.
    pub original_batch_id: String,

    /// The aggregation param in the original request.
    pub original_aggregation_parameter: Vec<u8>,

    /// The SHA-256 of the request that attempted to mutate the aggregation job.
    #[derivative(Debug(format_with = "fmt_hash_option"))]
    pub mutating_request_hash: Option<[u8; 32]>,

    /// The ordered report metadatas from the request that attempted to mutate the aggregation job.
    pub mutating_request_report_metadatas: Vec<ReportMetadata>,

    /// The batch ID of the mutating request.
    pub mutating_request_batch_id: String,

    /// The aggregation param in the mutating request.
    pub mutating_request_aggregation_parameter: Vec<u8>,
}

fn fmt_hash_option(
    v: &Option<[u8; 32]>,
    f: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    write!(f, "{:?}", v.map(hex::encode))
}

/// Write an event.
///
/// The [`std::fmt::Debug`] representation of `event` will be written to a file named
/// `<event_type>-<timestamp>-<ID>-<version>`, where `event_type` is the provided argument,
/// `timestamp` is the time at which the event was recorded, `ID` is a UUIDv4 and `version` is the
/// version of Janus that generated the event.
pub fn write_event<P: AsRef<Path>>(
    event_storage: P,
    event_type: &'static str,
    event: Box<dyn Debug>,
) -> Result<Uuid, anyhow::Error> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("failed to get current time")?;
    let event_id = Uuid::new_v4();
    let version = env!("CARGO_PKG_VERSION");

    let mut f = File::create(
        event_storage
            .as_ref()
            .join(format!("{event_type}-{now:?}-{event_id}-{version}")),
    )
    .context("failed to open file to write event")?;

    write!(&mut f, "{event:#?}").context("failed to write event")?;

    Ok(event_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{read, read_dir};
    use tempfile::tempdir;

    #[test]
    fn write_two_events() {
        let tempdir = tempdir().unwrap();

        let first_event = "something happened 1";
        let first_event_id = write_event(&tempdir, "test-event", Box::new(first_event)).unwrap();
        let second_event = "something happened 2";
        let second_event_id = write_event(&tempdir, "test-event", Box::new(second_event)).unwrap();

        let entries: Vec<_> = read_dir(&tempdir).unwrap().collect();
        assert_eq!(entries.len(), 2);

        let mut saw_first_event = false;
        let mut saw_second_event = false;

        for entry in entries {
            let event_path = entry.as_ref().unwrap().path();
            let filename = event_path.file_name().unwrap().to_str().unwrap();

            assert!(filename.starts_with("test-event"));
            assert!(filename.ends_with(env!("CARGO_PKG_VERSION")));

            let file_contents = read(&event_path).unwrap();

            if file_contents == b"\"something happened 1\"" {
                assert!(filename.contains(&first_event_id.to_string()));
                saw_first_event = true
            } else if file_contents == b"\"something happened 2\"" {
                assert!(filename.contains(&second_event_id.to_string()));
                saw_second_event = true
            } else {
                panic!("saw unexpected event {file_contents:?}");
            }
        }

        assert!(saw_first_event);
        assert!(saw_second_event);
    }
}
