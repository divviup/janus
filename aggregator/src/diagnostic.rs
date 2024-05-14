//! Writing diagnostic files to disk.

use anyhow::Context;
use derivative::Derivative;
use janus_messages::{AggregationJobId, ReportMetadata, TaskId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fs::File, path::Path, time::SystemTime};
use uuid::Uuid;

/// Represents an illegal attempt to mutate an aggregation job.
#[derive(Derivative, Clone, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct AggregationJobInitForbiddenMutationEvent {
    /// The ID of the task.
    #[serde(with = "serialize_task_id")]
    pub task_id: TaskId,

    /// The ID of the aggregation job.
    #[serde(with = "serialize_job_id")]
    pub aggregation_job_id: AggregationJobId,

    /// The SHA-256 of the request that created the aggregation job.
    #[serde(with = "serialize_hash_option")]
    #[derivative(Debug(format_with = "fmt_hash_option"))]
    pub original_request_hash: Option<[u8; 32]>,

    /// The ordered report metadatas from the request that created the aggregation job.
    #[serde(with = "serialize_metadata_vec")]
    pub original_report_metadatas: Vec<ReportMetadata>,

    /// The batch ID in the original request.
    pub original_batch_id: String,

    /// The aggregation param in the original request.
    pub original_aggregation_parameter: Vec<u8>,

    /// The SHA-256 of the request that attempted to mutate the aggregation job.
    #[serde(with = "serialize_hash_option")]
    #[derivative(Debug(format_with = "fmt_hash_option"))]
    pub mutating_request_hash: Option<[u8; 32]>,

    /// The ordered report metadatas from the request that attempted to mutate the aggregation job.
    #[serde(with = "serialize_metadata_vec")]
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

mod serialize_hash_option {
    use super::*;

    pub fn serialize<S: Serializer>(
        value: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.serialize_some(&hex::encode(value)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(_deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        todo!("can't deserialize yet")
    }
}

mod serialize_task_id {
    use super::*;

    pub fn serialize<S: Serializer>(value: &TaskId, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{value:?}"))
    }

    pub fn deserialize<'de, D>(_deserializer: D) -> Result<TaskId, D::Error>
    where
        D: Deserializer<'de>,
    {
        todo!("can't deserialize yet")
    }
}

mod serialize_job_id {
    use super::*;

    pub fn serialize<S: Serializer>(
        value: &AggregationJobId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{value:?}"))
    }

    pub fn deserialize<'de, D>(_deserializer: D) -> Result<AggregationJobId, D::Error>
    where
        D: Deserializer<'de>,
    {
        todo!("can't deserialize yet")
    }
}

mod serialize_metadata_vec {
    use super::*;

    pub fn serialize<S: Serializer>(
        value: &[ReportMetadata],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct SerializableReportMetadata {
            report_id: String,
            time: String,
        }

        serializer.collect_seq(value.iter().map(|rm| SerializableReportMetadata {
            report_id: format!("{:?}", rm.id()),
            time: format!("{:?}", rm.time()),
        }))
    }

    pub fn deserialize<'de, D>(_deserializer: D) -> Result<Vec<ReportMetadata>, D::Error>
    where
        D: Deserializer<'de>,
    {
        todo!("can't deserialize yet")
    }
}

/// An event along with some metadata describing it.
#[derive(Debug, Serialize, Deserialize)]
struct Event<E> {
    /// Unique identifier for the event.
    id: Uuid,
    /// Unix epoch time at which the event was recorded.
    time: String,
    /// Type of the event.
    event_type: String,
    /// Version of Janus that recorded the event.
    janus_version: String,
    /// The event itself.
    event: E,
}

/// Write an event.
///
/// The JSON representation of `event` will be written to a file named
/// `<event_type>-<timestamp>-<ID>-<version>.json`, where `event_type` is the provided argument,
/// `timestamp` is the time at which the event was recorded, `ID` is a UUIDv4 and `version` is the
/// version of Janus that generated the event. The JSON document will also contain this metadata in
/// a structured form.
pub async fn write_event<P: AsRef<Path>, S: Serialize + Send + Sync + 'static>(
    event_storage: P,
    event_type: &'static str,
    event: S,
) -> Result<Uuid, anyhow::Error> {
    let now = format!(
        "{:?}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .context("failed to get current time")?
    );
    let event_id = Uuid::new_v4();
    let janus_version = env!("CARGO_PKG_VERSION");

    let event_with_metadata = Event {
        id: event_id,
        time: now.clone(),
        event_type: event_type.to_string(),
        janus_version: janus_version.to_string(),
        event,
    };

    let event_storage_path = event_storage.as_ref().join(format!(
        "{event_type}-{now}-{event_id}-{janus_version}.json"
    ));

    tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
        let mut f =
            File::create(event_storage_path).context("failed to open file to write event")?;

        serde_json::to_writer(&mut f, &event_with_metadata).context("failed to write event")?;

        f.sync_all().context("failed to sync file contents")?;

        Ok(())
    })
    .await??;

    Ok(event_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::read_dir, io::BufReader};
    use tempfile::tempdir;

    #[tokio::test]
    async fn write_two_events() {
        let tempdir = tempdir().unwrap();

        let first_event_id = write_event(&tempdir, "test-event", 1).await.unwrap();
        let second_event_id = write_event(&tempdir, "test-event", 2).await.unwrap();

        let entries: Vec<_> = read_dir(&tempdir).unwrap().map(|r| r.unwrap()).collect();
        assert_eq!(entries.len(), 2);

        let mut saw_first_event = false;
        let mut saw_second_event = false;

        for entry in entries {
            let event_path = entry.path();
            let filename = event_path.file_name().unwrap().to_str().unwrap();

            assert!(filename.starts_with("test-event"));
            assert!(filename.ends_with(&format!("{}.json", env!("CARGO_PKG_VERSION"))));

            let event: Event<u32> =
                serde_json::from_reader(BufReader::new(File::open(&event_path).unwrap())).unwrap();

            assert_eq!(event.event_type, "test-event");
            assert_eq!(event.janus_version, env!("CARGO_PKG_VERSION"));

            if event.id == first_event_id {
                assert!(filename.contains(&first_event_id.to_string()));
                assert_eq!(event.event, 1);
                saw_first_event = true
            } else if event.id == second_event_id {
                assert!(filename.contains(&second_event_id.to_string()));
                assert_eq!(event.event, 2);
                saw_second_event = true
            } else {
                panic!("saw unexpected event {event:?}");
            }
        }

        assert!(saw_first_event);
        assert!(saw_second_event);
    }
}
