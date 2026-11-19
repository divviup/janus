use janus_messages::{
    AggregateShareId, AggregationJobId, AggregationJobStep, CollectionJobId, TaskId,
};

use url::Url;

/// Extension trait for [`Url`].
pub trait UrlExt: Sized {
    /// Returns this URL, modified to end with a slash if it does not already.
    ///
    /// A base URL must end with a slash for [`Url::join`] to preserve its last path component.
    fn ensure_trailing_slash(self) -> Self;

    /// Construct a URI relative to which other DAP resource URIs can be constructed.
    fn tasks_uri(&self, task_id: TaskId) -> Result<Self, url::ParseError>;

    /// Construct a URI relative to this URL for the leader report upload resource.
    fn report_upload_uri(&self, task_id: TaskId) -> Result<Self, url::ParseError>;

    /// Construct a URI relative to this URL for the helper aggregation job creation resource.
    fn aggregation_job_creation_uri(&self, task_id: TaskId) -> Result<Self, url::ParseError>;

    /// Construct a URI relative to this URL for the helper aggregation job resource.
    fn aggregation_job_uri(
        &self,
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
        step: Option<AggregationJobStep>,
    ) -> Result<Url, url::ParseError>;

    /// Construct a URI relative to this URL for the leader collection job creation resource.
    fn collection_job_creation_uri(&self, task_id: TaskId) -> Result<Self, url::ParseError>;

    /// Construct a URI relative to this URL for the leader collection job resource.
    fn collection_job_uri(
        &self,
        task_id: TaskId,
        collection_job_id: CollectionJobId,
    ) -> Result<Url, url::ParseError>;

    /// Construct a URI relative to this URL for the helper aggregate share creation resource.
    fn aggregate_share_creation_uri(&self, task_id: TaskId) -> Result<Self, url::ParseError>;

    /// Construct a URI relative to this URL for the helper aggregate share resource.
    fn aggregate_share_uri(
        &self,
        task_id: TaskId,
        aggregate_share_id: AggregateShareId,
    ) -> Result<Url, url::ParseError>;
}

impl UrlExt for Url {
    fn ensure_trailing_slash(mut self) -> Self {
        if !self.as_str().ends_with('/') {
            self.set_path(&format!("{}/", self.path()));
        }
        self
    }

    fn tasks_uri(&self, task_id: TaskId) -> Result<Self, url::ParseError> {
        // Ensure the base URL has a trailing slash, and then append a path component with a
        // trailing URL so other methods can subsequently append path components.
        Ok(self
            .clone()
            .ensure_trailing_slash()
            .join(&format!("tasks/{task_id}/"))?)
    }

    fn report_upload_uri(&self, task_id: TaskId) -> Result<Self, url::ParseError> {
        self.tasks_uri(task_id)?.join("reports")
    }

    fn aggregation_job_creation_uri(&self, task_id: TaskId) -> Result<Self, url::ParseError> {
        self.tasks_uri(task_id)?.join("aggregation_jobs")
    }

    fn aggregation_job_uri(
        &self,
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
        step: Option<AggregationJobStep>,
    ) -> Result<Url, url::ParseError> {
        let mut uri = self
            .aggregation_job_creation_uri(task_id)?
            .ensure_trailing_slash()
            .join(&format!("{aggregation_job_id}"))?;

        if let Some(step) = step {
            uri.query_pairs_mut()
                .append_pair("step", &u16::from(step).to_string());
        }

        Ok(uri)
    }

    fn collection_job_creation_uri(&self, task_id: TaskId) -> Result<Self, url::ParseError> {
        self.tasks_uri(task_id)?.join("collection_jobs")
    }

    fn collection_job_uri(
        &self,
        task_id: TaskId,
        collection_job_id: CollectionJobId,
    ) -> Result<Url, url::ParseError> {
        Ok(self
            .collection_job_creation_uri(task_id)?
            .ensure_trailing_slash()
            .join(&format!("{collection_job_id}"))?)
    }

    fn aggregate_share_creation_uri(&self, task_id: TaskId) -> Result<Self, url::ParseError> {
        self.tasks_uri(task_id)?.join("aggregate_shares")
    }

    fn aggregate_share_uri(
        &self,
        task_id: TaskId,
        aggregate_share_id: AggregateShareId,
    ) -> Result<Url, url::ParseError> {
        Ok(self
            .aggregate_share_creation_uri(task_id)?
            .ensure_trailing_slash()
            .join(&format!("{aggregate_share_id}"))?)
    }
}

/// Converts a [`janus_messages::Url`] into a [`url::Url`] ready for [`Url::join`], ensuring a
/// trailing slash so `join` does not drop the last path component.
///
/// The trailing-slash fixup applies only to this routing copy, never to the stored
/// [`janus_messages::Url`] — its exact bytes are bound into HPKE AADs and must not be re-encoded
/// (DAP-18 §4.1).
pub fn url_for_join(url: &janus_messages::Url) -> Result<Url, url::ParseError> {
    Ok(Url::try_from(url)?.ensure_trailing_slash())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn dap_uri_construction() {
        let task_id = TaskId::from_str("ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4").unwrap();
        let job_id = "_Ruk_njErWlidLK2YtFxPA";

        for (
            description,
            base,
            expect_upload,
            expect_aggregation_job_create,
            expect_aggregation_job_no_step,
            expect_aggregation_job_with_step,
            expect_collection_job_create,
            expect_collection_job,
            expect_aggregate_share_create,
            expect_aggregate_share,
        ) in [
            (
                "no path, no trailing slash",
                "https://example.com",
                "https://example.com/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/reports",
                "https://example.com/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregation_jobs",
                "https://example.com/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregation_jobs/_Ruk_njErWlidLK2YtFxPA",
                "https://example.com/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregation_jobs/_Ruk_njErWlidLK2YtFxPA?step=1",
                "https://example.com/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/collection_jobs",
                "https://example.com/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/collection_jobs/_Ruk_njErWlidLK2YtFxPA",
                "https://example.com/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregate_shares",
                "https://example.com/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregate_shares/_Ruk_njErWlidLK2YtFxPA",
            ),
            (
                "no path, trailing slash",
                "https://example.com",
                "https://example.com/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/reports",
                "https://example.com/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregation_jobs",
                "https://example.com/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregation_jobs/_Ruk_njErWlidLK2YtFxPA",
                "https://example.com/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregation_jobs/_Ruk_njErWlidLK2YtFxPA?step=1",
                "https://example.com/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/collection_jobs",
                "https://example.com/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/collection_jobs/_Ruk_njErWlidLK2YtFxPA",
                "https://example.com/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregate_shares",
                "https://example.com/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregate_shares/_Ruk_njErWlidLK2YtFxPA",
            ),
            (
                "path, no trailing slash",
                "https://example.com/path/components",
                "https://example.com/path/components/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/reports",
                "https://example.com/path/components/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregation_jobs",
                "https://example.com/path/components/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregation_jobs/_Ruk_njErWlidLK2YtFxPA",
                "https://example.com/path/components/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregation_jobs/_Ruk_njErWlidLK2YtFxPA?step=1",
                "https://example.com/path/components/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/collection_jobs",
                "https://example.com/path/components/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/collection_jobs/_Ruk_njErWlidLK2YtFxPA",
                "https://example.com/path/components/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregate_shares",
                "https://example.com/path/components/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregate_shares/_Ruk_njErWlidLK2YtFxPA",
            ),
            (
                "path, trailing slash",
                "https://example.com/path/components/",
                "https://example.com/path/components/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/reports",
                "https://example.com/path/components/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregation_jobs",
                "https://example.com/path/components/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregation_jobs/_Ruk_njErWlidLK2YtFxPA",
                "https://example.com/path/components/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregation_jobs/_Ruk_njErWlidLK2YtFxPA?step=1",
                "https://example.com/path/components/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/collection_jobs",
                "https://example.com/path/components/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/collection_jobs/_Ruk_njErWlidLK2YtFxPA",
                "https://example.com/path/components/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregate_shares",
                "https://example.com/path/components/tasks/ii_NZYRUHjMI9YCQMmD2ZJNUpLiVz1KHEg-ANpWWnG4/aggregate_shares/_Ruk_njErWlidLK2YtFxPA",
            ),
        ] {
            let base = Url::parse(base).unwrap();
            assert_eq!(
                base.report_upload_uri(task_id).unwrap(),
                Url::parse(expect_upload).unwrap(),
                "{description}",
            );
            assert_eq!(
                base.aggregation_job_creation_uri(task_id).unwrap(),
                Url::parse(expect_aggregation_job_create).unwrap(),
                "{description}",
            );
            assert_eq!(
                base.aggregation_job_uri(
                    task_id,
                    AggregationJobId::from_str(job_id).unwrap(),
                    None
                )
                .unwrap(),
                Url::parse(expect_aggregation_job_no_step).unwrap(),
                "{description}",
            );
            assert_eq!(
                base.aggregation_job_uri(
                    task_id,
                    AggregationJobId::from_str(job_id).unwrap(),
                    Some(1.into())
                )
                .unwrap(),
                Url::parse(expect_aggregation_job_with_step).unwrap(),
                "{description}",
            );
            assert_eq!(
                base.collection_job_creation_uri(task_id).unwrap(),
                Url::parse(expect_collection_job_create).unwrap(),
                "{description}",
            );
            assert_eq!(
                base.collection_job_uri(task_id, CollectionJobId::from_str(job_id).unwrap())
                    .unwrap(),
                Url::parse(expect_collection_job).unwrap(),
                "{description}",
            );
            assert_eq!(
                base.aggregate_share_creation_uri(task_id).unwrap(),
                Url::parse(expect_aggregate_share_create).unwrap(),
                "{description}",
            );
            assert_eq!(
                base.aggregate_share_uri(task_id, AggregateShareId::from_str(job_id).unwrap())
                    .unwrap(),
                Url::parse(expect_aggregate_share).unwrap(),
                "{description}",
            );
        }
    }
}
