//! Extensions on report ID representations from `janus_messages`.

use aws_lc_rs::digest::{SHA256, SHA256_OUTPUT_LEN, digest};
use janus_messages::{ReportId, ReportIdChecksum};

/// Additional methods for working with a [`ReportIdChecksum`].
pub trait ReportIdChecksumExt: Sized {
    /// Initialize a checksum from a single report ID.
    fn for_report_id(report_id: &ReportId) -> Self;

    /// Initialize a checksum from multiple report IDs.
    fn from_report_ids(report_ids: &[ReportId]) -> Self {
        let mut ret = Self::for_report_id(&report_ids[0]);
        for report_id in &report_ids[1..] {
            ret = ret.updated_with(report_id);
        }

        ret
    }

    /// Incorporate the provided report ID into this checksum.
    fn updated_with(self, report_id: &ReportId) -> Self;

    /// Combine another checksum with this one.
    fn combined_with(self, other: &Self) -> Self;
}

impl ReportIdChecksumExt for ReportIdChecksum {
    fn for_report_id(report_id: &ReportId) -> Self {
        Self::from(report_id_digest(report_id))
    }

    fn updated_with(self, report_id: &ReportId) -> Self {
        self.combined_with(&Self::for_report_id(report_id))
    }

    fn combined_with(mut self, other: &Self) -> Self {
        self.as_mut()
            .iter_mut()
            .zip(other.as_ref())
            .for_each(|(x, y)| *x ^= y);
        self
    }
}

fn report_id_digest(report_id: &ReportId) -> [u8; SHA256_OUTPUT_LEN] {
    digest(&SHA256, report_id.as_ref())
        .as_ref()
        .try_into()
        // panic if somehow the digest ring computes isn't 32 bytes long.
        .unwrap()
}
