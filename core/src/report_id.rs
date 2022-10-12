//! Extensions on report ID representations from `janus_messages`.

use janus_messages::{ReportId, ReportIdChecksum};
use ring::digest::{digest, SHA256, SHA256_OUTPUT_LEN};

/// Additional methods for working with a [`ReportIdChecksum`].
pub trait ReportIdChecksumExt {
    /// Initialize a checksum from a single report ID.
    fn for_report_id(report_id: &ReportId) -> Self;

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
