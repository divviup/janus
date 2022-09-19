//! Extensions on report ID representations from `janus_messages`.

use janus_messages::{ReportId, ReportIdChecksum};
use ring::digest::{digest, SHA256, SHA256_OUTPUT_LEN};

/// Additional methods for working with a [`ReportIdChecksum`].
pub trait ReportIdChecksumExt {
    /// Initialize a checksum from a single report ID.
    fn for_report_id(report_id: &ReportId) -> Self;

    /// Compute the SHA256 hash of a report ID.
    fn report_id_digest(report_id: &ReportId) -> [u8; SHA256_OUTPUT_LEN];

    /// Incorporate the provided report ID into this checksum.
    fn update(&mut self, report_id: &ReportId);

    /// Combine another checksum with this one.
    fn combine(&mut self, other: &ReportIdChecksum);
}

impl ReportIdChecksumExt for ReportIdChecksum {
    fn for_report_id(report_id: &ReportId) -> Self {
        Self::from(Self::report_id_digest(report_id))
    }

    fn report_id_digest(report_id: &ReportId) -> [u8; SHA256_OUTPUT_LEN] {
        digest(&SHA256, report_id.as_ref())
            .as_ref()
            .try_into()
            // panic if somehow the digest ring computes isn't 32 bytes long.
            .unwrap()
    }

    fn update(&mut self, report_id: &ReportId) {
        self.combine(&Self::for_report_id(report_id))
    }

    fn combine(&mut self, other: &ReportIdChecksum) {
        self.as_mut()
            .iter_mut()
            .zip(other.as_ref())
            .for_each(|(x, y)| *x ^= y)
    }
}
