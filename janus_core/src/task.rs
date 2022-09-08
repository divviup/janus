use reqwest::Url;
use ring::constant_time;

/// Identifiers for supported VDAFs, corresponding to definitions in
/// [draft-irtf-cfrg-vdaf-00][1] and implementations in [`prio::vdaf::prio3`].
///
/// [1]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/00/
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum VdafInstance {
    /// A `prio3` counter using the AES 128 pseudorandom generator.
    Prio3Aes128Count,
    /// A `prio3` sum using the AES 128 pseudorandom generator.
    Prio3Aes128Sum { bits: u32 },
    /// A `prio3` histogram using the AES 128 pseudorandom generator.
    Prio3Aes128Histogram { buckets: Vec<u64> },
    /// The `poplar1` VDAF. Support for this VDAF is experimental.
    Poplar1 { bits: usize },
}

/// An authentication (bearer) token used by aggregators for aggregator-to-aggregator and
/// collector-to-aggregator authentication.
#[derive(Clone)]
pub struct AuthenticationToken(Vec<u8>);

impl From<Vec<u8>> for AuthenticationToken {
    fn from(token: Vec<u8>) -> Self {
        Self(token)
    }
}

impl AuthenticationToken {
    /// Returns a view of the aggregator authentication token as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq for AuthenticationToken {
    fn eq(&self, other: &Self) -> bool {
        // We attempt constant-time comparisons of the token data. Note that this function still
        // leaks whether the lengths of the tokens are equal -- this is acceptable because we expect
        // the content of the tokens to provide enough randomness that needs to be guessed even if
        // the length is known.
        constant_time::verify_slices_are_equal(&self.0, &other.0).is_ok()
    }
}

impl Eq for AuthenticationToken {}

/// Modifies a [`Url`] in place to ensure it ends with a slash.
///
/// Aggregator endpoint URLs should end with a slash if they will be used with [`Url::join`],
/// because that method will drop the last path component of the base URL if it does not end with a
/// slash.
pub fn url_ensure_trailing_slash(url: &mut Url) {
    if !url.as_str().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
}
