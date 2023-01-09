use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{distributions::Standard, prelude::Distribution};
use reqwest::Url;
use ring::constant_time;
use serde::{Deserialize, Serialize};

/// HTTP header where auth tokens are provided in messages between participants.
pub const DAP_AUTH_HEADER: &str = "DAP-Auth-Token";

/// The length of the verify key parameter for Prio3 AES-128 VDAF instantiations.
pub const PRIO3_AES128_VERIFY_KEY_LENGTH: usize = 16;

/// Identifiers for supported VDAFs, corresponding to definitions in
/// [draft-irtf-cfrg-vdaf-03][1] and implementations in [`prio::vdaf::prio3`].
///
/// [1]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/03/
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum VdafInstance {
    /// A `prio3` counter using the AES 128 pseudorandom generator.
    Prio3Aes128Count,
    /// A vector of `prio3` counters using the AES 128 pseudorandom generator.
    Prio3Aes128CountVec { length: usize },
    /// A `prio3` sum using the AES 128 pseudorandom generator.
    Prio3Aes128Sum { bits: u32 },
    /// A `prio3` histogram using the AES 128 pseudorandom generator.
    Prio3Aes128Histogram { buckets: Vec<u64> },
    /// The `poplar1` VDAF. Support for this VDAF is experimental.
    Poplar1 { bits: usize },

    /// A fake, no-op VDAF.
    #[cfg(feature = "test-util")]
    #[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
    Fake,
    /// A fake, no-op VDAF that always fails during initialization of input preparation.
    #[cfg(feature = "test-util")]
    #[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
    FakeFailsPrepInit,
    /// A fake, no-op VDAF that always fails when stepping input preparation.
    #[cfg(feature = "test-util")]
    #[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
    FakeFailsPrepStep,
}

impl VdafInstance {
    /// Returns the expected length of a VDAF verification key for a VDAF of this type.
    pub fn verify_key_length(&self) -> usize {
        match self {
            #[cfg(feature = "test-util")]
            VdafInstance::Fake
            | VdafInstance::FakeFailsPrepInit
            | VdafInstance::FakeFailsPrepStep => 0,

            // All "real" VDAFs use a verify key of length 16 currently. (Poplar1 may not, but it's
            // not yet done being specified, so choosing 16 bytes is fine for testing.)
            _ => PRIO3_AES128_VERIFY_KEY_LENGTH,
        }
    }
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

impl Distribution<AuthenticationToken> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> AuthenticationToken {
        let buf: [u8; 16] = rng.gen();
        URL_SAFE_NO_PAD.encode(buf).into_bytes().into()
    }
}

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

#[cfg(test)]
mod tests {
    use super::VdafInstance;
    use serde_test::{assert_tokens, Token};

    #[test]
    fn vdaf_serialization() {
        // The `Vdaf` type must have a stable serialization, as it gets stored in a JSON database
        // column.
        assert_tokens(
            &VdafInstance::Prio3Aes128Count,
            &[Token::UnitVariant {
                name: "VdafInstance",
                variant: "Prio3Aes128Count",
            }],
        );
        assert_tokens(
            &VdafInstance::Prio3Aes128CountVec { length: 8 },
            &[
                Token::StructVariant {
                    name: "VdafInstance",
                    variant: "Prio3Aes128CountVec",
                    len: 1,
                },
                Token::Str("length"),
                Token::U64(8),
                Token::StructVariantEnd,
            ],
        );
        assert_tokens(
            &VdafInstance::Prio3Aes128Sum { bits: 64 },
            &[
                Token::StructVariant {
                    name: "VdafInstance",
                    variant: "Prio3Aes128Sum",
                    len: 1,
                },
                Token::Str("bits"),
                Token::U32(64),
                Token::StructVariantEnd,
            ],
        );
        assert_tokens(
            &VdafInstance::Prio3Aes128Histogram {
                buckets: Vec::from([0, 100, 200, 400]),
            },
            &[
                Token::StructVariant {
                    name: "VdafInstance",
                    variant: "Prio3Aes128Histogram",
                    len: 1,
                },
                Token::Str("buckets"),
                Token::Seq { len: Some(4) },
                Token::U64(0),
                Token::U64(100),
                Token::U64(200),
                Token::U64(400),
                Token::SeqEnd,
                Token::StructVariantEnd,
            ],
        );
        assert_tokens(
            &VdafInstance::Poplar1 { bits: 64 },
            &[
                Token::StructVariant {
                    name: "VdafInstance",
                    variant: "Poplar1",
                    len: 1,
                },
                Token::Str("bits"),
                Token::U64(64),
                Token::StructVariantEnd,
            ],
        );
        assert_tokens(
            &VdafInstance::Fake,
            &[Token::UnitVariant {
                name: "VdafInstance",
                variant: "Fake",
            }],
        );
        assert_tokens(
            &VdafInstance::FakeFailsPrepInit,
            &[Token::UnitVariant {
                name: "VdafInstance",
                variant: "FakeFailsPrepInit",
            }],
        );
        assert_tokens(
            &VdafInstance::FakeFailsPrepStep,
            &[Token::UnitVariant {
                name: "VdafInstance",
                variant: "FakeFailsPrepStep",
            }],
        );
    }
}
