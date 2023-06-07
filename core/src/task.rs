use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use derivative::Derivative;
use http::header::{HeaderValue, AUTHORIZATION};
use rand::{distributions::Standard, prelude::Distribution};
use reqwest::Url;
use ring::constant_time;
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str};

/// HTTP header where auth tokens are provided in messages between participants.
pub const DAP_AUTH_HEADER: &str = "DAP-Auth-Token";

/// The length of the verify key parameter for Prio3 VDAF instantiations.
pub const PRIO3_VERIFY_KEY_LENGTH: usize = 16;

/// Identifiers for supported VDAFs, corresponding to definitions in
/// [draft-irtf-cfrg-vdaf-03][1] and implementations in [`prio::vdaf::prio3`].
///
/// [1]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/03/
#[derive(Derivative, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[derivative(Debug)]
#[non_exhaustive]
pub enum VdafInstance {
    /// A `Prio3` counter.
    Prio3Count,
    /// A vector of `Prio3` counters.
    Prio3CountVec { length: usize },
    /// A `Prio3` sum.
    Prio3Sum { bits: usize },
    /// A vector of `Prio3` sums.
    Prio3SumVec { bits: usize, length: usize },
    /// A `Prio3` histogram.
    Prio3Histogram {
        #[derivative(Debug(format_with = "bucket_count"))]
        buckets: Vec<u64>,
    },
    /// A `Prio3` 16-bit fixed point vector sum with bounded L2 norm.
    #[cfg(feature = "fpvec_bounded_l2")]
    Prio3FixedPoint16BitBoundedL2VecSum { length: usize },
    /// A `Prio3` 32-bit fixed point vector sum with bounded L2 norm.
    #[cfg(feature = "fpvec_bounded_l2")]
    Prio3FixedPoint32BitBoundedL2VecSum { length: usize },
    /// A `Prio3` 64-bit fixedpoint vector sum with bounded L2 norm.
    #[cfg(feature = "fpvec_bounded_l2")]
    Prio3FixedPoint64BitBoundedL2VecSum { length: usize },
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

fn bucket_count(buckets: &Vec<u64>, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "[{} buckets]", buckets.len() + 1)
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
            _ => PRIO3_VERIFY_KEY_LENGTH,
        }
    }
}

/// Internal implementation details of [`vdaf_dispatch`](crate::vdaf_dispatch).
#[macro_export]
macro_rules! vdaf_dispatch_impl_base {
    // Provide the dispatched type only, don't construct a VDAF instance.
    (impl match base $vdaf_instance:expr, (_, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count => {
                type $Vdaf = ::prio::vdaf::prio3::Prio3Count;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3CountVec { length } => {
                type $Vdaf = ::prio::vdaf::prio3::Prio3SumVecMultithreaded;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3Sum { bits } => {
                type $Vdaf = ::prio::vdaf::prio3::Prio3Sum;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3SumVec { bits, length } => {
                type $Vdaf = ::prio::vdaf::prio3::Prio3SumVecMultithreaded;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3Histogram { buckets } => {
                type $Vdaf = ::prio::vdaf::prio3::Prio3Histogram;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            _ => unreachable!(),
        }
    };

    // Construct a VDAF instance, and provide that to the block as well.
    (impl match base $vdaf_instance:expr, ($vdaf:ident, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count => {
                let $vdaf = ::prio::vdaf::prio3::Prio3::new_count(2)?;
                type $Vdaf = ::prio::vdaf::prio3::Prio3Count;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3CountVec { length } => {
                // Prio3CountVec is implemented as a 1-bit sum vec
                let $vdaf = ::prio::vdaf::prio3::Prio3::new_sum_vec_multithreaded(2, 1, *length)?;
                type $Vdaf = ::prio::vdaf::prio3::Prio3SumVecMultithreaded;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3Sum { bits } => {
                let $vdaf = ::prio::vdaf::prio3::Prio3::new_sum(2, *bits)?;
                type $Vdaf = ::prio::vdaf::prio3::Prio3Sum;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3SumVec { bits, length } => {
                let $vdaf =
                    ::prio::vdaf::prio3::Prio3::new_sum_vec_multithreaded(2, *bits, *length)?;
                type $Vdaf = ::prio::vdaf::prio3::Prio3SumVecMultithreaded;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3Histogram { buckets } => {
                let $vdaf = ::prio::vdaf::prio3::Prio3::new_histogram(2, buckets)?;
                type $Vdaf = ::prio::vdaf::prio3::Prio3Histogram;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            _ => unreachable!(),
        }
    };
}

/// Internal implementation details of [`vdaf_dispatch`](crate::vdaf_dispatch).
#[cfg(feature = "fpvec_bounded_l2")]
#[macro_export]
macro_rules! vdaf_dispatch_impl_fpvec_bounded_l2 {
    // Provide the dispatched type only, don't construct a VDAF instance.
    (impl match fpvec_bounded_l2 $vdaf_instance:expr, (_, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { length } => {
                type $Vdaf = ::prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded<
                    ::fixed::FixedI16<::fixed::types::extra::U15>,
                >;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { length } => {
                type $Vdaf = ::prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded<
                    ::fixed::FixedI32<::fixed::types::extra::U31>,
                >;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { length } => {
                type $Vdaf = ::prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded<
                    ::fixed::FixedI64<::fixed::types::extra::U63>,
                >;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            _ => unreachable!(),
        }
    };

    // Construct a VDAF instance, and provide that to the block as well.
    (impl match fpvec_bounded_l2 $vdaf_instance:expr, ($vdaf:ident, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { length } => {
                let $vdaf =
                    ::prio::vdaf::prio3::Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(
                        2, *length,
                    )?;
                type $Vdaf = ::prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded<
                    ::fixed::FixedI16<::fixed::types::extra::U15>,
                >;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { length } => {
                let $vdaf =
                    ::prio::vdaf::prio3::Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(
                        2, *length,
                    )?;
                type $Vdaf = ::prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded<
                    ::fixed::FixedI32<::fixed::types::extra::U31>,
                >;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { length } => {
                let $vdaf =
                    ::prio::vdaf::prio3::Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(
                        2, *length,
                    )?;
                type $Vdaf = ::prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded<
                    ::fixed::FixedI64<::fixed::types::extra::U63>,
                >;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::task::PRIO3_VERIFY_KEY_LENGTH;
                $body
            }

            _ => unreachable!(),
        }
    };
}

/// Internal implementation details of [`vdaf_dispatch`](crate::vdaf_dispatch).
#[cfg(feature = "test-util")]
#[macro_export]
macro_rules! vdaf_dispatch_impl_test_util {
    // Provide the dispatched type only, don't construct a VDAF instance.
    (impl match test_util $vdaf_instance:expr, (_, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Fake => {
                type $Vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf;
                const $VERIFY_KEY_LENGTH: usize = 0;
                $body
            }

            ::janus_core::task::VdafInstance::FakeFailsPrepInit => {
                type $Vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf;
                const $VERIFY_KEY_LENGTH: usize = 0;
                $body
            }

            ::janus_core::task::VdafInstance::FakeFailsPrepStep => {
                type $Vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf;
                const $VERIFY_KEY_LENGTH: usize = 0;
                $body
            }

            _ => unreachable!(),
        }
    };

    // Construct a VDAF instance, and provide that to the block as well.
    (impl match test_util $vdaf_instance:expr, ($vdaf:ident, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Fake => {
                let $vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf::new();
                type $Vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf;
                const $VERIFY_KEY_LENGTH: usize = 0;
                $body
            }

            ::janus_core::task::VdafInstance::FakeFailsPrepInit => {
                let $vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf::new().with_prep_init_fn(
                    |_| -> Result<(), ::prio::vdaf::VdafError> {
                        ::std::result::Result::Err(::prio::vdaf::VdafError::Uncategorized(
                            "FakeFailsPrepInit failed at prep_init".to_string(),
                        ))
                    }
                );
                type $Vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf;
                const $VERIFY_KEY_LENGTH: usize = 0;
                $body
            }

            ::janus_core::task::VdafInstance::FakeFailsPrepStep => {
                let $vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf::new().with_prep_step_fn(
                    || -> Result<
                        ::prio::vdaf::PrepareTransition<::janus_core::test_util::dummy_vdaf::Vdaf, 0, 16>,
                        ::prio::vdaf::VdafError,
                    > {
                        ::std::result::Result::Err(::prio::vdaf::VdafError::Uncategorized(
                            "FakeFailsPrepStep failed at prep_step".to_string(),
                        ))
                    }
                );
                type $Vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf;
                const $VERIFY_KEY_LENGTH: usize = 0;
                $body
            }

            _ => unreachable!(),
        }
    };
}

/// Internal implementation details of [`vdaf_dispatch`](crate::vdaf_dispatch).
#[cfg(all(feature = "fpvec_bounded_l2", feature = "test-util"))]
#[macro_export]
macro_rules! vdaf_dispatch_impl {
    // Provide the dispatched type only, don't construct a VDAF instance.
    (impl match all $vdaf_instance:expr, (_, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count
            | ::janus_core::task::VdafInstance::Prio3CountVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Sum { .. }
            | ::janus_core::task::VdafInstance::Prio3SumVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Histogram { .. } => {
                ::janus_core::vdaf_dispatch_impl_base!(impl match base $vdaf_instance, (_, $Vdaf, $VERIFY_KEY_LENGTH) => $body)
            }

            ::janus_core::task::VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { .. }
            | ::janus_core::task::VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { .. }
            | ::janus_core::task::VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { .. } => {
                ::janus_core::vdaf_dispatch_impl_fpvec_bounded_l2!(impl match fpvec_bounded_l2 $vdaf_instance, (_, $Vdaf, $VERIFY_KEY_LENGTH) => $body)
            }

            ::janus_core::task::VdafInstance::Fake
            | ::janus_core::task::VdafInstance::FakeFailsPrepInit
            | ::janus_core::task::VdafInstance::FakeFailsPrepStep => {
                ::janus_core::vdaf_dispatch_impl_test_util!(impl match test_util $vdaf_instance, (_, $Vdaf, $VERIFY_KEY_LENGTH) => $body)
            }

            _ => panic!("VDAF {:?} is not yet supported", $vdaf_instance),
        }
    };

    // Construct a VDAF instance, and provide that to the block as well.
    (impl match all $vdaf_instance:expr, ($vdaf:ident, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count
            | ::janus_core::task::VdafInstance::Prio3CountVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Sum { .. }
            | ::janus_core::task::VdafInstance::Prio3SumVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Histogram { .. } => {
                ::janus_core::vdaf_dispatch_impl_base!(impl match base $vdaf_instance, ($vdaf, $Vdaf, $VERIFY_KEY_LENGTH) => $body)
            }

            ::janus_core::task::VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { .. }
            | ::janus_core::task::VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { .. }
            | ::janus_core::task::VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { .. } => {
                ::janus_core::vdaf_dispatch_impl_fpvec_bounded_l2!(impl match fpvec_bounded_l2 $vdaf_instance, ($vdaf, $Vdaf, $VERIFY_KEY_LENGTH) => $body)
            }

            ::janus_core::task::VdafInstance::Fake
            | ::janus_core::task::VdafInstance::FakeFailsPrepInit
            | ::janus_core::task::VdafInstance::FakeFailsPrepStep => {
                ::janus_core::vdaf_dispatch_impl_test_util!(impl match test_util $vdaf_instance, ($vdaf, $Vdaf, $VERIFY_KEY_LENGTH) => $body)
            }

            _ => panic!("VDAF {:?} is not yet supported", $vdaf_instance),
        }
    };
}

/// Internal implementation details of [`vdaf_dispatch`](crate::vdaf_dispatch).
#[cfg(all(feature = "fpvec_bounded_l2", not(feature = "test-util")))]
#[macro_export]
macro_rules! vdaf_dispatch_impl {
    // Provide the dispatched type only, don't construct a VDAF instance.
    (impl match all $vdaf_instance:expr, (_, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count
            | ::janus_core::task::VdafInstance::Prio3CountVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Sum { .. }
            | ::janus_core::task::VdafInstance::Prio3SumVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Histogram { .. } => {
                ::janus_core::vdaf_dispatch_impl_base!(impl match base $vdaf_instance, (_, $Vdaf, $VERIFY_KEY_LENGTH) => $body)
            }

            ::janus_core::task::VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { .. }
            | ::janus_core::task::VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { .. }
            | ::janus_core::task::VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { .. } => {
                ::janus_core::vdaf_dispatch_impl_fpvec_bounded_l2!(impl match fpvec_bounded_l2 $vdaf_instance, (_, $Vdaf, $VERIFY_KEY_LENGTH) => $body)
            }

            _ => panic!("VDAF {:?} is not yet supported", $vdaf_instance),
        }
    };

    // Construct a VDAF instance, and provide that to the block as well.
    (impl match all $vdaf_instance:expr, ($vdaf:ident, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count
            | ::janus_core::task::VdafInstance::Prio3CountVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Sum { .. }
            | ::janus_core::task::VdafInstance::Prio3SumVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Histogram { .. } => {
                ::janus_core::vdaf_dispatch_impl_base!(impl match base $vdaf_instance, ($vdaf, $Vdaf, $VERIFY_KEY_LENGTH) => $body)
            }

            ::janus_core::task::VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { .. }
            | ::janus_core::task::VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { .. }
            | ::janus_core::task::VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { .. } => {
                ::janus_core::vdaf_dispatch_impl_fpvec_bounded_l2!(impl match fpvec_bounded_l2 $vdaf_instance, ($vdaf, $Vdaf, $VERIFY_KEY_LENGTH) => $body)
            }

            _ => panic!("VDAF {:?} is not yet supported", $vdaf_instance),
        }
    };
}

/// Internal implementation details of [`vdaf_dispatch`](crate::vdaf_dispatch).
#[cfg(all(not(feature = "fpvec_bounded_l2"), feature = "test-util"))]
#[macro_export]
macro_rules! vdaf_dispatch_impl {
    // Provide the dispatched type only, don't construct a VDAF instance.
    (impl match all $vdaf_instance:expr, (_, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count
            | ::janus_core::task::VdafInstance::Prio3CountVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Sum { .. }
            | ::janus_core::task::VdafInstance::Prio3SumVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Histogram { .. } => {
                ::janus_core::vdaf_dispatch_impl_base!(impl match base $vdaf_instance, (_, $Vdaf, $VERIFY_KEY_LENGTH) => $body)
            }

            ::janus_core::task::VdafInstance::Fake
            | ::janus_core::task::VdafInstance::FakeFailsPrepInit
            | ::janus_core::task::VdafInstance::FakeFailsPrepStep => {
                ::janus_core::vdaf_dispatch_impl_test_util!(impl match test_util $vdaf_instance, (_, $Vdaf, $VERIFY_KEY_LENGTH) => $body)
            }

            _ => panic!("VDAF {:?} is not yet supported", $vdaf_instance),
        }
    };

    // Construct a VDAF instance, and provide that to the block as well.
    (impl match all $vdaf_instance:expr, ($vdaf:ident, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count
            | ::janus_core::task::VdafInstance::Prio3CountVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Sum { .. }
            | ::janus_core::task::VdafInstance::Prio3SumVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Histogram { .. } => {
                ::janus_core::vdaf_dispatch_impl_base!(impl match base $vdaf_instance, ($vdaf, $Vdaf, $VERIFY_KEY_LENGTH) => $body)
            }

            ::janus_core::task::VdafInstance::Fake
            | ::janus_core::task::VdafInstance::FakeFailsPrepInit
            | ::janus_core::task::VdafInstance::FakeFailsPrepStep => {
                ::janus_core::vdaf_dispatch_impl_test_util!(impl match test_util $vdaf_instance, ($vdaf, $Vdaf, $VERIFY_KEY_LENGTH) => $body)
            }

            _ => panic!("VDAF {:?} is not yet supported", $vdaf_instance),
        }
    };
}

/// Internal implementation details of [`vdaf_dispatch`](crate::vdaf_dispatch).
#[cfg(all(not(feature = "fpvec_bounded_l2"), not(feature = "test-util")))]
#[macro_export]
macro_rules! vdaf_dispatch_impl {
    // Provide the dispatched type only, don't construct a VDAF instance.
    (impl match all $vdaf_instance:expr, (_, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count
            | ::janus_core::task::VdafInstance::Prio3CountVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Sum { .. }
            | ::janus_core::task::VdafInstance::Prio3SumVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Histogram { .. } => {
                ::janus_core::vdaf_dispatch_impl_base!(impl match base $vdaf_instance, (_, $Vdaf, $VERIFY_KEY_LENGTH) => $body)
            }

            _ => panic!("VDAF {:?} is not yet supported", $vdaf_instance),
        }
    };

    // Construct a VDAF instance, and provide that to the block as well.
    (impl match all $vdaf_instance:expr, ($vdaf:ident, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count
            | ::janus_core::task::VdafInstance::Prio3CountVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Sum { .. }
            | ::janus_core::task::VdafInstance::Prio3SumVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Histogram { .. } => {
                ::janus_core::vdaf_dispatch_impl_base!(impl match base $vdaf_instance, ($vdaf, $Vdaf, $VERIFY_KEY_LENGTH) => $body)
            }

            _ => panic!("VDAF {:?} is not yet supported", $vdaf_instance),
        }
    };
}

/// Emits a match block dispatching on a [`VdafInstance`]. This must be called inside a method that
/// returns a result, with an error type that [`prio::vdaf::VdafError`] can be converted into. Takes
/// a `&VdafInstance` as the first argument, followed by a pseudo-pattern and body. The
/// pseudo-pattern takes a variable name for the constructed VDAF, a type alias name that the block
/// can use to explicitly specify the VDAF's type, and the name of a const that will be set to the
/// VDAF's verify key length, also for explicitly specifying type parameters.
///
/// # Example:
///
/// ```
/// # use janus_core::vdaf_dispatch;
/// # fn handle_request_generic<A, const SEED_SIZE: usize>(_vdaf: &A) -> Result<(), prio::vdaf::VdafError>
/// # where
/// #     A: prio::vdaf::Aggregator<SEED_SIZE, 16>,
/// # {
/// #     Ok(())
/// # }
/// # fn test() -> Result<(), prio::vdaf::VdafError> {
/// #     let vdaf = janus_core::task::VdafInstance::Prio3Count;
/// vdaf_dispatch!(&vdaf, (vdaf, VdafType, VERIFY_KEY_LENGTH) => {
///     handle_request_generic::<VdafType, VERIFY_KEY_LENGTH>(&vdaf)
/// })
/// # }
/// ```
#[macro_export]
macro_rules! vdaf_dispatch {
    // Provide the dispatched type only, don't construct a VDAF instance.
    ($vdaf_instance:expr, (_, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident) => $body:tt) => {
        ::janus_core::vdaf_dispatch_impl!(impl match all $vdaf_instance, (_, $Vdaf, $VERIFY_KEY_LENGTH) => $body)
    };

    // Construct a VDAF instance, and provide that to the block as well.
    ($vdaf_instance:expr, ($vdaf:ident, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident) => $body:tt) => {
        ::janus_core::vdaf_dispatch_impl!(impl match all $vdaf_instance, ($vdaf, $Vdaf, $VERIFY_KEY_LENGTH) => $body)
    };
}

/// Different modes of authentication supported by Janus for either sending requests (e.g., leader
/// to helper) or receiving them (e.g., collector to leader).
#[derive(Clone, Derivative, Serialize, Deserialize)]
#[derivative(Debug)]
#[serde(tag = "type", content = "token")]
#[non_exhaustive]
pub enum AuthenticationToken {
    /// A bearer token. The value is an opaque byte string. Its Base64 encoding is inserted into
    /// HTTP requests as specified in [RFC 6750 section 2.1][1]. The token is not necessarily an
    /// OAuth token.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
    Bearer(
        #[derivative(Debug = "ignore")]
        #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
        Vec<u8>,
    ),

    /// Token presented as the value of the "DAP-Auth-Token" HTTP header. Conforms to
    /// [draft-dcook-ppm-dap-interop-test-design-03][1], sections [4.3.3][2] and [4.4.2][3], and
    /// [draft-ietf-dap-ppm-01 section 3.2][4].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-dcook-ppm-dap-interop-test-design-03
    /// [2]: https://datatracker.ietf.org/doc/html/draft-dcook-ppm-dap-interop-test-design-03#section-4.3.3
    /// [3]: https://datatracker.ietf.org/doc/html/draft-dcook-ppm-dap-interop-test-design-03#section-4.4.2
    /// [4]: https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-01#name-https-sender-authentication
    DapAuth(DapAuthToken),
}

impl AuthenticationToken {
    /// Returns an HTTP header and value that should be used to authenticate an HTTP request with
    /// this credential.
    pub fn request_authentication(&self) -> (&'static str, Vec<u8>) {
        match self {
            Self::Bearer(token) => (
                AUTHORIZATION.as_str(),
                // When encoding into a request, we use Base64 standard encoding
                format!("Bearer {}", STANDARD.encode(token.as_slice())).into_bytes(),
            ),
            // A DAP-Auth-Token is already HTTP header-safe, so no encoding is needed. Cloning is
            // unfortunate but necessary since other arms must allocate.
            Self::DapAuth(token) => (DAP_AUTH_HEADER, token.as_ref().to_vec()),
        }
    }
}

impl PartialEq for AuthenticationToken {
    fn eq(&self, other: &Self) -> bool {
        let (own, other) = match (self, other) {
            (Self::Bearer(own), Self::Bearer(other)) => (own.as_slice(), other.as_slice()),
            (Self::DapAuth(own), Self::DapAuth(other)) => (own.as_ref(), other.as_ref()),
            _ => {
                return false;
            }
        };
        // We attempt constant-time comparisons of the token data to mitigate timing attacks. Note
        // that this function still eaks whether the lengths of the tokens are equal -- this is
        // acceptable because we expec the content of the tokens to provide enough randomness that
        // needs to be guessed even if the length is known.
        constant_time::verify_slices_are_equal(own, other).is_ok()
    }
}

impl Eq for AuthenticationToken {}

impl AsRef<[u8]> for AuthenticationToken {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::DapAuth(token) => token.as_ref(),
            Self::Bearer(token) => token.as_ref(),
        }
    }
}

/// Serialize bytes into format suitable for bearer tokens in Janus configuration files.
fn as_base64<S: Serializer, T: AsRef<[u8]>>(key: &T, serializer: S) -> Result<S::Ok, S::Error> {
    let bytes: &[u8] = key.as_ref();
    serializer.serialize_str(&STANDARD.encode(bytes))
}

/// Deserialize bytes from Janus configuration files into a bearer token.
fn from_base64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    String::deserialize(deserializer).and_then(|s| {
        STANDARD
            .decode(s)
            .map_err(|e| D::Error::custom(format!("cannot decode value from Base64: {e:?}")))
    })
}

impl Distribution<AuthenticationToken> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> AuthenticationToken {
        AuthenticationToken::Bearer(Vec::from(rng.gen::<[u8; 16]>()))
    }
}

/// Token presented as the value of the "DAP-Auth-Token" HTTP header. The token is used directly in
/// the HTTP request without further encoding and so must be a legal HTTP header value. Conforms to
/// [draft-ietf-dap-ppm-01 section 3.2][1].
///
/// This opaque type ensures it's impossible to construct an [`AuthenticationToken::DapAuth`] whose
/// contents are invalid.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-01#name-https-sender-authentication
#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct DapAuthToken(#[derivative(Debug = "ignore")] Vec<u8>);

impl DapAuthToken {}

impl AsRef<[u8]> for DapAuthToken {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for DapAuthToken {
    type Error = anyhow::Error;

    fn try_from(token: Vec<u8>) -> Result<Self, Self::Error> {
        HeaderValue::try_from(token.as_slice())?;
        Ok(Self(token))
    }
}

impl Serialize for DapAuthToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(self.as_ref()))
    }
}

impl<'de> Deserialize<'de> for DapAuthToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Verify that the string is a safe HTTP header value
        String::deserialize(deserializer)
            .and_then(|string| {
                URL_SAFE_NO_PAD.decode(string).map_err(|e| {
                    D::Error::custom(format!(
                        "cannot decode value from unpadded Base64URL: {e:?}"
                    ))
                })
            })
            .and_then(|bytes| Self::try_from(bytes).map_err(D::Error::custom))
    }
}

impl Distribution<DapAuthToken> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> DapAuthToken {
        DapAuthToken(Vec::from(hex::encode(rng.gen::<[u8; 16]>())))
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
    use super::{AuthenticationToken, VdafInstance};
    use serde_test::{assert_tokens, Token};

    #[test]
    fn vdaf_serialization() {
        // The `Vdaf` type must have a stable serialization, as it gets stored in a JSON database
        // column.
        assert_tokens(
            &VdafInstance::Prio3Count,
            &[Token::UnitVariant {
                name: "VdafInstance",
                variant: "Prio3Count",
            }],
        );
        assert_tokens(
            &VdafInstance::Prio3CountVec { length: 8 },
            &[
                Token::StructVariant {
                    name: "VdafInstance",
                    variant: "Prio3CountVec",
                    len: 1,
                },
                Token::Str("length"),
                Token::U64(8),
                Token::StructVariantEnd,
            ],
        );
        assert_tokens(
            &VdafInstance::Prio3Sum { bits: 64 },
            &[
                Token::StructVariant {
                    name: "VdafInstance",
                    variant: "Prio3Sum",
                    len: 1,
                },
                Token::Str("bits"),
                Token::U64(64),
                Token::StructVariantEnd,
            ],
        );
        assert_tokens(
            &VdafInstance::Prio3Histogram {
                buckets: Vec::from([0, 100, 200, 400]),
            },
            &[
                Token::StructVariant {
                    name: "VdafInstance",
                    variant: "Prio3Histogram",
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

    #[test]
    fn reject_invalid_dap_auth_token() {
        let err = serde_yaml::from_str::<AuthenticationToken>(
            "{type: \"DapAuth\", token: \"AAAAAAAAAAAAAA\"}",
        )
        .unwrap_err();
        assert!(err.to_string().contains("failed to parse header value"));
    }
}
