use derivative::Derivative;
use janus_messages::taskprov;
use serde::{Deserialize, Serialize};
use std::str;
use url::Url;

/// The length of the verify key parameter for Prio3 & Poplar1 VDAF instantiations.
pub const VERIFY_KEY_LENGTH: usize = 16;

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
    Prio3CountVec { length: usize, chunk_length: usize },
    /// A `Prio3` sum.
    Prio3Sum { bits: usize },
    /// A vector of `Prio3` sums.
    Prio3SumVec {
        bits: usize,
        length: usize,
        chunk_length: usize,
    },
    /// A `Prio3` histogram with `length` buckets in it.
    Prio3Histogram { length: usize, chunk_length: usize },
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

impl VdafInstance {
    /// Returns the expected length of a VDAF verification key for a VDAF of this type.
    pub fn verify_key_length(&self) -> usize {
        match self {
            #[cfg(feature = "test-util")]
            VdafInstance::Fake
            | VdafInstance::FakeFailsPrepInit
            | VdafInstance::FakeFailsPrepStep => 0,

            // All "real" VDAFs use a verify key of length 16 currently.
            _ => VERIFY_KEY_LENGTH,
        }
    }
}

impl TryFrom<&taskprov::VdafType> for VdafInstance {
    type Error = &'static str;

    fn try_from(value: &taskprov::VdafType) -> Result<Self, Self::Error> {
        match value {
            taskprov::VdafType::Prio3Count => Ok(Self::Prio3Count),
            taskprov::VdafType::Prio3Sum { bits } => Ok(Self::Prio3Sum {
                bits: *bits as usize,
            }),
            taskprov::VdafType::Prio3Histogram {
                length,
                chunk_length,
            } => Ok(Self::Prio3Histogram {
                length: *length as usize,
                chunk_length: *chunk_length as usize,
            }),
            taskprov::VdafType::Poplar1 { bits } => Ok(Self::Poplar1 {
                bits: *bits as usize,
            }),
            _ => Err("unknown VdafType"),
        }
    }
}

/// Internal implementation details of [`vdaf_dispatch`](crate::vdaf_dispatch).
#[macro_export]
macro_rules! vdaf_dispatch_impl_base {
    // Provide the dispatched type only, don't construct a VDAF instance.
    (impl match base $vdaf_instance:expr, (_, $Vdaf:ident, $VERIFY_KEY_LEN:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count => {
                type $Vdaf = ::prio::vdaf::prio3::Prio3Count;
                const $VERIFY_KEY_LEN: usize = ::janus_core::task::VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3CountVec { length } => {
                type $Vdaf = ::prio::vdaf::prio3::Prio3SumVecMultithreaded;
                const $VERIFY_KEY_LEN: usize = ::janus_core::task::VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3Sum { bits } => {
                type $Vdaf = ::prio::vdaf::prio3::Prio3Sum;
                const $VERIFY_KEY_LEN: usize = ::janus_core::task::VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3SumVec { bits, length } => {
                type $Vdaf = ::prio::vdaf::prio3::Prio3SumVecMultithreaded;
                const $VERIFY_KEY_LEN: usize = ::janus_core::task::VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3Histogram { buckets } => {
                type $Vdaf = ::prio::vdaf::prio3::Prio3Histogram;
                const $VERIFY_KEY_LEN: usize = ::janus_core::task::VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Poplar1 { bits } => {
                type $Vdaf = ::prio::vdaf::poplar1::Poplar1<::prio::vdaf::prg::PrgSha3, 16>;
                const $VERIFY_KEY_LEN: usize = ::janus_core::task::VERIFY_KEY_LENGTH;
                $body
            }

            _ => unreachable!(),
        }
    };

    // Construct a VDAF instance, and provide that to the block as well.
    (impl match base $vdaf_instance:expr, ($vdaf:ident, $Vdaf:ident, $VERIFY_KEY_LEN:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count => {
                let $vdaf = ::prio::vdaf::prio3::Prio3::new_count(2)?;
                type $Vdaf = ::prio::vdaf::prio3::Prio3Count;
                const $VERIFY_KEY_LEN: usize = ::janus_core::task::VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3CountVec {
                length,
                chunk_length,
            } => {
                // Prio3CountVec is implemented as a 1-bit sum vec
                let $vdaf = ::prio::vdaf::prio3::Prio3::new_sum_vec_multithreaded(
                    2,
                    1,
                    *length,
                    *chunk_length,
                )?;
                type $Vdaf = ::prio::vdaf::prio3::Prio3SumVecMultithreaded;
                const $VERIFY_KEY_LEN: usize = ::janus_core::task::VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3Sum { bits } => {
                let $vdaf = ::prio::vdaf::prio3::Prio3::new_sum(2, *bits)?;
                type $Vdaf = ::prio::vdaf::prio3::Prio3Sum;
                const $VERIFY_KEY_LEN: usize = ::janus_core::task::VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3SumVec {
                bits,
                length,
                chunk_length,
            } => {
                let $vdaf = ::prio::vdaf::prio3::Prio3::new_sum_vec_multithreaded(
                    2,
                    *bits,
                    *length,
                    *chunk_length,
                )?;
                type $Vdaf = ::prio::vdaf::prio3::Prio3SumVecMultithreaded;
                const $VERIFY_KEY_LEN: usize = ::janus_core::task::VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3Histogram {
                length,
                chunk_length,
            } => {
                let $vdaf = ::prio::vdaf::prio3::Prio3::new_histogram(2, *length, *chunk_length)?;
                type $Vdaf = ::prio::vdaf::prio3::Prio3Histogram;
                const $VERIFY_KEY_LEN: usize = ::janus_core::task::VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Poplar1 { bits } => {
                let $vdaf = ::prio::vdaf::poplar1::Poplar1::new_shake128(*bits);
                type $Vdaf = ::prio::vdaf::poplar1::Poplar1<::prio::vdaf::xof::XofShake128, 16>;
                const $VERIFY_KEY_LEN: usize = ::janus_core::task::VERIFY_KEY_LENGTH;
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
    (impl match fpvec_bounded_l2 $vdaf_instance:expr, (_, $Vdaf:ident, $VERIFY_KEY_LEN:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { length } => {
                type $Vdaf = ::prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded<
                    ::fixed::FixedI16<::fixed::types::extra::U15>,
                >;
                const $VERIFY_KEY_LEN: usize = ::janus_core::task::VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { length } => {
                type $Vdaf = ::prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded<
                    ::fixed::FixedI32<::fixed::types::extra::U31>,
                >;
                const $VERIFY_KEY_LEN: usize = ::janus_core::task::VERIFY_KEY_LENGTH;
                $body
            }

            ::janus_core::task::VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { length } => {
                type $Vdaf = ::prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded<
                    ::fixed::FixedI64<::fixed::types::extra::U63>,
                >;
                const $VERIFY_KEY_LEN: usize = ::janus_core::task::VERIFY_KEY_LENGTH;
                $body
            }

            _ => unreachable!(),
        }
    };

    // Construct a VDAF instance, and provide that to the block as well.
    (impl match fpvec_bounded_l2 $vdaf_instance:expr, ($vdaf:ident, $Vdaf:ident, $VERIFY_KEY_LEN:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { length } => {
                let $vdaf =
                    ::prio::vdaf::prio3::Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(
                        2, *length,
                    )?;
                type $Vdaf = ::prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded<
                    ::fixed::FixedI16<::fixed::types::extra::U15>,
                >;
                const $VERIFY_KEY_LEN: usize = ::janus_core::task::VERIFY_KEY_LENGTH;
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
                const $VERIFY_KEY_LEN: usize = ::janus_core::task::VERIFY_KEY_LENGTH;
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
                const $VERIFY_KEY_LEN: usize = ::janus_core::task::VERIFY_KEY_LENGTH;
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
    (impl match test_util $vdaf_instance:expr, (_, $Vdaf:ident, $VERIFY_KEY_LEN:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Fake => {
                type $Vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf;
                const $VERIFY_KEY_LEN: usize = 0;
                $body
            }

            ::janus_core::task::VdafInstance::FakeFailsPrepInit => {
                type $Vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf;
                const $VERIFY_KEY_LEN: usize = 0;
                $body
            }

            ::janus_core::task::VdafInstance::FakeFailsPrepStep => {
                type $Vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf;
                const $VERIFY_KEY_LEN: usize = 0;
                $body
            }

            _ => unreachable!(),
        }
    };

    // Construct a VDAF instance, and provide that to the block as well.
    (impl match test_util $vdaf_instance:expr, ($vdaf:ident, $Vdaf:ident, $VERIFY_KEY_LEN:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Fake => {
                let $vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf::new();
                type $Vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf;
                const $VERIFY_KEY_LEN: usize = 0;
                $body
            }

            ::janus_core::task::VdafInstance::FakeFailsPrepInit => {
                let $vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf::new().with_prep_init_fn(
                    |_| -> Result<(), ::prio::vdaf::VdafError> {
                        ::std::result::Result::Err(::prio::vdaf::VdafError::Uncategorized(
                            "FakeFailsPrepInit failed at prep_init".to_string(),
                        ))
                    },
                );
                type $Vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf;
                const $VERIFY_KEY_LEN: usize = 0;
                $body
            }

            ::janus_core::task::VdafInstance::FakeFailsPrepStep => {
                let $vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf::new().with_prep_step_fn(
                            || -> Result<
                                ::prio::vdaf::PrepareTransition<
                                    ::janus_core::test_util::dummy_vdaf::Vdaf,
                                    0,
                                    16,
                                >,
                                ::prio::vdaf::VdafError,
                            > {
                                ::std::result::Result::Err(::prio::vdaf::VdafError::Uncategorized(
                                    "FakeFailsPrepStep failed at prep_step".to_string(),
                                ))
                            },
                        );
                type $Vdaf = ::janus_core::test_util::dummy_vdaf::Vdaf;
                const $VERIFY_KEY_LEN: usize = 0;
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
    (impl match all $vdaf_instance:expr, (_, $Vdaf:ident, $VERIFY_KEY_LEN:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count
            | ::janus_core::task::VdafInstance::Prio3CountVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Sum { .. }
            | ::janus_core::task::VdafInstance::Prio3SumVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Histogram { .. }
            | ::janus_core::task::VdafInstance::Poplar1 { .. } => {
                ::janus_core::vdaf_dispatch_impl_base!(impl match base $vdaf_instance, (_, $Vdaf, $VERIFY_KEY_LEN) => $body)
            }

            ::janus_core::task::VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { .. }
            | ::janus_core::task::VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { .. }
            | ::janus_core::task::VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { .. } => {
                ::janus_core::vdaf_dispatch_impl_fpvec_bounded_l2!(impl match fpvec_bounded_l2 $vdaf_instance, (_, $Vdaf, $VERIFY_KEY_LEN) => $body)
            }

            ::janus_core::task::VdafInstance::Fake
            | ::janus_core::task::VdafInstance::FakeFailsPrepInit
            | ::janus_core::task::VdafInstance::FakeFailsPrepStep => {
                ::janus_core::vdaf_dispatch_impl_test_util!(impl match test_util $vdaf_instance, (_, $Vdaf, $VERIFY_KEY_LEN) => $body)
            }

            _ => panic!("VDAF {:?} is not yet supported", $vdaf_instance),
        }
    };

    // Construct a VDAF instance, and provide that to the block as well.
    (impl match all $vdaf_instance:expr, ($vdaf:ident, $Vdaf:ident, $VERIFY_KEY_LEN:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count
            | ::janus_core::task::VdafInstance::Prio3CountVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Sum { .. }
            | ::janus_core::task::VdafInstance::Prio3SumVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Histogram { .. }
            | ::janus_core::task::VdafInstance::Poplar1 { .. } => {
                ::janus_core::vdaf_dispatch_impl_base!(impl match base $vdaf_instance, ($vdaf, $Vdaf, $VERIFY_KEY_LEN) => $body)
            }

            ::janus_core::task::VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { .. }
            | ::janus_core::task::VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { .. }
            | ::janus_core::task::VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { .. } => {
                ::janus_core::vdaf_dispatch_impl_fpvec_bounded_l2!(impl match fpvec_bounded_l2 $vdaf_instance, ($vdaf, $Vdaf, $VERIFY_KEY_LEN) => $body)
            }

            ::janus_core::task::VdafInstance::Fake
            | ::janus_core::task::VdafInstance::FakeFailsPrepInit
            | ::janus_core::task::VdafInstance::FakeFailsPrepStep => {
                ::janus_core::vdaf_dispatch_impl_test_util!(impl match test_util $vdaf_instance, ($vdaf, $Vdaf, $VERIFY_KEY_LEN) => $body)
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
    (impl match all $vdaf_instance:expr, (_, $Vdaf:ident, $VERIFY_KEY_LEN:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count
            | ::janus_core::task::VdafInstance::Prio3CountVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Sum { .. }
            | ::janus_core::task::VdafInstance::Prio3SumVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Histogram { .. }
            | ::janus_core::task::VdafInstance::Poplar1 { .. } => {
                ::janus_core::vdaf_dispatch_impl_base!(impl match base $vdaf_instance, (_, $Vdaf, $VERIFY_KEY_LEN) => $body)
            }

            ::janus_core::task::VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { .. }
            | ::janus_core::task::VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { .. }
            | ::janus_core::task::VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { .. } => {
                ::janus_core::vdaf_dispatch_impl_fpvec_bounded_l2!(impl match fpvec_bounded_l2 $vdaf_instance, (_, $Vdaf, $VERIFY_KEY_LEN) => $body)
            }

            _ => panic!("VDAF {:?} is not yet supported", $vdaf_instance),
        }
    };

    // Construct a VDAF instance, and provide that to the block as well.
    (impl match all $vdaf_instance:expr, ($vdaf:ident, $Vdaf:ident, $VERIFY_KEY_LEN:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count
            | ::janus_core::task::VdafInstance::Prio3CountVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Sum { .. }
            | ::janus_core::task::VdafInstance::Prio3SumVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Histogram { .. }
            | ::janus_core::task::VdafInstance::Poplar1 { .. } => {
                ::janus_core::vdaf_dispatch_impl_base!(impl match base $vdaf_instance, ($vdaf, $Vdaf, $VERIFY_KEY_LEN) => $body)
            }

            ::janus_core::task::VdafInstance::Prio3FixedPoint16BitBoundedL2VecSum { .. }
            | ::janus_core::task::VdafInstance::Prio3FixedPoint32BitBoundedL2VecSum { .. }
            | ::janus_core::task::VdafInstance::Prio3FixedPoint64BitBoundedL2VecSum { .. } => {
                ::janus_core::vdaf_dispatch_impl_fpvec_bounded_l2!(impl match fpvec_bounded_l2 $vdaf_instance, ($vdaf, $Vdaf, $VERIFY_KEY_LEN) => $body)
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
    (impl match all $vdaf_instance:expr, (_, $Vdaf:ident, $VERIFY_KEY_LEN:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count
            | ::janus_core::task::VdafInstance::Prio3CountVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Sum { .. }
            | ::janus_core::task::VdafInstance::Prio3SumVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Histogram { .. }
            | ::janus_core::task::VdafInstance::Poplar1 { .. } => {
                ::janus_core::vdaf_dispatch_impl_base!(impl match base $vdaf_instance, (_, $Vdaf, $VERIFY_KEY_LEN) => $body)
            }

            ::janus_core::task::VdafInstance::Fake
            | ::janus_core::task::VdafInstance::FakeFailsPrepInit
            | ::janus_core::task::VdafInstance::FakeFailsPrepStep => {
                ::janus_core::vdaf_dispatch_impl_test_util!(impl match test_util $vdaf_instance, (_, $Vdaf, $VERIFY_KEY_LEN) => $body)
            }

            _ => panic!("VDAF {:?} is not yet supported", $vdaf_instance),
        }
    };

    // Construct a VDAF instance, and provide that to the block as well.
    (impl match all $vdaf_instance:expr, ($vdaf:ident, $Vdaf:ident, $VERIFY_KEY_LEN:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count
            | ::janus_core::task::VdafInstance::Prio3CountVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Sum { .. }
            | ::janus_core::task::VdafInstance::Prio3SumVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Histogram { .. }
            | ::janus_core::task::VdafInstance::Poplar1 { .. } => {
                ::janus_core::vdaf_dispatch_impl_base!(impl match base $vdaf_instance, ($vdaf, $Vdaf, $VERIFY_KEY_LEN) => $body)
            }

            ::janus_core::task::VdafInstance::Fake
            | ::janus_core::task::VdafInstance::FakeFailsPrepInit
            | ::janus_core::task::VdafInstance::FakeFailsPrepStep => {
                ::janus_core::vdaf_dispatch_impl_test_util!(impl match test_util $vdaf_instance, ($vdaf, $Vdaf, $VERIFY_KEY_LEN) => $body)
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
    (impl match all $vdaf_instance:expr, (_, $Vdaf:ident, $VERIFY_KEY_LEN:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count
            | ::janus_core::task::VdafInstance::Prio3CountVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Sum { .. }
            | ::janus_core::task::VdafInstance::Prio3SumVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Histogram { .. }
            | ::janus_core::task::VdafInstance::Poplar1 { .. } => {
                ::janus_core::vdaf_dispatch_impl_base!(impl match base $vdaf_instance, (_, $Vdaf, $VERIFY_KEY_LEN) => $body)
            }

            _ => panic!("VDAF {:?} is not yet supported", $vdaf_instance),
        }
    };

    // Construct a VDAF instance, and provide that to the block as well.
    (impl match all $vdaf_instance:expr, ($vdaf:ident, $Vdaf:ident, $VERIFY_KEY_LEN:ident) => $body:tt) => {
        match $vdaf_instance {
            ::janus_core::task::VdafInstance::Prio3Count
            | ::janus_core::task::VdafInstance::Prio3CountVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Sum { .. }
            | ::janus_core::task::VdafInstance::Prio3SumVec { .. }
            | ::janus_core::task::VdafInstance::Prio3Histogram { .. }
            | ::janus_core::task::VdafInstance::Poplar1 { .. } => {
                ::janus_core::vdaf_dispatch_impl_base!(impl match base $vdaf_instance, ($vdaf, $Vdaf, $VERIFY_KEY_LEN) => $body)
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
/// vdaf_dispatch!(&vdaf, (vdaf, VdafType, VERIFY_KEY_LEN) => {
///     handle_request_generic::<VdafType, VERIFY_KEY_LEN>(&vdaf)
/// })
/// # }
/// ```
#[macro_export]
macro_rules! vdaf_dispatch {
    // Provide the dispatched type only, don't construct a VDAF instance.
    ($vdaf_instance:expr, (_, $Vdaf:ident, $VERIFY_KEY_LEN:ident) => $body:tt) => {
        ::janus_core::vdaf_dispatch_impl!(impl match all $vdaf_instance, (_, $Vdaf, $VERIFY_KEY_LEN) => $body)
    };

    // Construct a VDAF instance, and provide that to the block as well.
    ($vdaf_instance:expr, ($vdaf:ident, $Vdaf:ident, $VERIFY_KEY_LEN:ident) => $body:tt) => {
        ::janus_core::vdaf_dispatch_impl!(impl match all $vdaf_instance, ($vdaf, $Vdaf, $VERIFY_KEY_LEN) => $body)
    };
}

/// Returns the given [`Url`], possibly modified to end with a slash.
///
/// Aggregator endpoint URLs should end with a slash if they will be used with [`Url::join`],
/// because that method will drop the last path component of the base URL if it does not end with a
/// slash.
pub fn url_ensure_trailing_slash(mut url: Url) -> Url {
    if !url.as_str().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    url
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
            &VdafInstance::Prio3Count,
            &[Token::UnitVariant {
                name: "VdafInstance",
                variant: "Prio3Count",
            }],
        );
        assert_tokens(
            &VdafInstance::Prio3CountVec {
                length: 8,
                chunk_length: 3,
            },
            &[
                Token::StructVariant {
                    name: "VdafInstance",
                    variant: "Prio3CountVec",
                    len: 2,
                },
                Token::Str("length"),
                Token::U64(8),
                Token::Str("chunk_length"),
                Token::U64(3),
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
                length: 6,
                chunk_length: 2,
            },
            &[
                Token::StructVariant {
                    name: "VdafInstance",
                    variant: "Prio3Histogram",
                    len: 2,
                },
                Token::Str("length"),
                Token::U64(6),
                Token::Str("chunk_length"),
                Token::U64(2),
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
