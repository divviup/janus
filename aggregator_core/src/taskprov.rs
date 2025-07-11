use crate::{
    SecretBytes,
    task::{AggregationMode, Error},
};
use anyhow::anyhow;
use aws_lc_rs::{
    digest::{self, Digest, SHA256, digest},
    hkdf::{HKDF_SHA256, KeyType, Salt},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use educe::Educe;
use janus_core::{auth_tokens::AuthenticationToken, vdaf::VdafInstance};
use janus_messages::{Duration, HpkeConfig, Role, TaskId};
use rand::{distr::StandardUniform, prelude::Distribution};
use serde::{
    Deserialize, Serialize, Serializer,
    de::{self, Visitor},
};
use std::{fmt, str::FromStr, sync::LazyLock};
use url::Url;

#[derive(Educe, Clone, Copy, PartialEq, Eq)]
#[educe(Debug)]
pub struct VerifyKeyInit(#[educe(Debug(ignore))] [u8; Self::LEN]);

impl VerifyKeyInit {
    pub const LEN: usize = 32;
}

impl TryFrom<&[u8]> for VerifyKeyInit {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into().map_err(|_| {
            Error::InvalidParameter("byte slice has incorrect length for VerifyKeyInit")
        })?))
    }
}

impl AsRef<[u8; Self::LEN]> for VerifyKeyInit {
    fn as_ref(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl Serialize for VerifyKeyInit {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = URL_SAFE_NO_PAD.encode(self.as_ref());
        serializer.serialize_str(&encoded)
    }
}

struct VerifyKeyInitVisitor;

impl Visitor<'_> for VerifyKeyInitVisitor {
    type Value = VerifyKeyInit;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a base64url-encoded string")
    }

    fn visit_str<E>(self, value: &str) -> Result<VerifyKeyInit, E>
    where
        E: de::Error,
    {
        VerifyKeyInit::from_str(value).map_err(|err| E::custom(err.to_string()))
    }
}

/// This customized implementation deserializes a [`VerifyKeyInit`] as a base64url-encoded string,
/// instead of as a byte array. This is more compact and ergonomic when serialized to YAML.
impl<'de> Deserialize<'de> for VerifyKeyInit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(VerifyKeyInitVisitor)
    }
}

impl Distribution<VerifyKeyInit> for StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> VerifyKeyInit {
        VerifyKeyInit(rng.random())
    }
}

impl FromStr for VerifyKeyInit {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(VerifyKeyInit::try_from(
            URL_SAFE_NO_PAD.decode(s)?.as_ref(),
        )?)
    }
}

/// Represents another aggregator that is peered with our aggregator for taskprov purposes. Contains
/// data that needs to be identical between both aggregators for the taskprov flow to work.
#[derive(Clone, Educe, PartialEq, Eq)]
#[educe(Debug)]
pub struct PeerAggregator {
    /// The URL at which the peer aggregator can be reached. This, along with `role`, is used to
    /// uniquely represent the peer aggregator.
    #[educe(Debug(method(std::fmt::Display::fmt)))]
    endpoint: Url,

    /// The role that the peer aggregator takes in DAP. Must be [`Role::Leader`] or [`Role::Helper`].
    /// This, along with `endpoint`, uniquely represents the peer aggregator.
    peer_role: Role,

    /// The aggregation mode (e.g. synchronous vs asynchronous) to use for aggregation in any tasks
    /// associated with this aggregator. Populated only when we are in the Helper role.
    aggregation_mode: Option<AggregationMode>,

    /// The preshared key used to derive the VDAF verify key for each task.
    verify_key_init: VerifyKeyInit,

    // The HPKE configuration of the collector. This needs to be shared out-of-band with the peer
    // aggregator.
    collector_hpke_config: HpkeConfig,

    /// How long reports exist until they're eligible for GC. Set to None for no GC. This value is
    /// copied into the definition for a provisioned task.
    report_expiry_age: Option<Duration>,

    /// Auth tokens used for authenticating Leader to Helper requests.
    aggregator_auth_tokens: Vec<AuthenticationToken>,

    /// Auth tokens used for authenticating Collector to Leader requests. It should be empty if the
    /// peer aggregator is the Leader.
    collector_auth_tokens: Vec<AuthenticationToken>,
}

impl PeerAggregator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: Url,
        peer_role: Role,
        aggregation_mode: Option<AggregationMode>,
        verify_key_init: VerifyKeyInit,
        collector_hpke_config: HpkeConfig,
        report_expiry_age: Option<Duration>,
        aggregator_auth_tokens: Vec<AuthenticationToken>,
        collector_auth_tokens: Vec<AuthenticationToken>,
    ) -> anyhow::Result<Self> {
        if !peer_role.is_aggregator() {
            return Err(anyhow!("invalid role: {peer_role}"));
        }
        if peer_role == Role::Leader && aggregation_mode.is_none() {
            return Err(anyhow!("missing aggregation_mode"));
        }
        Ok(Self {
            endpoint,
            peer_role,
            aggregation_mode,
            verify_key_init,
            collector_hpke_config,
            report_expiry_age,
            aggregator_auth_tokens,
            collector_auth_tokens,
        })
    }

    /// Retrieve the URL endpoint of the peer.
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// Retrieve the role of the peer.
    pub fn peer_role(&self) -> &Role {
        &self.peer_role
    }

    /// Retrieves the aggregation mode (e.g. synchronous vs asynchronous) to use for aggregation
    /// in any tasks associated with this aggregator. Populated only when we are in the Helper role.
    pub fn aggregation_mode(&self) -> Option<&AggregationMode> {
        self.aggregation_mode.as_ref()
    }

    /// Retrieve the VDAF verify key initialization parameter, used for derivation of the VDAF
    /// verify key for a task.
    pub fn verify_key_init(&self) -> &VerifyKeyInit {
        &self.verify_key_init
    }

    /// Retrieve the collector HPKE configuration for this peer.
    pub fn collector_hpke_config(&self) -> &HpkeConfig {
        &self.collector_hpke_config
    }

    /// Retrieve the report expiry age that each task will be configured with.
    pub fn report_expiry_age(&self) -> Option<&Duration> {
        self.report_expiry_age.as_ref()
    }

    /// Retrieve the [`AuthenticationToken`]s used for authenticating leader to helper requests.
    pub fn aggregator_auth_tokens(&self) -> &[AuthenticationToken] {
        &self.aggregator_auth_tokens
    }

    /// Retrieve the [`AuthenticationToken`]s used for authenticating collector to leader requests.
    pub fn collector_auth_tokens(&self) -> &[AuthenticationToken] {
        &self.collector_auth_tokens
    }

    /// Returns the [`AuthenticationToken`] currently used by this peer to authenticate itself.
    pub fn primary_aggregator_auth_token(&self) -> &AuthenticationToken {
        self.aggregator_auth_tokens.iter().next_back().unwrap()
    }

    /// Checks if the given aggregator authentication token is valid (i.e. matches with an
    /// authentication token recognized by this task).
    pub fn check_aggregator_auth_token(&self, auth_token: &AuthenticationToken) -> bool {
        self.aggregator_auth_tokens
            .iter()
            .rev()
            .any(|t| t == auth_token)
    }

    /// Returns the [`AuthenticationToken`] currently used by the collector to authenticate itself
    /// to the aggregators.
    pub fn primary_collector_auth_token(&self) -> &AuthenticationToken {
        // Unwrap safety: self.collector_auth_tokens is never empty
        self.collector_auth_tokens.iter().next_back().unwrap()
    }

    /// Checks if the given collector authentication token is valid (i.e. matches with an
    /// authentication token recognized by this task).
    pub fn check_collector_auth_token(&self, auth_token: &AuthenticationToken) -> bool {
        self.collector_auth_tokens
            .iter()
            .rev()
            .any(|t| t == auth_token)
    }

    /// Computes the VDAF verify key using the method defined in [draft-wang-ppm-dap-taskprov][1].
    ///
    /// [1]: https://www.ietf.org/archive/id/draft-wang-ppm-dap-taskprov-04.html#name-deriving-the-vdaf-verificat
    pub fn derive_vdaf_verify_key(
        &self,
        task_id: &TaskId,
        vdaf_instance: &VdafInstance,
    ) -> SecretBytes {
        static SALT: LazyLock<Salt> =
            LazyLock::new(|| Salt::new(HKDF_SHA256, digest(&SHA256, b"dap-taskprov").as_ref()));

        let prk = SALT.extract(self.verify_key_init.as_ref());
        let info = [task_id.as_ref().as_slice()];

        // Unwrap safety: this function only errors if the OKM length is too long
        // (<= 255 * HashLength). It is not expected that a VDAF's verify key length will ever
        // be _that_ long.
        let length = vdaf_instance.verify_key_length();
        let okm = prk.expand(&info, VdafVerifyKeyLength(length)).unwrap();

        let mut vdaf_verify_key = vec![0; length];
        // Same unwrap rationale as above.
        okm.fill(&mut vdaf_verify_key).unwrap();
        SecretBytes::new(vdaf_verify_key)
    }
}

/// Helper type for using `ring::Prk::expand()`.
struct VdafVerifyKeyLength(usize);

impl KeyType for VdafVerifyKeyLength {
    fn len(&self) -> usize {
        self.0
    }
}

pub fn taskprov_task_id(encoded_task_config: &[u8]) -> TaskId {
    static TASK_ID_SALT: LazyLock<Digest> =
        LazyLock::new(|| digest(&SHA256, b"dap-taskprov task id"));

    let mut ctx = digest::Context::new(&SHA256);
    ctx.update(TASK_ID_SALT.as_ref());
    ctx.update(encoded_task_config);
    let digest = ctx.finish();
    // Unwrap safety: DAP task IDs, and SHA-256 hashes, are always 32 bytes long.
    TaskId::try_from(digest.as_ref()).unwrap()
}

#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util {
    use crate::{
        task::AggregationMode,
        taskprov::{PeerAggregator, VerifyKeyInit},
    };
    use janus_core::{auth_tokens::AuthenticationToken, hpke::HpkeKeypair};
    use janus_messages::{Duration, HpkeConfig, Role};
    use rand::random;
    use url::Url;

    #[derive(Debug, Clone)]
    pub struct PeerAggregatorBuilder {
        endpoint: Url,
        peer_role: Role,
        aggregation_mode: Option<AggregationMode>,
        verify_key_init: VerifyKeyInit,
        collector_hpke_config: HpkeConfig,
        report_expiry_age: Option<Duration>,
        aggregator_auth_tokens: Vec<AuthenticationToken>,
        collector_auth_tokens: Vec<AuthenticationToken>,
    }

    impl PeerAggregatorBuilder {
        pub fn new() -> Self {
            Self {
                endpoint: Url::parse("https://example.com").unwrap(),
                peer_role: Role::Leader,
                aggregation_mode: Some(AggregationMode::Synchronous),
                verify_key_init: random(),
                collector_hpke_config: HpkeKeypair::test().config().clone(),
                report_expiry_age: None,
                aggregator_auth_tokens: Vec::from([random()]),
                collector_auth_tokens: Vec::from([random()]),
            }
        }

        pub fn with_endpoint(mut self, endpoint: Url) -> Self {
            self.endpoint = endpoint;
            self
        }

        pub fn with_peer_role(mut self, peer_role: Role) -> Self {
            self.peer_role = peer_role;
            self
        }

        pub fn with_aggregation_mode(mut self, aggregation_mode: Option<AggregationMode>) -> Self {
            self.aggregation_mode = aggregation_mode;
            self
        }

        pub fn with_verify_key_init(mut self, verify_key_init: VerifyKeyInit) -> Self {
            self.verify_key_init = verify_key_init;
            self
        }

        pub fn with_collector_hpke_config(mut self, collector_hpke_config: HpkeConfig) -> Self {
            self.collector_hpke_config = collector_hpke_config;
            self
        }

        pub fn with_report_expiry_age(mut self, report_expiry_age: Option<Duration>) -> Self {
            self.report_expiry_age = report_expiry_age;
            self
        }

        pub fn with_aggregator_auth_tokens(
            mut self,
            aggregator_auth_tokens: Vec<AuthenticationToken>,
        ) -> Self {
            self.aggregator_auth_tokens = aggregator_auth_tokens;
            self
        }

        pub fn with_collector_auth_tokens(
            mut self,
            collector_auth_tokens: Vec<AuthenticationToken>,
        ) -> Self {
            self.collector_auth_tokens = collector_auth_tokens;
            self
        }

        pub fn build(self) -> anyhow::Result<PeerAggregator> {
            PeerAggregator::new(
                self.endpoint,
                self.peer_role,
                self.aggregation_mode,
                self.verify_key_init,
                self.collector_hpke_config,
                self.report_expiry_age,
                self.aggregator_auth_tokens,
                self.collector_auth_tokens,
            )
        }
    }

    impl From<PeerAggregator> for PeerAggregatorBuilder {
        fn from(value: PeerAggregator) -> Self {
            let PeerAggregator {
                endpoint,
                peer_role,
                aggregation_mode,
                verify_key_init,
                collector_hpke_config,
                report_expiry_age,
                aggregator_auth_tokens,
                collector_auth_tokens,
            } = value;
            Self {
                endpoint,
                peer_role,
                aggregation_mode,
                verify_key_init,
                collector_hpke_config,
                report_expiry_age,
                aggregator_auth_tokens,
                collector_auth_tokens,
            }
        }
    }

    impl Default for PeerAggregatorBuilder {
        fn default() -> Self {
            Self::new()
        }
    }
}
