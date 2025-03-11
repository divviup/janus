use anyhow::anyhow;
use aws_lc_rs::{
    constant_time,
    digest::{digest, SHA256, SHA256_OUTPUT_LEN},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use educe::Educe;
use http::{header::AUTHORIZATION, HeaderValue};
use rand::{distributions::Standard, prelude::Distribution};
use regex::Regex;
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    str::{self, FromStr},
    sync::OnceLock,
};

/// HTTP header where auth tokens are provided in messages between participants.
pub const DAP_AUTH_HEADER: &str = "DAP-Auth-Token";

/// Different modes of authentication supported by Janus for either sending requests (e.g., leader
/// to helper) or receiving them (e.g., collector to leader).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "token")]
#[non_exhaustive]
pub enum AuthenticationToken {
    /// A bearer token, presented as the value of the "Authorization" HTTP header as specified in
    /// [RFC 6750 section 2.1][1].
    ///
    /// The token is not necessarily an OAuth token.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
    Bearer(BearerToken),

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
    /// Attempts to create a new bearer token from the provided bytes.
    pub fn new_bearer_token_from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, anyhow::Error> {
        BearerToken::try_from(bytes.as_ref().to_vec()).map(AuthenticationToken::Bearer)
    }

    /// Attempts to create a new bearer token from the provided string
    pub fn new_bearer_token_from_string<T: Into<String>>(string: T) -> Result<Self, anyhow::Error> {
        BearerToken::try_from(string.into()).map(AuthenticationToken::Bearer)
    }

    /// Attempts to create a new DAP auth token from the provided bytes.
    pub fn new_dap_auth_token_from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, anyhow::Error> {
        DapAuthToken::try_from(bytes.as_ref().to_vec()).map(AuthenticationToken::DapAuth)
    }

    /// Attempts to create a new DAP auth token from the provided string.
    pub fn new_dap_auth_token_from_string<T: Into<String>>(
        string: T,
    ) -> Result<Self, anyhow::Error> {
        DapAuthToken::try_from(string.into()).map(AuthenticationToken::DapAuth)
    }

    /// Returns an HTTP header and value that should be used to authenticate an HTTP request with
    /// this credential.
    pub fn request_authentication(&self) -> (&'static str, String) {
        match self {
            Self::Bearer(token) => (AUTHORIZATION.as_str(), format!("Bearer {}", token.as_str())),
            // Cloning is unfortunate but necessary since other arms must allocate.
            Self::DapAuth(token) => (DAP_AUTH_HEADER, token.as_str().to_string()),
        }
    }

    /// Returns the token as a string.
    pub fn as_str(&self) -> &str {
        match self {
            Self::DapAuth(token) => token.as_str(),
            Self::Bearer(token) => token.as_str(),
        }
    }
}

impl AsRef<[u8]> for AuthenticationToken {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::DapAuth(token) => token.as_ref(),
            Self::Bearer(token) => token.as_ref(),
        }
    }
}

impl FromStr for AuthenticationToken {
    type Err = anyhow::Error;

    /// Parses an authentication token flag value into an AuthenticationToken, in the following way:
    ///   * `bearer:value` is translated into a Bearer token, with the given value.
    ///   * `dap:value` is translated into a DAP Auth token, with the given value.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(s) = s.strip_prefix("bearer:") {
            return Ok(Self::Bearer(BearerToken::from_str(s)?));
        }
        if let Some(s) = s.strip_prefix("dap:") {
            return Ok(Self::DapAuth(DapAuthToken::from_str(s)?));
        }
        Err(anyhow!(
            "bad or missing prefix on authentication token flag value"
        ))
    }
}

impl Distribution<AuthenticationToken> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> AuthenticationToken {
        AuthenticationToken::Bearer(Standard::sample(self, rng))
    }
}

/// A token value used to authenticate HTTP requests. This token is used in the "DAP-Auth-Token"
/// HTTP request header.
///
/// This token is used directly in HTTP request headers without further encoding and so must be a
/// legal HTTP header value. The literal value is the canonical form of the token and is used
/// directly, without any additional encoding or decoding, in configuration files, Janus aggregator
/// API requests, and HTTP authentication headers.
///
/// This opaque type ensures it's impossible to construct an [`AuthenticationToken`] whose contents
/// are invalid.
#[derive(Clone, Educe, Serialize)]
#[educe(Debug)]
#[serde(transparent)]
pub struct DapAuthToken(#[educe(Debug(ignore))] String);

impl DapAuthToken {
    /// Returns the token as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate that a DAP-Auth-Token value is a valid HTTP header value.
    fn validate(value: &str) -> Result<(), anyhow::Error> {
        HeaderValue::try_from(value)?;
        Ok(())
    }
}

impl AsRef<str> for DapAuthToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<[u8]> for DapAuthToken {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<DapAuthToken> for AuthenticationToken {
    fn from(value: DapAuthToken) -> Self {
        Self::DapAuth(value)
    }
}

impl TryFrom<String> for DapAuthToken {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::validate(&value)?;
        Ok(Self(value))
    }
}

impl FromStr for DapAuthToken {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_string())
    }
}

impl TryFrom<Vec<u8>> for DapAuthToken {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(String::from_utf8(value)?)
    }
}

impl<'de> Deserialize<'de> for DapAuthToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .and_then(|string| Self::try_from(string).map_err(D::Error::custom))
    }
}

impl PartialEq for DapAuthToken {
    fn eq(&self, other: &Self) -> bool {
        // We attempt constant-time comparisons of the token data to mitigate timing attacks. Note
        // that this function still leaks whether the lengths of the tokens are equal -- this is
        // acceptable because we expect the content of the tokens to provide enough randomness that
        // needs to be guessed even if the length is known.
        constant_time::verify_slices_are_equal(self.0.as_ref(), other.0.as_ref()).is_ok()
    }
}

impl Eq for DapAuthToken {}

impl Distribution<DapAuthToken> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> DapAuthToken {
        DapAuthToken(URL_SAFE_NO_PAD.encode(rng.gen::<[u8; 16]>()))
    }
}

/// A token value used to authenticate HTTP requests. This token is used in "Authorization: Bearer"
/// HTTP request headers.
///
/// Token values must follow the syntax in
/// <https://datatracker.ietf.org/doc/html/rfc6750#section-2.1>. Its literal value is the canonical
/// form of the token and is used directly, without any additional encoding or decoding, in
/// configuration files, Janus aggregator API requests, and HTTP authentication headers.
///
/// This opaque type ensures it's impossible to construct an [`AuthenticationToken`] whose contents
/// are invalid.
#[derive(Clone, Educe, Serialize)]
#[educe(Debug)]
#[serde(transparent)]
pub struct BearerToken(#[educe(Debug(ignore))] String);

impl BearerToken {
    /// Returns the token as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate that a bearer token value matches the format for [OAuth 2.0 bearer tokens][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
    fn validate(value: &str) -> Result<(), anyhow::Error> {
        static REGEX: OnceLock<Regex> = OnceLock::new();

        let regex = REGEX.get_or_init(|| Regex::new("^[-A-Za-z0-9._~+/]+=*$").unwrap());

        if regex.is_match(value) {
            Ok(())
        } else {
            Err(anyhow::anyhow!("bearer token has invalid format"))
        }
    }
}

impl AsRef<str> for BearerToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<[u8]> for BearerToken {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<BearerToken> for AuthenticationToken {
    fn from(value: BearerToken) -> Self {
        Self::Bearer(value)
    }
}

impl TryFrom<String> for BearerToken {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::validate(&value)?;
        Ok(Self(value))
    }
}

impl FromStr for BearerToken {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_string())
    }
}

impl TryFrom<Vec<u8>> for BearerToken {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(String::from_utf8(value)?)
    }
}

impl<'de> Deserialize<'de> for BearerToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .and_then(|string| Self::try_from(string).map_err(D::Error::custom))
    }
}

impl PartialEq for BearerToken {
    fn eq(&self, other: &Self) -> bool {
        // We attempt constant-time comparisons of the token data to mitigate timing attacks. Note
        // that this function still leaks whether the lengths of the tokens are equal -- this is
        // acceptable because we expect the content of the tokens to provide enough randomness that
        // needs to be guessed even if the length is known.
        constant_time::verify_slices_are_equal(self.0.as_bytes(), other.0.as_bytes()).is_ok()
    }
}

impl Eq for BearerToken {}

impl Distribution<BearerToken> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> BearerToken {
        BearerToken(URL_SAFE_NO_PAD.encode(rng.gen::<[u8; 16]>()))
    }
}

/// The hash of an authentication token, which may be used to validate tokens in incoming requests
/// but not to authenticate outgoing requests.
#[derive(Clone, Educe, Deserialize, Serialize, Eq)]
#[educe(Debug)]
#[serde(tag = "type", content = "hash")]
#[non_exhaustive]
pub enum AuthenticationTokenHash {
    /// A bearer token, presented as the value of the "Authorization" HTTP header as specified in
    /// [RFC 6750 section 2.1][1].
    ///
    /// The token is not necessarily an OAuth token.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
    Bearer(
        #[educe(Debug(ignore))]
        #[serde(
            serialize_with = "AuthenticationTokenHash::serialize_contents",
            deserialize_with = "AuthenticationTokenHash::deserialize_contents"
        )]
        [u8; SHA256_OUTPUT_LEN],
    ),

    /// Token presented as the value of the "DAP-Auth-Token" HTTP header. Conforms to
    /// [draft-dcook-ppm-dap-interop-test-design-03][1], sections [4.3.3][2] and [4.4.2][3], and
    /// [draft-ietf-dap-ppm-01 section 3.2][4].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-dcook-ppm-dap-interop-test-design-03
    /// [2]: https://datatracker.ietf.org/doc/html/draft-dcook-ppm-dap-interop-test-design-03#section-4.3.3
    /// [3]: https://datatracker.ietf.org/doc/html/draft-dcook-ppm-dap-interop-test-design-03#section-4.4.2
    /// [4]: https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-01#name-https-sender-authentication
    DapAuth(
        #[educe(Debug(ignore))]
        #[serde(
            serialize_with = "AuthenticationTokenHash::serialize_contents",
            deserialize_with = "AuthenticationTokenHash::deserialize_contents"
        )]
        [u8; SHA256_OUTPUT_LEN],
    ),
}

impl AuthenticationTokenHash {
    /// Returns true if the incoming unhashed token matches this token hash, false otherwise.
    pub fn validate(&self, incoming_token: &AuthenticationToken) -> bool {
        &Self::from(incoming_token) == self
    }

    fn serialize_contents<S: Serializer>(
        value: &[u8; SHA256_OUTPUT_LEN],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(value))
    }

    fn deserialize_contents<'de, D>(deserializer: D) -> Result<[u8; SHA256_OUTPUT_LEN], D::Error>
    where
        D: Deserializer<'de>,
    {
        let b64_digest: String = Deserialize::deserialize(deserializer)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(b64_digest)
            .map_err(D::Error::custom)?;

        decoded
            .try_into()
            .map_err(|_| D::Error::custom("digest has wrong length"))
    }
}

impl From<&AuthenticationToken> for AuthenticationTokenHash {
    fn from(value: &AuthenticationToken) -> Self {
        // unwrap safety: try_into is converting from &[u8] to [u8; SHA256_OUTPUT_LEN]. SHA256
        // output will always be that length, so this conversion should never fail.
        let digest = digest(&SHA256, value.as_ref()).as_ref().try_into().unwrap();

        match value {
            AuthenticationToken::Bearer(_) => Self::Bearer(digest),
            AuthenticationToken::DapAuth(_) => Self::DapAuth(digest),
        }
    }
}

impl PartialEq for AuthenticationTokenHash {
    fn eq(&self, other: &Self) -> bool {
        let (self_digest, other_digest) = match (self, other) {
            (Self::Bearer(self_digest), Self::Bearer(other_digest)) => (self_digest, other_digest),
            (Self::DapAuth(self_digest), Self::DapAuth(other_digest)) => {
                (self_digest, other_digest)
            }
            _ => return false,
        };

        // We attempt constant-time comparisons of the token data to mitigate timing attacks.
        constant_time::verify_slices_are_equal(self_digest.as_ref(), other_digest.as_ref()).is_ok()
    }
}

impl AsRef<[u8]> for AuthenticationTokenHash {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Bearer(inner) => inner.as_slice(),
            Self::DapAuth(inner) => inner.as_slice(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::auth_tokens::{AuthenticationToken, AuthenticationTokenHash};
    use rand::random;
    use std::str::FromStr as _;

    #[test]
    fn valid_dap_auth_token() {
        serde_yaml::from_str::<AuthenticationToken>(
            "{type: \"DapAuth\", token: \"correct-horse-battery-staple-!@#$\"}",
        )
        .unwrap();
    }

    #[test]
    fn valid_bearer_token() {
        serde_yaml::from_str::<AuthenticationToken>(
            "{type: \"Bearer\", token: \"AAAAAAA~-_/A===\"}",
        )
        .unwrap();
    }

    #[test]
    fn reject_invalid_auth_token_dap_auth() {
        serde_yaml::from_str::<AuthenticationToken>("{type: \"DapAuth\", token: \"\\x0b\"}")
            .unwrap_err();
        serde_yaml::from_str::<AuthenticationToken>("{type: \"DapAuth\", token: \"\\x00\"}")
            .unwrap_err();
    }

    #[test]
    fn reject_invalid_auth_token_bearer() {
        serde_yaml::from_str::<AuthenticationToken>("{type: \"Bearer\", token: \"é\"}")
            .unwrap_err();
        serde_yaml::from_str::<AuthenticationToken>("{type: \"Bearer\", token: \"^\"}")
            .unwrap_err();
        serde_yaml::from_str::<AuthenticationToken>("{type: \"Bearer\", token: \"=\"}")
            .unwrap_err();
        serde_yaml::from_str::<AuthenticationToken>("{type: \"Bearer\", token: \"AAAA==AAA\"}")
            .unwrap_err();
    }

    #[test]
    fn authentication_token_from_str() {
        for (value, expected_result) in [
            (
                "bearer:foo",
                Some(AuthenticationToken::new_bearer_token_from_string("foo").unwrap()),
            ),
            (
                "dap:foo",
                Some(AuthenticationToken::new_dap_auth_token_from_string("foo").unwrap()),
            ),
            ("badtype:foo", None),
            ("notype", None),
        ] {
            let rslt = AuthenticationToken::from_str(value);
            match expected_result {
                Some(expected_result) => assert_eq!(rslt.unwrap(), expected_result),
                None => assert!(rslt.is_err()),
            }
        }
    }

    #[rstest::rstest]
    #[case::bearer(r#"{ type: "Bearer", hash: "MJOoBO_ysLEuG_lv2C37eEOf1Ngetsr-Ers0ZYj4vdQ" }"#)]
    #[case::dap_auth(r#"{ type: "DapAuth", hash: "MJOoBO_ysLEuG_lv2C37eEOf1Ngetsr-Ers0ZYj4vdQ" }"#)]
    #[test]
    fn serde_aggregator_token_hash_valid(#[case] yaml: &str) {
        serde_yaml::from_str::<AuthenticationTokenHash>(yaml).unwrap();
    }

    #[rstest::rstest]
    #[case::bearer_token_invalid_encoding(r#"{ type: "Bearer", hash: "+" }"#)]
    #[case::bearer_token_wrong_length(
        r#"{ type: "Bearer", hash: "MJOoBO_ysLEuG_lv2C37eEOf1Ngetsr-Ers0ZYj4" }"#
    )]
    #[case::dap_auth_token_invalid_encoding(r#"{ type: "DapAuth", hash: "+" }"#)]
    #[case::dap_auth_token_wrong_length(
        r#"{ type: "DapAuth", hash: "MJOoBO_ysLEuG_lv2C37eEOf1Ngetsr-Ers0ZYj4" }"#
    )]
    #[test]
    fn serde_aggregator_token_hash_invalid(#[case] yaml: &str) {
        serde_yaml::from_str::<AuthenticationTokenHash>(yaml).unwrap_err();
    }

    #[test]
    fn validate_token() {
        let dap_auth_token_1 = AuthenticationToken::DapAuth(random());
        let dap_auth_token_2 = AuthenticationToken::DapAuth(random());
        let bearer_token_1 = AuthenticationToken::Bearer(random());
        let bearer_token_2 = AuthenticationToken::Bearer(random());

        assert_eq!(dap_auth_token_1, dap_auth_token_1);
        assert_ne!(dap_auth_token_1, dap_auth_token_2);
        assert_eq!(bearer_token_1, bearer_token_1);
        assert_ne!(bearer_token_1, bearer_token_2);
        assert_ne!(dap_auth_token_1, bearer_token_1);

        assert!(AuthenticationTokenHash::from(&dap_auth_token_1).validate(&dap_auth_token_1));
        assert!(!AuthenticationTokenHash::from(&dap_auth_token_1).validate(&dap_auth_token_2));
        assert!(AuthenticationTokenHash::from(&bearer_token_1).validate(&bearer_token_1));
        assert!(!AuthenticationTokenHash::from(&bearer_token_1).validate(&bearer_token_2));
        assert!(!AuthenticationTokenHash::from(&dap_auth_token_1).validate(&bearer_token_1));
    }
}
