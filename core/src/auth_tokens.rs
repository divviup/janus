use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use derivative::Derivative;
use http::header::AUTHORIZATION;
use rand::{distributions::Standard, prelude::Distribution};
use ring::{
    constant_time,
    digest::{digest, SHA256, SHA256_OUTPUT_LEN},
};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use std::str;

/// HTTP header where auth tokens are provided in messages between participants.
pub const DAP_AUTH_HEADER: &str = "DAP-Auth-Token";

/// Different modes of authentication supported by Janus for either sending requests (e.g., leader
/// to helper) or receiving them (e.g., collector to leader).
#[derive(Clone, Derivative, Serialize, Deserialize, PartialEq, Eq)]
#[derivative(Debug)]
#[serde(tag = "type", content = "token")]
#[non_exhaustive]
pub enum AuthenticationToken {
    /// A bearer token, presented as the value of the "Authorization" HTTP header as specified in
    /// [RFC 6750 section 2.1][1].
    ///
    /// The token is not necessarily an OAuth token.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
    Bearer(TokenInner),

    /// Token presented as the value of the "DAP-Auth-Token" HTTP header. Conforms to
    /// [draft-dcook-ppm-dap-interop-test-design-03][1], sections [4.3.3][2] and [4.4.2][3], and
    /// [draft-ietf-dap-ppm-01 section 3.2][4].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-dcook-ppm-dap-interop-test-design-03
    /// [2]: https://datatracker.ietf.org/doc/html/draft-dcook-ppm-dap-interop-test-design-03#section-4.3.3
    /// [3]: https://datatracker.ietf.org/doc/html/draft-dcook-ppm-dap-interop-test-design-03#section-4.4.2
    /// [4]: https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-01#name-https-sender-authentication
    DapAuth(TokenInner),
}

impl AuthenticationToken {
    /// Attempts to create a new bearer token from the provided bytes.
    pub fn new_bearer_token_from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, anyhow::Error> {
        TokenInner::try_from(bytes.as_ref().to_vec()).map(AuthenticationToken::Bearer)
    }

    /// Attempts to create a new bearer token from the provided string
    pub fn new_bearer_token_from_string<T: Into<String>>(string: T) -> Result<Self, anyhow::Error> {
        TokenInner::try_from_str(string.into()).map(AuthenticationToken::Bearer)
    }

    /// Attempts to create a new DAP auth token from the provided bytes.
    pub fn new_dap_auth_token_from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, anyhow::Error> {
        TokenInner::try_from(bytes.as_ref().to_vec()).map(AuthenticationToken::DapAuth)
    }

    /// Attempts to create a new DAP auth token from the provided string.
    pub fn new_dap_auth_token_from_string<T: Into<String>>(
        string: T,
    ) -> Result<Self, anyhow::Error> {
        TokenInner::try_from_str(string.into()).map(AuthenticationToken::DapAuth)
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

impl Distribution<AuthenticationToken> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> AuthenticationToken {
        AuthenticationToken::Bearer(Standard::sample(self, rng))
    }
}

/// A token value used to authenticate HTTP requests.
///
/// The token is used directly in HTTP request headers without further encoding and so much be a
/// legal HTTP header value. More specifically, the token is restricted to the unpadded, URL-safe
/// Base64 alphabet, as specified in [RFC 4648 section 5][1]. The unpadded, URL-safe Base64 string
/// is the canonical form of the token and is used in configuration files, Janus aggregator API
/// requests and HTTP authentication headers.
///
/// This opaque type ensures it's impossible to construct an [`AuthenticationToken`] whose contents
/// are invalid.
///
/// [1]: https://datatracker.ietf.org/doc/html/rfc4648#section-5
#[derive(Clone, Derivative, Serialize)]
#[derivative(Debug)]
#[serde(transparent)]
pub struct TokenInner(#[derivative(Debug = "ignore")] String);

impl TokenInner {
    /// Returns the token as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn try_from_str(value: String) -> Result<Self, anyhow::Error> {
        // Verify that the string is legal unpadded, URL-safe Base64
        URL_SAFE_NO_PAD.decode(&value)?;
        Ok(Self(value))
    }

    fn try_from(value: Vec<u8>) -> Result<Self, anyhow::Error> {
        Self::try_from_str(String::from_utf8(value)?)
    }
}

impl AsRef<[u8]> for TokenInner {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<'de> Deserialize<'de> for TokenInner {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .and_then(|string| Self::try_from_str(string).map_err(D::Error::custom))
    }
}

impl PartialEq for TokenInner {
    fn eq(&self, other: &Self) -> bool {
        // We attempt constant-time comparisons of the token data to mitigate timing attacks. Note
        // that this function still eaks whether the lengths of the tokens are equal -- this is
        // acceptable because we expec the content of the tokens to provide enough randomness that
        // needs to be guessed even if the length is known.
        constant_time::verify_slices_are_equal(self.0.as_bytes(), other.0.as_bytes()).is_ok()
    }
}

impl Eq for TokenInner {}

impl Distribution<TokenInner> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> TokenInner {
        TokenInner(URL_SAFE_NO_PAD.encode(rng.gen::<[u8; 16]>()))
    }
}

/// The hash of an authentication token, which may be used to validate tokens in incoming requests
/// but not to authenticate outgoing requests.
#[derive(Clone, Derivative, Deserialize, Serialize, Eq)]
#[derivative(Debug)]
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
        #[derivative(Debug = "ignore")]
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
        #[derivative(Debug = "ignore")]
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

    #[rstest::rstest]
    #[case::dap_auth("DapAuth")]
    #[case::bearer("Bearer")]
    #[test]
    fn reject_invalid_auth_token(#[case] token_type: &str) {
        serde_yaml::from_str::<AuthenticationToken>(&format!(
            "{{type: \"{token_type}\", token: \"é\"}}"
        ))
        .unwrap_err();
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
