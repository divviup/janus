use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use derivative::Derivative;
use http::{header::AUTHORIZATION, HeaderValue};
use rand::{distributions::Standard, prelude::Distribution};
use ring::constant_time;
use serde::{de::Error, Deserialize, Deserializer, Serialize};
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
#[derive(Clone, Derivative, Serialize)]
#[derivative(Debug)]
#[serde(transparent)]
pub struct DapAuthToken(#[derivative(Debug = "ignore")] String);

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

impl TryFrom<String> for DapAuthToken {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::validate(&value)?;
        Ok(Self(value))
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
#[derive(Clone, Derivative, Serialize)]
#[derivative(Debug)]
#[serde(transparent)]
pub struct BearerToken(#[derivative(Debug = "ignore")] String);

impl BearerToken {
    /// Returns the token as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate that a bearer token value matches the format in
    /// https://datatracker.ietf.org/doc/html/rfc6750#section-2.1.
    fn validate(value: &str) -> Result<(), anyhow::Error> {
        let mut iter = value.chars();
        let mut any_non_equals = false;
        // First loop: consume "normal" characters, stop when we see an equals sign for padding or
        // reach the end of the input.
        for c in &mut iter {
            match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '.' | '_' | '~' | '+' | '/' => {
                    any_non_equals = true;
                }
                '=' => {
                    if !any_non_equals {
                        return Err(anyhow::anyhow!("bearer token may not start with '='"));
                    }
                    break;
                }
                _ => return Err(anyhow::anyhow!("bearer token may not contain '{c}'")),
            }
        }
        // Second loop: consume any further padding characters, if present.
        for c in &mut iter {
            match c {
                '=' => {}
                _ => {
                    return Err(anyhow::anyhow!(
                        "bearer token may only contain '=' at the end"
                    ))
                }
            }
        }
        Ok(())
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

impl TryFrom<String> for BearerToken {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::validate(&value)?;
        Ok(Self(value))
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

#[cfg(test)]
mod tests {
    use crate::auth_tokens::AuthenticationToken;

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
}
