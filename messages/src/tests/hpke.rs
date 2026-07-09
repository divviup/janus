use serde_test::{Token, assert_de_tokens_error, assert_tokens};

use crate::{
    HpkeAeadId, HpkeCiphertext, HpkeConfig, HpkeConfigId, HpkeConfigList, HpkeKdfId, HpkeKemId,
    HpkePublicKey, roundtrip_encoding,
};

#[test]
fn roundtrip_hpke_config_id() {
    roundtrip_encoding(&[
        (HpkeConfigId(u8::MIN), "00"),
        (HpkeConfigId(10), "0A"),
        (HpkeConfigId(u8::MAX), "FF"),
    ])
}

#[test]
fn roundtrip_hpke_kem_id() {
    roundtrip_encoding(&[
        (HpkeKemId::P256HkdfSha256, "0010"),
        (HpkeKemId::X25519HkdfSha256, "0020"),
    ])
}

#[test]
fn roundtrip_hpke_kdf_id() {
    roundtrip_encoding(&[
        (HpkeKdfId::HkdfSha256, "0001"),
        (HpkeKdfId::HkdfSha384, "0002"),
        (HpkeKdfId::HkdfSha512, "0003"),
    ])
}

#[test]
fn roundtrip_hpke_aead_id() {
    roundtrip_encoding(&[
        (HpkeAeadId::Aes128Gcm, "0001"),
        (HpkeAeadId::Aes256Gcm, "0002"),
        (HpkeAeadId::ChaCha20Poly1305, "0003"),
    ])
}

#[test]
fn roundtrip_hpke_ciphertext() {
    roundtrip_encoding(&[
        (
            HpkeCiphertext::new(HpkeConfigId::from(10), Vec::from("0123"), Vec::from("4567")),
            concat!(
                "0A", // config_id
                concat!(
                    // encapsulated_key
                    "0004",     // length
                    "30313233", // opaque data
                ),
                concat!(
                    // payload
                    "00000004", // length
                    "34353637", // opaque data
                ),
            ),
        ),
        (
            HpkeCiphertext::new(HpkeConfigId::from(12), Vec::from("01234"), Vec::from("567")),
            concat!(
                "0C", // config_id
                concat!(
                    // encapsulated_key
                    "0005",       // length
                    "3031323334", // opaque data
                ),
                concat!(
                    // payload
                    "00000003", // length
                    "353637",   // opaque data
                ),
            ),
        ),
    ])
}

#[test]
fn hpke_ciphertext_equivalent() {
    use prio::codec::Decode;
    use prio::codec::Encode;

    /// DAP protocol message representing an HPKE ciphertext.
    #[derive(Clone, educe::Educe, Eq, PartialEq)]
    #[educe(Debug)]
    pub struct OldHpkeCiphertext {
        /// An identifier of the HPKE configuration used to seal the message.
        config_id: HpkeConfigId,
        /// An encapsulated HPKE key.
        #[educe(Debug(ignore))]
        encapsulated_key: Vec<u8>,
        /// An HPKE ciphertext.
        #[educe(Debug(ignore))]
        payload: Vec<u8>,
    }

    impl OldHpkeCiphertext {
        /// Construct a HPKE ciphertext message from its components.
        pub fn new(
            config_id: HpkeConfigId,
            encapsulated_key: Vec<u8>,
            payload: Vec<u8>,
        ) -> OldHpkeCiphertext {
            OldHpkeCiphertext {
                config_id,
                encapsulated_key,
                payload,
            }
        }
    }

    impl prio::codec::Encode for OldHpkeCiphertext {
        fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), prio::codec::CodecError> {
            self.config_id.encode(bytes)?;
            prio::codec::encode_u16_items(bytes, &(), &self.encapsulated_key)?;
            prio::codec::encode_u32_items(bytes, &(), &self.payload)
        }

        fn encoded_len(&self) -> Option<usize> {
            Some(
                self.config_id.encoded_len()?
                    + 2
                    + self.encapsulated_key.len()
                    + 4
                    + self.payload.len(),
            )
        }
    }

    impl prio::codec::Decode for OldHpkeCiphertext {
        fn decode(bytes: &mut std::io::Cursor<&[u8]>) -> Result<Self, prio::codec::CodecError> {
            let config_id = HpkeConfigId::decode(bytes)?;
            let encapsulated_key = prio::codec::decode_u16_items(&(), bytes)?;
            let payload = prio::codec::decode_u32_items(&(), bytes)?;

            Ok(Self {
                config_id,
                encapsulated_key,
                payload,
            })
        }
    }

    let old_ciphertext =
        OldHpkeCiphertext::new(HpkeConfigId::from(10), Vec::from("0123"), Vec::from("4567"));
    let new_ciphertext =
        HpkeCiphertext::new(HpkeConfigId::from(10), Vec::from("0123"), Vec::from("4567"));

    assert_eq!(
        old_ciphertext.get_encoded().unwrap(),
        new_ciphertext.get_encoded().unwrap()
    );

    let decode_old_as_new =
        HpkeCiphertext::get_decoded(old_ciphertext.get_encoded().unwrap().as_ref()).unwrap();
    assert_eq!(new_ciphertext, decode_old_as_new);

    let decode_new_as_old =
        OldHpkeCiphertext::get_decoded(new_ciphertext.get_encoded().unwrap().as_ref()).unwrap();
    assert_eq!(old_ciphertext, decode_new_as_old);
}

#[test]
fn roundtrip_hpke_public_key() {
    roundtrip_encoding(&[
        (
            HpkePublicKey::from(Vec::new()),
            concat!(
                "0000", // length
                "",     // opaque data
            ),
        ),
        (
            HpkePublicKey::from(Vec::from("0123456789abcdef")),
            concat!(
                "0010",                             // length
                "30313233343536373839616263646566"  // opaque data
            ),
        ),
    ])
}

#[test]
fn roundtrip_hpke_config() {
    roundtrip_encoding(&[
        (
            HpkeConfig::new(
                HpkeConfigId::from(12),
                HpkeKemId::P256HkdfSha256,
                HpkeKdfId::HkdfSha512,
                HpkeAeadId::Aes256Gcm,
                HpkePublicKey::from(Vec::new()),
            ),
            concat!(
                "0C",   // id
                "0010", // kem_id
                "0003", // kdf_id
                "0002", // aead_id
                concat!(
                    // public_key
                    "0000", // length
                    "",     // opaque data
                )
            ),
        ),
        (
            HpkeConfig::new(
                HpkeConfigId::from(23),
                HpkeKemId::X25519HkdfSha256,
                HpkeKdfId::HkdfSha256,
                HpkeAeadId::ChaCha20Poly1305,
                HpkePublicKey::from(Vec::from("0123456789abcdef")),
            ),
            concat!(
                "17",   // id
                "0020", // kem_id
                "0001", // kdf_id
                "0003", // aead_id
                concat!(
                    // public_key
                    "0010",                             // length
                    "30313233343536373839616263646566", // opaque data
                )
            ),
        ),
        (
            HpkeConfig::new(
                HpkeConfigId::from(12),
                HpkeKemId::Other(0x9999),
                HpkeKdfId::HkdfSha512,
                HpkeAeadId::Aes256Gcm,
                HpkePublicKey::from(Vec::new()),
            ),
            concat!(
                "0C",   // id
                "9999", // kem_id
                "0003", // kdf_id
                "0002", // aead_id
                concat!(
                    // public_key
                    "0000", // length
                    "",     // opaque data
                )
            ),
        ),
        (
            HpkeConfig::new(
                HpkeConfigId::from(12),
                HpkeKemId::P256HkdfSha256,
                HpkeKdfId::Other(0x9999),
                HpkeAeadId::Aes256Gcm,
                HpkePublicKey::from(Vec::new()),
            ),
            concat!(
                "0C",   // id
                "0010", // kem_id
                "9999", // kdf_id
                "0002", // aead_id
                concat!(
                    // public_key
                    "0000", // length
                    "",     // opaque data
                )
            ),
        ),
        (
            HpkeConfig::new(
                HpkeConfigId::from(12),
                HpkeKemId::P256HkdfSha256,
                HpkeKdfId::HkdfSha512,
                HpkeAeadId::Other(0x9999),
                HpkePublicKey::from(Vec::new()),
            ),
            concat!(
                "0C",   // id
                "0010", // kem_id
                "0003", // kdf_id
                "9999", // aead_id
                concat!(
                    // public_key
                    "0000", // length
                    "",     // opaque data
                )
            ),
        ),
    ])
}

#[test]
fn roundtrip_hpke_config_list() {
    roundtrip_encoding(&[(
        HpkeConfigList::new(Vec::from([
            HpkeConfig::new(
                HpkeConfigId::from(12),
                HpkeKemId::P256HkdfSha256,
                HpkeKdfId::HkdfSha512,
                HpkeAeadId::Aes256Gcm,
                HpkePublicKey::from(Vec::new()),
            ),
            HpkeConfig::new(
                HpkeConfigId::from(12),
                HpkeKemId::P256HkdfSha256,
                HpkeKdfId::HkdfSha512,
                HpkeAeadId::Other(0x9999),
                HpkePublicKey::from(Vec::new()),
            ),
        ])),
        concat!(
            "0012",
            concat!(
                "0C",   // id
                "0010", // kem_id
                "0003", // kdf_id
                "0002", // aead_id
                concat!(
                    // public_key
                    "0000", // length
                    "",     // opaque data
                )
            ),
            concat!(
                "0C",   // id
                "0010", // kem_id
                "0003", // kdf_id
                "9999", // aead_id
                concat!(
                    // public_key
                    "0000", // length
                    "",     // opaque data
                )
            ),
        ),
    )]);
}

#[test]
fn hpke_public_key_serde() {
    assert_tokens(
        &HpkePublicKey::from(Vec::from([1, 2, 3, 4])),
        &[Token::Str("AQIDBA")],
    );
    assert_de_tokens_error::<HpkePublicKey>(&[Token::Str("/AAAA")], "invalid base64url value");
}
