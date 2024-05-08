use serde_test::{assert_de_tokens_error, assert_tokens, Token};

use crate::{
    roundtrip_encoding, HpkeAeadId, HpkeCiphertext, HpkeConfig, HpkeConfigId, HpkeConfigList,
    HpkeKdfId, HpkeKemId, HpkePublicKey,
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
