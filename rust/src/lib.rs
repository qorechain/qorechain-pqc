//! QoreChain post-quantum cryptography.
//!
//! Standardized NIST primitives, wrapping audited pure-Rust implementations:
//! - ML-DSA   (FIPS-204) signatures — levels 44 / 65 / 87 (default 87)
//! - ML-KEM   (FIPS-203) key encapsulation — levels 512 / 768 / 1024 (default 1024)
//! - SHAKE-256 (FIPS-202) extendable-output hash
//!
//! The API mirrors the other language bindings in this repo and is validated
//! against the shared vectors in `/vectors`.

use sha3::digest::{ExtendableOutput, Update, XofReader};

/// SHAKE-256 (FIPS-202) with a 32-byte default digest.
pub fn shake256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    shake256_xof(data, &mut out);
    out
}

/// SHAKE-256 as an XOF with arbitrary output length.
pub fn shake256_xof(data: &[u8], out: &mut [u8]) {
    let mut h = sha3::Shake256::default();
    h.update(data);
    let mut reader = h.finalize_xof();
    reader.read(out);
}

/// `pubkey_hash`: SHAKE-256(public_key) truncated to `len` bytes (default 20 via
/// [`pubkey_hash20`]). Lets a chain store only the short hash in account state
/// and require the full key in the transaction (pay-to-pubkey-hash style).
pub fn pubkey_hash(public_key: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    shake256_xof(public_key, &mut out);
    out
}
pub fn pubkey_hash20(public_key: &[u8]) -> [u8; 20] {
    let mut out = [0u8; 20];
    shake256_xof(public_key, &mut out);
    out
}

// ── Hybrid sign-bytes ────────────────────────────────────────────────────────
// The message a PQC signature covers in QoreChain's hybrid-extension scheme,
// where `b0` is the tx body WITHOUT the PQC extension and `auth` the AuthInfo
// bytes. Two forms exist and a network accepts exactly ONE at any height:
//
//   v1 (legacy): BE32(len b0) ‖ b0 ‖ BE32(len auth) ‖ auth
//   v2:          "qorechain-pqc-hybrid-v2" ‖ BE64(len chain_id) ‖ chain_id ‖
//                  BE32(len b0) ‖ b0 ‖ BE32(len auth) ‖ auth
//
// The two networks that existed before v2 (`qorechain-vladi`, `qorechain-diana`)
// verify v1 until a switching upgrade is applied on them, v2 afterwards; every
// other chain verifies v2 from genesis. The switch has shipped under TWO plan
// names: testnet took it as "v3.1.98" and mainnet as "v3.2.0", and each network
// keeps its record forever. Ask the network for every name in
// `SIGN_BYTES_V2_UPGRADES` and pass the answers to
// `sign_bytes_version_for_applied`. This crate is pure: asking a network for its
// applied heights is left to the caller.

/// Domain tag of the v2 hybrid sign-bytes.
pub const HYBRID_SIGN_BYTES_DOMAIN: &str = "qorechain-pqc-hybrid-v2";
/// Every upgrade-plan name that switched a network to v2, newest first. Mirror of
/// the chain's `x/pqc/types.SignBytesV2Upgrades`. Any one of them applied
/// (height > 0) means the network verifies v2.
pub const SIGN_BYTES_V2_UPGRADES: [&str; 2] = ["v3.2.0", "v3.1.98"];
/// The primary (newest) name in [`SIGN_BYTES_V2_UPGRADES`].
///
/// **Deprecated:** a network may have taken the switch under any name in
/// [`SIGN_BYTES_V2_UPGRADES`] (testnet applied "v3.1.98", mainnet "v3.2.0"), so
/// querying only this one misreads testnet as not switched. Use
/// [`SIGN_BYTES_V2_UPGRADES`] with [`sign_bytes_version_for_applied`].
pub const SIGN_BYTES_V2_UPGRADE: &str = "v3.2.0";
/// Networks that verify v1 until one of [`SIGN_BYTES_V2_UPGRADES`] is applied on them.
pub const LEGACY_SIGN_BYTES_CHAINS: [&str; 2] = ["qorechain-vladi", "qorechain-diana"];

/// Hybrid sign-bytes form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignBytesVersion {
    /// Legacy form (no domain, no chain-id).
    V1,
    /// Domain-tagged, chain-bound form.
    V2,
}

/// The form a client must sign for `chain_id`, given the height at which the
/// switch to v2 was applied on it (0 = not applied) — already the greatest
/// height across [`SIGN_BYTES_V2_UPGRADES`]; prefer
/// [`sign_bytes_version_for_applied`], which computes it. Mirror of the chain's
/// `SignBytesVersionFor`.
pub fn sign_bytes_version_for(chain_id: &str, v2_applied_height: i64) -> SignBytesVersion {
    if v2_applied_height > 0 || !LEGACY_SIGN_BYTES_CHAINS.contains(&chain_id) {
        SignBytesVersion::V2
    } else {
        SignBytesVersion::V1
    }
}

/// [`sign_bytes_version_for`] over every known upgrade name. `applied_heights`
/// maps a plan name to the height at which the network applied it (absent or 0
/// = not applied); the greatest height across [`SIGN_BYTES_V2_UPGRADES`]
/// decides and other names are ignored. Mirror of the chain's
/// `SignBytesVersionForApplied`.
pub fn sign_bytes_version_for_applied<K>(
    chain_id: &str,
    applied_heights: &std::collections::HashMap<K, i64>,
) -> SignBytesVersion
where
    K: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let best = SIGN_BYTES_V2_UPGRADES
        .iter()
        .filter_map(|name| applied_heights.get(*name).copied())
        .fold(0i64, i64::max);
    sign_bytes_version_for(chain_id, best)
}

/// Legacy v1 hybrid sign-bytes: `BE32(len(b0))||b0||BE32(len(auth))||auth`.
pub fn hybrid_sign_bytes_v1(body_without_pqc_ext: &[u8], auth_info_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + body_without_pqc_ext.len() + auth_info_bytes.len());
    out.extend_from_slice(&(body_without_pqc_ext.len() as u32).to_be_bytes());
    out.extend_from_slice(body_without_pqc_ext);
    out.extend_from_slice(&(auth_info_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(auth_info_bytes);
    out
}

/// v2 hybrid sign-bytes: `domain||BE64(len(chain_id))||chain_id||<v1 layout>`,
/// byte-identical to the chain's `x/pqc/types.HybridSignBytes`.
///
/// This builder does not check its input. An empty `chain_id` produces bytes
/// that no network will verify (no network has an empty chain-id), so a
/// signature over them fails closed. [`try_hybrid_sign_bytes_v2`] is the
/// checked variant: it returns an error for an empty `chain_id` instead.
pub fn hybrid_sign_bytes_v2(
    chain_id: &str,
    body_without_pqc_ext: &[u8],
    auth_info_bytes: &[u8],
) -> Vec<u8> {
    let cid = chain_id.as_bytes();
    let mut out = Vec::with_capacity(
        HYBRID_SIGN_BYTES_DOMAIN.len()
            + 8
            + cid.len()
            + 8
            + body_without_pqc_ext.len()
            + auth_info_bytes.len(),
    );
    out.extend_from_slice(HYBRID_SIGN_BYTES_DOMAIN.as_bytes());
    out.extend_from_slice(&(cid.len() as u64).to_be_bytes());
    out.extend_from_slice(cid);
    out.extend_from_slice(&hybrid_sign_bytes_v1(body_without_pqc_ext, auth_info_bytes));
    out
}

/// [`hybrid_sign_bytes_v2`], returning an error for an empty `chain_id`: v2
/// sign-bytes exist to bind a signature to one network, and no network has an
/// empty chain-id.
pub fn try_hybrid_sign_bytes_v2(
    chain_id: &str,
    body_without_pqc_ext: &[u8],
    auth_info_bytes: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if chain_id.is_empty() {
        return Err("hybrid sign-bytes v2: chain_id is required");
    }
    Ok(hybrid_sign_bytes_v2(chain_id, body_without_pqc_ext, auth_info_bytes))
}

/// Hybrid sign-bytes in the given form. The version is required: there is no
/// implicit form, because each network accepts exactly one.
///
/// Like [`hybrid_sign_bytes_v2`], this does not check its input: v2 with an
/// empty `chain_id` produces bytes no network will verify.
/// [`try_hybrid_sign_bytes`] is the checked variant.
pub fn hybrid_sign_bytes(
    version: SignBytesVersion,
    chain_id: &str,
    body_without_pqc_ext: &[u8],
    auth_info_bytes: &[u8],
) -> Vec<u8> {
    match version {
        SignBytesVersion::V1 => hybrid_sign_bytes_v1(body_without_pqc_ext, auth_info_bytes),
        SignBytesVersion::V2 => {
            hybrid_sign_bytes_v2(chain_id, body_without_pqc_ext, auth_info_bytes)
        }
    }
}

/// [`hybrid_sign_bytes`], returning an error when v2 is asked for with an
/// empty `chain_id`.
pub fn try_hybrid_sign_bytes(
    version: SignBytesVersion,
    chain_id: &str,
    body_without_pqc_ext: &[u8],
    auth_info_bytes: &[u8],
) -> Result<Vec<u8>, &'static str> {
    match version {
        SignBytesVersion::V1 => Ok(hybrid_sign_bytes_v1(body_without_pqc_ext, auth_info_bytes)),
        SignBytesVersion::V2 => {
            try_hybrid_sign_bytes_v2(chain_id, body_without_pqc_ext, auth_info_bytes)
        }
    }
}

/// ML-DSA (FIPS-204) signatures.
pub mod mldsa {
    macro_rules! mldsa_level {
        ($modname:ident, $fips:path, $pk_len:expr, $sk_len:expr, $sig_len:expr) => {
            pub mod $modname {
                use $fips as scheme;
                use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

                pub const PUBLIC_KEY_LEN: usize = $pk_len;
                pub const SECRET_KEY_LEN: usize = $sk_len;
                pub const SIGNATURE_LEN: usize = $sig_len;

                /// Generate a fresh keypair. Returns `(public_key, secret_key)`.
                pub fn keygen() -> Result<(Vec<u8>, Vec<u8>), &'static str> {
                    let (pk, sk) = scheme::try_keygen().map_err(|_| "keygen failed")?;
                    Ok((pk.into_bytes().to_vec(), sk.into_bytes().to_vec()))
                }

                /// Deterministically derive `(public_key, secret_key)` from the
                /// 32-byte FIPS-204 xi seed — reproduces the shared `/vectors`
                /// and the other language bindings byte-for-byte.
                pub fn keygen_from_seed(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
                    let (pk, sk) = <scheme::KG as KeyGen>::keygen_from_seed(seed);
                    (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
                }

                /// Sign `message` with `secret_key` (empty context, FIPS-204 pure).
                ///
                /// DETERMINISTIC (FIPS-204 §3.4): same `(secret_key, message)`
                /// always yields the same signature, matching every other
                /// language binding and the shared `/vectors`. QoreChain's
                /// on-chain PQC verifier accepts any valid FIPS-204 signature,
                /// hedged or deterministic; the default keeps signatures
                /// reproducible. Use [`sign_hedged`] for randomized signatures,
                /// which the chain accepts equally.
                pub fn sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, &'static str> {
                    let arr: [u8; SECRET_KEY_LEN] =
                        secret_key.try_into().map_err(|_| "bad secret key length")?;
                    let sk = scheme::PrivateKey::try_from_bytes(arr).map_err(|_| "bad secret key")?;
                    // rnd = 32 zero bytes == the FIPS-204 deterministic variant.
                    let sig = sk
                        .try_sign_with_seed(&[0u8; 32], message, &[])
                        .map_err(|_| "sign failed")?;
                    Ok(sig.to_vec())
                }

                /// Randomized (hedged) signing per FIPS-204 — accepted by
                /// QoreChain's on-chain verifier like [`sign`]; not reproducible.
                pub fn sign_hedged(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, &'static str> {
                    let arr: [u8; SECRET_KEY_LEN] =
                        secret_key.try_into().map_err(|_| "bad secret key length")?;
                    let sk = scheme::PrivateKey::try_from_bytes(arr).map_err(|_| "bad secret key")?;
                    let sig = sk.try_sign(message, &[]).map_err(|_| "sign failed")?;
                    Ok(sig.to_vec())
                }

                /// Verify `signature` over `message` under `public_key`.
                pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
                    let pk_arr: [u8; PUBLIC_KEY_LEN] = match public_key.try_into() {
                        Ok(a) => a,
                        Err(_) => return false,
                    };
                    let sig_arr: [u8; SIGNATURE_LEN] = match signature.try_into() {
                        Ok(a) => a,
                        Err(_) => return false,
                    };
                    match scheme::PublicKey::try_from_bytes(pk_arr) {
                        Ok(pk) => pk.verify(message, &sig_arr, &[]),
                        Err(_) => false,
                    }
                }
            }
        };
    }
    mldsa_level!(ml_dsa_44, fips204::ml_dsa_44, 1312, 2560, 2420);
    mldsa_level!(ml_dsa_65, fips204::ml_dsa_65, 1952, 4032, 3309);
    mldsa_level!(ml_dsa_87, fips204::ml_dsa_87, 2592, 4896, 4627);

    /// QoreChain default signature level (security level 5).
    pub use ml_dsa_87 as default;
}

/// ML-KEM (FIPS-203) key encapsulation.
pub mod mlkem {
    macro_rules! mlkem_level {
        ($modname:ident, $fips:path, $ek_len:expr, $dk_len:expr, $ct_len:expr) => {
            pub mod $modname {
                use $fips as scheme;
                use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};

                pub const PUBLIC_KEY_LEN: usize = $ek_len;
                pub const SECRET_KEY_LEN: usize = $dk_len;
                pub const CIPHERTEXT_LEN: usize = $ct_len;
                pub const SHARED_SECRET_LEN: usize = 32;

                pub fn keygen() -> Result<(Vec<u8>, Vec<u8>), &'static str> {
                    let (ek, dk) = scheme::KG::try_keygen().map_err(|_| "keygen failed")?;
                    Ok((ek.into_bytes().to_vec(), dk.into_bytes().to_vec()))
                }

                /// Encapsulate to `public_key` -> `(ciphertext, shared_secret)`.
                pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, [u8; 32]), &'static str> {
                    let arr: [u8; PUBLIC_KEY_LEN] =
                        public_key.try_into().map_err(|_| "bad public key length")?;
                    let ek = scheme::EncapsKey::try_from_bytes(arr).map_err(|_| "bad public key")?;
                    let (ss, ct) = ek.try_encaps().map_err(|_| "encaps failed")?;
                    Ok((ct.into_bytes().to_vec(), ss.into_bytes()))
                }

                /// Decapsulate `ciphertext` with `secret_key` -> shared secret.
                pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<[u8; 32], &'static str> {
                    let sk_arr: [u8; SECRET_KEY_LEN] =
                        secret_key.try_into().map_err(|_| "bad secret key length")?;
                    let ct_arr: [u8; CIPHERTEXT_LEN] =
                        ciphertext.try_into().map_err(|_| "bad ciphertext length")?;
                    let dk = scheme::DecapsKey::try_from_bytes(sk_arr).map_err(|_| "bad secret key")?;
                    let ct = scheme::CipherText::try_from_bytes(ct_arr).map_err(|_| "bad ciphertext")?;
                    let ss = dk.try_decaps(&ct).map_err(|_| "decaps failed")?;
                    Ok(ss.into_bytes())
                }
            }
        };
    }
    mlkem_level!(ml_kem_512, fips203::ml_kem_512, 800, 1632, 768);
    mlkem_level!(ml_kem_768, fips203::ml_kem_768, 1184, 2400, 1088);
    mlkem_level!(ml_kem_1024, fips203::ml_kem_1024, 1568, 3168, 1568);

    /// QoreChain default KEM level (security level 5).
    pub use ml_kem_1024 as default;
}

pub const VERSION: &str = "0.2.1";
