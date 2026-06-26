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

/// `hybrid_sign_bytes`: the canonical message a PQC signature covers in
/// QoreChain's hybrid-extension scheme: `BE32(len(b0))||b0||BE32(len(auth))||auth`,
/// where `b0` is the tx body WITHOUT the PQC extension.
pub fn hybrid_sign_bytes(body_without_pqc_ext: &[u8], auth_info_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + body_without_pqc_ext.len() + auth_info_bytes.len());
    out.extend_from_slice(&(body_without_pqc_ext.len() as u32).to_be_bytes());
    out.extend_from_slice(body_without_pqc_ext);
    out.extend_from_slice(&(auth_info_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(auth_info_bytes);
    out
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

                /// Sign `message` with `secret_key` (empty context, FIPS-204 pure).
                pub fn sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, &'static str> {
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

pub const VERSION: &str = "0.1.0";
