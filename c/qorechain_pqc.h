/* qorechain_pqc.h — QoreChain post-quantum cryptography (C binding over liboqs).
 *
 * Standardized NIST primitives:
 *   - ML-DSA   (FIPS-204) signatures — "ML-DSA-44" / "ML-DSA-65" / "ML-DSA-87"
 *   - ML-KEM   (FIPS-203) key encapsulation — "ML-KEM-512" / "ML-KEM-768" / "ML-KEM-1024"
 *   - SHAKE-256 (FIPS-202) extendable-output hash
 *
 * The API mirrors the other language bindings in this repo and is validated
 * against the shared vectors in /vectors.
 */
#ifndef QORECHAIN_PQC_H
#define QORECHAIN_PQC_H

#include <stddef.h>
#include <stdint.h>

#define QPQC_OK 0
#define QPQC_ERR -1

#define QPQC_MLDSA_DEFAULT "ML-DSA-87"
#define QPQC_MLKEM_DEFAULT "ML-KEM-1024"

#ifdef __cplusplus
extern "C" {
#endif

/* ML-DSA: generate a keypair. Caller must qpqc_free() the returned buffers. */
int qpqc_mldsa_keygen(const char *alg, uint8_t **pk, size_t *pk_len, uint8_t **sk, size_t *sk_len);

/* ML-DSA: sign `msg` with `sk`. Caller must qpqc_free() *sig.
 * DETERMINISTIC (FIPS-204 §3.4): same (sk, msg) always yields the same
 * signature — required by QoreChain's on-chain PQC verifier and matched by the
 * shared /vectors. Not thread-safe against concurrent liboqs RNG use (see .c). */
int qpqc_mldsa_sign(const char *alg, const uint8_t *sk, size_t sk_len,
                    const uint8_t *msg, size_t msg_len, uint8_t **sig, size_t *sig_len);

/* ML-DSA: randomized (hedged) signing — NOT accepted by QoreChain's on-chain
 * verifier; opt-in for non-chain uses. Caller must qpqc_free() *sig. */
int qpqc_mldsa_sign_hedged(const char *alg, const uint8_t *sk, size_t sk_len,
                           const uint8_t *msg, size_t msg_len, uint8_t **sig, size_t *sig_len);

/* ML-DSA: verify. Returns 1 if valid, 0 if invalid, <0 on error. */
int qpqc_mldsa_verify(const char *alg, const uint8_t *pk, size_t pk_len,
                      const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len);

/* ML-KEM: decapsulate `ct` with `sk` into `ss_out` (32 bytes). */
int qpqc_mlkem_decapsulate(const char *alg, const uint8_t *sk, size_t sk_len,
                           const uint8_t *ct, size_t ct_len, uint8_t *ss_out, size_t *ss_len);

/* ML-KEM: encapsulate to `pk`. Caller must qpqc_free() *ct. ss_out is 32 bytes. */
int qpqc_mlkem_encapsulate(const char *alg, const uint8_t *pk, size_t pk_len,
                           uint8_t **ct, size_t *ct_len, uint8_t *ss_out, size_t *ss_len);

/* SHAKE-256 (FIPS-202) XOF. */
void qpqc_shake256(const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len);

/* pubkey_hash: SHAKE-256(pk) truncated to out_len bytes (e.g. 20). */
void qpqc_pubkey_hash(const uint8_t *pk, size_t pk_len, uint8_t *out, size_t out_len);

/* Hybrid sign-bytes: the message a PQC signature covers in QoreChain's
 * hybrid-extension scheme (b0 = tx body WITHOUT the PQC extension, auth =
 * AuthInfo bytes). Two forms exist and a network accepts exactly ONE at any height:
 *   v1 (legacy): BE32(len b0) || b0 || BE32(len auth) || auth
 *   v2:          "qorechain-pqc-hybrid-v2" || BE64(len chain_id) || chain_id || <v1 layout>
 * Networks that existed before chain release v3.1.98 verify v1 until that upgrade
 * is applied on them, v2 afterwards (qpqc_sign_bytes_version_for). This library is
 * pure: asking a network for its applied height is left to the caller. */
#define QPQC_HYBRID_SIGN_BYTES_DOMAIN "qorechain-pqc-hybrid-v2"
#define QPQC_SIGN_BYTES_V2_UPGRADE "v3.1.98"
#define QPQC_SIGN_BYTES_V1 1
#define QPQC_SIGN_BYTES_V2 2

/* QPQC_SIGN_BYTES_V2 if v2_applied_height > 0 or chain_id is not a legacy network
 * ("qorechain-vladi", "qorechain-diana"), else QPQC_SIGN_BYTES_V1. */
int qpqc_sign_bytes_version_for(const char *chain_id, int64_t v2_applied_height);

/* Legacy v1 form. Caller frees *out with qpqc_free. */
int qpqc_hybrid_sign_bytes_v1(const uint8_t *b0, size_t b0_len, const uint8_t *auth, size_t auth_len,
                              uint8_t **out, size_t *out_len);

/* v2 form; chain_id is chain_id_len UTF-8 bytes (no terminator needed). Caller frees *out. */
int qpqc_hybrid_sign_bytes_v2(const char *chain_id, size_t chain_id_len,
                              const uint8_t *b0, size_t b0_len, const uint8_t *auth, size_t auth_len,
                              uint8_t **out, size_t *out_len);

/* Form named by version (QPQC_SIGN_BYTES_V1 / _V2); any other version -> QPQC_ERR.
 * There is no implicit form. Caller frees *out. */
int qpqc_hybrid_sign_bytes(int version, const char *chain_id, size_t chain_id_len,
                           const uint8_t *b0, size_t b0_len, const uint8_t *auth, size_t auth_len,
                           uint8_t **out, size_t *out_len);

/* Free a buffer returned by this library. */
void qpqc_free(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* QORECHAIN_PQC_H */
