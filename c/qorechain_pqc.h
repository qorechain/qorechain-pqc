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

/* ML-DSA: sign `msg` with `sk`. Caller must qpqc_free() *sig. */
int qpqc_mldsa_sign(const char *alg, const uint8_t *sk, size_t sk_len,
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

/* hybrid_sign_bytes: BE32(len(b0))||b0||BE32(len(auth))||auth. Caller frees *out. */
int qpqc_hybrid_sign_bytes(const uint8_t *b0, size_t b0_len, const uint8_t *auth, size_t auth_len,
                           uint8_t **out, size_t *out_len);

/* Free a buffer returned by this library. */
void qpqc_free(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* QORECHAIN_PQC_H */
