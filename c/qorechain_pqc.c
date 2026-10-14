/* qorechain_pqc.c — implementation over liboqs (Open Quantum Safe). */
#include "qorechain_pqc.h"
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* liboqs draws all randomness from one process-global RNG, and the
 * deterministic sign path below switches that RNG to a zero filler for the
 * duration of the call. Every operation in this file that needs real
 * randomness takes the same lock, so a keygen or encapsulation on another
 * thread cannot land inside that window and draw zeros (which yields a key
 * anyone can reproduce). The lock covers this binding only: other liboqs
 * callers in the same process are not protected. */
static pthread_mutex_t qpqc_rng_lock = PTHREAD_MUTEX_INITIALIZER;

int qpqc_mldsa_keygen(const char *alg, uint8_t **pk, size_t *pk_len, uint8_t **sk, size_t *sk_len) {
    OQS_SIG *s = OQS_SIG_new(alg);
    if (!s) return QPQC_ERR;
    *pk = malloc(s->length_public_key);
    *sk = malloc(s->length_secret_key);
    if (!*pk || !*sk) { OQS_SIG_free(s); return QPQC_ERR; }
    pthread_mutex_lock(&qpqc_rng_lock);
    int rc = (OQS_SIG_keypair(s, *pk, *sk) == OQS_SUCCESS) ? QPQC_OK : QPQC_ERR;
    pthread_mutex_unlock(&qpqc_rng_lock);
    *pk_len = s->length_public_key; *sk_len = s->length_secret_key;
    OQS_SIG_free(s);
    return rc;
}

/* liboqs's ML-DSA signs hedged: it draws the 32-byte FIPS-204 `rnd` from
 * OQS_randombytes. QoreChain's on-chain PQC verifier accepts ONLY the
 * DETERMINISTIC variant (rnd = 32 zero bytes), matching the shared /vectors
 * and every other language binding — so qpqc_mldsa_sign routes OQS_randombytes
 * to a zero filler for the duration of the sign call, then restores the system
 * RNG. This default is consensus-critical: do not change it.
 *
 * The RNG switch is process-global in liboqs, so this call and every other
 * randomness consumer in this file serialise on qpqc_rng_lock. */
static void qpqc_zero_rng(uint8_t *out, size_t n) { memset(out, 0, n); }

int qpqc_mldsa_sign(const char *alg, const uint8_t *sk, size_t sk_len,
                    const uint8_t *msg, size_t msg_len, uint8_t **sig, size_t *sig_len) {
    OQS_SIG *s = OQS_SIG_new(alg);
    if (!s) return QPQC_ERR;
    if (sk_len != s->length_secret_key) { OQS_SIG_free(s); return QPQC_ERR; }
    *sig = malloc(s->length_signature);
    if (!*sig) { OQS_SIG_free(s); return QPQC_ERR; }
    pthread_mutex_lock(&qpqc_rng_lock);
    OQS_randombytes_custom_algorithm(qpqc_zero_rng);
    int rc = (OQS_SIG_sign(s, *sig, sig_len, msg, msg_len, sk) == OQS_SUCCESS) ? QPQC_OK : QPQC_ERR;
    OQS_randombytes_switch_algorithm(OQS_RAND_alg_system);
    pthread_mutex_unlock(&qpqc_rng_lock);
    OQS_SIG_free(s);
    return rc;
}

/* Randomized (hedged) signing per FIPS-204 — NOT accepted by QoreChain's
 * on-chain verifier; opt-in for non-chain uses. */
int qpqc_mldsa_sign_hedged(const char *alg, const uint8_t *sk, size_t sk_len,
                           const uint8_t *msg, size_t msg_len, uint8_t **sig, size_t *sig_len) {
    OQS_SIG *s = OQS_SIG_new(alg);
    if (!s) return QPQC_ERR;
    if (sk_len != s->length_secret_key) { OQS_SIG_free(s); return QPQC_ERR; }
    *sig = malloc(s->length_signature);
    if (!*sig) { OQS_SIG_free(s); return QPQC_ERR; }
    pthread_mutex_lock(&qpqc_rng_lock);
    int rc = (OQS_SIG_sign(s, *sig, sig_len, msg, msg_len, sk) == OQS_SUCCESS) ? QPQC_OK : QPQC_ERR;
    pthread_mutex_unlock(&qpqc_rng_lock);
    OQS_SIG_free(s);
    return rc;
}

int qpqc_mldsa_verify(const char *alg, const uint8_t *pk, size_t pk_len,
                      const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len) {
    OQS_SIG *s = OQS_SIG_new(alg);
    if (!s) return QPQC_ERR;
    if (pk_len != s->length_public_key) { OQS_SIG_free(s); return QPQC_ERR; }
    OQS_STATUS st = OQS_SIG_verify(s, msg, msg_len, sig, sig_len, pk);
    OQS_SIG_free(s);
    return st == OQS_SUCCESS ? 1 : 0;
}

int qpqc_mlkem_decapsulate(const char *alg, const uint8_t *sk, size_t sk_len,
                           const uint8_t *ct, size_t ct_len, uint8_t *ss_out, size_t *ss_len) {
    OQS_KEM *k = OQS_KEM_new(alg);
    if (!k) return QPQC_ERR;
    if (sk_len != k->length_secret_key || ct_len != k->length_ciphertext) { OQS_KEM_free(k); return QPQC_ERR; }
    int rc = (OQS_KEM_decaps(k, ss_out, ct, sk) == OQS_SUCCESS) ? QPQC_OK : QPQC_ERR;
    *ss_len = k->length_shared_secret;
    OQS_KEM_free(k);
    return rc;
}

int qpqc_mlkem_encapsulate(const char *alg, const uint8_t *pk, size_t pk_len,
                           uint8_t **ct, size_t *ct_len, uint8_t *ss_out, size_t *ss_len) {
    OQS_KEM *k = OQS_KEM_new(alg);
    if (!k) return QPQC_ERR;
    if (pk_len != k->length_public_key) { OQS_KEM_free(k); return QPQC_ERR; }
    *ct = malloc(k->length_ciphertext);
    if (!*ct) { OQS_KEM_free(k); return QPQC_ERR; }
    pthread_mutex_lock(&qpqc_rng_lock);
    int rc = (OQS_KEM_encaps(k, *ct, ss_out, pk) == OQS_SUCCESS) ? QPQC_OK : QPQC_ERR;
    pthread_mutex_unlock(&qpqc_rng_lock);
    *ct_len = k->length_ciphertext; *ss_len = k->length_shared_secret;
    OQS_KEM_free(k);
    return rc;
}

void qpqc_shake256(const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len) {
    /* SHAKE-256 (FIPS-202) via OpenSSL's XOF interface. */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
    EVP_DigestUpdate(ctx, data, data_len);
    EVP_DigestFinalXOF(ctx, out, out_len);
    EVP_MD_CTX_free(ctx);
}

void qpqc_pubkey_hash(const uint8_t *pk, size_t pk_len, uint8_t *out, size_t out_len) {
    qpqc_shake256(pk, pk_len, out, out_len);
}

static void be32(uint8_t *o, uint32_t n) { o[0]=n>>24; o[1]=n>>16; o[2]=n>>8; o[3]=n; }

static void be64(uint8_t *o, uint64_t n) { for (int i = 7; i >= 0; i--) { o[i] = (uint8_t)n; n >>= 8; } }

const char *const qpqc_sign_bytes_v2_upgrades[QPQC_SIGN_BYTES_V2_UPGRADE_COUNT] = {"v3.2.0", "v3.1.98"};

int qpqc_sign_bytes_version_for(const char *chain_id, int64_t v2_applied_height) {
    if (v2_applied_height > 0 || !chain_id) return QPQC_SIGN_BYTES_V2;
    if (!strcmp(chain_id, "qorechain-vladi") || !strcmp(chain_id, "qorechain-diana")) return QPQC_SIGN_BYTES_V1;
    return QPQC_SIGN_BYTES_V2;
}

int qpqc_sign_bytes_version_for_applied(const char *chain_id, const char *const *names,
                                        const int64_t *heights, size_t n) {
    int64_t best = 0;
    if (names && heights) {
        for (size_t i = 0; i < n; i++) {
            if (!names[i]) continue;
            for (size_t k = 0; k < QPQC_SIGN_BYTES_V2_UPGRADE_COUNT; k++) {
                if (!strcmp(names[i], qpqc_sign_bytes_v2_upgrades[k]) && heights[i] > best) best = heights[i];
            }
        }
    }
    return qpqc_sign_bytes_version_for(chain_id, best);
}

int qpqc_hybrid_sign_bytes_v1(const uint8_t *b0, size_t b0_len, const uint8_t *auth, size_t auth_len,
                              uint8_t **out, size_t *out_len) {
    size_t total = 8 + b0_len + auth_len;
    uint8_t *buf = malloc(total ? total : 1);
    if (!buf) return QPQC_ERR;
    be32(buf, (uint32_t)b0_len); if (b0_len) memcpy(buf + 4, b0, b0_len);
    be32(buf + 4 + b0_len, (uint32_t)auth_len); if (auth_len) memcpy(buf + 8 + b0_len, auth, auth_len);
    *out = buf; *out_len = total;
    return QPQC_OK;
}

int qpqc_hybrid_sign_bytes_v2(const char *chain_id, size_t chain_id_len,
                              const uint8_t *b0, size_t b0_len, const uint8_t *auth, size_t auth_len,
                              uint8_t **out, size_t *out_len) {
    if (!chain_id || chain_id_len == 0) return QPQC_ERR;
    const size_t dl = sizeof(QPQC_HYBRID_SIGN_BYTES_DOMAIN) - 1;
    size_t total = dl + 8 + chain_id_len + 8 + b0_len + auth_len;
    uint8_t *buf = malloc(total);
    if (!buf) return QPQC_ERR;
    size_t o = 0;
    memcpy(buf, QPQC_HYBRID_SIGN_BYTES_DOMAIN, dl); o += dl;
    be64(buf + o, (uint64_t)chain_id_len); o += 8;
    if (chain_id_len) memcpy(buf + o, chain_id, chain_id_len);
    o += chain_id_len;
    be32(buf + o, (uint32_t)b0_len); o += 4;
    if (b0_len) memcpy(buf + o, b0, b0_len);
    o += b0_len;
    be32(buf + o, (uint32_t)auth_len); o += 4;
    if (auth_len) memcpy(buf + o, auth, auth_len);
    *out = buf; *out_len = total;
    return QPQC_OK;
}

int qpqc_hybrid_sign_bytes(int version, const char *chain_id, size_t chain_id_len,
                           const uint8_t *b0, size_t b0_len, const uint8_t *auth, size_t auth_len,
                           uint8_t **out, size_t *out_len) {
    if (version == QPQC_SIGN_BYTES_V1) return qpqc_hybrid_sign_bytes_v1(b0, b0_len, auth, auth_len, out, out_len);
    if (version == QPQC_SIGN_BYTES_V2)
        return qpqc_hybrid_sign_bytes_v2(chain_id, chain_id_len, b0, b0_len, auth, auth_len, out, out_len);
    return QPQC_ERR;
}

void qpqc_free(uint8_t *buf, size_t len) { if (buf) { OQS_MEM_cleanse(buf, len); free(buf); } }
