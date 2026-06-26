/* qorechain_pqc.c — implementation over liboqs (Open Quantum Safe). */
#include "qorechain_pqc.h"
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

int qpqc_mldsa_keygen(const char *alg, uint8_t **pk, size_t *pk_len, uint8_t **sk, size_t *sk_len) {
    OQS_SIG *s = OQS_SIG_new(alg);
    if (!s) return QPQC_ERR;
    *pk = malloc(s->length_public_key);
    *sk = malloc(s->length_secret_key);
    if (!*pk || !*sk) { OQS_SIG_free(s); return QPQC_ERR; }
    int rc = (OQS_SIG_keypair(s, *pk, *sk) == OQS_SUCCESS) ? QPQC_OK : QPQC_ERR;
    *pk_len = s->length_public_key; *sk_len = s->length_secret_key;
    OQS_SIG_free(s);
    return rc;
}

int qpqc_mldsa_sign(const char *alg, const uint8_t *sk, size_t sk_len,
                    const uint8_t *msg, size_t msg_len, uint8_t **sig, size_t *sig_len) {
    OQS_SIG *s = OQS_SIG_new(alg);
    if (!s) return QPQC_ERR;
    if (sk_len != s->length_secret_key) { OQS_SIG_free(s); return QPQC_ERR; }
    *sig = malloc(s->length_signature);
    if (!*sig) { OQS_SIG_free(s); return QPQC_ERR; }
    int rc = (OQS_SIG_sign(s, *sig, sig_len, msg, msg_len, sk) == OQS_SUCCESS) ? QPQC_OK : QPQC_ERR;
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
    int rc = (OQS_KEM_encaps(k, *ct, ss_out, pk) == OQS_SUCCESS) ? QPQC_OK : QPQC_ERR;
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

int qpqc_hybrid_sign_bytes(const uint8_t *b0, size_t b0_len, const uint8_t *auth, size_t auth_len,
                           uint8_t **out, size_t *out_len) {
    size_t total = 8 + b0_len + auth_len;
    uint8_t *buf = malloc(total);
    if (!buf) return QPQC_ERR;
    be32(buf, (uint32_t)b0_len); memcpy(buf + 4, b0, b0_len);
    be32(buf + 4 + b0_len, (uint32_t)auth_len); memcpy(buf + 8 + b0_len, auth, auth_len);
    *out = buf; *out_len = total;
    return QPQC_OK;
}

void qpqc_free(uint8_t *buf, size_t len) { if (buf) { OQS_MEM_cleanse(buf, len); free(buf); } }
