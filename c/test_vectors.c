/* test_vectors.c — validates the C/liboqs binding against ../vectors/flat.txt
 * (the same shared cross-language vectors generated from @noble). */
#include "qorechain_pqc.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t unhex(const char *h, uint8_t *o, size_t cap) {
    if (!strcmp(h, "-")) return 0; /* empty message marker */
    size_t n = strlen(h) / 2;
    if (n > cap) return (size_t)-1;
    for (size_t i = 0; i < n; i++) { unsigned v; sscanf(h + 2 * i, "%2x", &v); o[i] = (uint8_t)v; }
    return n;
}
static void upper(char *s) { for (; *s; s++) *s = (char)toupper((unsigned char)*s); }

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "../vectors/flat.txt";
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return 2; }

    static char line[40000];
    static uint8_t a[8192], b[8192], c[16384], d[8192], ss[64];
    int total = 0, pass = 0;
    static char kind[16], alg[32], h1[20000], h2[20000], h3[20000], h4[20000];

    while (fgets(line, sizeof line, f)) {
        if (line[0] == '\n' || line[0] == '#') continue;
        int nf = sscanf(line, "%15s", kind);
        if (nf < 1) continue;

        if (!strcmp(kind, "mldsa")) {
            /* mldsa <alg> <pk> <msg> <sig> <secretKey> <seed> */
            sscanf(line, "%15s %31s %19999s %19999s %19999s %19999s", kind, alg, h1, h2, h3, h4);
            upper(alg);
            size_t pkl = unhex(h1, a, sizeof a), ml = unhex(h2, b, sizeof b), sl = unhex(h3, c, sizeof c);
            int r = qpqc_mldsa_verify(alg, a, pkl, b, ml, c, sl);
            total++; if (r == 1) pass++; else fprintf(stderr, "FAIL %s verify\n", alg);
            /* QoreChain's PQC ante verifier accepts only DETERMINISTIC (FIPS-204
             * section 3.4) signatures: sign must reproduce the vector byte-for-byte. */
            size_t skl = unhex(h4, d, sizeof d);
            uint8_t *sig2 = NULL; size_t sl2 = 0;
            int rs = qpqc_mldsa_sign(alg, d, skl, b, ml, &sig2, &sl2);
            total++;
            if (rs == QPQC_OK && sl2 == sl && memcmp(sig2, c, sl) == 0) pass++;
            else fprintf(stderr, "FAIL %s deterministic sign\n", alg);
            if (sig2) qpqc_free(sig2, sl2);
        } else if (!strcmp(kind, "mlkem")) {
            sscanf(line, "%15s %31s %19999s %19999s %19999s", kind, alg, h1, h2, h3);
            upper(alg);
            size_t skl = unhex(h1, a, sizeof a), ctl = unhex(h2, b, sizeof b), ssl_exp = unhex(h3, c, sizeof c);
            size_t ssl = 0;
            int r = qpqc_mlkem_decapsulate(alg, a, skl, b, ctl, ss, &ssl);
            total++;
            if (r == QPQC_OK && ssl == ssl_exp && memcmp(ss, c, ssl) == 0) pass++;
            else fprintf(stderr, "FAIL %s decaps\n", alg);
        } else if (!strcmp(kind, "hybrid_v2")) {
            /* hybrid_v2 <name> <chainIdHex> <b0Hex> <authHex> <signBytesHex> (chain v3.1.98 KAT) */
            static char name[64], hcid[512];
            static uint8_t cid[256];
            sscanf(line, "%15s %63s %511s %19999s %19999s %19999s", kind, name, hcid, h1, h2, h3);
            size_t cl = unhex(hcid, cid, sizeof cid), bl = unhex(h1, a, sizeof a), al = unhex(h2, b, sizeof b);
            size_t wl = unhex(h3, c, sizeof c);
            uint8_t *o1 = NULL, *o2 = NULL; size_t l1 = 0, l2 = 0;
            int ok = qpqc_hybrid_sign_bytes_v2((const char *)cid, cl, a, bl, b, al, &o1, &l1) == QPQC_OK &&
                     qpqc_hybrid_sign_bytes(QPQC_SIGN_BYTES_V2, (const char *)cid, cl, a, bl, b, al, &o2, &l2) == QPQC_OK &&
                     l1 == wl && l2 == wl && memcmp(o1, c, wl) == 0 && memcmp(o2, c, wl) == 0;
            total++; if (ok) pass++; else fprintf(stderr, "FAIL hybrid_v2 %s\n", name);
            qpqc_free(o1, l1); qpqc_free(o2, l2);
        } else if (!strcmp(kind, "shake")) {
            sscanf(line, "%15s %19999s %19999s %19999s", kind, h1, h2, h3);
            size_t ml = unhex(h1, a, sizeof a), e32 = unhex(h2, b, sizeof b), e64 = unhex(h3, c, sizeof c);
            uint8_t o[64];
            qpqc_shake256(a, ml, o, 32);
            int ok = (memcmp(o, b, 32) == 0);
            qpqc_shake256(a, ml, o, 64);
            ok = ok && (memcmp(o, c, 64) == 0) && e32 == 32 && e64 == 64;
            total++; if (ok) pass++; else fprintf(stderr, "FAIL shake\n");
        }
    }
    fclose(f);

    /* roundtrip + helper sanity */
    uint8_t *pk, *sk, *sig = NULL, *hb;
    size_t pkl, skl, sl = 0, hbl;
    int rt = 0;
    if (qpqc_mldsa_keygen(QPQC_MLDSA_DEFAULT, &pk, &pkl, &sk, &skl) == QPQC_OK) {
        uint8_t b0[3] = {1, 2, 3}, au[2] = {9, 9};
        qpqc_hybrid_sign_bytes_v1(b0, 3, au, 2, &hb, &hbl);
        uint8_t want[13] = {0,0,0,3,1,2,3,0,0,0,2,9,9};
        if (hbl == 13 && memcmp(hb, want, 13) == 0 &&
            qpqc_mldsa_sign(QPQC_MLDSA_DEFAULT, sk, skl, hb, hbl, &sig, &sl) == QPQC_OK &&
            qpqc_mldsa_verify(QPQC_MLDSA_DEFAULT, pk, pkl, hb, hbl, sig, sl) == 1) rt = 1;
        qpqc_free(sig, sl); sig = NULL;
        /* v2 signature verifies over v2 bytes, not over v1; bad version rejected. */
        uint8_t *v2 = NULL; size_t v2l = 0, sl2 = 0; uint8_t *sig2 = NULL, *bad = NULL; size_t badl = 0;
        const char *cid = "qorechain-vladi";
        if (qpqc_hybrid_sign_bytes(QPQC_SIGN_BYTES_V2, cid, strlen(cid), b0, 3, au, 2, &v2, &v2l) != QPQC_OK ||
            qpqc_mldsa_sign(QPQC_MLDSA_DEFAULT, sk, skl, v2, v2l, &sig2, &sl2) != QPQC_OK ||
            qpqc_mldsa_verify(QPQC_MLDSA_DEFAULT, pk, pkl, v2, v2l, sig2, sl2) != 1 ||
            qpqc_mldsa_verify(QPQC_MLDSA_DEFAULT, pk, pkl, hb, hbl, sig2, sl2) == 1 ||
            qpqc_hybrid_sign_bytes(3, cid, strlen(cid), b0, 3, au, 2, &bad, &badl) != QPQC_ERR) rt = 0;
        /* version truth table */
        if (qpqc_sign_bytes_version_for("qorechain-vladi", 0) != QPQC_SIGN_BYTES_V1 ||
            qpqc_sign_bytes_version_for("qorechain-diana", 0) != QPQC_SIGN_BYTES_V1 ||
            qpqc_sign_bytes_version_for("qorechain-vladi", 5746000) != QPQC_SIGN_BYTES_V2 ||
            qpqc_sign_bytes_version_for("qorechain-diana", 5746000) != QPQC_SIGN_BYTES_V2 ||
            qpqc_sign_bytes_version_for("qorechain-other", 0) != QPQC_SIGN_BYTES_V2 ||
            qpqc_sign_bytes_version_for("qorechain-other", 5746000) != QPQC_SIGN_BYTES_V2) rt = 0;
        qpqc_free(v2, v2l); qpqc_free(sig2, sl2);
        qpqc_free(pk, pkl); qpqc_free(sk, skl); qpqc_free(hb, hbl);
    }
    total++; if (rt) pass++; else fprintf(stderr, "FAIL roundtrip\n");

    printf("C/liboqs vectors: %d/%d passed\n", pass, total);
    return pass == total ? 0 : 1;
}
