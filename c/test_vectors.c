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
    static uint8_t a[8192], b[8192], c[16384], ss[64];
    int total = 0, pass = 0;
    char kind[16], alg[32], h1[20000], h2[20000], h3[20000];

    while (fgets(line, sizeof line, f)) {
        if (line[0] == '\n' || line[0] == '#') continue;
        int nf = sscanf(line, "%15s", kind);
        if (nf < 1) continue;

        if (!strcmp(kind, "mldsa")) {
            sscanf(line, "%15s %31s %19999s %19999s %19999s", kind, alg, h1, h2, h3);
            upper(alg);
            size_t pkl = unhex(h1, a, sizeof a), ml = unhex(h2, b, sizeof b), sl = unhex(h3, c, sizeof c);
            int r = qpqc_mldsa_verify(alg, a, pkl, b, ml, c, sl);
            total++; if (r == 1) pass++; else fprintf(stderr, "FAIL %s verify\n", alg);
        } else if (!strcmp(kind, "mlkem")) {
            sscanf(line, "%15s %31s %19999s %19999s %19999s", kind, alg, h1, h2, h3);
            upper(alg);
            size_t skl = unhex(h1, a, sizeof a), ctl = unhex(h2, b, sizeof b), ssl_exp = unhex(h3, c, sizeof c);
            size_t ssl = 0;
            int r = qpqc_mlkem_decapsulate(alg, a, skl, b, ctl, ss, &ssl);
            total++;
            if (r == QPQC_OK && ssl == ssl_exp && memcmp(ss, c, ssl) == 0) pass++;
            else fprintf(stderr, "FAIL %s decaps\n", alg);
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
    uint8_t *pk, *sk, *sig, *hb;
    size_t pkl, skl, sl, hbl;
    int rt = 0;
    if (qpqc_mldsa_keygen(QPQC_MLDSA_DEFAULT, &pk, &pkl, &sk, &skl) == QPQC_OK) {
        uint8_t b0[3] = {1, 2, 3}, au[2] = {9, 9};
        qpqc_hybrid_sign_bytes(b0, 3, au, 2, &hb, &hbl);
        uint8_t want[13] = {0,0,0,3,1,2,3,0,0,0,2,9,9};
        if (hbl == 13 && memcmp(hb, want, 13) == 0 &&
            qpqc_mldsa_sign(QPQC_MLDSA_DEFAULT, sk, skl, hb, hbl, &sig, &sl) == QPQC_OK &&
            qpqc_mldsa_verify(QPQC_MLDSA_DEFAULT, pk, pkl, hb, hbl, sig, sl) == 1) rt = 1;
        qpqc_free(pk, pkl); qpqc_free(sk, skl); qpqc_free(sig, sl); qpqc_free(hb, hbl);
    }
    total++; if (rt) pass++; else fprintf(stderr, "FAIL roundtrip\n");

    printf("C/liboqs vectors: %d/%d passed\n", pass, total);
    return pass == total ? 0 : 1;
}
