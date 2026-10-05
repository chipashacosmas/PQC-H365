/*
 * channel_client.c — Step 27+28
 * Replay-protected multi-message secure channel client.
 * Reads lines from stdin, encrypts with counter nonce, sends to server, prints echo.
 * Type QUIT to end session.
 */
#include "aead.h"
#include "framing.h"
#include "hybrid_kdf.h"
#include "secret_print.h"
#include "timing.h"

#include <oqs/oqs.h>
#include <openssl/evp.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_PORT  4452
#define X25519_LEN    32U
#define AAD           "PQC_H365_CHANNEL_V1"
#define CTR_BYTES     8U

static void ctr_to_nonce(uint64_t c, uint8_t n[PQC_AES_GCM_NONCE_LEN]) {
    memset(n, 0, PQC_AES_GCM_NONCE_LEN);
    for (int i = 7; i >= 0; i--) { n[4+i] = (uint8_t)(c & 0xFF); c >>= 8; }
}
static uint64_t read_ctr(const uint8_t *b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}
static void write_ctr(uint8_t *b, uint64_t c) {
    for (int i = 7; i >= 0; i--) { b[i] = (uint8_t)(c & 0xFF); c >>= 8; }
}

static int chan_enc(const uint8_t sk[PQC_SESSION_KEY_LEN], uint64_t ctr,
                    const uint8_t *plain, size_t plen,
                    uint8_t *out, size_t cap) {
    if (cap < CTR_BYTES + PQC_AES_GCM_TAG_LEN + plen) return -1;
    uint8_t nonce[PQC_AES_GCM_NONCE_LEN];
    ctr_to_nonce(ctr, nonce);
    write_ctr(out, ctr);
    uint8_t *tag = out + CTR_BYTES;
    uint8_t *ct  = out + CTR_BYTES + PQC_AES_GCM_TAG_LEN;
    int cl = pqc_aes256_gcm_encrypt(sk, nonce, plain, plen,
                                     (const uint8_t *)AAD, strlen(AAD), ct, tag);
    return cl < 0 ? -1 : (int)(CTR_BYTES + PQC_AES_GCM_TAG_LEN + (size_t)cl);
}

static int chan_dec(const uint8_t sk[PQC_SESSION_KEY_LEN], uint64_t *last,
                    const uint8_t *frame, uint32_t flen,
                    uint8_t *plain, size_t cap) {
    if (flen < CTR_BYTES + PQC_AES_GCM_TAG_LEN) return -1;
    uint64_t ctr = read_ctr(frame);
    if (ctr <= *last) {
        fprintf(stderr, "[CLIENT] REPLAY ctr=%llu\n", (unsigned long long)ctr);
        return -2;
    }
    uint8_t nonce[PQC_AES_GCM_NONCE_LEN];
    ctr_to_nonce(ctr, nonce);
    const uint8_t *tag = frame + CTR_BYTES;
    const uint8_t *ct  = frame + CTR_BYTES + PQC_AES_GCM_TAG_LEN;
    size_t cl = flen - CTR_BYTES - PQC_AES_GCM_TAG_LEN;
    if (cl > cap) return -1;
    int pl = pqc_aes256_gcm_decrypt(sk, nonce, ct, cl,
                                     (const uint8_t *)AAD, strlen(AAD), tag, plain);
    if (pl < 0) { fprintf(stderr, "[CLIENT] GCM FAIL\n"); return -1; }
    *last = ctr;
    return pl;
}

static int connect_server(const char *host, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port   = htons(port);
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        perror("connect"); close(fd); return -1;
    }
    return fd;
}

static EVP_PKEY *gen_x25519(void) {
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *k = NULL;
    if (c && EVP_PKEY_keygen_init(c) > 0) EVP_PKEY_keygen(c, &k);
    EVP_PKEY_CTX_free(c);
    return k;
}

static int derive_x25519(EVP_PKEY *priv, const uint8_t peer[X25519_LEN],
                          uint8_t sec[X25519_LEN]) {
    EVP_PKEY *p = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer, X25519_LEN);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(priv, NULL);
    size_t l = X25519_LEN;
    int ok = p && c && EVP_PKEY_derive_init(c) > 0 &&
             EVP_PKEY_derive_set_peer(c, p) > 0 &&
             EVP_PKEY_derive(c, sec, &l) > 0 && l == X25519_LEN;
    EVP_PKEY_CTX_free(c); EVP_PKEY_free(p);
    return ok ? 0 : -1;
}

static size_t build_tr(uint8_t *o,
                        const uint8_t *sx,
                        const uint8_t *sk, size_t skl,
                        const uint8_t *sp, size_t spl,
                        const uint8_t *cx,
                        const uint8_t *cc, size_t ccl) {
    uint8_t *p = o;
    memcpy(p, sx, X25519_LEN); p += X25519_LEN;
    memcpy(p, sk, skl);        p += skl;
    memcpy(p, sp, spl);        p += spl;
    memcpy(p, cx, X25519_LEN); p += X25519_LEN;
    memcpy(p, cc, ccl);        p += ccl;
    return (size_t)(p - o);
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <server-ip> [port]\n", argv[0]);
        return 1;
    }
    uint16_t port = argc == 3 ? (uint16_t)atoi(argv[2]) : DEFAULT_PORT;
    OQS_init();

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    EVP_PKEY *xk = gen_x25519();

    uint8_t cxpub[X25519_LEN]; size_t xl = sizeof(cxpub);
    EVP_PKEY_get_raw_public_key(xk, cxpub, &xl);

    uint8_t *kpub = malloc(kem->length_public_key);
    uint8_t *kct  = malloc(kem->length_ciphertext);
    uint8_t *spub = malloc(sig->length_public_key);
    uint8_t *sgn  = malloc(sig->length_signature);
    /* ephemeral client DSA keypair for mutual auth */
    uint8_t *cspk = malloc(sig->length_public_key);
    uint8_t *cssk = malloc(sig->length_secret_key);
    uint8_t *csgn = malloc(sig->length_signature);
    uint8_t *tr   = malloc(X25519_LEN + kem->length_public_key +
                            sig->length_public_key + X25519_LEN + kem->length_ciphertext);
    uint8_t sxpub[X25519_LEN], xs[X25519_LEN], ks[32], session_key[PQC_SESSION_KEY_LEN];

    OQS_SIG_keypair(sig, cspk, cssk);

    int fd = connect_server(argv[1], port);
    if (fd < 0) return 1;
    printf("[CHANNEL CLIENT] connected\n");

    /* ── handshake ── */
    uint32_t sxl = 0, kpl = 0, spl = 0;
    pqc_recv_frame(fd, sxpub, sizeof(sxpub), &sxl);
    pqc_recv_frame(fd, kpub, (uint32_t)kem->length_public_key, &kpl);
    pqc_recv_frame(fd, spub, (uint32_t)sig->length_public_key, &spl);

    derive_x25519(xk, sxpub, xs);
    OQS_KEM_encaps(kem, kct, ks, kpub);
    pqc_hybrid_session_key(xs, sizeof(xs), ks, sizeof(ks), session_key);

    pqc_send_frame(fd, cxpub, X25519_LEN);
    pqc_send_frame(fd, kct, (uint32_t)kem->length_ciphertext);

    /* receive server signature, verify */
    uint32_t sgl = 0;
    pqc_recv_frame(fd, sgn, (uint32_t)sig->length_signature, &sgl);
    size_t trl = build_tr(tr, sxpub, kpub, kem->length_public_key,
                           spub, sig->length_public_key,
                           cxpub, kct, kem->length_ciphertext);
    int vok = OQS_SIG_verify(sig, tr, trl, sgn, sgl, spub) == OQS_SUCCESS;
    printf("[CLIENT] server sig: %s\n", vok ? "PASS" : "FAIL");

    /* send client signature + pubkey */
    size_t csgl = 0;
    OQS_SIG_sign(sig, csgn, &csgl, tr, trl, cssk);
    pqc_send_frame(fd, csgn, (uint32_t)csgl);
    pqc_send_frame(fd, cspk, (uint32_t)sig->length_public_key);

    pqc_print_secret_sha256_prefix("channel session key", session_key, sizeof(session_key));
    printf("[CLIENT] handshake complete — type messages, QUIT to exit\n\n");

    /* ── channel loop ── */
    uint64_t sctr = 0, rctr = 0;
    uint8_t fbuf[PQC_MAX_FRAME_SIZE], pbuf[PQC_MAX_FRAME_SIZE], ebuf[PQC_MAX_FRAME_SIZE];
    char line[1024];

    for (;;) {
        printf("> "); fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        size_t ll = strlen(line);
        if (ll > 0 && line[ll-1] == '\n') { line[ll-1] = '\0'; ll--; }
        if (ll == 0) continue;

        ++sctr;
        int enc = chan_enc(session_key, sctr, (uint8_t *)line, ll, ebuf, sizeof(ebuf));
        if (enc < 0) break;
        pqc_send_frame(fd, ebuf, (uint32_t)enc);
        printf("[CLIENT] sent ctr=%llu: %s\n", (unsigned long long)sctr, line);
        if (strcmp(line, "QUIT") == 0) break;

        uint32_t fl = 0;
        if (pqc_recv_frame(fd, fbuf, sizeof(fbuf), &fl) != 0) break;
        int pl = chan_dec(session_key, &rctr, fbuf, fl, pbuf, sizeof(pbuf));
        if (pl < 0) continue;
        pbuf[pl] = '\0';
        printf("[CLIENT] echo  ctr=%llu: %s\n\n",
               (unsigned long long)rctr, (char *)pbuf);
    }

    free(kpub); free(kct); free(spub); free(sgn);
    free(cspk); free(cssk); free(csgn); free(tr);
    EVP_PKEY_free(xk);
    OQS_KEM_free(kem); OQS_SIG_free(sig);
    OQS_destroy();
    close(fd);
    printf("[CLIENT] done\n");
    return 0;
}
