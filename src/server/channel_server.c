/*
 * channel_server.c — Step 27+28
 * Replay-protected multi-message secure channel server.
 * Uses pqc_common library (aead, framing, hybrid_kdf).
 * Port 4452. Wire: [counter(8B)|tag(16B)|ciphertext] per frame.
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
#define BACKLOG       8
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
        fprintf(stderr, "[SERVER] REPLAY: got=%llu last=%llu\n",
                (unsigned long long)ctr, (unsigned long long)*last);
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
    if (pl < 0) { fprintf(stderr, "[SERVER] GCM FAIL\n"); return -1; }
    *last = ctr;
    return pl;
}

static int listen_socket(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    int y = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &y, sizeof(y));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family      = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port        = htons(port);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(fd, BACKLOG) != 0) {
        perror("bind/listen"); close(fd); return -1;
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
    uint16_t port = argc == 2 ? (uint16_t)atoi(argv[1]) : DEFAULT_PORT;
    OQS_init();

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    EVP_PKEY *xk = gen_x25519();

    uint8_t xpub[X25519_LEN]; size_t xpl = sizeof(xpub);
    EVP_PKEY_get_raw_public_key(xk, xpub, &xpl);

    uint8_t *kpub = malloc(kem->length_public_key);
    uint8_t *ksk  = malloc(kem->length_secret_key);
    uint8_t *kct  = malloc(kem->length_ciphertext);
    uint8_t *spub = malloc(sig->length_public_key);
    uint8_t *ssk  = malloc(sig->length_secret_key);
    uint8_t *sgn  = malloc(sig->length_signature);
    uint8_t *tr   = malloc(X25519_LEN + kem->length_public_key +
                            sig->length_public_key + X25519_LEN + kem->length_ciphertext);
    uint8_t xs[X25519_LEN], ks[32], session_key[PQC_SESSION_KEY_LEN];

    OQS_KEM_keypair(kem, kpub, ksk);
    OQS_SIG_keypair(sig, spub, ssk);

    int lfd = listen_socket(port);
    if (lfd < 0) return 1;
    printf("[CHANNEL SERVER] port %u — waiting\n", port);

    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) { perror("accept"); return 1; }
    printf("[CHANNEL SERVER] client connected\n");

    /* ── handshake (mirrors pqc_secure_server) ── */
    pqc_send_frame(cfd, xpub, X25519_LEN);
    pqc_send_frame(cfd, kpub, (uint32_t)kem->length_public_key);
    pqc_send_frame(cfd, spub, (uint32_t)sig->length_public_key);

    uint8_t cxpub[X25519_LEN]; uint32_t cxl = 0, kctl = 0;
    pqc_recv_frame(cfd, cxpub, sizeof(cxpub), &cxl);
    pqc_recv_frame(cfd, kct, (uint32_t)kem->length_ciphertext, &kctl);

    derive_x25519(xk, cxpub, xs);
    OQS_KEM_decaps(kem, ks, kct, ksk);
    pqc_hybrid_session_key(xs, sizeof(xs), ks, sizeof(ks), session_key);

    size_t trl = build_tr(tr, xpub, kpub, kem->length_public_key,
                           spub, sig->length_public_key,
                           cxpub, kct, kem->length_ciphertext);
    size_t sgl = 0;
    OQS_SIG_sign(sig, sgn, &sgl, tr, trl, ssk);
    pqc_send_frame(cfd, sgn, (uint32_t)sgl);

    /* receive client signature + client sig pubkey */
    uint8_t *csgn = malloc(sig->length_signature);
    uint8_t *cspk = malloc(sig->length_public_key);
    uint32_t csgl = 0, cspkl = 0;
    pqc_recv_frame(cfd, csgn, (uint32_t)sig->length_signature, &csgl);
    pqc_recv_frame(cfd, cspk, (uint32_t)sig->length_public_key, &cspkl);

    int auth = OQS_SIG_verify(sig, tr, trl, csgn, csgl, cspk) == OQS_SUCCESS;
    if (!auth) {
        fprintf(stderr, "[SERVER] client auth FAIL\n");
        close(cfd); close(lfd); return 1;
    }
    pqc_print_secret_sha256_prefix("channel session key", session_key, sizeof(session_key));
    printf("[SERVER] auth OK — channel open. Send QUIT to end.\n\n");

    /* ── channel loop ── */
    uint64_t rctr = 0, sctr = 0;
    uint8_t fbuf[PQC_MAX_FRAME_SIZE], pbuf[PQC_MAX_FRAME_SIZE];
    uint8_t echo[PQC_MAX_FRAME_SIZE], ebuf[PQC_MAX_FRAME_SIZE];

    for (;;) {
        uint32_t fl = 0;
        if (pqc_recv_frame(cfd, fbuf, sizeof(fbuf), &fl) != 0) break;

        int pl = chan_dec(session_key, &rctr, fbuf, fl, pbuf, sizeof(pbuf));
        if (pl == -2) continue;
        if (pl < 0)   { fprintf(stderr, "[SERVER] drop\n"); continue; }
        pbuf[pl] = '\0';
        printf("[SERVER] ctr=%-4llu in(%d B): %s\n",
               (unsigned long long)rctr, pl, (char *)pbuf);

        if (strcmp((char *)pbuf, "QUIT") == 0) break;

        const char pfx[] = "ECHO: ";
        size_t pfxl = strlen(pfx);
        memcpy(echo, pfx, pfxl);
        memcpy(echo + pfxl, pbuf, (size_t)pl);
        size_t el = pfxl + (size_t)pl;

        ++sctr;
        int enc = chan_enc(session_key, sctr, echo, el, ebuf, sizeof(ebuf));
        if (enc < 0) break;
        pqc_send_frame(cfd, ebuf, (uint32_t)enc);
        printf("[SERVER] ctr=%-4llu out(%zu B)\n\n",
               (unsigned long long)sctr, el);
    }

    close(cfd); close(lfd);
    free(kpub); free(ksk); free(kct); free(spub); free(ssk);
    free(sgn); free(tr); free(csgn); free(cspk);
    EVP_PKEY_free(xk);
    OQS_KEM_free(kem); OQS_SIG_free(sig);
    OQS_destroy();
    printf("[SERVER] session closed\n");
    return 0;
}
