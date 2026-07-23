#include "framing.h"
#include "hybrid_kdf.h"
#include "secret_print.h"
#include "timing.h"
#include "state_machine.h"
#include "tun.h"
#include "aead.h"

#include <oqs/oqs.h>
#include <openssl/evp.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define DEFAULT_PORT 4447
#define BACKLOG 8
#define X25519_LEN 32U
#define MAX_CLIENTS 64
#define TIMEOUT_SEC 5

typedef struct {
    pqc_connection_t base;
    uint8_t client_x_public[X25519_LEN];
    uint8_t session_key[PQC_SESSION_KEY_LEN];
} hybrid_conn_t;

static int listen_socket(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd); return -1;
    }
    if (pqc_make_nonblocking(fd) != 0) {
        close(fd); return -1;
    }
    if (listen(fd, BACKLOG) != 0) {
        close(fd); return -1;
    }
    return fd;
}

static EVP_PKEY *generate_x25519(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *key = NULL;
    if (ctx && EVP_PKEY_keygen_init(ctx) > 0) EVP_PKEY_keygen(ctx, &key);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int derive_x25519(EVP_PKEY *private_key, EVP_PKEY *peer_key, uint8_t *secret, size_t *secret_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx) return -1;
    int ok = EVP_PKEY_derive_init(ctx) > 0 &&
             EVP_PKEY_derive_set_peer(ctx, peer_key) > 0 &&
             EVP_PKEY_derive(ctx, secret, secret_len) > 0;
    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
}

int main(int argc, char **argv) {
    uint16_t port = argc == 2 ? (uint16_t)atoi(argv[1]) : DEFAULT_PORT;

    OQS_init();
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    OQS_SIG *dsa = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    EVP_PKEY *x_key = generate_x25519();

    if (!kem || !dsa || !x_key) {
        fprintf(stderr, "crypto init failed\n");
        return 1;
    }

    uint8_t x_public[X25519_LEN];
    size_t x_public_len = sizeof(x_public);
    EVP_PKEY_get_raw_public_key(x_key, x_public, &x_public_len);

    uint8_t *kem_public = malloc(kem->length_public_key);
    uint8_t *kem_secret_key = malloc(kem->length_secret_key);
    if (OQS_KEM_keypair(kem, kem_public, kem_secret_key) != OQS_SUCCESS) return 1;

    uint8_t *dsa_public = malloc(dsa->length_public_key);
    uint8_t *dsa_secret_key = malloc(dsa->length_secret_key);
    if (OQS_SIG_keypair(dsa, dsa_public, dsa_secret_key) != OQS_SUCCESS) return 1;

    int lfd = listen_socket(port);
    if (lfd < 0) return 1;

    char tun_name[16] = "tun0";
    int tun_fd = pqc_tun_alloc(tun_name);
    if (tun_fd >= 0) {
        pqc_make_nonblocking(tun_fd);
        printf("Created virtual interface: %s\n", tun_name);
    } else {
        printf("Failed to create TUN interface. Data plane will drop packets.\n");
    }

    printf("hybrid_seq_server listening on port %u\n", port);

    hybrid_conn_t clients[MAX_CLIENTS];
    for (int i = 0; i < MAX_CLIENTS; i++) clients[i].base.fd = -1;

    while (1) {
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds); FD_ZERO(&write_fds);
        FD_SET(lfd, &read_fds);
        int max_fd = lfd;

        if (tun_fd >= 0) {
            FD_SET(tun_fd, &read_fds);
            if (tun_fd > max_fd) max_fd = tun_fd;
        }

        struct timeval now;
        gettimeofday(&now, NULL);

        for (int i = 0; i < MAX_CLIENTS; i++) {
            int fd = clients[i].base.fd;
            if (fd != -1) {
                // Timeouts (DDoS mitigation)
                if (clients[i].base.state != STATE_DATA_PLANE && 
                    (now.tv_sec - clients[i].base.last_activity.tv_sec > TIMEOUT_SEC)) {
                    printf("client fd %d timed out\n", fd);
                    close(fd);
                    clients[i].base.fd = -1;
                    continue;
                }

                FD_SET(fd, &read_fds);
                int state = clients[i].base.state;
                if (state == STATE_SEND_X25519_PUBLIC_KEY || 
                    state == STATE_SEND_HYBRID_KEM_PUBLIC_KEY ||
                    state == STATE_SEND_DSA_SIGNATURE) {
                    FD_SET(fd, &write_fds);
                }
                if (fd > max_fd) max_fd = fd;
            }
        }

        struct timeval timeout = {1, 0};
        int activity = select(max_fd + 1, &read_fds, &write_fds, NULL, &timeout);
        if (activity < 0 && errno != EINTR) break;

        // New connections
        if (FD_ISSET(lfd, &read_fds)) {
            struct sockaddr_in peer;
            socklen_t plen = sizeof(peer);
            int new_fd = accept(lfd, (struct sockaddr *)&peer, &plen);
            if (new_fd >= 0) {
                pqc_make_nonblocking(new_fd);
                int added = 0;
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (clients[i].base.fd == -1) {
                        pqc_conn_init(&clients[i].base, new_fd);
                        clients[i].base.state = STATE_SEND_X25519_PUBLIC_KEY;
                        added = 1; break;
                    }
                }
                if (!added) close(new_fd);
            }
        }

        // Data Plane: Read from TUN and send to clients
        if (tun_fd >= 0 && FD_ISSET(tun_fd, &read_fds)) {
            uint8_t tun_buf[PQC_MAX_FRAME_SIZE];
            int n = read(tun_fd, tun_buf, sizeof(tun_buf));
            if (n > 0) {
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (clients[i].base.fd != -1 && clients[i].base.state == STATE_DATA_PLANE) {
                        // Encrypt packet and send
                        uint8_t nonce[PQC_AES_GCM_NONCE_LEN] = {0}; // Static for prototype
                        uint8_t ciphertext[PQC_MAX_FRAME_SIZE + PQC_AES_GCM_TAG_LEN];
                        uint8_t tag[PQC_AES_GCM_TAG_LEN];
                        pqc_aes256_gcm_encrypt(clients[i].session_key, nonce, tun_buf, n, NULL, 0, ciphertext, tag);
                        memcpy(ciphertext + n, tag, PQC_AES_GCM_TAG_LEN);
                        pqc_send_frame(clients[i].base.fd, ciphertext, n + PQC_AES_GCM_TAG_LEN);
                    }
                }
            }
        }

        // Client sockets
        for (int i = 0; i < MAX_CLIENTS; i++) {
            int fd = clients[i].base.fd;
            if (fd == -1) continue;

            if (clients[i].base.state == STATE_SEND_X25519_PUBLIC_KEY && FD_ISSET(fd, &write_fds)) {
                if (pqc_send_frame(fd, x_public, X25519_LEN) == 0) {
                    clients[i].base.state = STATE_WAIT_X25519_PUBLIC_KEY;
                    gettimeofday(&clients[i].base.last_activity, NULL);
                }
            } 
            else if (clients[i].base.state == STATE_WAIT_X25519_PUBLIC_KEY && FD_ISSET(fd, &read_fds)) {
                uint32_t len = 0;
                if (pqc_recv_frame(fd, clients[i].client_x_public, X25519_LEN, &len) == 0 && len == X25519_LEN) {
                    clients[i].base.state = STATE_SEND_HYBRID_KEM_PUBLIC_KEY;
                    gettimeofday(&clients[i].base.last_activity, NULL);
                }
            }
            else if (clients[i].base.state == STATE_SEND_HYBRID_KEM_PUBLIC_KEY && FD_ISSET(fd, &write_fds)) {
                if (pqc_send_frame(fd, kem_public, (uint32_t)kem->length_public_key) == 0) {
                    clients[i].base.state = STATE_WAIT_HYBRID_KEM_ENCAPSULATION;
                    gettimeofday(&clients[i].base.last_activity, NULL);
                }
            }
            else if (clients[i].base.state == STATE_WAIT_HYBRID_KEM_ENCAPSULATION && FD_ISSET(fd, &read_fds)) {
                uint32_t len = 0;
                if (pqc_recv_frame(fd, clients[i].base.read_buffer, sizeof(clients[i].base.read_buffer), &len) == 0) {
                    if (len == kem->length_ciphertext) {
                        EVP_PKEY *client_x_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, clients[i].client_x_public, X25519_LEN);
                        uint8_t x_secret[32]; size_t x_secret_len = sizeof(x_secret);
                        derive_x25519(x_key, client_x_key, x_secret, &x_secret_len);

                        uint8_t kem_secret[32];
                        OQS_KEM_decaps(kem, kem_secret, clients[i].base.read_buffer, kem_secret_key);
                        
                        pqc_hybrid_session_key(x_secret, sizeof(x_secret), kem_secret, sizeof(kem_secret), clients[i].session_key);
                        clients[i].base.state = STATE_SEND_DSA_SIGNATURE;
                        gettimeofday(&clients[i].base.last_activity, NULL);
                    }
                }
            }
            else if (clients[i].base.state == STATE_SEND_DSA_SIGNATURE && FD_ISSET(fd, &write_fds)) {
                uint8_t *sig = malloc(dsa->length_signature);
                size_t sig_len = 0;
                // Sign the session key to prove identity and transcript integrity
                if (OQS_SIG_sign(dsa, sig, &sig_len, clients[i].session_key, sizeof(clients[i].session_key), dsa_secret_key) == OQS_SUCCESS) {
                    // Send pubkey and signature
                    uint8_t *payload = malloc(dsa->length_public_key + sig_len);
                    memcpy(payload, dsa_public, dsa->length_public_key);
                    memcpy(payload + dsa->length_public_key, sig, sig_len);
                    
                    if (pqc_send_frame(fd, payload, dsa->length_public_key + sig_len) == 0) {
                        clients[i].base.state = STATE_DATA_PLANE;
                        printf("client fd %d entered DATA PLANE\n", fd);
                    }
                    free(payload);
                }
                free(sig);
            }
            else if (clients[i].base.state == STATE_DATA_PLANE && FD_ISSET(fd, &read_fds)) {
                uint32_t len = 0;
                int ret = pqc_recv_frame(fd, clients[i].base.read_buffer, sizeof(clients[i].base.read_buffer), &len);
                if (ret == 0 && len > PQC_AES_GCM_TAG_LEN) {
                    // Decrypt AEAD packet
                    uint8_t nonce[PQC_AES_GCM_NONCE_LEN] = {0};
                    uint8_t plaintext[PQC_MAX_FRAME_SIZE];
                    uint8_t tag[PQC_AES_GCM_TAG_LEN];
                    memcpy(tag, clients[i].base.read_buffer + len - PQC_AES_GCM_TAG_LEN, PQC_AES_GCM_TAG_LEN);
                    
                    if (pqc_aes256_gcm_decrypt(clients[i].session_key, nonce, clients[i].base.read_buffer, len - PQC_AES_GCM_TAG_LEN, NULL, 0, tag, plaintext) == 0) {
                        if (tun_fd >= 0) {
                            write(tun_fd, plaintext, len - PQC_AES_GCM_TAG_LEN);
                        }
                    }
                } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    close(fd); clients[i].base.fd = -1;
                }
            }
        }
    }

    return 0;
}
