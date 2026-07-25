#include "framing.h"
#include "hybrid_kdf.h"
#include "secret_print.h"
#include "timing.h"
#include "tun.h"
#include "aead.h"
#include "state_machine.h"

#include <oqs/oqs.h>
#include <openssl/evp.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>

#define DEFAULT_PORT 4448
#define X25519_LEN 32U

typedef struct {
    EVP_PKEY *key;
    const uint8_t *peer_public;
    uint8_t public_key[X25519_LEN];
    uint8_t secret[X25519_LEN];
    int ok;
} x25519_task_t;

typedef struct {
    OQS_KEM *kem;
    const uint8_t *public_key;
    uint8_t *ciphertext;
    uint8_t secret[32];
    int ok;
} kem_task_t;

static int connect_server(const char *host, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd); return -1;
    }
    return fd;
}

static void *x25519_thread(void *arg) {
    x25519_task_t *task = arg;
    EVP_PKEY_CTX *keygen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    size_t public_len = sizeof(task->public_key);
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *derive_ctx = NULL;
    size_t secret_len = sizeof(task->secret);

    task->ok = keygen_ctx != NULL &&
               EVP_PKEY_keygen_init(keygen_ctx) > 0 &&
               EVP_PKEY_keygen(keygen_ctx, &task->key) > 0 &&
               EVP_PKEY_get_raw_public_key(task->key, task->public_key, &public_len) > 0 &&
               public_len == X25519_LEN;

    if (task->ok) {
        peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, task->peer_public, X25519_LEN);
        derive_ctx = EVP_PKEY_CTX_new(task->key, NULL);
        task->ok = peer != NULL && derive_ctx != NULL &&
                   EVP_PKEY_derive_init(derive_ctx) > 0 &&
                   EVP_PKEY_derive_set_peer(derive_ctx, peer) > 0 &&
                   EVP_PKEY_derive(derive_ctx, task->secret, &secret_len) > 0 &&
                   secret_len == X25519_LEN;
    }

    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(keygen_ctx);
    return NULL;
}

static void *kem_thread(void *arg) {
    kem_task_t *task = arg;
    task->ok = OQS_KEM_encaps(task->kem, task->ciphertext, task->secret, task->public_key) == OQS_SUCCESS;
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <server-ip> [port]\n", argv[0]);
        return 1;
    }
    uint16_t port = argc == 3 ? (uint16_t)atoi(argv[2]) : DEFAULT_PORT;

    OQS_init();
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    OQS_SIG *dsa = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    
    if (!kem || !dsa) {
        fprintf(stderr, "crypto init failed\n");
        return 1;
    }

    uint8_t *client_dsa_pub = malloc(dsa->length_public_key);
    uint8_t *client_dsa_sec = malloc(dsa->length_secret_key);
    if (OQS_SIG_keypair(dsa, client_dsa_pub, client_dsa_sec) != OQS_SUCCESS) {
        fprintf(stderr, "client ML-DSA keypair failed\n");
        return 1;
    }

    uint8_t server_x_public[X25519_LEN];
    uint8_t *kem_public = malloc(kem->length_public_key);
    uint8_t *kem_ciphertext = malloc(kem->length_ciphertext);
    uint8_t session_key[PQC_SESSION_KEY_LEN];

    if (!kem_public || !kem_ciphertext) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }

    uint64_t start = pqc_now_ns();
    int fd = connect_server(argv[1], port);
    if (fd < 0) return 1;

    uint32_t server_x_len = 0;
    uint32_t kem_public_len = 0;
    if (pqc_recv_padded_frame(fd, server_x_public, sizeof(server_x_public), &server_x_len) != 0 ||
        pqc_recv_padded_frame(fd, kem_public, (uint32_t)kem->length_public_key, &kem_public_len) != 0) {
        fprintf(stderr, "failed to receive server public keys\n");
        close(fd); return 1;
    }

    // PARALLEL EXECUTION: Derive X25519 and Encapsulate ML-KEM-768
    x25519_task_t x_task = {0};
    x_task.peer_public = server_x_public;
    kem_task_t kem_task = {kem, kem_public, kem_ciphertext, {0}, 0};

    pthread_t x_thread_id, kem_thread_id;
    uint64_t crypto_start = pqc_now_ns();
    pthread_create(&x_thread_id, NULL, x25519_thread, &x_task);
    pthread_create(&kem_thread_id, NULL, kem_thread, &kem_task);
    pthread_join(x_thread_id, NULL);
    pthread_join(kem_thread_id, NULL);
    uint64_t crypto_end = pqc_now_ns();

    if (!x_task.ok || !kem_task.ok) {
        fprintf(stderr, "parallel crypto execution failed\n");
        close(fd); return 1;
    }

    pqc_send_padded_frame(fd, x_task.public_key, X25519_LEN);
    pqc_send_padded_frame(fd, kem_ciphertext, (uint32_t)kem->length_ciphertext);

    if (pqc_hybrid_session_key(x_task.secret, sizeof(x_task.secret),
                               kem_task.secret, sizeof(kem_task.secret),
                               session_key) != 0) {
        fprintf(stderr, "HKDF session key derivation failed\n");
        close(fd); return 1;
    }

    // Verify Server ML-DSA-65 Signature & Anti-Downgrade Policy
    uint32_t payload_len = 0;
    uint8_t *payload = malloc(PQC_MAX_FRAME_SIZE);
    if (pqc_recv_padded_frame(fd, payload, PQC_MAX_FRAME_SIZE, &payload_len) != 0 || payload_len < dsa->length_public_key) {
        fprintf(stderr, "failed to receive ML-DSA payload\n");
        close(fd); return 1;
    }

    uint8_t *server_dsa_public = payload;
    uint32_t policy_lock = 0;
    memcpy(&policy_lock, payload + dsa->length_public_key, sizeof(policy_lock));
    uint8_t *server_sig = payload + dsa->length_public_key + sizeof(policy_lock);
    size_t sig_len = payload_len - dsa->length_public_key - sizeof(policy_lock);

    uint8_t signed_msg[64];
    memcpy(signed_msg, session_key, 32);
    memcpy(signed_msg + 32, &policy_lock, sizeof(policy_lock));

    if (OQS_SIG_verify(dsa, signed_msg, sizeof(signed_msg), server_sig, sig_len, server_dsa_public) != OQS_SUCCESS) {
        fprintf(stderr, "Server ML-DSA-65 signature verification failed!\n");
        close(fd); return 1;
    }

    if (!(policy_lock & PQC_POLICY_STRICT_PQC)) {
        fprintf(stderr, "ANTI-DOWNGRADE ALERT: Server policy did not mandate PQC enforcement! Aborting.\n");
        close(fd); return 1;
    }
    printf("[PASS] Server ML-DSA-65 signature & Anti-Downgrade Policy Verified.\n");
    free(payload);

    // MUTUAL PQC (mPQC): Client signs session key and sends to server
    uint8_t *client_sig = malloc(dsa->length_signature);
    size_t client_sig_len = 0;
    if (OQS_SIG_sign(dsa, client_sig, &client_sig_len, session_key, 32, client_dsa_sec) != OQS_SUCCESS) {
        fprintf(stderr, "Client mPQC signing failed\n");
        close(fd); return 1;
    }

    uint8_t *client_auth_payload = malloc(dsa->length_public_key + client_sig_len);
    memcpy(client_auth_payload, client_dsa_pub, dsa->length_public_key);
    memcpy(client_auth_payload + dsa->length_public_key, client_sig, client_sig_len);

    if (pqc_send_padded_frame(fd, client_auth_payload, (uint32_t)(dsa->length_public_key + client_sig_len)) != 0) {
        fprintf(stderr, "Failed to send client mPQC auth payload\n");
        close(fd); return 1;
    }
    printf("[PASS] Client ML-DSA-65 signature sent to server (mPQC Complete).\n");
    free(client_sig); free(client_auth_payload);

    uint64_t end = pqc_now_ns();
    pqc_print_secret_sha256_prefix("client session key", session_key, sizeof(session_key));
    printf("parallel hybrid handshake time: %.3f ms\n", pqc_elapsed_ms(start, end));

    OPENSSL_cleanse(x_task.secret, sizeof(x_task.secret));
    OQS_MEM_cleanse(kem_task.secret, sizeof(kem_task.secret));
    EVP_PKEY_free(x_task.key);
    free(kem_public); free(kem_ciphertext);
    free(client_dsa_pub); free(client_dsa_sec);
    OQS_KEM_free(kem); OQS_SIG_free(dsa);

    // Data Plane setup
    char tun_name[16] = "tun1";
    int tun_fd = pqc_tun_alloc(tun_name);
    if (tun_fd < 0) {
        fprintf(stderr, "Failed to create TUN interface. Exiting.\n");
        close(fd); return 1;
    }
    printf("Created parallel virtual interface: %s\n", tun_name);
    printf("Entering CAMOUFLAGED mPQC DATA PLANE. Routing packets...\n");

    pqc_make_nonblocking(fd);
    pqc_make_nonblocking(tun_fd);

    uint8_t tun_buf[PQC_MAX_FRAME_SIZE];
    uint8_t sock_buf[PQC_MAX_FRAME_SIZE];
    uint64_t tx_seq = 1;

    while (1) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(fd, &read_fds);
        FD_SET(tun_fd, &read_fds);
        int max_fd = fd > tun_fd ? fd : tun_fd;

        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) break;

        if (FD_ISSET(tun_fd, &read_fds)) {
            int n = read(tun_fd, tun_buf, sizeof(tun_buf));
            if (n > 0) {
                uint8_t nonce[PQC_AES_GCM_NONCE_LEN] = {0};
                uint64_t seq = tx_seq++;
                memcpy(nonce, &seq, sizeof(seq));

                uint8_t ciphertext[PQC_MAX_FRAME_SIZE + PQC_AES_GCM_TAG_LEN];
                uint8_t tag[PQC_AES_GCM_TAG_LEN];
                pqc_aes256_gcm_encrypt(session_key, nonce, tun_buf, n, NULL, 0, ciphertext, tag);
                memcpy(ciphertext + n, tag, PQC_AES_GCM_TAG_LEN);
                
                // CAMOUFLAGE: Padded frame
                pqc_send_padded_frame(fd, ciphertext, n + PQC_AES_GCM_TAG_LEN);
            }
        }

        if (FD_ISSET(fd, &read_fds)) {
            uint32_t len = 0;
            int ret = pqc_recv_padded_frame(fd, sock_buf, sizeof(sock_buf), &len);
            if (ret == 0 && len > PQC_AES_GCM_TAG_LEN) {
                uint8_t nonce[PQC_AES_GCM_NONCE_LEN] = {0};
                uint8_t plaintext[PQC_MAX_FRAME_SIZE];
                uint8_t tag[PQC_AES_GCM_TAG_LEN];
                memcpy(tag, sock_buf + len - PQC_AES_GCM_TAG_LEN, PQC_AES_GCM_TAG_LEN);
                
                if (pqc_aes256_gcm_decrypt(session_key, nonce, sock_buf, len - PQC_AES_GCM_TAG_LEN, NULL, 0, tag, plaintext) == 0) {
                    write(tun_fd, plaintext, len - PQC_AES_GCM_TAG_LEN);
                }
            } else if (ret != 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                printf("Server disconnected.\n");
                break;
            }
        }
    }

    close(tun_fd); close(fd); OQS_destroy();
    return 0;
}
