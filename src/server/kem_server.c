#include "framing.h"
#include "secret_print.h"
#include "timing.h"
#include "state_machine.h"

#include <oqs/oqs.h>

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

#define DEFAULT_PORT 4445
#define BACKLOG 8
#define MAX_CLIENTS 64

static int create_listen_socket(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    int enabled = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
        perror("setsockopt");
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    if (pqc_make_nonblocking(fd) != 0) {
        perror("make_nonblocking");
        close(fd);
        return -1;
    }

    if (listen(fd, BACKLOG) != 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

static void cleanup(OQS_KEM *kem, uint8_t *public_key, uint8_t *secret_key) {
    free(public_key);
    if (secret_key != NULL && kem != NULL) {
        OQS_MEM_secure_free(secret_key, kem->length_secret_key);
    }
    OQS_KEM_free(kem);
    OQS_destroy();
}

int main(int argc, char **argv) {
    uint16_t port = DEFAULT_PORT;
    if (argc == 2) {
        port = (uint16_t)atoi(argv[1]);
    }

    OQS_init();
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        fprintf(stderr, "failed to initialize ML-KEM-768\n");
        OQS_destroy();
        return 1;
    }

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    if (public_key == NULL || secret_key == NULL) {
        fprintf(stderr, "allocation failed\n");
        cleanup(kem, public_key, secret_key);
        return 1;
    }

    uint64_t keypair_start = pqc_now_ns();
    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "ML-KEM keypair failed\n");
        cleanup(kem, public_key, secret_key);
        return 1;
    }
    uint64_t keypair_end = pqc_now_ns();

    int listen_fd = create_listen_socket(port);
    if (listen_fd < 0) {
        cleanup(kem, public_key, secret_key);
        return 1;
    }

    printf("pqc_kem_server listening on port %u\n", port);
    printf("ML-KEM public key ready: %zu bytes\n", kem->length_public_key);

    pqc_connection_t clients[MAX_CLIENTS];
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].fd = -1;
    }

    while (1) {
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        FD_SET(listen_fd, &read_fds);
        int max_fd = listen_fd;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].fd != -1) {
                FD_SET(clients[i].fd, &read_fds);
                // In a true async machine, we'd only set write_fds if we have data to send.
                // But for this simplified state machine, if state is STATE_SEND_KEM_PUBLIC_KEY, we wait to write.
                if (clients[i].state == STATE_SEND_KEM_PUBLIC_KEY) {
                    FD_SET(clients[i].fd, &write_fds);
                }
                if (clients[i].fd > max_fd) {
                    max_fd = clients[i].fd;
                }
            }
        }

        struct timeval timeout = {1, 0};

        int activity = select(max_fd + 1, &read_fds, &write_fds, NULL, &timeout);
        if (activity < 0 && errno != EINTR) {
            perror("select error");
            break;
        }

        if (FD_ISSET(listen_fd, &read_fds)) {
            struct sockaddr_in peer_addr;
            socklen_t peer_len = sizeof(peer_addr);
            int new_fd = accept(listen_fd, (struct sockaddr *)&peer_addr, &peer_len);
            if (new_fd >= 0) {
                pqc_make_nonblocking(new_fd);
                int added = 0;
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (clients[i].fd == -1) {
                        pqc_conn_init(&clients[i], new_fd);
                        clients[i].state = STATE_SEND_KEM_PUBLIC_KEY;
                        char peer_ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, sizeof(peer_ip));
                        printf("client connected from %s:%u (fd %d)\n", peer_ip, ntohs(peer_addr.sin_port), new_fd);
                        added = 1;
                        break;
                    }
                }
                if (!added) {
                    printf("max clients reached\n");
                    close(new_fd);
                }
            }
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].fd != -1) {
                if (clients[i].state == STATE_SEND_KEM_PUBLIC_KEY && FD_ISSET(clients[i].fd, &write_fds)) {
                    if (pqc_send_frame(clients[i].fd, public_key, (uint32_t)kem->length_public_key) == 0) {
                        clients[i].state = STATE_WAIT_KEM_ENCAPSULATION;
                    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        printf("client fd %d error sending PK\n", clients[i].fd);
                        close(clients[i].fd);
                        clients[i].fd = -1;
                    }
                } else if (clients[i].state == STATE_WAIT_KEM_ENCAPSULATION && FD_ISSET(clients[i].fd, &read_fds)) {
                    uint32_t ciphertext_len = 0;
                    int ret = pqc_recv_frame(clients[i].fd, clients[i].read_buffer, sizeof(clients[i].read_buffer), &ciphertext_len);
                    
                    if (ret == 0) {
                        if (ciphertext_len == kem->length_ciphertext) {
                            uint8_t *shared_secret = malloc(kem->length_shared_secret);
                            if (OQS_KEM_decaps(kem, shared_secret, clients[i].read_buffer, secret_key) == OQS_SUCCESS) {
                                printf("client fd %d established ML-KEM session\n", clients[i].fd);
                                pqc_print_secret_sha256_prefix("server shared secret", shared_secret, kem->length_shared_secret);
                            }
                            OQS_MEM_secure_free(shared_secret, kem->length_shared_secret);
                        }
                        close(clients[i].fd);
                        clients[i].fd = -1;
                    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        printf("client fd %d disconnected\n", clients[i].fd);
                        close(clients[i].fd);
                        clients[i].fd = -1;
                    }
                }
            }
        }
    }

    close(listen_fd);
    cleanup(kem, public_key, secret_key);
    return 0;
}
