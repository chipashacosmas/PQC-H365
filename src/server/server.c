#include "framing.h"
#include "timing.h"
#include "state_machine.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>

#define DEFAULT_PORT 4444
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

int main(int argc, char **argv) {
    uint16_t port = DEFAULT_PORT;
    if (argc == 2) {
        port = (uint16_t)atoi(argv[1]);
    }

    int listen_fd = create_listen_socket(port);
    if (listen_fd < 0) {
        return 1;
    }

    printf("pqc_server listening on port %u\n", port);

    pqc_connection_t clients[MAX_CLIENTS];
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].fd = -1;
    }

    while (1) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_fd, &read_fds);
        int max_fd = listen_fd;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].fd != -1) {
                FD_SET(clients[i].fd, &read_fds);
                if (clients[i].fd > max_fd) {
                    max_fd = clients[i].fd;
                }
            }
        }

        struct timeval timeout = {1, 0}; // 1 second timeout

        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
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
                        char peer_ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, sizeof(peer_ip));
                        printf("client connected from %s:%u (fd %d)\n", peer_ip, ntohs(peer_addr.sin_port), new_fd);
                        added = 1;
                        break;
                    }
                }
                if (!added) {
                    printf("max clients reached, rejecting connection\n");
                    close(new_fd);
                }
            }
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].fd != -1 && FD_ISSET(clients[i].fd, &read_fds)) {
                // In a full implementation, we'd have a non-blocking state machine here.
                // For this prototype of the event loop, we will do a simple recv.
                uint32_t len = 0;
                int ret = pqc_recv_frame(clients[i].fd, clients[i].read_buffer, sizeof(clients[i].read_buffer), &len);
                
                if (ret == 0) {
                    printf("received %u bytes from fd %d\n", len, clients[i].fd);
                    const char reply[] = "SERVER_HELLO_FRAME_OK";
                    pqc_send_frame(clients[i].fd, (const uint8_t *)reply, (uint32_t)strlen(reply));
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

    close(listen_fd);
    return 0;
}
