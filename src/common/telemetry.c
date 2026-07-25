#include "telemetry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define closesocket close
#endif

static SOCKET g_telemetry_fd = INVALID_SOCKET;
static struct sockaddr_in g_target_addr;

int pqc_telemetry_init(uint16_t target_port) {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    g_telemetry_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_telemetry_fd == INVALID_SOCKET) {
        return -1;
    }

    memset(&g_target_addr, 0, sizeof(g_target_addr));
    g_target_addr.sin_family = AF_INET;
    g_target_addr.sin_port = htons(target_port);
    g_target_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    return 0;
}

int pqc_telemetry_send_handshake(const char *mode, double latency_ms, int active_clients) {
    if (g_telemetry_fd == INVALID_SOCKET) return -1;

    char buf[512];
    time_t now = time(NULL);
    snprintf(buf, sizeof(buf),
             "{\"type\":\"handshake\",\"mode\":\"%s\",\"latency\":%.2f,\"active_clients\":%d,\"timestamp\":%ld}",
             mode ? mode : "hybrid_parallel", latency_ms, active_clients, (long)now);

    int len = (int)strlen(buf);
    sendto(g_telemetry_fd, buf, len, 0, (struct sockaddr *)&g_target_addr, sizeof(g_target_addr));
    return 0;
}

int pqc_telemetry_send_metrics(uint64_t bytes_sent, uint64_t bytes_recv, int active_clients) {
    if (g_telemetry_fd == INVALID_SOCKET) return -1;

    char buf[512];
    time_t now = time(NULL);
    snprintf(buf, sizeof(buf),
             "{\"type\":\"metrics\",\"bytes_sent\":%lu,\"bytes_recv\":%lu,\"active_clients\":%d,\"timestamp\":%ld}",
             (unsigned long)bytes_sent, (unsigned long)bytes_recv, active_clients, (long)now);

    int len = (int)strlen(buf);
    sendto(g_telemetry_fd, buf, len, 0, (struct sockaddr *)&g_target_addr, sizeof(g_target_addr));
    return 0;
}

void pqc_telemetry_cleanup(void) {
    if (g_telemetry_fd != INVALID_SOCKET) {
        closesocket(g_telemetry_fd);
        g_telemetry_fd = INVALID_SOCKET;
    }
}
