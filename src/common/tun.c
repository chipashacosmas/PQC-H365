#include "tun.h"

#ifdef __linux__
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

int pqc_tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; 

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}
#else

// Mock implementation for non-Linux platforms (e.g., Windows development)
#include <stdio.h>
int pqc_tun_alloc(char *dev) {
    fprintf(stderr, "TUN interface is only supported on Linux. Returning mock fd.\n");
    // Return a dummy fd so the select loop doesn't crash immediately.
    // In a real scenario, this would use the Windows tap-windows6 driver.
    return -1; 
}
#endif
