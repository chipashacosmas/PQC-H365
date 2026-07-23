#ifndef PQC_TUN_H
#define PQC_TUN_H

// Allocates a TUN interface. On success, returns the file descriptor.
// If dev is non-empty, tries to open that specific device (e.g., "tun0").
// Otherwise, the kernel assigns a name, and dev is updated.
int pqc_tun_alloc(char *dev);

#endif // PQC_TUN_H
