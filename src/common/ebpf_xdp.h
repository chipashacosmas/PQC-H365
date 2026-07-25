#ifndef PQC_EBPF_XDP_H
#define PQC_EBPF_XDP_H

// Attach eBPF XDP hook to network interface for in-kernel packet filtering & fast-path routing
int pqc_ebpf_xdp_attach(const char *ifname);

// Detach eBPF XDP hook
int pqc_ebpf_xdp_detach(const char *ifname);

#endif // PQC_EBPF_XDP_H
