#include "timing.h"

#include <time.h>

uint64_t pqc_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

double pqc_elapsed_ms(uint64_t start_ns, uint64_t end_ns) {
    return (double)(end_ns - start_ns) / 1000000.0;
}

