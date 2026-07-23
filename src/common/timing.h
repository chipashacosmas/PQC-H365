#ifndef PQC_TIMING_H
#define PQC_TIMING_H

#include <stdint.h>

uint64_t pqc_now_ns(void);
double pqc_elapsed_ms(uint64_t start_ns, uint64_t end_ns);

#endif

