#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "relic/relic.h"
#include "util.h"

int init() {
	if (core_init() != RLC_OK) {
    core_clean();
    return RLC_ERR;
  }

  // Initializes the elliptic parameters (for 128-bit security).
	if (ec_param_set_any() == RLC_ERR) {
    RLC_THROW(ERR_NO_CURVE);
    core_clean();
    return RLC_ERR;
  }

	// Set the secp256k1 curve, which is used in Bitcoin.
	ep_param_set(SECG_K256);

	return RLC_OK;
}

int clean() {
	return core_clean();
}

void memzero(void *ptr, size_t len) {
  typedef void *(*memset_t)(void *, int, size_t);
  static volatile memset_t memset_func = memset;
  memset_func(ptr, 0, len);
}

uint64_t cpucycles(void) {
	uint64_t cycles;
	asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
			: "=a" (cycles) :: "%rdx");
	return cycles;
}

uint64_t mtimer(void) {
	struct timespec time;
	clock_gettime(CLOCK_MONOTONIC, &time);
	return (uint64_t) (time.tv_sec * CLOCK_PRECISION + time.tv_nsec);
}