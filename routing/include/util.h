#ifndef MPMHL_ROUTING_INCLUDE_UTIL
#define MPMHL_ROUTING_INCLUDE_UTIL

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define CLOCK_PRECISION 1E9

int init();
int clean();

void memzero(void *ptr, size_t len);
uint64_t cpucycles(void);
uint64_t mtimer(void);

#endif // MPMHL_ROUTING_INCLUDE_UTIL