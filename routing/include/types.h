#ifndef MPMHL_ROUTING_INCLUDE_TYPES
#define MPMHL_ROUTING_INCLUDE_TYPES

#include <stdlib.h>
#include "relic/relic.h"

// Wrapper types for bn_t and ec_t of RELIC, in order to use them  
// with our vector_t data structure.
typedef struct {
  bn_t bn;
} wbn_st;

typedef wbn_st *wbn_t;

#define wbn_null(wbn) wbn = NULL;

#define wbn_new(wbn)              \
  do {                            \
    wbn = malloc(sizeof(wbn_st)); \
    if (wbn == NULL) {            \
      RLC_THROW(ERR_NO_MEMORY);       \
    }                             \
    bn_new((wbn)->bn);            \
  } while (0)

#define wbn_free(wbn)             \
  do {                            \
    bn_free((wbn)->bn);           \
    free(wbn);                    \
    wbn = NULL;                   \
  } while (0)

typedef struct {
  ec_t ec;
} wec_st;

typedef wec_st *wec_t;

#define wec_null(wec) wec = NULL;

#define wec_new(wec)              \
  do {                            \
    wec = malloc(sizeof(wec_st)); \
    if (wec == NULL) {            \
      RLC_THROW(ERR_NO_MEMORY);       \
    }                             \
    ec_new((wec)->ec);            \
  } while (0)

#define wec_free(wec)             \
  do {                            \
    ec_free((wec)->ec);           \
    free(wec);                    \
    wec = NULL;                   \
  } while (0)

#define wec_copy(res, wec)        \
  do {                            \
    ec_copy((res)->ec, wec->ec);  \
  } while (0)

#endif // MPMHL_ROUTING_INCLUDE_TYPES