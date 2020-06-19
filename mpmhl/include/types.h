#ifndef MPMHL_NOAS_INCLUDE_TYPES
#define MPMHL_NOAS_INCLUDE_TYPES

#include <stdlib.h>
#include "pari/pari.h"
#include "relic/relic.h"

#define MAX_THREAD_COUNT      1
#define ENDPOINT_STRING_SIZE  30
#define BN_SIZE_COMPRESSED    32
#define EC_SIZE_COMPRESSED    33  
#define CL_SECRET_KEY_SIZE    290
#define CL_PUBLIC_KEY_SIZE    1070
#define CL_CIPHERTEXT_SIZE    1100
#define LOCK_SIZE             (EC_SIZE_COMPRESSED + (6 * CL_CIPHERTEXT_SIZE) + 8)

typedef struct {
  char *type;
  uint8_t *data;
} message_st;

typedef message_st *message_t;

#define message_null(message) message = NULL;

#define message_new(message, type_length, data_length)                  \
  do {                                                                  \
    message = malloc(sizeof(message_st));                               \
    if (message == NULL) {                                              \
      RLC_THROW(ERR_NO_MEMORY);                                             \
    }                                                                   \
    (message)->type = malloc(sizeof(char) * type_length);               \
    if ((message)->type == NULL) {                                      \
      RLC_THROW(ERR_NO_MEMORY);                                             \
    }                                                                   \
    (message)->data = malloc(sizeof(uint8_t) * data_length);            \
    if ((message)->data == NULL) {                                      \
      RLC_THROW(ERR_NO_MEMORY);                                             \
    }                                                                   \
  } while (0)

#define message_free(message)                                           \
  do {                                                                  \
    free((message)->type);                                              \
    free((message)->data);                                              \
    free(message);                                                      \
    message = NULL;                                                     \
  } while (0)

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
  GEN Delta_K;  // fundamental discriminant
  GEN E;        // the secp256k1 elliptic curve
  GEN q;        // the order of the elliptic curve
  GEN G;        // the generator of the elliptic curve group
  GEN g_q;      // the generator of G^q
  GEN bound;    // the bound for exponentiation
} cl_params_st;

typedef cl_params_st *cl_params_t;

#define cl_params_null(params) params = NULL;

#define cl_params_new(params)                         \
  do {                                                \
    params = malloc(sizeof(cl_params_st));            \
    if (params == NULL) {                             \
      RLC_THROW(ERR_NO_MEMORY);                           \
    }                                                 \
  } while (0)

#define cl_params_free(params)                        \
  do {                                                \
    free(params);                                     \
    params = NULL;                                    \
  } while (0)

typedef struct {
  GEN c1;
  GEN c2;
} cl_ciphertext_st;

typedef cl_ciphertext_st *cl_ciphertext_t;

#define cl_ciphertext_null(ciphertext) ciphertext = NULL;

#define cl_ciphertext_new(ciphertext)                 \
  do {                                                \
    ciphertext = malloc(sizeof(cl_ciphertext_st));    \
    if (ciphertext == NULL) {                         \
      RLC_THROW(ERR_NO_MEMORY);                           \
    }                                                 \
  } while (0)

#define cl_ciphertext_free(ciphertext)                \
  do {                                                \
    free(ciphertext);                                 \
    ciphertext = NULL;                                \
  } while (0)

#define cl_ciphertext_copy(result, ciphertext)        \
  do {                                                \
    (result)->c1 = gcopy((ciphertext)->c1);           \
    (result)->c2 = gcopy((ciphertext)->c2);           \
  } while (0)

typedef struct {
  cl_ciphertext_t ctx_1;
  cl_ciphertext_t ctx_2;
} cl_double_ciphertext_st;

typedef cl_double_ciphertext_st *cl_double_ciphertext_t;

#define cl_double_ciphertext_null(ciphertext) ciphertext = NULL;

#define cl_double_ciphertext_new(ciphertext)                  \
  do {                                                        \
    ciphertext = malloc(sizeof(cl_double_ciphertext_st));     \
    if (ciphertext == NULL) {                                 \
      RLC_THROW(ERR_NO_MEMORY);                                   \
    }                                                         \
    cl_ciphertext_new((ciphertext)->ctx_1);                   \
    cl_ciphertext_new((ciphertext)->ctx_2);                   \
  } while (0)

#define cl_double_ciphertext_free(ciphertext)                 \
  do {                                                        \
    cl_ciphertext_free((ciphertext)->ctx_1);                  \
    cl_ciphertext_free((ciphertext)->ctx_2);                  \
    free(ciphertext);                                         \
    ciphertext = NULL;                                        \
  } while (0)

#define cl_double_ciphertext_copy(result, ciphertext)         \
  do {                                                        \
    cl_ciphertext_copy((result)->ctx_1, (ciphertext->ctx_1)); \
    cl_ciphertext_copy((result)->ctx_2, (ciphertext->ctx_2)); \
  } while (0)

typedef struct {
  GEN sk;
  GEN pk;
} cl_key_pair_st;

typedef cl_key_pair_st *cl_key_pair_t;

#define cl_key_pair_null(key_pair) key_pair = NULL;

#define cl_key_pair_new(key_pair)                     \
  do {                                                \
    key_pair = malloc(sizeof(cl_key_pair_st));        \
    if (key_pair == NULL) {                           \
      RLC_THROW(ERR_NO_MEMORY);                           \
    }                                                 \
  } while (0)

#define cl_key_pair_free(key_pair)                    \
  do {                                                \
    free(key_pair);                                   \
    key_pair = NULL;                                  \
  } while (0)


typedef struct {
  ec_t ell;
  cl_ciphertext_t ctx_w;
  cl_double_ciphertext_t ctx_x;
  size_t id;
} lock_st;

typedef lock_st *lock_t;

#define lock_null(lock) lock = NULL;

#define lock_new(lock)                                                  \
  do {                                                                  \
    lock = malloc(sizeof(lock_st));                                     \
    if (lock == NULL) {                                                 \
      RLC_THROW(ERR_NO_MEMORY);                                             \
    }                                                                   \
    ec_new((lock)->ell);                                                \
    cl_ciphertext_new((lock)->ctx_w);                                   \
    cl_double_ciphertext_new((lock)->ctx_x);                            \
  } while (0)

#define lock_free(lock)                                                 \
  do {                                                                  \
    ec_free((lock)->ell);                                               \
    cl_ciphertext_free((lock)->ctx_w);                                  \
    cl_double_ciphertext_free((lock)->ctx_x);                           \
    free(lock);                                                         \
    lock = NULL;                                                        \
  } while (0)

#define lock_copy(result, lock)                                         \
  do {                                                                  \
    ec_copy((result)->ell, (lock)->ell);                                \
    cl_ciphertext_copy((result)->ctx_w, (lock)->ctx_w);                 \
    cl_double_ciphertext_copy((result)->ctx_x, (lock)->ctx_x);          \
    memcpy(&(result)->id, &(lock)->id, sizeof(size_t));                 \
  } while (0)

typedef struct {
  char *left_address;
  lock_t left_lock;
  bn_t witness;
  lock_t right_lock;
  char *right_address;
} lock_pair_st;

typedef lock_pair_st *lock_pair_t;

#define lock_pair_null(lock_pair) lock_pair = NULL;

#define lock_pair_new(lock_pair)                                              \
  do {                                                                        \
    lock_pair = malloc(sizeof(lock_pair_st));                                 \
    if (lock_pair == NULL) {                                                  \
      RLC_THROW(ERR_NO_MEMORY);                                                   \
    }                                                                         \
    (lock_pair)->left_address = calloc(ENDPOINT_STRING_SIZE, sizeof(char));   \
    if ((lock_pair)->left_address == NULL) {                                  \
      RLC_THROW(ERR_NO_MEMORY);                                                   \
    }                                                                         \
    (lock_pair)->right_address = calloc(ENDPOINT_STRING_SIZE, sizeof(char));  \
    if ((lock_pair)->right_address == NULL) {                                 \
      RLC_THROW(ERR_NO_MEMORY);                                                   \
    }                                                                         \
    bn_new((lock_pair)->witness);                                             \
    lock_new((lock_pair)->left_lock);                                         \
    lock_new((lock_pair)->right_lock);                                        \
  } while (0)

#define lock_pair_free(lock_pair)                               \
  do {                                                          \
    lock_free((lock_pair)->left_lock);                          \
    lock_free((lock_pair)->right_lock);                         \
    bn_free((lock_pair)->withness);                             \
    free((lock_pair)->left_address);                            \
    free((lock_pair)->right_address);                           \
    free(lock_pair);                                            \
    lock_pair = NULL;                                           \
  } while (0)

typedef struct {
  char *address;
  unsigned value;
  unsigned sent;
} next_hop_st;

typedef next_hop_st *next_hop_t;

#define next_hop_null(next_hop) next_hop = NULL;

#define next_hop_new(next_hop)                                                \
  do {                                                                        \
    next_hop = malloc(sizeof(next_hop_st));                                   \
    if (next_hop == NULL) {                                                   \
      RLC_THROW(ERR_NO_MEMORY);                                                   \
    }                                                                         \
    (next_hop)->address = calloc(ENDPOINT_STRING_SIZE, sizeof(char));         \
    if ((next_hop)->address == NULL) {                                        \
      RLC_THROW(ERR_NO_MEMORY);                                                   \
    }                                                                         \
    (next_hop)->value = 0;                                                    \
    (next_hop)->sent = 0;                                                     \
  } while (0)

#define next_hop_free(next_hop)                                 \
  do {                                                          \
    free((next_hop)->address);                                  \
    free(next_hop);                                             \
    next_hop = NULL;                                            \
  } while (0)

#endif // MPMHL_NOAS_INCLUDE_TYPES