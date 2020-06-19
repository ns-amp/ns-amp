#ifndef MPMHL_NOAS_INCLUDE_INTERMEDIARY
#define MPMHL_NOAS_INCLUDE_INTERMEDIARY

#include "relic/relic.h"
#include "zmq.h"
#include "types.h"
#include "vector.h"

typedef enum {
  LOCK_INIT,
  LOCK_DONE,
  RELEASE_INIT,
  RELEASE_DONE,
} msgcode_t;

typedef struct {
  char *key;
  msgcode_t code;
} symstruct_t;

static symstruct_t msg_lookuptable[] = {
  { "lock_init", LOCK_INIT },
  { "lock_done", LOCK_DONE },
  { "release_init", RELEASE_INIT },
  { "release_done", RELEASE_DONE }
};

#define TOTAL_MESSAGES (sizeof(msg_lookuptable) / sizeof(symstruct_t))

typedef struct {
  unsigned mt;
  vector_t locks;
  vector_t next_hops;
  cl_params_t cl_params;
  unsigned lock_done_count;
  unsigned release_done_count;
} intermediary_state_st;

typedef intermediary_state_st *intermediary_state_t;

#define intermediary_state_null(state) state = NULL;

#define intermediary_state_new(state)                     \
  do {                                                    \
    state = malloc(sizeof(intermediary_state_st));        \
    if (state == NULL) {                                  \
      RLC_THROW(ERR_NO_MEMORY);                           \
    }                                                     \
    (state)->mt = 0;                                      \
    (state)->locks = vector_init(1);                      \
    (state)->next_hops = vector_init(1);                  \
    cl_params_new((state)->cl_params);                    \
    (state)->lock_done_count = 0;                         \
    (state)->release_done_count = 0;                      \
  } while (0)

#define intermediary_state_free(state)                    \
  do {                                                    \
    vector_free((state)->locks);                          \
    vector_free((state)->next_hops);                      \
    cl_params_free((state)->cl_params);                   \
    free(state);                                          \
    state = NULL;                                         \
  } while (0)

typedef int (*msg_handler_t)(intermediary_state_t, void*, void*, uint8_t*);

int get_message_type(char *key);
msg_handler_t get_message_handler(char *key);
int handle_message(intermediary_state_t state, void* context, void *socket, zmq_msg_t message);
int receive_message(intermediary_state_t state, void* context, void *socket);

int lock_init_handler(intermediary_state_t state, void* context, void *socket, uint8_t *data);
int lock_done_handler(intermediary_state_t state, void *context, void *socket, uint8_t *data);
int release_init_handler(intermediary_state_t state, void* context, void *socket, uint8_t *data);
int release_done_handler(intermediary_state_t state, void* context, void *socket, uint8_t *data);

#endif // MPMHL_NOAS_INCLUDE_INTERMEDIARY