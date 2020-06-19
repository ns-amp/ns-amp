#ifndef MPMHL_NOAS_INCLUDE_SENDER
#define MPMHL_NOAS_INCLUDE_SENDER

#include "relic/relic.h"
#include "zmq.h"
#include "types.h"
#include "vector.h"

typedef enum {
  SETUP_DONE,
  LOCK_DONE,
  RELEASE_INIT,
} msgcode_t;

typedef struct {
  char *key;
  msgcode_t code;
} symstruct_t;

static symstruct_t msg_lookuptable[] = {
  { "setup_done", SETUP_DONE },
  { "lock_done", LOCK_DONE },
  { "release_init", RELEASE_INIT }
};

#define TOTAL_MESSAGES (sizeof(msg_lookuptable) / sizeof(symstruct_t))

typedef struct {
  unsigned mt;
  unsigned value;
  unsigned lock_done_count;
  unsigned release_done_count;
  vector_t locks;
  vector_t next_hops;
  vector_t trapdoor_keys;
  bn_t trapdoor;
  cl_params_t cl_params;
} sender_state_st;

typedef sender_state_st *sender_state_t;

#define sender_state_null(state) state = NULL;

#define sender_state_new(state)                           \
  do {                                                    \
    state = malloc(sizeof(sender_state_st));              \
    if (state == NULL) {                                  \
      RLC_THROW(ERR_NO_MEMORY);                           \
    }                                                     \
    (state)->mt = 0;                                      \
    (state)->lock_done_count = 0;                         \
    (state)->release_done_count = 0;                      \
    (state)->locks = vector_init(1);                      \
    (state)->next_hops = vector_init(1);                  \
    (state)->trapdoor_keys = vector_init(1);              \
    bn_new((state)->trapdoor);                            \
    cl_params_new((state)->cl_params);                    \
  } while (0)

#define sender_state_free(state)                          \
  do {                                                    \
    vector_free((state)->locks);                          \
    vector_free((state)->next_hops);                      \
    vector_free((state)->trapdoor_keys);                  \
    bn_free((state)->trapdoor);                           \
    cl_params_free((state)->cl_params);                   \
    free(state);                                          \
    state = NULL;                                         \
  } while (0)

typedef int (*msg_handler_t)(sender_state_t, void*, void*, uint8_t*);

int get_message_type(char *key);
msg_handler_t get_message_handler(char *key);
int handle_message(sender_state_t state, void* context, void *socket, zmq_msg_t message);
int receive_message(sender_state_t state, void* context, void *socket);

int setup_init_handler(sender_state_t state, void* context, void *socket);
int setup_done_handler(sender_state_t state, void* context, void *socket, uint8_t *data);
int lock_init_handler(sender_state_t state, void* context, void *socket);
int lock_done_handler(sender_state_t state, void* context, void *socket, uint8_t *data);
int release_init_handler(sender_state_t state, void* context, void *socket, uint8_t *data);

#endif // MPMHL_NOAS_INCLUDE_SENDER