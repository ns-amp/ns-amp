#ifndef MPMHL_NOAS_INCLUDE_RECEIVER
#define MPMHL_NOAS_INCLUDE_RECEIVER

#include "relic/relic.h"
#include "zmq.h"
#include "types.h"
#include "vector.h"

typedef enum {
  SETUP_INIT,
  LOCK_INIT,
  RELEASE_DONE,
} msgcode_t;

typedef struct {
  char *key;
  msgcode_t code;
} symstruct_t;

static symstruct_t msg_lookuptable[] = {
  { "setup_init", SETUP_INIT },
  { "lock_init", LOCK_INIT },
  { "release_done", RELEASE_DONE }
};

#define TOTAL_MESSAGES (sizeof(msg_lookuptable) / sizeof(symstruct_t))

typedef struct {
  unsigned mt;
  unsigned value;
  vector_t locks;
  vector_t trapdoor_keys;
  bn_t trapdoor;
  cl_params_t cl_params;
  unsigned release_done_count;
} receiver_state_st;

typedef receiver_state_st *receiver_state_t;

#define receiver_state_null(state) state = NULL;

#define receiver_state_new(state)                         \
  do {                                                    \
    state = malloc(sizeof(receiver_state_st));            \
    if (state == NULL) {                                  \
      RLC_THROW(ERR_NO_MEMORY);                           \
    }                                                     \
    (state)->mt = 0;                                      \
    (state)->locks = vector_init(1);                      \
    (state)->trapdoor_keys = vector_init(1);              \
    bn_new((state)->trapdoor);                            \
    cl_params_new((state)->cl_params);                    \
    (state)->release_done_count = 0;                      \
  } while (0)

#define receiver_state_free(state)                        \
  do {                                                    \
    vector_free((state)->locks);                          \
    vector_free((state)->trapdoor_keys);                  \
    bn_free((state)->trapdoor);                           \
    cl_params_free((state)->cl_params);                   \
    free(state);                                          \
    state = NULL;                                         \
  } while (0)

typedef int (*msg_handler_t)(receiver_state_t, void*, void*, uint8_t*);

int get_message_type(char *key);
msg_handler_t get_message_handler(char *key);
int handle_message(receiver_state_t state, void* context, void *socket, zmq_msg_t message);
int receive_message(receiver_state_t state, void* context, void *socket);

int setup_init_handler(receiver_state_t state, void* context, void *socket, uint8_t *data);
int lock_init_handler(receiver_state_t state, void* context, void *socket, uint8_t *data);
int extract_init_handler(receiver_state_t state, void* context, void *socket);
int release_done_handler(receiver_state_t state, void* context, void *socket, uint8_t *data);

#endif // MPMHL_NOAS_INCLUDE_RECEIVER