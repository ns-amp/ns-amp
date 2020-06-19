#include <omp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pari/pari.h"
#include "relic/relic.h"
#include "zmq.h"
#include "receiver.h"
#include "types.h"
#include "util.h"

unsigned SETUP_DONE_FLAG;
unsigned LOCK_DONE_FLAG;
unsigned RELEASE_DONE_FLAG;
char RECEIVER_ENDPOINT[ENDPOINT_STRING_SIZE];
char RECEIVER_ENDPOINT_FULL[ENDPOINT_STRING_SIZE];

int get_message_type(char *key) {
  for (size_t i = 0; i < TOTAL_MESSAGES; i++) {
    symstruct_t sym = msg_lookuptable[i];
    if (strcmp(sym.key, key) == 0) {
      return sym.code;
    }
  }
  return -1;
}

msg_handler_t get_message_handler(char *key) {
  switch (get_message_type(key))
  {
    case SETUP_INIT:
      return setup_init_handler;

    case LOCK_INIT:
      return lock_init_handler;

    case RELEASE_DONE:
      return release_done_handler;

    default:
      fprintf(stderr, "Error: invalid message type.\n");
      exit(1);
  }
}

int handle_message(receiver_state_t state, void* context, void *socket, zmq_msg_t message) {
  int result_status = RLC_OK;

  message_t msg;
  message_null(msg);

  RLC_TRY {
    printf("Received message size: %ld bytes\n", zmq_msg_size(&message));
    deserialize_message(&msg, (uint8_t *) zmq_msg_data(&message));

    printf("Executing %s...\n", msg->type);
    msg_handler_t msg_handler = get_message_handler(msg->type);
    if (msg_handler(state, context, socket, msg->data) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    printf("Finished executing %s.\n\n", msg->type);
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    if (msg != NULL) message_free(msg);
  }

  return result_status;
}

int receive_message(receiver_state_t state, void* context, void *socket) {
  int result_status = RLC_OK;

  zmq_msg_t message;

  RLC_TRY {
    int rc = zmq_msg_init(&message);
    if (rc != 0) {
      fprintf(stderr, "Error: could not initialize the message.\n");
      RLC_THROW(ERR_CAUGHT);
    }

    rc = zmq_msg_recv(&message, socket, ZMQ_DONTWAIT);
    if (rc != -1 && handle_message(state, context, socket, message) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    zmq_msg_close(&message);
  }

  return result_status;
}

int setup_init_handler(receiver_state_t state, void* context, void *socket, uint8_t *data) {
  if (state == NULL || context == NULL || socket == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  message_t setup_done_msg;
  uint8_t *serialized_message = NULL;

  RLC_TRY {
    // Deserialize the data from the message.
    memcpy(&state->value, data, sizeof(unsigned));

    for (size_t i = 0; i < state->value; i++) {
      cl_key_pair_t key_pair_i;
      cl_key_pair_null(key_pair_i);
      cl_key_pair_new(key_pair_i);

      char serialized_cl_sk[CL_SECRET_KEY_SIZE];
      char serialized_cl_pk[CL_PUBLIC_KEY_SIZE];

      memcpy(serialized_cl_sk, data + sizeof(unsigned) + (i * CL_SECRET_KEY_SIZE) + (i * CL_PUBLIC_KEY_SIZE), CL_SECRET_KEY_SIZE);
      memcpy(serialized_cl_pk, data + sizeof(unsigned) + (i * CL_SECRET_KEY_SIZE) + (i * CL_PUBLIC_KEY_SIZE) + CL_SECRET_KEY_SIZE, CL_PUBLIC_KEY_SIZE);

      key_pair_i->sk = gp_read_str(serialized_cl_sk);
      key_pair_i->pk = gp_read_str(serialized_cl_pk);
      vector_add(state->trapdoor_keys, key_pair_i);
    }

    // Build and define the message.
    char *msg_type = "setup_done";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = 0;
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(setup_done_msg, msg_type_length, msg_data_length);

    // Serialize the message.
    memcpy(setup_done_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, setup_done_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t setup_done;
    int rc = zmq_msg_init_size(&setup_done, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&setup_done), serialized_message, total_msg_length);
    rc = zmq_msg_send(&setup_done, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    SETUP_DONE_FLAG = 1;
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    if (serialized_message != NULL) free(serialized_message);
    if (setup_done_msg != NULL) message_free(setup_done_msg);
  }

  return result_status;
}

int lock_init_handler(receiver_state_t state, void* context, void *socket, uint8_t *data) {
  if (state == NULL || context == NULL || socket == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  message_t lock_done_msg;
  uint8_t *serialized_message = NULL;

  unsigned count;
  char address[ENDPOINT_STRING_SIZE];

  RLC_TRY {
    // Deserialize the data from the message.
    memcpy(address, data, (ENDPOINT_STRING_SIZE * sizeof(char)));
    memcpy(&count, data + (ENDPOINT_STRING_SIZE * sizeof(char)), sizeof(unsigned));

    for (size_t i = 0; i < count; i++) {
      lock_pair_t lock_pair;
      lock_pair_null(lock_pair);
      lock_pair_new(lock_pair);

      deserialize_lock(lock_pair->left_lock, data + (ENDPOINT_STRING_SIZE * sizeof(char)) + sizeof(unsigned) + (i * LOCK_SIZE));
      strncpy(lock_pair->left_address, address, ENDPOINT_STRING_SIZE);
      vector_add(state->locks, lock_pair);
    }

    // Build and define the message.
    char *msg_type = "lock_done";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = sizeof(unsigned);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(lock_done_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    memcpy(lock_done_msg->data, &count, sizeof(unsigned));

    // Serialize the message.
    memcpy(lock_done_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, lock_done_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t lock_done;
    int rc = zmq_msg_init_size(&lock_done, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&lock_done), serialized_message, total_msg_length);
    rc = zmq_msg_send(&lock_done, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    if (vector_size(state->locks) == state->value) {
      LOCK_DONE_FLAG = 1;
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    if (serialized_message != NULL) free(serialized_message);
    if (lock_done_msg != NULL) message_free(lock_done_msg);
  }

  return result_status;
}

int extract_init_handler(receiver_state_t state, void* context, void *socket) {
  if (state == NULL || context == NULL || socket == NULL 
   || vector_size(state->locks) != state->value) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  size_t numthread = (size_t) omp_get_num_procs();
  if (numthread > state->value) {
    numthread = state->value;
  } else if (numthread > MAX_THREAD_COUNT) {
    numthread = MAX_THREAD_COUNT;
  }
  if (!state->mt) {
    numthread = 1;
  }
  omp_set_num_threads(numthread);

  struct pari_thread pth[numthread];
  for (size_t i = 0; i < numthread; i++) {
    pari_thread_alloc(&pth[i], 100000000, NULL);
  }

  message_t release_init_msg;
  uint8_t *serialized_message = NULL;

  vector_t keys = vector_init(state->value);
  bn_t x, q, w_star;
  bn_t xis[state->value];

  bn_null(x);
  bn_null(q);
  bn_null(w_star);
  for (size_t i = 0; i < state->value; i++) {
    bn_null(xis[i]);
  }

  RLC_TRY {
    bn_new(x);
    bn_new(q);
    bn_new(w_star);
    for (size_t i = 0; i < state->value; i++) {
      bn_new(xis[i]);
    }

    uint64_t start_time = mtimer();

    ec_curve_get_ord(q);
    bn_set_dig(state->trapdoor, 0);

    #pragma omp parallel //shared(state)
    {
      int thnum = omp_get_thread_num();
      if (thnum) {
        (void) pari_thread_start(&pth[thnum]);
      }

      vector_t keys_private = vector_init(state->value / numthread);

      #pragma omp for schedule(static)
      for (size_t i = 0; i < state->value; i++) {
        lock_pair_t lock_pair = (lock_pair_t) vector_get(state->locks, i);
        lock_t lock = lock_pair->left_lock;
        cl_key_pair_t key_pair = (cl_key_pair_t) vector_get(state->trapdoor_keys, lock->id);

        GEN xi;
        if (cl_dec(&xi, lock->ctx_x->ctx_1, key_pair->sk, state->cl_params) != RLC_OK) {
          RLC_THROW(ERR_CAUGHT);
        }
        bn_read_str(xis[i], GENtostr(xi), strlen(GENtostr(xi)), 10);
      }

      #pragma omp barrier
      #pragma omp single
      for (size_t i = 0; i < state->value; i++) {
        bn_add(state->trapdoor, state->trapdoor, xis[i]);
        bn_mod(state->trapdoor, state->trapdoor, q);
      }

      #pragma omp for schedule(static)
      for (size_t i = 0; i < state->value; i++) {
        lock_pair_t lock_pair = (lock_pair_t) vector_get(state->locks, i);
        lock_t lock = lock_pair->left_lock;
        cl_key_pair_t key_pair = (cl_key_pair_t) vector_get(state->trapdoor_keys, lock->id);

        GEN wi;
        if (cl_dec(&wi, lock->ctx_w, key_pair->sk, state->cl_params) != RLC_OK) {
          RLC_THROW(ERR_CAUGHT);
        }
        bn_read_str(w_star, GENtostr(wi), strlen(GENtostr(wi)), 10);

        wbn_t k;
        wbn_null(k);
        wbn_new(k);

        bn_mul(k->bn, state->trapdoor, w_star);
        bn_mod(k->bn, k->bn, q);

        if (verify_lock(lock, k->bn) != RLC_OK) {
          RLC_THROW(ERR_CAUGHT);
        }
        vector_add(keys_private, k);
      }

      #pragma omp for ordered
      for (size_t i = 0; i < numthread; i++) {
        #pragma omp ordered
        vector_copy(keys, keys_private);
      }

      if (thnum) {
        pari_thread_close();
      }
    }

    uint64_t stop_time = mtimer();
    uint64_t total_time = stop_time - start_time;
    printf("\nTime to extract locks (count=%u): %.5f sec\n", state->value, total_time / CLOCK_PRECISION);

    for (size_t i = 0; i < state->value; i++) {
      RELEASE_DONE_FLAG = 0;
      lock_pair_t lock_pair = (lock_pair_t) vector_get(state->locks, i);
      lock_t lock = lock_pair->left_lock;
      wbn_t ki = (wbn_t) vector_get(keys, i);

      socket = zmq_socket(context, ZMQ_REQ);
      if (!socket) {
        fprintf(stderr, "Error: could not create a socket.\n");
        exit(1);
      }

      printf("Connecting to the previous intermediary (%s)...\n", lock_pair->left_address);
      int rc = zmq_connect(socket, lock_pair->left_address);
      if (rc != 0) {
        fprintf(stderr, "Error: could not connect to the intermediary.\n");
        RLC_THROW(ERR_CAUGHT);
      }

      // Build and define the message.
      char *msg_type = "release_init";
      const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
      const unsigned msg_data_length = (ENDPOINT_STRING_SIZE * sizeof(char)) + sizeof(size_t) + BN_SIZE_COMPRESSED;
      const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
      message_new(release_init_msg, msg_type_length, msg_data_length);

      // Serialize the data for the message.
      memcpy(release_init_msg->data, RECEIVER_ENDPOINT_FULL, (ENDPOINT_STRING_SIZE * sizeof(char)));
      memcpy(release_init_msg->data + (ENDPOINT_STRING_SIZE * sizeof(char)), &lock->id, sizeof(size_t));
      bn_write_bin(release_init_msg->data + (ENDPOINT_STRING_SIZE * sizeof(char)) + sizeof(size_t), BN_SIZE_COMPRESSED, ki->bn);

      memcpy(release_init_msg->type, msg_type, msg_type_length);
      free(serialized_message);
      serialize_message(&serialized_message, release_init_msg, msg_type_length, msg_data_length);

      // Send the message.
      zmq_msg_t release_init;
      rc = zmq_msg_init_size(&release_init, total_msg_length);
      if (rc < 0) {
        fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
        RLC_THROW(ERR_CAUGHT);
      }

      memcpy(zmq_msg_data(&release_init), serialized_message, total_msg_length);
      rc = zmq_msg_send(&release_init, socket, ZMQ_DONTWAIT);
      if (rc != total_msg_length) {
        fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
        RLC_THROW(ERR_CAUGHT);
      }

      while (!RELEASE_DONE_FLAG) {
        if (receive_message(state, context, socket) != RLC_OK) {
          RLC_THROW(ERR_CAUGHT);
        }
      }

      rc = zmq_close(socket);
      if (rc != 0) {
        fprintf(stderr, "Error: could not close the socket.\n");
        exit(1);
      }
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    vector_free(keys);
    bn_free(x);
    bn_free(q);
    bn_free(w_star);
    for (size_t i = 0; i < state->value; i++) {
      bn_free(xis[i]);
    }
    if (serialized_message != NULL) free(serialized_message);
    if (release_init_msg != NULL) message_free(release_init_msg);
  }

  return result_status;
}

int release_done_handler(receiver_state_t state, void* context, void *socket, uint8_t *data) {
  if (state == NULL || context == NULL || socket == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  RELEASE_DONE_FLAG = 1;
  state->release_done_count += 1;
  return RLC_OK;
}

int main(int argc, char *argv[]) {
  if (argc != 4) {
    fprintf(stderr, "Error: invalid arguments.\nUsage: %s id address mt\n", argv[0]);
    exit(1);
  }

  unsigned id = strtoul(argv[1], NULL, 10);
  char *address = argv[2];
  unsigned mt = strtoul(argv[3], NULL, 10);
  snprintf(RECEIVER_ENDPOINT, ENDPOINT_STRING_SIZE, "%s%s%u", "tcp://*:81", id < 10 ? "0" : "", id);
  snprintf(RECEIVER_ENDPOINT_FULL, ENDPOINT_STRING_SIZE, "%s", address);

  init();
  int result_status = RLC_OK;

  SETUP_DONE_FLAG = 0;
  LOCK_DONE_FLAG = 0;
  RELEASE_DONE_FLAG = 0;

  uint64_t start_time, stop_time, total_time;

  receiver_state_t state;
  receiver_state_null(state);

  // Bind the socket to talk to clients.
  void *context = zmq_ctx_new();
  if (!context) {
    fprintf(stderr, "Error: could not create a context.\n");
    exit(1);
  }
  
  void *socket = zmq_socket(context, ZMQ_REP);
  if (!socket) {
    fprintf(stderr, "Error: could not create a socket.\n");
    exit(1);
  }

  int rc = zmq_bind(socket, RECEIVER_ENDPOINT);
  if (rc != 0) {
    fprintf(stderr, "Error: could not bind the socket.\n");
    exit(1);
  }

  RLC_TRY {
    receiver_state_new(state);
    state->mt = mt;

    if (generate_cl_params(state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    start_time = mtimer();
    while (!SETUP_DONE_FLAG) {
      if (receive_message(state, context, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }
    stop_time = mtimer();
    total_time = stop_time - start_time;
    printf("\nTime to complete setup: %.5f sec\n", total_time / CLOCK_PRECISION);

    start_time = mtimer();
    while (!LOCK_DONE_FLAG) {
      if (receive_message(state, context, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }
    stop_time = mtimer();
    total_time = stop_time - start_time;
    printf("\nTime to complete locking: %.5f sec\n", total_time / CLOCK_PRECISION);

    start_time = mtimer();
    if (extract_init_handler(state, context, socket) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }
    stop_time = mtimer();
    total_time = stop_time - start_time;
    printf("\nTime to complete extraction: %.5f sec\n", total_time / CLOCK_PRECISION);
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    receiver_state_free(state);
  }

  rc = zmq_close(socket);
  if (rc != 0) {
    fprintf(stderr, "Error: could not close the socket.\n");
    exit(1);
  }

  rc = zmq_ctx_destroy(context);
  if (rc != 0) {
    fprintf(stderr, "Error: could not destroy the context.\n");
    exit(1);
  }

  clean();
  return result_status;
}