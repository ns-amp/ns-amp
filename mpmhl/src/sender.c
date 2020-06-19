#include <omp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "pari/pari.h"
#include "relic/relic.h"
#include "zmq.h"
#include "sender.h"
#include "types.h"
#include "util.h"
#include "vector.h"

char SENDER_ENDPOINT[ENDPOINT_STRING_SIZE];
char SENDER_ENDPOINT_FULL[ENDPOINT_STRING_SIZE];
char RECEIVER_ENDPOINT[ENDPOINT_STRING_SIZE];
unsigned SETUP_DONE_FLAG;
unsigned LOCK_DONE_FLAG;
unsigned TERMINATE_FLAG;

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
    case SETUP_DONE:
      return setup_done_handler;

    case LOCK_DONE:
      return lock_done_handler;

    case RELEASE_INIT:
      return release_init_handler;

    default:
      fprintf(stderr, "Error: invalid message type.\n");
      exit(1);
  }
}

int handle_message(sender_state_t state, void* context, void *socket, zmq_msg_t message) {
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

int receive_message(sender_state_t state, void *context, void *socket) {
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

int setup_init_handler(sender_state_t state, void *context, void *socket) {
  if (state == NULL || context == NULL || socket == NULL) {
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

  message_t setup_init_msg;
  uint8_t *serialized_message = NULL;

  bn_t y, q;
  bn_t xis[state->value];
  bn_t ris[state->value];

  bn_null(y);
  bn_null(q);
  for (size_t i = 0; i < state->value; i++) {
    bn_null(xis[i]);
    bn_null(ris[i]);
  }

  RLC_TRY {
    bn_new(y);
    bn_new(q);
    for (size_t i = 0; i < state->value; i++) {
      bn_new(xis[i]);
      bn_new(ris[i]);
    }

    ep_curve_get_ord(q);
    bn_set_dig(state->trapdoor, 0);

    uint64_t start_time = mtimer();

    #pragma omp parallel //shared(state)
    {
      int thnum = omp_get_thread_num();
      if (thnum) {
        (void) pari_thread_start(&pth[thnum]);
      }

      vector_t trapdoor_keys_private = vector_init(state->value / numthread);
      vector_t locks_private = vector_init(state->value / numthread);

      #pragma omp for schedule(static)
      for (size_t i = 0; i < state->value; i++) {
        bn_rand_mod(ris[i], q);
        bn_rand_mod(xis[i], q);

        cl_key_pair_t key_pair_i;
        cl_key_pair_null(key_pair_i);
        cl_key_pair_new(key_pair_i);

        key_pair_i->sk = randomi(state->cl_params->bound);
        key_pair_i->pk = nupow(state->cl_params->g_q, key_pair_i->sk, NULL);
        vector_add(trapdoor_keys_private, key_pair_i);

        lock_pair_t lock_pair_i;
        lock_pair_null(lock_pair_i);
        lock_pair_new(lock_pair_i);

        const unsigned xi_str_len = bn_size_str(xis[i], 10);
        char xi_str[xi_str_len];
        bn_write_str(xi_str, xi_str_len, xis[i], 10);
        GEN plain_xi = strtoi(xi_str);

        if (cl_enc(lock_pair_i->right_lock->ctx_x->ctx_1, plain_xi, key_pair_i->pk, state->cl_params) != RLC_OK) {
          RLC_THROW(ERR_CAUGHT);
        }

        if (cl_enc(lock_pair_i->right_lock->ctx_x->ctx_2, gen_0, key_pair_i->pk, state->cl_params) != RLC_OK) {
          RLC_THROW(ERR_CAUGHT);
        }

        const unsigned ri_str_len = bn_size_str(ris[i], 10);
        char ri_str[ri_str_len];
        bn_write_str(ri_str, ri_str_len, ris[i], 10);
        GEN plain_ri = strtoi(ri_str);

        if (cl_enc(lock_pair_i->right_lock->ctx_w, plain_ri, key_pair_i->pk, state->cl_params) != RLC_OK) {
          RLC_THROW(ERR_CAUGHT);
        }

        lock_pair_i->right_lock->id = i;
        vector_add(locks_private, lock_pair_i);
      }

      #pragma omp barrier
      #pragma omp single
      for (size_t i = 0; i < state->value; i++) {
        bn_add(state->trapdoor, state->trapdoor, xis[i]);
        bn_mod(state->trapdoor, state->trapdoor, q);
      }

      #pragma omp for ordered
      for (size_t i = 0; i < numthread; i++) {
        #pragma omp ordered
        {
          vector_copy(state->locks, locks_private);
          vector_copy(state->trapdoor_keys, trapdoor_keys_private);
        }
      }

      #pragma omp for schedule(static) private(y)
      for (size_t i = 0; i < state->value; i++) {
        bn_mul(y, state->trapdoor, ris[i]);
        bn_mod(y, y, q);

        lock_pair_t lock_pair = (lock_pair_t) vector_get(state->locks, i);
        ec_mul_gen(lock_pair->right_lock->ell, y);
      }

      if (thnum) {
        pari_thread_close();
      }
    }

    uint64_t stop_time = mtimer();
    uint64_t total_time = stop_time - start_time;
    printf("\nTime to cryptographic operations of setup: %.5f sec\n", total_time / CLOCK_PRECISION);

    // Build and define the message.
    char *msg_type = "setup_init";
    const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    const unsigned msg_data_length = sizeof(unsigned) + (state->value * CL_SECRET_KEY_SIZE) + (state->value * CL_PUBLIC_KEY_SIZE);
    const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(setup_init_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    memcpy(setup_init_msg->data, &state->value, sizeof(unsigned));
    for (size_t i = 0; i < state->value; i++) {
      cl_key_pair_t key_pair_i = (cl_key_pair_t) vector_get(state->trapdoor_keys, i);
      memcpy(setup_init_msg->data + sizeof(unsigned) + (i * CL_SECRET_KEY_SIZE) + (i * CL_PUBLIC_KEY_SIZE), 
             GENtostr(key_pair_i->sk), CL_SECRET_KEY_SIZE);
      memcpy(setup_init_msg->data + sizeof(unsigned) + (i * CL_SECRET_KEY_SIZE) + (i * CL_PUBLIC_KEY_SIZE) + CL_SECRET_KEY_SIZE, 
             GENtostr(key_pair_i->pk), CL_PUBLIC_KEY_SIZE);
    }

    memcpy(setup_init_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, setup_init_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t setup_init;
    int rc = zmq_msg_init_size(&setup_init, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&setup_init), serialized_message, total_msg_length);
    rc = zmq_msg_send(&setup_init, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(y);
    bn_free(q);
    for (size_t i = 0; i < state->value; i++) {
      bn_free(xis[i]);
      bn_free(ris[i]);
    }

    if (serialized_message != NULL) free(serialized_message);
    if (setup_init_msg != NULL) message_free(setup_init_msg);
  }

  return result_status;
}

int setup_done_handler(sender_state_t state, void *context, void *socket, uint8_t *data) {
  if (state == NULL || context == NULL || socket == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }
  
  SETUP_DONE_FLAG = 1;
  return RLC_OK;
}

int lock_init_handler(sender_state_t state, void *context, void *socket) {
  if (state == NULL || context == NULL || socket == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  unsigned total_value = 0;
  for (size_t i = 0; i < vector_size(state->next_hops); i++) {
    next_hop_t next_hop = (next_hop_t) vector_get(state->next_hops, i);
    total_value += next_hop->value;
  }

  if (total_value != state->value) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  message_t lock_init_msg;
  uint8_t *serialized_message = NULL;
  
  bn_t q;
  bn_null(q);

  RLC_TRY {
    bn_new(q);
    ec_curve_get_ord(q);

    uint64_t start_time = mtimer();

    for (size_t j = 0; j < vector_size(state->next_hops); j++) {
      LOCK_DONE_FLAG = 0;
      next_hop_t next_hop = (next_hop_t) vector_get(state->next_hops, j);
      lock_t locks[next_hop->value];

      for (size_t i = 0; i < next_hop->value; i++) {
        lock_pair_t lock_pair = (lock_pair_t) vector_get_random(state->locks, unused_lock_condition);
        if (lock_pair == NULL) {
          RLC_THROW(ERR_CAUGHT);
        }

        strncpy(lock_pair->right_address, next_hop->address, ENDPOINT_STRING_SIZE);
        locks[i] = lock_pair->right_lock;
        next_hop->sent++;
      }

      int rc = zmq_close(socket);
      if (rc != 0) {
        fprintf(stderr, "Error: could not close the socket.\n");
        RLC_THROW(ERR_CAUGHT);
      }

      socket = zmq_socket(context, ZMQ_REQ);
      if (!socket) {
        fprintf(stderr, "Error: could not create a socket.\n");
        exit(1);
      }

      printf("Connecting to the intermediary (%s)...\n\n", next_hop->address);
      rc = zmq_connect(socket, next_hop->address);
      if (rc != 0) {
        fprintf(stderr, "Error: could not connect to the intermediary.\n");
        RLC_THROW(ERR_CAUGHT);
      }

      // Build and define the message.
      char *msg_type = "lock_init";
      const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
      const unsigned msg_data_length = (ENDPOINT_STRING_SIZE * sizeof(char)) + sizeof(unsigned) + (next_hop->value * LOCK_SIZE);
      const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
      message_new(lock_init_msg, msg_type_length, msg_data_length);

      // Serialize the data for the message.
      memcpy(lock_init_msg->data, SENDER_ENDPOINT_FULL, (ENDPOINT_STRING_SIZE * sizeof(char)));
      memcpy(lock_init_msg->data + (ENDPOINT_STRING_SIZE * sizeof(char)), &next_hop->value, sizeof(unsigned));

      for (size_t i = 0; i < next_hop->value; i++) {
        lock_t lock = locks[i];
        serialize_lock(lock_init_msg->data + (ENDPOINT_STRING_SIZE * sizeof(char)) + sizeof(unsigned) + (i * LOCK_SIZE), lock);
      }

      memcpy(lock_init_msg->type, msg_type, msg_type_length);
      serialize_message(&serialized_message, lock_init_msg, msg_type_length, msg_data_length);

      // Send the message.
      zmq_msg_t lock_init;
      rc = zmq_msg_init_size(&lock_init, total_msg_length);
      if (rc < 0) {
        fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
        RLC_THROW(ERR_CAUGHT);
      }

      memcpy(zmq_msg_data(&lock_init), serialized_message, total_msg_length);
      rc = zmq_msg_send(&lock_init, socket, ZMQ_DONTWAIT);
      if (rc != total_msg_length) {
        fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
        RLC_THROW(ERR_CAUGHT);
      }

      while (!LOCK_DONE_FLAG) {
        if (receive_message(state, context, socket) != RLC_OK) {
          RLC_THROW(ERR_CAUGHT);
        }
      }

      if (serialized_message != NULL) free(serialized_message);
      if (lock_init_msg != NULL) message_free(lock_init_msg);
    }

    uint64_t stop_time = mtimer();
    uint64_t total_time = stop_time - start_time;
    printf("\nTime to forward all locks: %.5f sec\n", total_time / CLOCK_PRECISION);

    int rc = zmq_close(socket);
    if (rc != 0) {
      fprintf(stderr, "Error: could not close the socket.\n");
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
  }

  return result_status;
}

int lock_done_handler(sender_state_t state, void *context, void *socket, uint8_t *data) {
  if (state == NULL || context == NULL || socket == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  unsigned count;
  memcpy(&count, data, sizeof(unsigned));
  state->lock_done_count += count;

  LOCK_DONE_FLAG = 1;
  return RLC_OK;
}

int release_init_handler(sender_state_t state, void* context, void *socket, uint8_t *data) {
  if (state == NULL || context == NULL || socket == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  message_t release_done_msg;
  uint8_t *serialized_message = NULL;

  char address[ENDPOINT_STRING_SIZE];
  size_t lock_id;

  bn_t k;
  bn_null(k);

  RLC_TRY {
    bn_new(k);

    memcpy(address, data, (ENDPOINT_STRING_SIZE * sizeof(char)));
    memcpy(&lock_id, data + (ENDPOINT_STRING_SIZE * sizeof(char)), sizeof(size_t));
    bn_read_bin(k, data + (ENDPOINT_STRING_SIZE * sizeof(char)) + sizeof(size_t), BN_SIZE_COMPRESSED);

    // Build and define the message.
    char *msg_type = "release_done";
    unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
    unsigned msg_data_length = 0;
    int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(release_done_msg, msg_type_length, msg_data_length);

    // Serialize the message.
    memcpy(release_done_msg->type, msg_type, msg_type_length);
    serialize_message(&serialized_message, release_done_msg, msg_type_length, msg_data_length);

    // Send the message.
    zmq_msg_t release_done;
    int rc = zmq_msg_init_size(&release_done, total_msg_length);
    if (rc < 0) {
      fprintf(stderr, "Error: could not initialize the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    memcpy(zmq_msg_data(&release_done), serialized_message, total_msg_length);
    rc = zmq_msg_send(&release_done, socket, ZMQ_DONTWAIT);
    if (rc != total_msg_length) {
      fprintf(stderr, "Error: could not send the message (%s).\n", msg_type);
      RLC_THROW(ERR_CAUGHT);
    }

    state->release_done_count += 1;
    if (state->release_done_count == state->value) {
      TERMINATE_FLAG = 1;
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(k);
  }

  return result_status;
}

int main(int argc, char *argv[]) {
  if (argc != 6) {
    fprintf(stderr, "Error: invalid arguments.\nUsage: %s id address recv_address value mt\n", argv[0]);
    exit(1);
  }

  unsigned id = strtoul(argv[1], NULL, 10);
  char *address = argv[2];
  char *recv_address = argv[3];
  unsigned value = strtoul(argv[4], NULL, 10);
  unsigned mt = strtoul(argv[5], NULL, 10);
  snprintf(SENDER_ENDPOINT, ENDPOINT_STRING_SIZE, "%s%s%u", "tcp://*:81", id < 10 ? "0" : "", id);
  snprintf(SENDER_ENDPOINT_FULL, ENDPOINT_STRING_SIZE, "%s", address);
  snprintf(RECEIVER_ENDPOINT, ENDPOINT_STRING_SIZE, "%s", recv_address);

  size_t len;
  ssize_t read;
  char *line = NULL;

  FILE *fp_graph = fopen("graph.dot", "r");
  FILE *fp_metadata = fopen("graph.metadata", "r");
  if (fp_graph == NULL || fp_metadata == NULL) {
    fprintf(stderr, "Error: file not found.\n");
    exit(1);
  }

  char v[3];
  unsigned nodes = 0;
  if ((read = getline(&line, &len, fp_metadata)) != -1) {
    if (2 != sscanf(line, "%*[^0123456789]%s%*[^0123456789]%u", v, &nodes)) {
      fprintf(stderr, "Error: could not parse the file.\n");
      exit(1);
    }
  }

  char **addresses = malloc(sizeof(char *) * (nodes + 1));
  for (size_t i = 0; i < nodes; i++) {
    int int_id;
    char *inter_address = calloc(25, sizeof(char));
    fscanf(fp_metadata, "id: %d\taddress: %s\n", &int_id, inter_address);
    addresses[i] = inter_address;
  }
  addresses[nodes] = NULL;

  init();
  srand(time(NULL));
  int result_status = RLC_OK;

  SETUP_DONE_FLAG = 0;
  LOCK_DONE_FLAG  = 0;
  TERMINATE_FLAG  = 0;

  uint64_t start_time, stop_time, total_time;

  sender_state_t state;
  sender_state_null(state);

  // Bind the socket to talk to clients.
  void *context = zmq_ctx_new();
  if (!context) {
    fprintf(stderr, "Error: could not create a context.\n");
    exit(1);
  }
  
  void *socket = zmq_socket(context, ZMQ_REQ);
  if (!socket) {
    fprintf(stderr, "Error: could not create a socket.\n");
    exit(1);
  }

  printf("Connecting to the receiver (%s)...\n\n", RECEIVER_ENDPOINT);
  int rc = zmq_connect(socket, RECEIVER_ENDPOINT);
  if (rc != 0) {
    fprintf(stderr, "Error: could not connect to the receiver.\n");
    exit(1);
  }

  RLC_TRY {
    sender_state_new(state);
    state->value = value;
    state->mt = mt;

    getline(&line, &len, fp_graph);
    while ((read = getline(&line, &len, fp_graph)) != -1) {
      unsigned src_id, dest_id, value;
      if (3 == sscanf(line, "%*[^0123456789]%d%*[^0123456789]%d%*[^0123456789]%d", &src_id, &dest_id, &value) && src_id == id) {
        next_hop_t next_hop;
        next_hop_null(next_hop);
        next_hop_new(next_hop);

        snprintf(next_hop->address, ENDPOINT_STRING_SIZE, "%s", addresses[dest_id-1]);
        next_hop->value = value;
        vector_add(state->next_hops, next_hop);
      }
    }

    if (generate_cl_params(state->cl_params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    start_time = mtimer();
    if (setup_init_handler(state, context, socket) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    while (!SETUP_DONE_FLAG) {
      if (receive_message(state, context, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }
    stop_time = mtimer();
    total_time = stop_time - start_time;
    printf("\nTime to complete setup: %.5f sec\n", total_time / CLOCK_PRECISION);

    if (lock_init_handler(state, context, socket) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    socket = zmq_socket(context, ZMQ_REP);
    if (!socket) {
      fprintf(stderr, "Error: could not create a socket.\n");
      exit(1);
    }

    rc = zmq_bind(socket, SENDER_ENDPOINT);
    if (rc != 0) {
      fprintf(stderr, "Error: could not connect bind the socket.\n");
      RLC_THROW(ERR_CAUGHT);
    }

    while (!TERMINATE_FLAG) {
      if (receive_message(state, context, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    sender_state_free(state);
    fclose(fp_graph);
    fclose(fp_metadata);
    if (line != NULL) free(line);
    for (size_t i = 0; i < nodes; i++) free(addresses[i]);
    free(addresses);

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

  stop_time = mtimer();
  total_time = stop_time - start_time;
  printf("\nTime to complete payment: %.5f sec\n", total_time / CLOCK_PRECISION);

  clean();
  return result_status;
}