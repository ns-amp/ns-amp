#include <omp.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pari/pari.h"
#include "relic/relic.h"
#include "zmq.h"
#include "intermediary.h"
#include "types.h"
#include "util.h"

static jmp_buf buf;
unsigned LOCK_DONE_FLAG;
unsigned RELEASE_DONE_FLAG;
unsigned TERMINATE_FLAG;
char INTERMEDIARY_ENDPOINT[ENDPOINT_STRING_SIZE];
char INTERMEDIARY_ENDPOINT_FULL[ENDPOINT_STRING_SIZE];

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
    case LOCK_INIT:
      return lock_init_handler;

    case LOCK_DONE:
      return lock_done_handler;

    case RELEASE_INIT:
      return release_init_handler;

    case RELEASE_DONE:
      return release_done_handler;

    default:
      fprintf(stderr, "Error: invalid message type.\n");
      exit(1);
  }
}

int handle_message(intermediary_state_t state, void* context, void *socket, zmq_msg_t message) {
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

int receive_message(intermediary_state_t state, void* context, void *socket) {
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

int lock_init_handler(intermediary_state_t state, void* context, void *socket, uint8_t *data) {
  if (state == NULL || context == NULL || socket == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  message_t lock_done_msg, lock_init_msg;
  uint8_t *serialized_message = NULL;

  unsigned count;
  char address[ENDPOINT_STRING_SIZE];

  cl_ciphertext_t ctx_sk, ctx_zero, ctx_w_prime;
  cl_ciphertext_null(ctx_sk);
  cl_ciphertext_null(ctx_zero);
  cl_ciphertext_null(ctx_w_prime);

  bn_t q;
  bn_null(q);

  RLC_TRY {
    cl_ciphertext_new(ctx_sk);
    cl_ciphertext_new(ctx_zero);
    cl_ciphertext_new(ctx_w_prime);

    bn_new(q);
    ec_curve_get_ord(q);

    // Deserialize the data from the message.
    memcpy(address, data, (ENDPOINT_STRING_SIZE * sizeof(char)));
    memcpy(&count, data + (ENDPOINT_STRING_SIZE * sizeof(char)), sizeof(unsigned));

    for (size_t i = 0; i < count; i++) {
      lock_pair_t lock_pair;
      lock_pair_null(lock_pair);
      lock_pair_new(lock_pair);

      deserialize_lock(lock_pair->left_lock, data + (ENDPOINT_STRING_SIZE * sizeof(char)) + sizeof(unsigned) + (i * LOCK_SIZE));
      strncpy(lock_pair->left_address, address, ENDPOINT_STRING_SIZE);
      lock_copy(lock_pair->right_lock, lock_pair->left_lock);
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

    if (serialized_message != NULL) free(serialized_message);
    if (lock_done_msg != NULL) message_free(lock_done_msg);

    unsigned unused_lock_count = vector_get_count(state->locks, unused_lock_condition);
    while (unused_lock_count > 0) {
      printf("Starting forwarding...\n");
      uint64_t start_time = mtimer();

      next_hop_t next_hop = vector_get_random(state->next_hops, unused_next_hop_condition);
      if (next_hop == NULL) {
        RLC_THROW(ERR_CAUGHT);
      }
      LOCK_DONE_FLAG = 0;

      const unsigned count = MIN(next_hop->value - next_hop->sent, unused_lock_count);
      vector_t locks = vector_init(count);

      for (size_t i = 0; i < count; i++) {
        lock_pair_t lock_pair = (lock_pair_t) vector_get_random(state->locks, unused_lock_condition);
        lock_t lock = lock_pair->right_lock;
        
        bn_rand_mod(lock_pair->witness, q);
        ec_mul(lock->ell, lock->ell, lock_pair->witness);

        const unsigned w_str_len = bn_size_str(lock_pair->witness, 10);
        char w_str[w_str_len];
        bn_write_str(w_str, w_str_len, lock_pair->witness, 10);
        GEN plain_w = strtoi(w_str);

        lock->ctx_w->c1 = nupow(lock->ctx_w->c1, plain_w, NULL);
        lock->ctx_w->c2 = nupow(lock->ctx_w->c2, plain_w, NULL);

        GEN r_1 = randomi(state->cl_params->bound);
        GEN r_2 = randomi(state->cl_params->bound);

        GEN ctx_c1_r1 = nupow(lock->ctx_x->ctx_2->c1, r_1, NULL);
        GEN ctx_c2_r1 = nupow(lock->ctx_x->ctx_2->c2, r_1, NULL);
        lock->ctx_x->ctx_1->c1 = gmul(lock->ctx_x->ctx_1->c1, ctx_c1_r1);
        lock->ctx_x->ctx_1->c2 = gmul(lock->ctx_x->ctx_1->c2, ctx_c2_r1);

        lock->ctx_x->ctx_2->c1 = nupow(lock->ctx_x->ctx_2->c1, r_2, NULL);
        lock->ctx_x->ctx_2->c2 = nupow(lock->ctx_x->ctx_2->c2, r_2, NULL);

        strncpy(lock_pair->right_address, next_hop->address, ENDPOINT_STRING_SIZE);
        vector_add(locks, lock);
      }

      uint64_t stop_time = mtimer();
      uint64_t total_time = stop_time - start_time;
      printf("Time to randomize locks (count=%u): %.5f sec\n", count, total_time / CLOCK_PRECISION);

      rc = zmq_close(socket);
      if (rc != 0) {
        fprintf(stderr, "Error: could not close the socket.\n");
        RLC_THROW(ERR_CAUGHT);
      }

      socket = zmq_socket(context, ZMQ_REQ);
      if (!socket) {
        fprintf(stderr, "Error: could not create a socket.\n");
        exit(1);
      }

      printf("Connecting to the next intermediary (%s)...\n", next_hop->address);
      rc = zmq_connect(socket, next_hop->address);
      if (rc != 0) {
        fprintf(stderr, "Error: could not connect to the intermediary.\n");
        RLC_THROW(ERR_CAUGHT);
      }

      // Build and define the message.
      char *msg_type = "lock_init";
      const unsigned msg_type_length = (unsigned) strlen(msg_type) + 1;
      const unsigned msg_data_length = (ENDPOINT_STRING_SIZE * sizeof(char)) + sizeof(unsigned) + (count * LOCK_SIZE);
      const int total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
      message_new(lock_init_msg, msg_type_length, msg_data_length);

      // Serialize the data for the message.
      memcpy(lock_init_msg->data, INTERMEDIARY_ENDPOINT_FULL, (ENDPOINT_STRING_SIZE * sizeof(char)));
      memcpy(lock_init_msg->data + (ENDPOINT_STRING_SIZE * sizeof(char)), &count, sizeof(unsigned));

      for (size_t i = 0; i < count; i++) {
        lock_t lock = (lock_t) vector_get(locks, i);
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

      printf("Forwarding the locks...\n");
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

      vector_free(locks);
      next_hop->sent += count;
      unused_lock_count = vector_get_count(state->locks, unused_lock_condition);
      printf("Finished forwarding the lock.\n");

      stop_time = mtimer();
      total_time = stop_time - start_time;
      printf("Time to forward locks (count=%u): %.5f sec\n", count, total_time / CLOCK_PRECISION);
    }

    rc = zmq_close(socket);
    if (rc != 0) {
      fprintf(stderr, "Error: could not close the socket.\n");
      RLC_THROW(ERR_CAUGHT);
    }

    longjmp(buf, 1);
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    cl_ciphertext_free(ctx_sk);
    cl_ciphertext_free(ctx_zero);
    cl_ciphertext_free(ctx_w_prime);
    bn_free(q);
  }

  return result_status;
}

int lock_done_handler(intermediary_state_t state, void* context, void *socket, uint8_t *data) {
  if (state == NULL || context == NULL || socket == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  unsigned count;
  memcpy(&count, data, sizeof(unsigned));
  state->lock_done_count += count;

  LOCK_DONE_FLAG = 1;
  return RLC_OK;
}

int release_init_handler(intermediary_state_t state, void* context, void *socket, uint8_t *data) {
  if (state == NULL || context == NULL || socket == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  int result_status = RLC_OK;

  message_t release_done_msg, release_init_msg;
  uint8_t *serialized_message = NULL;

  char address[ENDPOINT_STRING_SIZE];
  size_t lock_id;

  bn_t x, q, witness_inverse;
  bn_t k, k_prime;
  bn_null(x);
  bn_null(q);
  bn_null(witness_inverse);
  bn_null(k);
  bn_null(k_prime);

  RLC_TRY {
    bn_new(x);
    bn_new(q);
    bn_new(witness_inverse);
    bn_new(k);
    bn_new(k_prime);

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

    uint64_t start_time = mtimer();
    RELEASE_DONE_FLAG = 0;

    lock_pair_t lock_pair = (lock_pair_t) vector_get_by_value(state->locks, get_right_lock_by_id_callback, (void *) lock_id);
    if (lock_pair == NULL) {
      RLC_THROW(ERR_CAUGHT);
    }
    lock_t lock = lock_pair->left_lock;

    ec_curve_get_ord(q);

    bn_gcd_ext(x, witness_inverse, NULL, lock_pair->witness, q);
    if (bn_sign(witness_inverse) == RLC_NEG) {
      bn_add(witness_inverse, witness_inverse, q);
    }

    bn_mul(k_prime, k, witness_inverse);
    bn_mod(k_prime, k_prime, q);
    if (verify_lock(lock, k_prime) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    uint64_t stop_time = mtimer();
    uint64_t total_time = stop_time - start_time;
    printf("Time to release (id: %zu): %.5f sec\n", lock->id, total_time / CLOCK_PRECISION);

    socket = zmq_socket(context, ZMQ_REQ);
    if (!socket) {
      fprintf(stderr, "Error: could not create a socket.\n");
      exit(1);
    }

    printf("Connecting to the previous intermediary (%s)...\n", lock_pair->left_address);
    rc = zmq_connect(socket, lock_pair->left_address);
    if (rc != 0) {
      fprintf(stderr, "Error: could not connect to the intermediary.\n");
      RLC_THROW(ERR_CAUGHT);
    }

    // Build and define the message.
    msg_type = "release_init";
    msg_type_length = (unsigned) strlen(msg_type) + 1;
    msg_data_length = (ENDPOINT_STRING_SIZE * sizeof(char)) + sizeof(size_t) + BN_SIZE_COMPRESSED;
    total_msg_length = msg_type_length + msg_data_length + (2 * sizeof(unsigned));
    message_new(release_init_msg, msg_type_length, msg_data_length);

    // Serialize the data for the message.
    memcpy(release_init_msg->data, INTERMEDIARY_ENDPOINT_FULL, (ENDPOINT_STRING_SIZE * sizeof(char)));
    memcpy(release_init_msg->data + (ENDPOINT_STRING_SIZE * sizeof(char)), &lock->id, sizeof(size_t));
    bn_write_bin(release_init_msg->data + (ENDPOINT_STRING_SIZE * sizeof(char)) + sizeof(size_t), BN_SIZE_COMPRESSED, k_prime);

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

    stop_time = mtimer();
    total_time = stop_time - start_time;
    printf("Time to release and forward key (id: %zu): %.5f sec\n", lock->id, total_time / CLOCK_PRECISION);

    rc = zmq_close(socket);
    if (rc != 0) {
      fprintf(stderr, "Error: could not close the socket.\n");
      RLC_THROW(ERR_CAUGHT);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(x);
    bn_free(q);
    bn_free(witness_inverse);
    bn_free(k);
    bn_free(k_prime);
    if (serialized_message != NULL) free(serialized_message);
    if (release_init_msg != NULL) message_free(release_init_msg);
    if (release_done_msg != NULL) message_free(release_done_msg);
  }

  return result_status;
}

int release_done_handler(intermediary_state_t state, void* context, void *socket, uint8_t *data) {
  if (state == NULL || context == NULL || socket == NULL || data == NULL) {
    RLC_THROW(ERR_NO_VALID);
  }

  state->release_done_count += 1;
  RELEASE_DONE_FLAG = 1;
  
  if (state->release_done_count == state->lock_done_count) {
    TERMINATE_FLAG = 1;
  }

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
  snprintf(INTERMEDIARY_ENDPOINT, ENDPOINT_STRING_SIZE, "%s%s%u", "tcp://*:81", id < 10 ? "0" : "", id);
  snprintf(INTERMEDIARY_ENDPOINT_FULL, ENDPOINT_STRING_SIZE, "%s", address);

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
  int result_status = RLC_OK;

  LOCK_DONE_FLAG = 0;
  RELEASE_DONE_FLAG = 0;
  TERMINATE_FLAG = 0;

  intermediary_state_t state;
  intermediary_state_null(state);

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

  int rc = zmq_bind(socket, INTERMEDIARY_ENDPOINT);
  if (rc != 0) {
    fprintf(stderr, "Error: could not bind socket.\n");
    exit(1);
  }

  RLC_TRY {
    intermediary_state_new(state);
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

    if (setjmp(buf)) {
      printf("\nListening for messages...\n");
      
      socket = zmq_socket(context, ZMQ_REP);
      if (!socket) {
        fprintf(stderr, "Error: could not create a socket.\n");
        exit(1);
      }

      rc = zmq_bind(socket, INTERMEDIARY_ENDPOINT);
      if (rc != 0) {
        fprintf(stderr, "Error: could not bind the socket.\n");
        exit(1);
      }
    }

    while (!TERMINATE_FLAG) {
      if (receive_message(state, context, socket) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
      }
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    intermediary_state_free(state);
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

  clean();
  return result_status;
}