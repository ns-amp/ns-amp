#ifndef MPMHL_NOAS_INCLUDE_UTIL
#define MPMHL_NOAS_INCLUDE_UTIL

#include "pari/pari.h"
#include "relic/relic.h"
#include "types.h"

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define CLOCK_PRECISION 1E9

int init();
int clean();

void memzero(void *ptr, size_t len);
uint64_t cpucycles(void);
uint64_t mtimer(void);

void serialize_message(uint8_t **serialized,
											 const message_t message,
											 const unsigned msg_type_length,
											 const unsigned msg_data_length);
void deserialize_message(message_t *deserialized_message,
												 const uint8_t *serialized);

void serialize_lock(uint8_t *serialized, const lock_t lock);
void deserialize_lock(lock_t lock, const uint8_t *serialized);
void print_lock(const lock_t lock);
int verify_lock(lock_t lock, bn_t k);

int unused_lock_condition(void *data);
int unused_next_hop_condition(void *data);
int get_lock_by_hash_callback(void *data, void *value);
int get_right_lock_by_id_callback(void *data, void *value);
int get_left_lock_by_id_callback(void *data, void *value);
void strreplace(char *target, const char *needle, const char *replacement);

int generate_cl_params(cl_params_t params);
int cl_key_pair_generate(cl_key_pair_t key_pair, const cl_params_t params);
int cl_enc(cl_ciphertext_t ciphertext,
					 const GEN plaintext,
					 const GEN public_key,
					 const cl_params_t params);
int cl_dec(GEN *plaintext,
					 const cl_ciphertext_t ciphertext,
					 const GEN secret_key,
					 const cl_params_t params);

#endif // MPMHL_NOAS_INCLUDE_UTIL