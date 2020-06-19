#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "pari/pari.h"
#include "relic/relic.h"
#include "types.h"
#include "util.h"

int init() {
	if (core_init() != RLC_OK) {
    core_clean();
    return RLC_ERR;
  }

  // Initializes the elliptic parameters (for 128-bit security).
	if (ec_param_set_any() == RLC_ERR) {
    RLC_THROW(ERR_NO_CURVE);
    core_clean();
    return RLC_ERR;
  }

	// Set the secp256k1 curve, which is used in Bitcoin.
	ep_param_set(SECG_K256);

	// Initialize the PARI stack (in bytes) and randomness.
	pari_init(1000000000, 2);
	setrand(getwalltime());

	return RLC_OK;
}

int clean() {
	pari_close();
	return core_clean();
}

void memzero(void *ptr, size_t len) {
  typedef void *(*memset_t)(void *, int, size_t);
  static volatile memset_t memset_func = memset;
  memset_func(ptr, 0, len);
}

uint64_t cpucycles(void) {
	uint64_t cycles;
	asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
			: "=a" (cycles) :: "%rdx");
	return cycles;
}

uint64_t mtimer(void) {
	struct timespec time;
	clock_gettime(CLOCK_MONOTONIC, &time);
	return (uint64_t) (time.tv_sec * CLOCK_PRECISION + time.tv_nsec);
}

void serialize_message(uint8_t **serialized,
											 const message_t message,
											 const unsigned msg_type_length,
											 const unsigned msg_data_length) {
	*serialized = malloc(msg_type_length + msg_data_length + (2 * sizeof(unsigned)));
	if (*serialized == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
	}

	memcpy(*serialized, &msg_type_length, sizeof(unsigned));
	memcpy(*serialized + sizeof(unsigned), message->type, msg_type_length);
	
	if (msg_data_length > 0) {
		memcpy(*serialized + sizeof(unsigned) + msg_type_length, &msg_data_length, sizeof(unsigned));
		memcpy(*serialized + (2 * sizeof(unsigned)) + msg_type_length, message->data, msg_data_length);
	} else {
		memset(*serialized + sizeof(unsigned) + msg_type_length, 0, sizeof(unsigned));
	}
}

void deserialize_message(message_t *deserialized_message, const uint8_t *serialized) {
	unsigned msg_type_length;
	memcpy(&msg_type_length, serialized, sizeof(unsigned));
	unsigned msg_data_length;
	memcpy(&msg_data_length, serialized + sizeof(unsigned) + msg_type_length, sizeof(unsigned));

	message_null(*deserialized_message);
	message_new(*deserialized_message, msg_type_length, msg_data_length);

	memcpy((*deserialized_message)->type, serialized + sizeof(unsigned), msg_type_length);
	if (msg_data_length > 0) {
		memcpy((*deserialized_message)->data, serialized + (2 * sizeof(unsigned)) + msg_type_length, msg_data_length);
	}
}

void serialize_lock(uint8_t *serialized, const lock_t lock) {
	ec_write_bin(serialized, EC_SIZE_COMPRESSED, lock->ell, 1);
	memcpy(serialized + EC_SIZE_COMPRESSED, GENtostr(lock->ctx_w->c1), CL_CIPHERTEXT_SIZE);
	memcpy(serialized + EC_SIZE_COMPRESSED + CL_CIPHERTEXT_SIZE, GENtostr(lock->ctx_w->c2), CL_CIPHERTEXT_SIZE);
	memcpy(serialized + EC_SIZE_COMPRESSED + (2 * CL_CIPHERTEXT_SIZE), GENtostr(lock->ctx_x->ctx_1->c1), CL_CIPHERTEXT_SIZE);
	memcpy(serialized + EC_SIZE_COMPRESSED + (3 * CL_CIPHERTEXT_SIZE), GENtostr(lock->ctx_x->ctx_1->c2), CL_CIPHERTEXT_SIZE);
	memcpy(serialized + EC_SIZE_COMPRESSED + (4 * CL_CIPHERTEXT_SIZE), GENtostr(lock->ctx_x->ctx_2->c1), CL_CIPHERTEXT_SIZE);
	memcpy(serialized + EC_SIZE_COMPRESSED + (5 * CL_CIPHERTEXT_SIZE), GENtostr(lock->ctx_x->ctx_2->c2), CL_CIPHERTEXT_SIZE);
	memcpy(serialized + EC_SIZE_COMPRESSED + (6 * CL_CIPHERTEXT_SIZE), &lock->id, sizeof(size_t));
}

void deserialize_lock(lock_t lock, const uint8_t *serialized) {
	char serialized_cl_ctx[CL_CIPHERTEXT_SIZE];

	ec_read_bin(lock->ell, serialized, EC_SIZE_COMPRESSED);

	memcpy(serialized_cl_ctx, serialized + EC_SIZE_COMPRESSED, CL_CIPHERTEXT_SIZE);
	lock->ctx_w->c1 = gp_read_str(serialized_cl_ctx);
	memzero(serialized_cl_ctx, CL_CIPHERTEXT_SIZE);

	memcpy(serialized_cl_ctx, serialized + EC_SIZE_COMPRESSED + CL_CIPHERTEXT_SIZE, CL_CIPHERTEXT_SIZE);
	lock->ctx_w->c2 = gp_read_str(serialized_cl_ctx);
	memzero(serialized_cl_ctx, CL_CIPHERTEXT_SIZE);

	memcpy(serialized_cl_ctx, serialized + EC_SIZE_COMPRESSED + (2 * CL_CIPHERTEXT_SIZE), CL_CIPHERTEXT_SIZE);
	lock->ctx_x->ctx_1->c1 = gp_read_str(serialized_cl_ctx);
	memzero(serialized_cl_ctx, CL_CIPHERTEXT_SIZE);

	memcpy(serialized_cl_ctx, serialized + EC_SIZE_COMPRESSED + (3 * CL_CIPHERTEXT_SIZE), CL_CIPHERTEXT_SIZE);
	lock->ctx_x->ctx_1->c2 = gp_read_str(serialized_cl_ctx);
	memzero(serialized_cl_ctx, CL_CIPHERTEXT_SIZE);

	memcpy(serialized_cl_ctx, serialized + EC_SIZE_COMPRESSED + (4 * CL_CIPHERTEXT_SIZE), CL_CIPHERTEXT_SIZE);
	lock->ctx_x->ctx_2->c1 = gp_read_str(serialized_cl_ctx);
	memzero(serialized_cl_ctx, CL_CIPHERTEXT_SIZE);

	memcpy(serialized_cl_ctx, serialized + EC_SIZE_COMPRESSED + (5 * CL_CIPHERTEXT_SIZE), CL_CIPHERTEXT_SIZE);
	lock->ctx_x->ctx_2->c2 = gp_read_str(serialized_cl_ctx);

	memcpy(&lock->id, serialized + EC_SIZE_COMPRESSED + (6 * CL_CIPHERTEXT_SIZE), sizeof(size_t));
}

void print_lock(const lock_t lock) {
	printf("Lock:\n");
	
	printf("ell: ");
	ec_print(lock->ell);
	
	printf("ctx_w->c1: "); 
	print(lock->ctx_w->c1);
	printf("ctx_w->c2: ");
	print(lock->ctx_w->c2);
	printf("ctx_x->ctx_1->c1: ");
	print(lock->ctx_x->ctx_1->c1);
	printf("ctx_x->ctx_1->c2: ");
	print(lock->ctx_x->ctx_1->c2);
	printf("ctx_x->ctx_2->c1: ");
	print(lock->ctx_x->ctx_2->c1);
	printf("ctx_x->ctx_2->c2: ");
	print(lock->ctx_x->ctx_2->c2);

	printf("id: %zu\n", lock->id);
}

int verify_lock(lock_t lock, bn_t k) {
	int result_status = RLC_ERR;

	ec_t h;
	ec_null(h);

	RLC_TRY {
		ec_new(h);

		ec_mul_gen(h, k);
		if (ec_cmp(h, lock->ell) == RLC_EQ) {
			result_status = RLC_OK;
		}
	} RLC_CATCH_ANY {
		result_status = RLC_ERR;
	} RLC_FINALLY {
		ec_free(h);
	}

	return result_status;
}

int unused_lock_condition(void *data) {
	lock_pair_t lock_pair = (lock_pair_t) data;
	if (lock_pair->right_address[0] == '\0') return 1;
	return 0;
}

int unused_next_hop_condition(void *data) {
	next_hop_t next_hop = (next_hop_t) data;
	if (next_hop->sent < next_hop->value) return 1;
	return 0;
}

int get_lock_by_hash_callback(void *data, void *value) {
	lock_pair_t lock_pair = (lock_pair_t) data;
	uint8_t *input_lock_hash = (uint8_t *) value;

	uint8_t right_lock_hash[RLC_MD_LEN];
	uint8_t serialized_lock[LOCK_SIZE];
	serialize_lock(serialized_lock, lock_pair->right_lock);
	md_map(right_lock_hash, serialized_lock, LOCK_SIZE);

	if (memcmp(right_lock_hash, input_lock_hash, RLC_MD_LEN) == 0) return 1;
	return 0;
}

int get_right_lock_by_id_callback(void *data, void *value) {
	lock_pair_t lock_pair = (lock_pair_t) data;
	size_t lock_id = (size_t) value;

	if (lock_pair->right_lock == NULL) return 0;

	if (lock_pair->right_lock->id == lock_id) return 1;
	return 0;
}

int get_left_lock_by_id_callback(void *data, void *value) {
	lock_pair_t lock_pair = (lock_pair_t) data;
	size_t lock_id = (size_t) value;

	if (lock_pair->left_lock == NULL) return 0;

	if (lock_pair->left_lock->id == lock_id) return 1;
	return 0;
}

void strreplace(char *target, const char *needle, const char *replacement) {
	char buffer[1024] = {0};
	char *insert_point = &buffer[0];
	const char *tmp = target;
	size_t needle_len = strlen(needle);
	size_t repl_len = strlen(replacement);

	while (1) {
		const char *p = strstr(tmp, needle);

		// walked past last occurrence of needle; copy remaining part
		if (p == NULL) {
			strcpy(insert_point, tmp);
			break;
		}

		// copy part before needle
		memcpy(insert_point, tmp, p - tmp);
		insert_point += p - tmp;

		// copy replacement string
		memcpy(insert_point, replacement, repl_len);
		insert_point += repl_len;

		// adjust pointers, move on
		tmp = p + needle_len;
	}

	// write altered string back to target
	strcpy(target, buffer);
}

int generate_cl_params(cl_params_t params) {
	int result_status = RLC_OK;

	RLC_TRY {
		if (params == NULL) {
			RLC_THROW(ERR_CAUGHT);
		}

		// Parameters generated using HSM.sage script.
		params->Delta_K = negi(strtoi("7917297328878683784842235952488620683924100338715963369693275768732162831834859052302716918416013031853265985178593375655994934704463023676296364363803257769443921988228513012040548137047446483986199954435962221122006965317176921759968659376932101987729556148116190707955808747136944623277094531007901655971804163515065712136708172984834192213773138039179492400722665370317221867505959207212674207052581946756527848674480328854830559945140752059719739492686061412113598389028096554833252668553020964851121112531561161799093718416247246137641387797659"));
		// Bound for exponentiation, for uniform sampling to be at 2^{-40} from the unifom in <g_q>.
    params->bound = strtoi("25413151665722220203610173826311975594790577398151861612310606875883990655261658217495681782816066858410439979225400605895077952191850577877370585295070770312182177789916520342292660169492395314400288273917787194656036294620169343699612953311314935485124063580486497538161801803224580096");

    GEN g_q_a = strtoi("4008431686288539256019978212352910132512184203702279780629385896624473051840259706993970111658701503889384191610389161437594619493081376284617693948914940268917628321033421857293703008209538182518138447355678944124861126384966287069011522892641935034510731734298233539616955610665280660839844718152071538201031396242932605390717004106131705164194877377");
    GEN g_q_b = negi(strtoi("3117991088204303366418764671444893060060110057237597977724832444027781815030207752301780903747954421114626007829980376204206959818582486516608623149988315386149565855935873517607629155593328578131723080853521348613293428202727746191856239174267496577422490575311784334114151776741040697808029563449966072264511544769861326483835581088191752567148165409"));
    GEN g_q_c = strtoi("7226982982667784284607340011220616424554394853592495056851825214613723615410492468400146084481943091452495677425649405002137153382700126963171182913281089395393193450415031434185562111748472716618186256410737780813669746598943110785615647848722934493732187571819575328802273312361412673162473673367423560300753412593868713829574117975260110889575205719");

		// Order of the secp256k1 elliptic curve group and the group G^q.
		params->q = strtoi("115792089237316195423570985008687907852837564279074904382605163141518161494337");
		params->g_q = qfi(g_q_a, g_q_b, g_q_c);

		GEN A = strtoi("0");
		GEN B = strtoi("7");
		GEN p = strtoi("115792089237316195423570985008687907853269984665640564039457584007908834671663");
		GEN coeff = mkvecn(2, A, B);
		params->E = ellinit(coeff, p, 1);

		GEN Gx = strtoi("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
		GEN Gy = strtoi("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
		params->G = mkvecn(2, Gx, Gy);
	} RLC_CATCH_ANY {
		result_status = RLC_ERR;
	}

	return result_status;
}

int cl_key_pair_generate(cl_key_pair_t key_pair, const cl_params_t params) {
	int result_status = RLC_OK;

	RLC_TRY {
		key_pair->sk = randomi(params->bound);
    key_pair->pk = nupow(params->g_q, key_pair->sk, NULL);
	} RLC_CATCH_ANY {
		result_status = RLC_ERR;
	}

	return result_status;
}

int cl_enc(cl_ciphertext_t ciphertext,
					 const GEN plaintext,
					 const GEN public_key,
					 const cl_params_t params) {
  int result_status = RLC_OK;

  RLC_TRY {
    GEN r = randomi(params->bound);
    ciphertext->c1 = nupow(params->g_q, r, NULL);

		GEN fm = gen_1;
		if (!equalii(plaintext, gen_0)) {
			GEN L = Fp_inv(plaintext, params->q);
			if (!mpodd(L)) {
				L = subii(L, params->q);
			}
			
			// f^plaintext = (q^2, Lq, (L - Delta_k) / 4)
    	fm = qfi(sqri(params->q), mulii(L, params->q), shifti(subii(sqri(L), params->Delta_K), -2));
		}

    ciphertext->c2 = gmul(nupow(public_key, r, NULL), fm);
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  }

  return result_status;
}

int cl_dec(GEN *plaintext,
					 const cl_ciphertext_t ciphertext,
					 const GEN secret_key,
					 const cl_params_t params) {
  int result_status = RLC_OK;

  RLC_TRY {
		// c2 * (c1^sk)^(-1)
    GEN fm = gmul(ciphertext->c2, ginv(nupow(ciphertext->c1, secret_key, NULL)));
		GEN Lq = gel(fm, 2);
		if (equalii(Lq, gen_1)) {
			*plaintext = gen_0;
		} else {
			GEN L = diviiexact(Lq, params->q);
    	*plaintext = Fp_inv(L, params->q);
		}
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  }

  return result_status;
}