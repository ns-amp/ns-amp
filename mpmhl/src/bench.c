#include <omp.h>
#include <stdio.h>
#include <string.h>
#include "pari/pari.h"
#include "relic/relic.h"
#include "cmdline.h"
#include "types.h"
#include "util.h"
#include "vector.h"

size_t MAX_THREAD;
size_t MAX_COUNT;
size_t BENCH_ITER;

int setup(vector_t locks,
          vector_t trapdoor_keys,
          const cl_params_t params,
          const size_t count,
          const size_t threads) {
  int result_status = RLC_OK;

  size_t numthread = (size_t) omp_get_num_procs();
  if (numthread > count) {
    numthread = count;
  }
  omp_set_num_threads(numthread);

  struct pari_thread pth[numthread];
  for (size_t i = 0; i < numthread; i++) {
    pari_thread_alloc(&pth[i], 100000000, NULL);
  }
  
  bn_t y, q, trapdoor;
  bn_t xis[count];
  bn_t ris[count];

  bn_null(y);
  bn_null(q);
  bn_null(trapdoor);
  for (size_t i = 0; i < count; i++) {
    bn_null(xis[i]);
    bn_null(ris[i]);
  }

  RLC_TRY {
    bn_new(y);
    bn_new(q);
    bn_new(trapdoor);
    for (size_t i = 0; i < count; i++) {
      bn_new(xis[i]);
      bn_new(ris[i]);
    }

    ep_curve_get_ord(q);
    bn_set_dig(trapdoor, 0);

    #pragma omp parallel //shared(trapdoor)
    {
      int thnum = omp_get_thread_num();
      if (thnum) {
        (void) pari_thread_start(&pth[thnum]);
      }

      vector_t trapdoor_keys_private = vector_init(count / numthread);
      vector_t locks_private = vector_init(count / numthread);

      #pragma omp for schedule(static)
      for (size_t i = 0; i < count; i++) {
        bn_rand_mod(ris[i], q);
        bn_rand_mod(xis[i], q);

        cl_key_pair_t key_pair_i;
        cl_key_pair_null(key_pair_i);
        cl_key_pair_new(key_pair_i);

        key_pair_i->sk = randomi(params->bound);
        key_pair_i->pk = nupow(params->g_q, key_pair_i->sk, NULL);
        vector_add(trapdoor_keys_private, key_pair_i);

        lock_pair_t lock_pair_i;
        lock_pair_null(lock_pair_i);
        lock_pair_new(lock_pair_i);

        const unsigned xi_str_len = bn_size_str(xis[i], 10);
        char xi_str[xi_str_len];
        bn_write_str(xi_str, xi_str_len, xis[i], 10);
        GEN plain_xi = strtoi(xi_str);

        if (cl_enc(lock_pair_i->right_lock->ctx_x->ctx_1, plain_xi, key_pair_i->pk, params) != RLC_OK) {
          RLC_THROW(ERR_CAUGHT);
        }

        if (cl_enc(lock_pair_i->right_lock->ctx_x->ctx_2, gen_0, key_pair_i->pk, params) != RLC_OK) {
          RLC_THROW(ERR_CAUGHT);
        }

        const unsigned ri_str_len = bn_size_str(ris[i], 10);
        char ri_str[ri_str_len];
        bn_write_str(ri_str, ri_str_len, ris[i], 10);
        GEN plain_ri = strtoi(ri_str);

        if (cl_enc(lock_pair_i->right_lock->ctx_w, plain_ri, key_pair_i->pk, params) != RLC_OK) {
          RLC_THROW(ERR_CAUGHT);
        }

        lock_pair_i->right_lock->id = i;
        vector_add(locks_private, lock_pair_i);
      }

      #pragma omp single
      for (size_t i = 0; i < count; i++) {
        bn_add(trapdoor, trapdoor, xis[i]);
        bn_mod(trapdoor, trapdoor, q);
      }

      #pragma omp for ordered
      for (size_t i = 0; i < numthread; i++) {
        #pragma omp ordered
        {
          vector_copy(locks, locks_private);
          vector_copy(trapdoor_keys, trapdoor_keys_private);
        }
      }

      #pragma omp for schedule(static) private(y)
      for (size_t i = 0; i < count; i++) {
        bn_mul(y, trapdoor, ris[i]);
        bn_mod(y, y, q);

        lock_pair_t lock_pair = (lock_pair_t) vector_get(locks, i);
        ec_mul_gen(lock_pair->right_lock->ell, y);
      }

      if (thnum) {
        pari_thread_close();
      }
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(y);
    bn_free(q);
    bn_free(trapdoor);
    for (size_t i = 0; i < count; i++) {
      bn_free(xis[i]);
      bn_free(ris[i]);
    }
  }

  return result_status;
}

int lock(vector_t locks, const cl_params_t params, const size_t threads) {
  int result_status = RLC_OK;

  size_t numthread = (size_t) omp_get_num_procs();
  size_t count = (size_t) vector_size(locks);
  if (numthread > count) {
    numthread = count;
  }
  omp_set_num_threads(numthread);

  struct pari_thread pth[numthread];
  for (size_t i = 0; i < numthread; i++) {
    pari_thread_alloc(&pth[i], 100000000, NULL);
  }

  bn_t q;
  bn_null(q);

  RLC_TRY {
    bn_new(q);
    ec_curve_get_ord(q);

    #pragma omp parallel //shared(locks)
    {
      int thnum = omp_get_thread_num();
      if (thnum) {
        (void) pari_thread_start(&pth[thnum]);
      }

      #pragma omp for schedule(static)
      for (size_t i = 0; i < count; i++) {
        lock_pair_t lock_pair = (lock_pair_t) vector_get(locks, i);
        lock_t lock = lock_pair->right_lock;

        bn_rand_mod(lock_pair->witness, q);
        ec_mul(lock->ell, lock->ell, lock_pair->witness);

        const unsigned w_str_len = bn_size_str(lock_pair->witness, 10);
        char w_str[w_str_len];
        bn_write_str(w_str, w_str_len, lock_pair->witness, 10);
        GEN plain_w = strtoi(w_str);

        lock->ctx_w->c1 = nupow(lock->ctx_w->c1, plain_w, NULL);
        lock->ctx_w->c2 = nupow(lock->ctx_w->c2, plain_w, NULL);

        GEN r_1 = randomi(params->bound);
        GEN r_2 = randomi(params->bound);

        GEN ctx_c1_r1 = nupow(lock->ctx_x->ctx_2->c1, r_1, NULL);
        GEN ctx_c2_r1 = nupow(lock->ctx_x->ctx_2->c2, r_1, NULL);
        lock->ctx_x->ctx_1->c1 = gmul(lock->ctx_x->ctx_1->c1, ctx_c1_r1);
        lock->ctx_x->ctx_1->c2 = gmul(lock->ctx_x->ctx_1->c2, ctx_c2_r1);

        lock->ctx_x->ctx_2->c1 = nupow(lock->ctx_x->ctx_2->c1, r_2, NULL);
        lock->ctx_x->ctx_2->c2 = nupow(lock->ctx_x->ctx_2->c2, r_2, NULL);
      }

      if (thnum) {
        pari_thread_close();
      }
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
  }

  return result_status;
}

int extract(vector_t keys,
            const vector_t locks,
            const vector_t trapdoor_keys,
            const cl_params_t params,
            const size_t threads) {
  int result_status = RLC_OK;

  size_t numthread = (size_t) omp_get_num_procs();
  size_t count = (size_t) vector_size(locks);
  if (numthread > count) {
    numthread = count;
  }
  omp_set_num_threads(numthread);

  struct pari_thread pth[numthread];
  for (size_t i = 0; i < numthread; i++) {
    pari_thread_alloc(&pth[i], 100000000, NULL);
  }

  bn_t x, q, w_star;
  bn_t trapdoor;
  bn_t xis[count];

  bn_null(x);
  bn_null(q);
  bn_null(w_star);
  bn_null(trapdoor);
  for (size_t i = 0; i < count; i++) {
    bn_null(xis[i]);
  }

  RLC_TRY {
    bn_new(x);
    bn_new(q);
    bn_new(w_star);
    bn_new(trapdoor);
    for (size_t i = 0; i < count; i++) {
      bn_new(xis[i]);
    }

    ec_curve_get_ord(q);
    bn_set_dig(trapdoor, 0);

    #pragma omp parallel //shared(trapdoor)
    {
      int thnum = omp_get_thread_num();
      if (thnum) {
        (void) pari_thread_start(&pth[thnum]);
      }

      vector_t keys_private = vector_init(count / numthread);

      #pragma omp for schedule(static)
      for (size_t i = 0; i < count; i++) {
        lock_pair_t lock_pair = (lock_pair_t) vector_get(locks, i);
        lock_t lock = lock_pair->right_lock;
        cl_key_pair_t key_pair = (cl_key_pair_t) vector_get(trapdoor_keys, lock->id);

        GEN xi;
        if (cl_dec(&xi, lock->ctx_x->ctx_1, key_pair->sk, params) != RLC_OK) {
          RLC_THROW(ERR_CAUGHT);
        }
        bn_read_str(xis[i], GENtostr(xi), strlen(GENtostr(xi)), 10);
      }

      #pragma omp single
      for (size_t i = 0; i < count; i++) {
        bn_add(trapdoor, trapdoor, xis[i]);
        bn_mod(trapdoor, trapdoor, q);
      }

      #pragma omp for schedule(static)
      for (size_t i = 0; i < vector_size(locks); i++) {
        lock_pair_t lock_pair = (lock_pair_t) vector_get(locks, i);
        lock_t lock = lock_pair->right_lock;
        cl_key_pair_t key_pair = (cl_key_pair_t) vector_get(trapdoor_keys, lock->id);

        GEN wi;
        if (cl_dec(&wi, lock->ctx_w, key_pair->sk, params) != RLC_OK) {
          RLC_THROW(ERR_CAUGHT);
        }
        bn_read_str(w_star, GENtostr(wi), strlen(GENtostr(wi)), 10);

        wbn_t k;
        wbn_null(k);
        wbn_new(k);

        bn_mul(k->bn, trapdoor, w_star);
        bn_mod(k->bn, k->bn, q);
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
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(x);
    bn_free(q);
    bn_free(w_star);
    bn_free(trapdoor);
    for (size_t i = 0; i < count; i++) {
      bn_free(xis[i]);
    }
  }

  return result_status;
}

int release(vector_t keys, vector_t locks) {
  int result_status = RLC_OK;

  bn_t x, q, witness_inverse;
  bn_null(x);
  bn_null(q);
  bn_null(witness_inverse);

  RLC_TRY {
    bn_new(x);
    bn_new(q);
    bn_new(witness_inverse);

    ec_curve_get_ord(q);

    for (size_t i = 0; i < vector_size(locks); i++) {
      lock_pair_t lock_pair = (lock_pair_t) vector_get(locks, i);
      lock_t lock = lock_pair->right_lock;
      wbn_t k = (wbn_t) vector_get(keys, i);

      bn_gcd_ext(x, witness_inverse, NULL, lock_pair->witness, q);
      if (bn_sign(witness_inverse) == RLC_NEG) {
        bn_add(witness_inverse, witness_inverse, q);
      }

      bn_mul(k->bn, k->bn, witness_inverse);
      bn_mod(k->bn, k->bn, q);
      ec_mul(lock->ell, lock->ell, witness_inverse);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(x);
    bn_free(q);
    bn_free(witness_inverse);
  }

  return result_status;
}

int verify(const vector_t locks, const vector_t keys) {
  int result_status = RLC_ERR;

  ec_t h;
  ec_null(h);

  RLC_TRY {
    ec_new(h);

    for (size_t i = 0; i < vector_size(locks); i++) {
      lock_pair_t lock_pair = (lock_pair_t) vector_get(locks, i);
      lock_t lock = lock_pair->right_lock;
      wbn_t k = (wbn_t) vector_get(keys, i);

      ec_mul_gen(h, k->bn);
      if (ec_cmp(h, lock->ell) == RLC_EQ) {
        result_status = RLC_OK;
      }
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    ec_free(h);
  }

  return result_status;
}

int main(int argc, char *argv[]) {
  struct gengetopt_args_info argsinfo;
  if (cmdline_parser(argc, argv, &argsinfo) != 0) {
    exit(1);
  }

  if (strncmp(argsinfo.mode_arg, "lock", 5) != 0
  &&  strncmp(argsinfo.mode_arg, "thread", 7) != 0) {
    fprintf(stderr, "Error: invalid value for mode.\n");
    cmdline_parser_print_help();
  }

  MAX_COUNT = (size_t) argsinfo.lock_arg;
  MAX_THREAD = (size_t) argsinfo.thread_arg;
  BENCH_ITER = (size_t) argsinfo.iter_arg;

  size_t start_thread_loop;
  size_t start_lock_loop;
  if (strncmp(argsinfo.mode_arg, "lock", 5) == 0) {
    start_lock_loop = 1;
    start_thread_loop = MAX_THREAD;
  } else {
    start_lock_loop = MAX_COUNT;
    start_thread_loop = 1;
  }

  char filename[25];
  snprintf(filename, 25, "bench_%s_l%zu_t%zu.csv", argsinfo.mode_arg, MAX_COUNT, MAX_THREAD);
  FILE *fptr = fopen(filename, "w");
  fprintf(fptr, "n,setup,lock,release,extract,verify\n");

  init();
  int result_status = RLC_OK;

  uint64_t start_time, stop_time;
  double setup_time, lock_time, release_time;
  double extract_time, verify_time;

  cl_params_t params;
  cl_params_null(params);

  RLC_TRY {
    cl_params_new(params);

    if (generate_cl_params(params) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

    for (size_t t = start_thread_loop; t <= MAX_THREAD; t *= 2) {
      for (size_t i = start_lock_loop; i <= MAX_COUNT; i++) {
        setup_time = 0;
        lock_time = 0;
        release_time = 0;
        extract_time = 0;
        verify_time = 0;

        for (size_t j = 0; j < BENCH_ITER; j++) {
          vector_t locks = vector_init(i);
          vector_t trapdoor_keys = vector_init(i);
          vector_t keys = vector_init(i);

          start_time = mtimer();
          if (setup(locks, trapdoor_keys, params, i, t) != RLC_OK) {
            RLC_THROW(ERR_CAUGHT);
          }
          stop_time = mtimer();
          setup_time += ((stop_time - start_time) / CLOCK_PRECISION);

          start_time = mtimer();
          if (lock(locks, params, t) != RLC_OK) {
            RLC_THROW(ERR_CAUGHT);
          }
          stop_time = mtimer();
          lock_time += ((stop_time - start_time) / CLOCK_PRECISION);

          start_time = mtimer();
          if (extract(keys, locks, trapdoor_keys, params, t) != RLC_OK) {
            RLC_THROW(ERR_CAUGHT);
          }
          stop_time = mtimer();
          extract_time += ((stop_time - start_time) / CLOCK_PRECISION);

          start_time = mtimer();
          if (release(keys, locks) != RLC_OK) {
            RLC_THROW(ERR_CAUGHT);
          }
          stop_time = mtimer();
          release_time += ((stop_time - start_time) / CLOCK_PRECISION);

          start_time = mtimer();
          if (verify(locks, keys) != RLC_OK) {
            RLC_THROW(ERR_CAUGHT);
          }
          stop_time = mtimer();
          verify_time += ((stop_time - start_time) / CLOCK_PRECISION);

          vector_free(locks);
          vector_free(trapdoor_keys);
          vector_free(keys);
        }

        printf("==== COUNT: %2zu, THREAD: %2zu ====\n", i, t);
        printf("setup  : %12.5lf ms\n", (setup_time / BENCH_ITER) * 1000);
        printf("lock   : %12.5lf ms\n", (lock_time / BENCH_ITER) * 1000);
        printf("release: %12.5lf ms\n", (release_time / BENCH_ITER) * 1000);
        printf("extract: %12.5lf ms\n", (extract_time / BENCH_ITER) * 1000);
        printf("verify : %12.5lf ms\n", (verify_time / BENCH_ITER) * 1000);
        printf("===============================\n\n");

        fprintf(fptr, "%zu,%lf,%lf,%lf,%lf,%lf\n", strncmp(argsinfo.mode_arg, "lock", 5) == 0 ? i : t, 
              (setup_time / BENCH_ITER) * 1000, (lock_time / BENCH_ITER) * 1000, (release_time / BENCH_ITER) * 1000,
              (extract_time / BENCH_ITER) * 1000, (verify_time / BENCH_ITER) * 1000);
      }
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    cl_params_free(params);
  }

  fclose(fptr);
  clean();
  return result_status;
}