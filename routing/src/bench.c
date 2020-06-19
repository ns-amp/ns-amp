#include <stdio.h>
#include "relic/relic.h"
#include "types.h"
#include "util.h"
#include "vector.h"

unsigned MAX_NEIGHBORS = 5;
unsigned MAX_LENGTH    = 50;
unsigned BENCH_ITER    = 100;

int join_route(vector_t coords) {
  int result_status = RLC_OK;

  bn_t q;
  bn_null(q);

  RLC_TRY {
    bn_new(q);
    ec_curve_get_ord(q);

    wbn_t rho;
    wbn_null(rho);
    wbn_new(rho);
    bn_rand_mod(rho->bn, q);

    vector_add(coords, rho);
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
  }

  return result_status;
}

int init_route(vector_t rand_coords, const vector_t coords) {
  int result_status = RLC_OK;

  bn_t q, zeta;
  bn_null(q);
  bn_null(zeta);

  RLC_TRY {
    bn_new(q);
    bn_new(zeta);

    ec_curve_get_ord(q);
    bn_rand_mod(zeta, q);

    wbn_t rho_0 = (wbn_t) vector_get(coords, 0);
    wec_t rho_star_0;
    wec_null(rho_star_0);
    wec_new(rho_star_0);
    
    ec_mul_gen(rho_star_0->ec, rho_0->bn);
    ec_mul(rho_star_0->ec, rho_star_0->ec, zeta);
    vector_add(rand_coords, rho_star_0);

    for (size_t i = 1; i < vector_size(coords); i++) {
      wbn_t rho_i = (wbn_t) vector_get(coords, i);
      wec_t rho_star_i_minus_1 = (wec_t) vector_get(rand_coords, i-1);

      wec_t rho_star_i;
      wec_null(rho_star_i);
      wec_new(rho_star_i);
      wec_copy(rho_star_i, rho_star_i_minus_1);

      ec_mul(rho_star_i->ec, rho_star_i->ec, rho_i->bn);
      vector_add(rand_coords, rho_star_i);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
    bn_free(zeta);
  }

  return result_status;
}

int route_check(vector_t rand_coords, const vector_t identifiers) {
  int result_status = RLC_OK;

  bn_t q;
  ec_t tmp_coord;

  bn_null(q);
  ec_null(tmp_coord);

  RLC_TRY {
    bn_new(q);
    ec_new(tmp_coord);

    for (size_t j = 0; j < vector_size(identifiers); j++) {
      vector_t vec_rho_i = (vector_t) vector_get(identifiers, j);
      unsigned count = MIN(vector_size(rand_coords), vector_size(vec_rho_i));

      for (size_t i = 1; i < count; i++) {
        wbn_t rho_i_j = (wbn_t) vector_get(vec_rho_i, i);
        wec_t rho_star_i_minus_i = (wec_t) vector_get(rand_coords, i-1);
        wec_t rho_star_i = (wec_t) vector_get(rand_coords, i);

        ec_mul(tmp_coord, rho_star_i_minus_i->ec, rho_i_j->bn);
        if (ec_cmp(tmp_coord, rho_star_i->ec) == RLC_EQ) {
          continue;
        }
      }
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
    ec_free(tmp_coord);
  }

  return result_status;
}

int route_rand(vector_t rand_coords) {
  int result_status = RLC_OK;

  bn_t q, zeta_star;

  bn_null(q);
  bn_null(zeta_star);

  RLC_TRY {
    bn_new(q);
    bn_new(zeta_star);

    ec_curve_get_ord(q);
    bn_rand_mod(zeta_star, q);

    for (size_t i = 0; i < vector_size(rand_coords); i++) {
      wec_t rho_star_i = (wec_t) vector_get(rand_coords, i);
      ec_mul(rho_star_i->ec, rho_star_i->ec, zeta_star);
      vector_set(rand_coords, i, rho_star_i);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
    bn_free(zeta_star);
  }

  return result_status;
}

int route_full(vector_t rand_coords, const vector_t identifiers) {
  int result_status = RLC_OK;

  size_t t = 0;

  bn_t q, zeta_star;
  ec_t tmp_coord;

  bn_null(q);
  bn_null(zeta_star);
  ec_null(tmp_coord);

  RLC_TRY {
    bn_new(q);
    bn_new(zeta_star);
    ec_new(tmp_coord);

    for (size_t j = 0; j < vector_size(identifiers); j++) {
      vector_t vec_rho_i = (vector_t) vector_get(identifiers, j);
      unsigned count = MIN(vector_size(rand_coords), vector_size(vec_rho_i));

      for (size_t i = 1; i < count; i++) {
        wbn_t rho_i_j = (wbn_t) vector_get(vec_rho_i, i);
        wec_t rho_star_i_minus_i = (wec_t) vector_get(rand_coords, i-1);
        wec_t rho_star_i = (wec_t) vector_get(rand_coords, i);

        ec_mul(tmp_coord, rho_star_i_minus_i->ec, rho_i_j->bn);
        if (ec_cmp(tmp_coord, rho_star_i->ec) == RLC_EQ && t < i) {
          t = i;
        }
      }
    }

    if (t != 0) {
      ec_curve_get_ord(q);
      bn_rand_mod(zeta_star, q);

      for (size_t i = 0; i < vector_size(rand_coords); i++) {
        wec_t rho_star_i = (wec_t) vector_get(rand_coords, i);
        ec_mul(rho_star_i->ec, rho_star_i->ec, zeta_star);
        vector_set(rand_coords, i, rho_star_i);
      }
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
    bn_free(zeta_star);
    ec_free(tmp_coord);
  }

  return result_status;
}

int main(void) {
  init();
  int result_status = RLC_OK;

  uint64_t start_time, stop_time;
  double join_time, init_time, route_time;
  //double route_check_time, route_rand_time;

  FILE *fptr = fopen("bench.csv", "w");
  fprintf(fptr, "n,join,init,route\n");

  bn_t q;
  bn_null(q);

  RLC_TRY {
    bn_new(q);
    ec_curve_get_ord(q);

    for (size_t i = 1; i <= MAX_LENGTH; i++) {
      join_time = 0;
      init_time = 0;
      route_time = 0;

      for (size_t k = 0; k < BENCH_ITER; k++) {
        vector_t coords = vector_init(i+1);
        vector_t rand_coords = vector_init(i+1);
        vector_t identifiers = vector_init(i+1);
        
        for (size_t j = 0; j < i; j++) {
          wbn_t rho_j;
          wbn_null(rho_j);
          wbn_new(rho_j);

          bn_rand_mod(rho_j->bn, q);
          vector_add(coords, rho_j);
        }

        start_time = mtimer();
        if (join_route(coords) != RLC_OK) {
          RLC_THROW(ERR_CAUGHT);
        }
        stop_time = mtimer();
        join_time += ((stop_time - start_time) / CLOCK_PRECISION);
        
        start_time = mtimer();
        if (init_route(rand_coords, coords) != RLC_OK) {
          RLC_THROW(ERR_CAUGHT);
        }
        stop_time = mtimer();
        init_time += ((stop_time - start_time) / CLOCK_PRECISION);

        for (size_t t = 0; t < MAX_NEIGHBORS; t++) {
          vector_t id = vector_init(vector_size(coords));
          vector_copy(id, coords);
          vector_add(identifiers, id);
        }

        // start_time = mtimer();
        // if (route_check(rand_coords, identifiers) != RLC_OK) {
        //   RLC_THROW(ERR_CAUGHT);
        // }
        // stop_time = mtimer();
        // route_check_time += ((stop_time - start_time) / CLOCK_PRECISION);

        // start_time = mtimer();
        // if (route_rand(rand_coords) != RLC_OK) {
        //   RLC_THROW(ERR_CAUGHT);
        // }
        // stop_time = mtimer();
        // route_rand_time += ((stop_time - start_time) / CLOCK_PRECISION);
        start_time = mtimer();
        if (route_full(rand_coords, identifiers) != RLC_OK) {
          RLC_THROW(ERR_CAUGHT);
        }
        stop_time = mtimer();
        route_time += ((stop_time - start_time) / CLOCK_PRECISION);

        for (size_t t = 0; t < MAX_NEIGHBORS; t++) {
          vector_t id_i = (vector_t) vector_get(identifiers, t);
          vector_free(id_i);
        }
        vector_free(identifiers);
        vector_free(rand_coords);
        vector_free(coords);
      }

      printf("==== LENGTH: %2zu ========\n", i);
      printf("join_route: %9.5lf ms\n", (join_time / BENCH_ITER) * 1000);
      printf("init_route: %9.5lf ms\n", (init_time / BENCH_ITER) * 1000);
      printf("route     : %9.5lf ms\n", (route_time / BENCH_ITER) * 1000);
      // printf("route_check: %9.5lf ms\n", (route_check_time / BENCH_ITER) * 1000);
      // printf("route_rand : %9.5lf ms\n", (route_rand_time / BENCH_ITER) * 1000);
      printf("========================\n\n");

      fprintf(fptr, "%zu,%lf,%lf,%lf\n", i+1, (join_time / BENCH_ITER) * 1000, 
             (init_time / BENCH_ITER) * 1000, (route_time / BENCH_ITER) * 1000);
    }
  } RLC_CATCH_ANY {
    result_status = RLC_ERR;
  } RLC_FINALLY {
    bn_free(q);
  }

  fclose(fptr);
  clean();
  return result_status;
}