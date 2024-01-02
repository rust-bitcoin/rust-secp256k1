/***********************************************************************
 * Copyright (c) 2016 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifndef EXHAUSTIVE_TEST_ORDER
/* see group_impl.h for allowable values */
#define EXHAUSTIVE_TEST_ORDER 13
#endif

/* These values of B are all values in [1, 8] that result in a curve with even order. */
#define EXHAUSTIVE_TEST_CURVE_HAS_EVEN_ORDER (SECP256K1_B == 1 || SECP256K1_B == 6 || SECP256K1_B == 8)

#ifdef USE_EXTERNAL_DEFAULT_CALLBACKS
    #pragma message("Ignoring USE_EXTERNAL_CALLBACKS in exhaustive_tests.")
    #undef USE_EXTERNAL_DEFAULT_CALLBACKS
#endif
#include "secp256k1.c"

#include "../include/secp256k1.h"
#include "assumptions.h"
#include "group.h"
#include "testrand_impl.h"
#include "ecmult_compute_table_impl.h"
#include "ecmult_gen_compute_table_impl.h"
#include "util.h"

static int count = 2;

/** stolen from tests.c */
static void ge_equals_ge(const rustsecp256k1_v0_9_2_ge *a, const rustsecp256k1_v0_9_2_ge *b) {
    CHECK(a->infinity == b->infinity);
    if (a->infinity) {
        return;
    }
    CHECK(rustsecp256k1_v0_9_2_fe_equal(&a->x, &b->x));
    CHECK(rustsecp256k1_v0_9_2_fe_equal(&a->y, &b->y));
}

static void ge_equals_gej(const rustsecp256k1_v0_9_2_ge *a, const rustsecp256k1_v0_9_2_gej *b) {
    rustsecp256k1_v0_9_2_fe z2s;
    rustsecp256k1_v0_9_2_fe u1, u2, s1, s2;
    CHECK(a->infinity == b->infinity);
    if (a->infinity) {
        return;
    }
    /* Check a.x * b.z^2 == b.x && a.y * b.z^3 == b.y, to avoid inverses. */
    rustsecp256k1_v0_9_2_fe_sqr(&z2s, &b->z);
    rustsecp256k1_v0_9_2_fe_mul(&u1, &a->x, &z2s);
    u2 = b->x;
    rustsecp256k1_v0_9_2_fe_mul(&s1, &a->y, &z2s); rustsecp256k1_v0_9_2_fe_mul(&s1, &s1, &b->z);
    s2 = b->y;
    CHECK(rustsecp256k1_v0_9_2_fe_equal(&u1, &u2));
    CHECK(rustsecp256k1_v0_9_2_fe_equal(&s1, &s2));
}

static void random_fe(rustsecp256k1_v0_9_2_fe *x) {
    unsigned char bin[32];
    do {
        rustsecp256k1_v0_9_2_testrand256(bin);
        if (rustsecp256k1_v0_9_2_fe_set_b32_limit(x, bin)) {
            return;
        }
    } while(1);
}

static void random_fe_non_zero(rustsecp256k1_v0_9_2_fe *nz) {
    int tries = 10;
    while (--tries >= 0) {
        random_fe(nz);
        rustsecp256k1_v0_9_2_fe_normalize(nz);
        if (!rustsecp256k1_v0_9_2_fe_is_zero(nz)) {
            break;
        }
    }
    /* Infinitesimal probability of spurious failure here */
    CHECK(tries >= 0);
}
/** END stolen from tests.c */

static uint32_t num_cores = 1;
static uint32_t this_core = 0;

SECP256K1_INLINE static int skip_section(uint64_t* iter) {
    if (num_cores == 1) return 0;
    *iter += 0xe7037ed1a0b428dbULL;
    return ((((uint32_t)*iter ^ (*iter >> 32)) * num_cores) >> 32) != this_core;
}

static int rustsecp256k1_v0_9_2_nonce_function_smallint(unsigned char *nonce32, const unsigned char *msg32,
                                      const unsigned char *key32, const unsigned char *algo16,
                                      void *data, unsigned int attempt) {
    rustsecp256k1_v0_9_2_scalar s;
    int *idata = data;
    (void)msg32;
    (void)key32;
    (void)algo16;
    /* Some nonces cannot be used because they'd cause s and/or r to be zero.
     * The signing function has retry logic here that just re-calls the nonce
     * function with an increased `attempt`. So if attempt > 0 this means we
     * need to change the nonce to avoid an infinite loop. */
    if (attempt > 0) {
        *idata = (*idata + 1) % EXHAUSTIVE_TEST_ORDER;
    }
    rustsecp256k1_v0_9_2_scalar_set_int(&s, *idata);
    rustsecp256k1_v0_9_2_scalar_get_b32(nonce32, &s);
    return 1;
}

static void test_exhaustive_endomorphism(const rustsecp256k1_v0_9_2_ge *group) {
    int i;
    for (i = 0; i < EXHAUSTIVE_TEST_ORDER; i++) {
        rustsecp256k1_v0_9_2_ge res;
        rustsecp256k1_v0_9_2_ge_mul_lambda(&res, &group[i]);
        ge_equals_ge(&group[i * EXHAUSTIVE_TEST_LAMBDA % EXHAUSTIVE_TEST_ORDER], &res);
    }
}

static void test_exhaustive_addition(const rustsecp256k1_v0_9_2_ge *group, const rustsecp256k1_v0_9_2_gej *groupj) {
    int i, j;
    uint64_t iter = 0;

    /* Sanity-check (and check infinity functions) */
    CHECK(rustsecp256k1_v0_9_2_ge_is_infinity(&group[0]));
    CHECK(rustsecp256k1_v0_9_2_gej_is_infinity(&groupj[0]));
    for (i = 1; i < EXHAUSTIVE_TEST_ORDER; i++) {
        CHECK(!rustsecp256k1_v0_9_2_ge_is_infinity(&group[i]));
        CHECK(!rustsecp256k1_v0_9_2_gej_is_infinity(&groupj[i]));
    }

    /* Check all addition formulae */
    for (j = 0; j < EXHAUSTIVE_TEST_ORDER; j++) {
        rustsecp256k1_v0_9_2_fe fe_inv;
        if (skip_section(&iter)) continue;
        rustsecp256k1_v0_9_2_fe_inv(&fe_inv, &groupj[j].z);
        for (i = 0; i < EXHAUSTIVE_TEST_ORDER; i++) {
            rustsecp256k1_v0_9_2_ge zless_gej;
            rustsecp256k1_v0_9_2_gej tmp;
            /* add_var */
            rustsecp256k1_v0_9_2_gej_add_var(&tmp, &groupj[i], &groupj[j], NULL);
            ge_equals_gej(&group[(i + j) % EXHAUSTIVE_TEST_ORDER], &tmp);
            /* add_ge */
            if (j > 0) {
                rustsecp256k1_v0_9_2_gej_add_ge(&tmp, &groupj[i], &group[j]);
                ge_equals_gej(&group[(i + j) % EXHAUSTIVE_TEST_ORDER], &tmp);
            }
            /* add_ge_var */
            rustsecp256k1_v0_9_2_gej_add_ge_var(&tmp, &groupj[i], &group[j], NULL);
            ge_equals_gej(&group[(i + j) % EXHAUSTIVE_TEST_ORDER], &tmp);
            /* add_zinv_var */
            zless_gej.infinity = groupj[j].infinity;
            zless_gej.x = groupj[j].x;
            zless_gej.y = groupj[j].y;
            rustsecp256k1_v0_9_2_gej_add_zinv_var(&tmp, &groupj[i], &zless_gej, &fe_inv);
            ge_equals_gej(&group[(i + j) % EXHAUSTIVE_TEST_ORDER], &tmp);
        }
    }

    /* Check doubling */
    for (i = 0; i < EXHAUSTIVE_TEST_ORDER; i++) {
        rustsecp256k1_v0_9_2_gej tmp;
        rustsecp256k1_v0_9_2_gej_double(&tmp, &groupj[i]);
        ge_equals_gej(&group[(2 * i) % EXHAUSTIVE_TEST_ORDER], &tmp);
        rustsecp256k1_v0_9_2_gej_double_var(&tmp, &groupj[i], NULL);
        ge_equals_gej(&group[(2 * i) % EXHAUSTIVE_TEST_ORDER], &tmp);
    }

    /* Check negation */
    for (i = 1; i < EXHAUSTIVE_TEST_ORDER; i++) {
        rustsecp256k1_v0_9_2_ge tmp;
        rustsecp256k1_v0_9_2_gej tmpj;
        rustsecp256k1_v0_9_2_ge_neg(&tmp, &group[i]);
        ge_equals_ge(&group[EXHAUSTIVE_TEST_ORDER - i], &tmp);
        rustsecp256k1_v0_9_2_gej_neg(&tmpj, &groupj[i]);
        ge_equals_gej(&group[EXHAUSTIVE_TEST_ORDER - i], &tmpj);
    }
}

static void test_exhaustive_ecmult(const rustsecp256k1_v0_9_2_ge *group, const rustsecp256k1_v0_9_2_gej *groupj) {
    int i, j, r_log;
    uint64_t iter = 0;
    for (r_log = 1; r_log < EXHAUSTIVE_TEST_ORDER; r_log++) {
        for (j = 0; j < EXHAUSTIVE_TEST_ORDER; j++) {
            if (skip_section(&iter)) continue;
            for (i = 0; i < EXHAUSTIVE_TEST_ORDER; i++) {
                rustsecp256k1_v0_9_2_gej tmp;
                rustsecp256k1_v0_9_2_scalar na, ng;
                rustsecp256k1_v0_9_2_scalar_set_int(&na, i);
                rustsecp256k1_v0_9_2_scalar_set_int(&ng, j);

                rustsecp256k1_v0_9_2_ecmult(&tmp, &groupj[r_log], &na, &ng);
                ge_equals_gej(&group[(i * r_log + j) % EXHAUSTIVE_TEST_ORDER], &tmp);

            }
        }
    }

    for (j = 0; j < EXHAUSTIVE_TEST_ORDER; j++) {
        for (i = 0; i < EXHAUSTIVE_TEST_ORDER; i++) {
            int ret;
            rustsecp256k1_v0_9_2_gej tmp;
            rustsecp256k1_v0_9_2_fe xn, xd, tmpf;
            rustsecp256k1_v0_9_2_scalar ng;

            if (skip_section(&iter)) continue;

            rustsecp256k1_v0_9_2_scalar_set_int(&ng, j);

            /* Test rustsecp256k1_v0_9_2_ecmult_const. */
            rustsecp256k1_v0_9_2_ecmult_const(&tmp, &group[i], &ng);
            ge_equals_gej(&group[(i * j) % EXHAUSTIVE_TEST_ORDER], &tmp);

            if (i != 0 && j != 0) {
                /* Test rustsecp256k1_v0_9_2_ecmult_const_xonly with all curve X coordinates, and xd=NULL. */
                ret = rustsecp256k1_v0_9_2_ecmult_const_xonly(&tmpf, &group[i].x, NULL, &ng, 0);
                CHECK(ret);
                CHECK(rustsecp256k1_v0_9_2_fe_equal(&tmpf, &group[(i * j) % EXHAUSTIVE_TEST_ORDER].x));

                /* Test rustsecp256k1_v0_9_2_ecmult_const_xonly with all curve X coordinates, with random xd. */
                random_fe_non_zero(&xd);
                rustsecp256k1_v0_9_2_fe_mul(&xn, &xd, &group[i].x);
                ret = rustsecp256k1_v0_9_2_ecmult_const_xonly(&tmpf, &xn, &xd, &ng, 0);
                CHECK(ret);
                CHECK(rustsecp256k1_v0_9_2_fe_equal(&tmpf, &group[(i * j) % EXHAUSTIVE_TEST_ORDER].x));
            }
        }
    }
}

typedef struct {
    rustsecp256k1_v0_9_2_scalar sc[2];
    rustsecp256k1_v0_9_2_ge pt[2];
} ecmult_multi_data;

static int ecmult_multi_callback(rustsecp256k1_v0_9_2_scalar *sc, rustsecp256k1_v0_9_2_ge *pt, size_t idx, void *cbdata) {
    ecmult_multi_data *data = (ecmult_multi_data*) cbdata;
    *sc = data->sc[idx];
    *pt = data->pt[idx];
    return 1;
}

static void test_exhaustive_ecmult_multi(const rustsecp256k1_v0_9_2_context *ctx, const rustsecp256k1_v0_9_2_ge *group) {
    int i, j, k, x, y;
    uint64_t iter = 0;
    rustsecp256k1_v0_9_2_scratch *scratch = rustsecp256k1_v0_9_2_scratch_create(&ctx->error_callback, 4096);
    for (i = 0; i < EXHAUSTIVE_TEST_ORDER; i++) {
        for (j = 0; j < EXHAUSTIVE_TEST_ORDER; j++) {
            for (k = 0; k < EXHAUSTIVE_TEST_ORDER; k++) {
                for (x = 0; x < EXHAUSTIVE_TEST_ORDER; x++) {
                    if (skip_section(&iter)) continue;
                    for (y = 0; y < EXHAUSTIVE_TEST_ORDER; y++) {
                        rustsecp256k1_v0_9_2_gej tmp;
                        rustsecp256k1_v0_9_2_scalar g_sc;
                        ecmult_multi_data data;

                        rustsecp256k1_v0_9_2_scalar_set_int(&data.sc[0], i);
                        rustsecp256k1_v0_9_2_scalar_set_int(&data.sc[1], j);
                        rustsecp256k1_v0_9_2_scalar_set_int(&g_sc, k);
                        data.pt[0] = group[x];
                        data.pt[1] = group[y];

                        rustsecp256k1_v0_9_2_ecmult_multi_var(&ctx->error_callback, scratch, &tmp, &g_sc, ecmult_multi_callback, &data, 2);
                        ge_equals_gej(&group[(i * x + j * y + k) % EXHAUSTIVE_TEST_ORDER], &tmp);
                    }
                }
            }
        }
    }
    rustsecp256k1_v0_9_2_scratch_destroy(&ctx->error_callback, scratch);
}

static void r_from_k(rustsecp256k1_v0_9_2_scalar *r, const rustsecp256k1_v0_9_2_ge *group, int k, int* overflow) {
    rustsecp256k1_v0_9_2_fe x;
    unsigned char x_bin[32];
    k %= EXHAUSTIVE_TEST_ORDER;
    x = group[k].x;
    rustsecp256k1_v0_9_2_fe_normalize(&x);
    rustsecp256k1_v0_9_2_fe_get_b32(x_bin, &x);
    rustsecp256k1_v0_9_2_scalar_set_b32(r, x_bin, overflow);
}

static void test_exhaustive_verify(const rustsecp256k1_v0_9_2_context *ctx, const rustsecp256k1_v0_9_2_ge *group) {
    int s, r, msg, key;
    uint64_t iter = 0;
    for (s = 1; s < EXHAUSTIVE_TEST_ORDER; s++) {
        for (r = 1; r < EXHAUSTIVE_TEST_ORDER; r++) {
            for (msg = 1; msg < EXHAUSTIVE_TEST_ORDER; msg++) {
                for (key = 1; key < EXHAUSTIVE_TEST_ORDER; key++) {
                    rustsecp256k1_v0_9_2_ge nonconst_ge;
                    rustsecp256k1_v0_9_2_ecdsa_signature sig;
                    rustsecp256k1_v0_9_2_pubkey pk;
                    rustsecp256k1_v0_9_2_scalar sk_s, msg_s, r_s, s_s;
                    rustsecp256k1_v0_9_2_scalar s_times_k_s, msg_plus_r_times_sk_s;
                    int k, should_verify;
                    unsigned char msg32[32];

                    if (skip_section(&iter)) continue;

                    rustsecp256k1_v0_9_2_scalar_set_int(&s_s, s);
                    rustsecp256k1_v0_9_2_scalar_set_int(&r_s, r);
                    rustsecp256k1_v0_9_2_scalar_set_int(&msg_s, msg);
                    rustsecp256k1_v0_9_2_scalar_set_int(&sk_s, key);

                    /* Verify by hand */
                    /* Run through every k value that gives us this r and check that *one* works.
                     * Note there could be none, there could be multiple, ECDSA is weird. */
                    should_verify = 0;
                    for (k = 0; k < EXHAUSTIVE_TEST_ORDER; k++) {
                        rustsecp256k1_v0_9_2_scalar check_x_s;
                        r_from_k(&check_x_s, group, k, NULL);
                        if (r_s == check_x_s) {
                            rustsecp256k1_v0_9_2_scalar_set_int(&s_times_k_s, k);
                            rustsecp256k1_v0_9_2_scalar_mul(&s_times_k_s, &s_times_k_s, &s_s);
                            rustsecp256k1_v0_9_2_scalar_mul(&msg_plus_r_times_sk_s, &r_s, &sk_s);
                            rustsecp256k1_v0_9_2_scalar_add(&msg_plus_r_times_sk_s, &msg_plus_r_times_sk_s, &msg_s);
                            should_verify |= rustsecp256k1_v0_9_2_scalar_eq(&s_times_k_s, &msg_plus_r_times_sk_s);
                        }
                    }
                    /* nb we have a "high s" rule */
                    should_verify &= !rustsecp256k1_v0_9_2_scalar_is_high(&s_s);

                    /* Verify by calling verify */
                    rustsecp256k1_v0_9_2_ecdsa_signature_save(&sig, &r_s, &s_s);
                    memcpy(&nonconst_ge, &group[sk_s], sizeof(nonconst_ge));
                    rustsecp256k1_v0_9_2_pubkey_save(&pk, &nonconst_ge);
                    rustsecp256k1_v0_9_2_scalar_get_b32(msg32, &msg_s);
                    CHECK(should_verify ==
                          rustsecp256k1_v0_9_2_ecdsa_verify(ctx, &sig, msg32, &pk));
                }
            }
        }
    }
}

static void test_exhaustive_sign(const rustsecp256k1_v0_9_2_context *ctx, const rustsecp256k1_v0_9_2_ge *group) {
    int i, j, k;
    uint64_t iter = 0;

    /* Loop */
    for (i = 1; i < EXHAUSTIVE_TEST_ORDER; i++) {  /* message */
        for (j = 1; j < EXHAUSTIVE_TEST_ORDER; j++) {  /* key */
            if (skip_section(&iter)) continue;
            for (k = 1; k < EXHAUSTIVE_TEST_ORDER; k++) {  /* nonce */
                const int starting_k = k;
                int ret;
                rustsecp256k1_v0_9_2_ecdsa_signature sig;
                rustsecp256k1_v0_9_2_scalar sk, msg, r, s, expected_r;
                unsigned char sk32[32], msg32[32];
                rustsecp256k1_v0_9_2_scalar_set_int(&msg, i);
                rustsecp256k1_v0_9_2_scalar_set_int(&sk, j);
                rustsecp256k1_v0_9_2_scalar_get_b32(sk32, &sk);
                rustsecp256k1_v0_9_2_scalar_get_b32(msg32, &msg);

                ret = rustsecp256k1_v0_9_2_ecdsa_sign(ctx, &sig, msg32, sk32, rustsecp256k1_v0_9_2_nonce_function_smallint, &k);
                CHECK(ret == 1);

                rustsecp256k1_v0_9_2_ecdsa_signature_load(ctx, &r, &s, &sig);
                /* Note that we compute expected_r *after* signing -- this is important
                 * because our nonce-computing function function might change k during
                 * signing. */
                r_from_k(&expected_r, group, k, NULL);
                CHECK(r == expected_r);
                CHECK((k * s) % EXHAUSTIVE_TEST_ORDER == (i + r * j) % EXHAUSTIVE_TEST_ORDER ||
                      (k * (EXHAUSTIVE_TEST_ORDER - s)) % EXHAUSTIVE_TEST_ORDER == (i + r * j) % EXHAUSTIVE_TEST_ORDER);

                /* Overflow means we've tried every possible nonce */
                if (k < starting_k) {
                    break;
                }
            }
        }
    }

    /* We would like to verify zero-knowledge here by counting how often every
     * possible (s, r) tuple appears, but because the group order is larger
     * than the field order, when coercing the x-values to scalar values, some
     * appear more often than others, so we are actually not zero-knowledge.
     * (This effect also appears in the real code, but the difference is on the
     * order of 1/2^128th the field order, so the deviation is not useful to a
     * computationally bounded attacker.)
     */
}

#ifdef ENABLE_MODULE_RECOVERY
#include "modules/recovery/tests_exhaustive_impl.h"
#endif

#ifdef ENABLE_MODULE_EXTRAKEYS
#include "modules/extrakeys/tests_exhaustive_impl.h"
#endif

#ifdef ENABLE_MODULE_SCHNORRSIG
#include "modules/schnorrsig/tests_exhaustive_impl.h"
#endif

#ifdef ENABLE_MODULE_ELLSWIFT
#include "modules/ellswift/tests_exhaustive_impl.h"
#endif

int main(int argc, char** argv) {
    int i;
    rustsecp256k1_v0_9_2_gej groupj[EXHAUSTIVE_TEST_ORDER];
    rustsecp256k1_v0_9_2_ge group[EXHAUSTIVE_TEST_ORDER];
    unsigned char rand32[32];
    rustsecp256k1_v0_9_2_context *ctx;

    /* Disable buffering for stdout to improve reliability of getting
     * diagnostic information. Happens right at the start of main because
     * setbuf must be used before any other operation on the stream. */
    setbuf(stdout, NULL);
    /* Also disable buffering for stderr because it's not guaranteed that it's
     * unbuffered on all systems. */
    setbuf(stderr, NULL);

    printf("Exhaustive tests for order %lu\n", (unsigned long)EXHAUSTIVE_TEST_ORDER);

    /* find iteration count */
    if (argc > 1) {
        count = strtol(argv[1], NULL, 0);
    }
    printf("test count = %i\n", count);

    /* find random seed */
    rustsecp256k1_v0_9_2_testrand_init(argc > 2 ? argv[2] : NULL);

    /* set up split processing */
    if (argc > 4) {
        num_cores = strtol(argv[3], NULL, 0);
        this_core = strtol(argv[4], NULL, 0);
        if (num_cores < 1 || this_core >= num_cores) {
            fprintf(stderr, "Usage: %s [count] [seed] [numcores] [thiscore]\n", argv[0]);
            return 1;
        }
        printf("running tests for core %lu (out of [0..%lu])\n", (unsigned long)this_core, (unsigned long)num_cores - 1);
    }

    /* Recreate the ecmult{,_gen} tables using the right generator (as selected via EXHAUSTIVE_TEST_ORDER) */
    rustsecp256k1_v0_9_2_ecmult_gen_compute_table(&rustsecp256k1_v0_9_2_ecmult_gen_prec_table[0][0], &rustsecp256k1_v0_9_2_ge_const_g, ECMULT_GEN_PREC_BITS);
    rustsecp256k1_v0_9_2_ecmult_compute_two_tables(rustsecp256k1_v0_9_2_pre_g, rustsecp256k1_v0_9_2_pre_g_128, WINDOW_G, &rustsecp256k1_v0_9_2_ge_const_g);

    while (count--) {
        /* Build context */
        ctx = rustsecp256k1_v0_9_2_context_create(SECP256K1_CONTEXT_NONE);
        rustsecp256k1_v0_9_2_testrand256(rand32);
        CHECK(rustsecp256k1_v0_9_2_context_randomize(ctx, rand32));

        /* Generate the entire group */
        rustsecp256k1_v0_9_2_gej_set_infinity(&groupj[0]);
        rustsecp256k1_v0_9_2_ge_set_gej(&group[0], &groupj[0]);
        for (i = 1; i < EXHAUSTIVE_TEST_ORDER; i++) {
            rustsecp256k1_v0_9_2_gej_add_ge(&groupj[i], &groupj[i - 1], &rustsecp256k1_v0_9_2_ge_const_g);
            rustsecp256k1_v0_9_2_ge_set_gej(&group[i], &groupj[i]);
            if (count != 0) {
                /* Set a different random z-value for each Jacobian point, except z=1
                   is used in the last iteration. */
                rustsecp256k1_v0_9_2_fe z;
                random_fe(&z);
                rustsecp256k1_v0_9_2_gej_rescale(&groupj[i], &z);
            }

            /* Verify against ecmult_gen */
            {
                rustsecp256k1_v0_9_2_scalar scalar_i;
                rustsecp256k1_v0_9_2_gej generatedj;
                rustsecp256k1_v0_9_2_ge generated;

                rustsecp256k1_v0_9_2_scalar_set_int(&scalar_i, i);
                rustsecp256k1_v0_9_2_ecmult_gen(&ctx->ecmult_gen_ctx, &generatedj, &scalar_i);
                rustsecp256k1_v0_9_2_ge_set_gej(&generated, &generatedj);

                CHECK(group[i].infinity == 0);
                CHECK(generated.infinity == 0);
                CHECK(rustsecp256k1_v0_9_2_fe_equal(&generated.x, &group[i].x));
                CHECK(rustsecp256k1_v0_9_2_fe_equal(&generated.y, &group[i].y));
            }
        }

        /* Run the tests */
        test_exhaustive_endomorphism(group);
        test_exhaustive_addition(group, groupj);
        test_exhaustive_ecmult(group, groupj);
        test_exhaustive_ecmult_multi(ctx, group);
        test_exhaustive_sign(ctx, group);
        test_exhaustive_verify(ctx, group);

#ifdef ENABLE_MODULE_RECOVERY
        test_exhaustive_recovery(ctx, group);
#endif
#ifdef ENABLE_MODULE_EXTRAKEYS
        test_exhaustive_extrakeys(ctx, group);
#endif
#ifdef ENABLE_MODULE_SCHNORRSIG
        test_exhaustive_schnorrsig(ctx);
#endif
#ifdef ENABLE_MODULE_ELLSWIFT
    /* The ellswift algorithm does have additional edge cases when operating on
     * curves of even order, which are not included in the code as secp256k1 is
     * of odd order. Skip the ellswift tests if the used exhaustive tests curve
     * is even-ordered accordingly. */
    #if !EXHAUSTIVE_TEST_CURVE_HAS_EVEN_ORDER
        test_exhaustive_ellswift(ctx, group);
    #endif
#endif

        rustsecp256k1_v0_9_2_context_destroy(ctx);
    }

    rustsecp256k1_v0_9_2_testrand_finish();

    printf("no problems found\n");
    return 0;
}
