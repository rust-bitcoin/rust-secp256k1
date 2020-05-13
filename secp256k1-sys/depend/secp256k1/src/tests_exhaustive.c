/***********************************************************************
 * Copyright (c) 2016 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include <time.h>

#undef USE_ECMULT_STATIC_PRECOMPUTATION

#ifndef EXHAUSTIVE_TEST_ORDER
/* see group_impl.h for allowable values */
#define EXHAUSTIVE_TEST_ORDER 13
#define EXHAUSTIVE_TEST_LAMBDA 9   /* cube root of 1 mod 13 */
#endif

#include "include/secp256k1.h"
#include "group.h"
#include "secp256k1.c"
#include "testrand_impl.h"

#ifdef ENABLE_MODULE_RECOVERY
#include "src/modules/recovery/main_impl.h"
#include "include/secp256k1_recovery.h"
#endif

/** stolen from tests.c */
void ge_equals_ge(const rustsecp256k1_v0_1_2_ge *a, const rustsecp256k1_v0_1_2_ge *b) {
    CHECK(a->infinity == b->infinity);
    if (a->infinity) {
        return;
    }
    CHECK(rustsecp256k1_v0_1_2_fe_equal_var(&a->x, &b->x));
    CHECK(rustsecp256k1_v0_1_2_fe_equal_var(&a->y, &b->y));
}

void ge_equals_gej(const rustsecp256k1_v0_1_2_ge *a, const rustsecp256k1_v0_1_2_gej *b) {
    rustsecp256k1_v0_1_2_fe z2s;
    rustsecp256k1_v0_1_2_fe u1, u2, s1, s2;
    CHECK(a->infinity == b->infinity);
    if (a->infinity) {
        return;
    }
    /* Check a.x * b.z^2 == b.x && a.y * b.z^3 == b.y, to avoid inverses. */
    rustsecp256k1_v0_1_2_fe_sqr(&z2s, &b->z);
    rustsecp256k1_v0_1_2_fe_mul(&u1, &a->x, &z2s);
    u2 = b->x; rustsecp256k1_v0_1_2_fe_normalize_weak(&u2);
    rustsecp256k1_v0_1_2_fe_mul(&s1, &a->y, &z2s); rustsecp256k1_v0_1_2_fe_mul(&s1, &s1, &b->z);
    s2 = b->y; rustsecp256k1_v0_1_2_fe_normalize_weak(&s2);
    CHECK(rustsecp256k1_v0_1_2_fe_equal_var(&u1, &u2));
    CHECK(rustsecp256k1_v0_1_2_fe_equal_var(&s1, &s2));
}

void random_fe(rustsecp256k1_v0_1_2_fe *x) {
    unsigned char bin[32];
    do {
        rustsecp256k1_v0_1_2_rand256(bin);
        if (rustsecp256k1_v0_1_2_fe_set_b32(x, bin)) {
            return;
        }
    } while(1);
}
/** END stolen from tests.c */

int rustsecp256k1_v0_1_2_nonce_function_smallint(unsigned char *nonce32, const unsigned char *msg32,
                                      const unsigned char *key32, const unsigned char *algo16,
                                      void *data, unsigned int attempt) {
    rustsecp256k1_v0_1_2_scalar s;
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
    rustsecp256k1_v0_1_2_scalar_set_int(&s, *idata);
    rustsecp256k1_v0_1_2_scalar_get_b32(nonce32, &s);
    return 1;
}

#ifdef USE_ENDOMORPHISM
void test_exhaustive_endomorphism(const rustsecp256k1_v0_1_2_ge *group, int order) {
    int i;
    for (i = 0; i < order; i++) {
        rustsecp256k1_v0_1_2_ge res;
        rustsecp256k1_v0_1_2_ge_mul_lambda(&res, &group[i]);
        ge_equals_ge(&group[i * EXHAUSTIVE_TEST_LAMBDA % EXHAUSTIVE_TEST_ORDER], &res);
    }
}
#endif

void test_exhaustive_addition(const rustsecp256k1_v0_1_2_ge *group, const rustsecp256k1_v0_1_2_gej *groupj, int order) {
    int i, j;

    /* Sanity-check (and check infinity functions) */
    CHECK(rustsecp256k1_v0_1_2_ge_is_infinity(&group[0]));
    CHECK(rustsecp256k1_v0_1_2_gej_is_infinity(&groupj[0]));
    for (i = 1; i < order; i++) {
        CHECK(!rustsecp256k1_v0_1_2_ge_is_infinity(&group[i]));
        CHECK(!rustsecp256k1_v0_1_2_gej_is_infinity(&groupj[i]));
    }

    /* Check all addition formulae */
    for (j = 0; j < order; j++) {
        rustsecp256k1_v0_1_2_fe fe_inv;
        rustsecp256k1_v0_1_2_fe_inv(&fe_inv, &groupj[j].z);
        for (i = 0; i < order; i++) {
            rustsecp256k1_v0_1_2_ge zless_gej;
            rustsecp256k1_v0_1_2_gej tmp;
            /* add_var */
            rustsecp256k1_v0_1_2_gej_add_var(&tmp, &groupj[i], &groupj[j], NULL);
            ge_equals_gej(&group[(i + j) % order], &tmp);
            /* add_ge */
            if (j > 0) {
                rustsecp256k1_v0_1_2_gej_add_ge(&tmp, &groupj[i], &group[j]);
                ge_equals_gej(&group[(i + j) % order], &tmp);
            }
            /* add_ge_var */
            rustsecp256k1_v0_1_2_gej_add_ge_var(&tmp, &groupj[i], &group[j], NULL);
            ge_equals_gej(&group[(i + j) % order], &tmp);
            /* add_zinv_var */
            zless_gej.infinity = groupj[j].infinity;
            zless_gej.x = groupj[j].x;
            zless_gej.y = groupj[j].y;
            rustsecp256k1_v0_1_2_gej_add_zinv_var(&tmp, &groupj[i], &zless_gej, &fe_inv);
            ge_equals_gej(&group[(i + j) % order], &tmp);
        }
    }

    /* Check doubling */
    for (i = 0; i < order; i++) {
        rustsecp256k1_v0_1_2_gej tmp;
        if (i > 0) {
            rustsecp256k1_v0_1_2_gej_double_nonzero(&tmp, &groupj[i]);
            ge_equals_gej(&group[(2 * i) % order], &tmp);
        }
        rustsecp256k1_v0_1_2_gej_double_var(&tmp, &groupj[i], NULL);
        ge_equals_gej(&group[(2 * i) % order], &tmp);
    }

    /* Check negation */
    for (i = 1; i < order; i++) {
        rustsecp256k1_v0_1_2_ge tmp;
        rustsecp256k1_v0_1_2_gej tmpj;
        rustsecp256k1_v0_1_2_ge_neg(&tmp, &group[i]);
        ge_equals_ge(&group[order - i], &tmp);
        rustsecp256k1_v0_1_2_gej_neg(&tmpj, &groupj[i]);
        ge_equals_gej(&group[order - i], &tmpj);
    }
}

void test_exhaustive_ecmult(const rustsecp256k1_v0_1_2_context *ctx, const rustsecp256k1_v0_1_2_ge *group, const rustsecp256k1_v0_1_2_gej *groupj, int order) {
    int i, j, r_log;
    for (r_log = 1; r_log < order; r_log++) {
        for (j = 0; j < order; j++) {
            for (i = 0; i < order; i++) {
                rustsecp256k1_v0_1_2_gej tmp;
                rustsecp256k1_v0_1_2_scalar na, ng;
                rustsecp256k1_v0_1_2_scalar_set_int(&na, i);
                rustsecp256k1_v0_1_2_scalar_set_int(&ng, j);

                rustsecp256k1_v0_1_2_ecmult(&ctx->ecmult_ctx, &tmp, &groupj[r_log], &na, &ng);
                ge_equals_gej(&group[(i * r_log + j) % order], &tmp);

                if (i > 0) {
                    rustsecp256k1_v0_1_2_ecmult_const(&tmp, &group[i], &ng, 256);
                    ge_equals_gej(&group[(i * j) % order], &tmp);
                }
            }
        }
    }
}

typedef struct {
    rustsecp256k1_v0_1_2_scalar sc[2];
    rustsecp256k1_v0_1_2_ge pt[2];
} ecmult_multi_data;

static int ecmult_multi_callback(rustsecp256k1_v0_1_2_scalar *sc, rustsecp256k1_v0_1_2_ge *pt, size_t idx, void *cbdata) {
    ecmult_multi_data *data = (ecmult_multi_data*) cbdata;
    *sc = data->sc[idx];
    *pt = data->pt[idx];
    return 1;
}

void test_exhaustive_ecmult_multi(const rustsecp256k1_v0_1_2_context *ctx, const rustsecp256k1_v0_1_2_ge *group, int order) {
    int i, j, k, x, y;
    rustsecp256k1_v0_1_2_scratch *scratch = rustsecp256k1_v0_1_2_scratch_create(&ctx->error_callback, 4096);
    for (i = 0; i < order; i++) {
        for (j = 0; j < order; j++) {
            for (k = 0; k < order; k++) {
                for (x = 0; x < order; x++) {
                    for (y = 0; y < order; y++) {
                        rustsecp256k1_v0_1_2_gej tmp;
                        rustsecp256k1_v0_1_2_scalar g_sc;
                        ecmult_multi_data data;

                        rustsecp256k1_v0_1_2_scalar_set_int(&data.sc[0], i);
                        rustsecp256k1_v0_1_2_scalar_set_int(&data.sc[1], j);
                        rustsecp256k1_v0_1_2_scalar_set_int(&g_sc, k);
                        data.pt[0] = group[x];
                        data.pt[1] = group[y];

                        rustsecp256k1_v0_1_2_ecmult_multi_var(&ctx->error_callback, &ctx->ecmult_ctx, scratch, &tmp, &g_sc, ecmult_multi_callback, &data, 2);
                        ge_equals_gej(&group[(i * x + j * y + k) % order], &tmp);
                    }
                }
            }
        }
    }
    rustsecp256k1_v0_1_2_scratch_destroy(&ctx->error_callback, scratch);
}

void r_from_k(rustsecp256k1_v0_1_2_scalar *r, const rustsecp256k1_v0_1_2_ge *group, int k) {
    rustsecp256k1_v0_1_2_fe x;
    unsigned char x_bin[32];
    k %= EXHAUSTIVE_TEST_ORDER;
    x = group[k].x;
    rustsecp256k1_v0_1_2_fe_normalize(&x);
    rustsecp256k1_v0_1_2_fe_get_b32(x_bin, &x);
    rustsecp256k1_v0_1_2_scalar_set_b32(r, x_bin, NULL);
}

void test_exhaustive_verify(const rustsecp256k1_v0_1_2_context *ctx, const rustsecp256k1_v0_1_2_ge *group, int order) {
    int s, r, msg, key;
    for (s = 1; s < order; s++) {
        for (r = 1; r < order; r++) {
            for (msg = 1; msg < order; msg++) {
                for (key = 1; key < order; key++) {
                    rustsecp256k1_v0_1_2_ge nonconst_ge;
                    rustsecp256k1_v0_1_2_ecdsa_signature sig;
                    rustsecp256k1_v0_1_2_pubkey pk;
                    rustsecp256k1_v0_1_2_scalar sk_s, msg_s, r_s, s_s;
                    rustsecp256k1_v0_1_2_scalar s_times_k_s, msg_plus_r_times_sk_s;
                    int k, should_verify;
                    unsigned char msg32[32];

                    rustsecp256k1_v0_1_2_scalar_set_int(&s_s, s);
                    rustsecp256k1_v0_1_2_scalar_set_int(&r_s, r);
                    rustsecp256k1_v0_1_2_scalar_set_int(&msg_s, msg);
                    rustsecp256k1_v0_1_2_scalar_set_int(&sk_s, key);

                    /* Verify by hand */
                    /* Run through every k value that gives us this r and check that *one* works.
                     * Note there could be none, there could be multiple, ECDSA is weird. */
                    should_verify = 0;
                    for (k = 0; k < order; k++) {
                        rustsecp256k1_v0_1_2_scalar check_x_s;
                        r_from_k(&check_x_s, group, k);
                        if (r_s == check_x_s) {
                            rustsecp256k1_v0_1_2_scalar_set_int(&s_times_k_s, k);
                            rustsecp256k1_v0_1_2_scalar_mul(&s_times_k_s, &s_times_k_s, &s_s);
                            rustsecp256k1_v0_1_2_scalar_mul(&msg_plus_r_times_sk_s, &r_s, &sk_s);
                            rustsecp256k1_v0_1_2_scalar_add(&msg_plus_r_times_sk_s, &msg_plus_r_times_sk_s, &msg_s);
                            should_verify |= rustsecp256k1_v0_1_2_scalar_eq(&s_times_k_s, &msg_plus_r_times_sk_s);
                        }
                    }
                    /* nb we have a "high s" rule */
                    should_verify &= !rustsecp256k1_v0_1_2_scalar_is_high(&s_s);

                    /* Verify by calling verify */
                    rustsecp256k1_v0_1_2_ecdsa_signature_save(&sig, &r_s, &s_s);
                    memcpy(&nonconst_ge, &group[sk_s], sizeof(nonconst_ge));
                    rustsecp256k1_v0_1_2_pubkey_save(&pk, &nonconst_ge);
                    rustsecp256k1_v0_1_2_scalar_get_b32(msg32, &msg_s);
                    CHECK(should_verify ==
                          rustsecp256k1_v0_1_2_ecdsa_verify(ctx, &sig, msg32, &pk));
                }
            }
        }
    }
}

void test_exhaustive_sign(const rustsecp256k1_v0_1_2_context *ctx, const rustsecp256k1_v0_1_2_ge *group, int order) {
    int i, j, k;

    /* Loop */
    for (i = 1; i < order; i++) {  /* message */
        for (j = 1; j < order; j++) {  /* key */
            for (k = 1; k < order; k++) {  /* nonce */
                const int starting_k = k;
                rustsecp256k1_v0_1_2_ecdsa_signature sig;
                rustsecp256k1_v0_1_2_scalar sk, msg, r, s, expected_r;
                unsigned char sk32[32], msg32[32];
                rustsecp256k1_v0_1_2_scalar_set_int(&msg, i);
                rustsecp256k1_v0_1_2_scalar_set_int(&sk, j);
                rustsecp256k1_v0_1_2_scalar_get_b32(sk32, &sk);
                rustsecp256k1_v0_1_2_scalar_get_b32(msg32, &msg);

                rustsecp256k1_v0_1_2_ecdsa_sign(ctx, &sig, msg32, sk32, rustsecp256k1_v0_1_2_nonce_function_smallint, &k);

                rustsecp256k1_v0_1_2_ecdsa_signature_load(ctx, &r, &s, &sig);
                /* Note that we compute expected_r *after* signing -- this is important
                 * because our nonce-computing function function might change k during
                 * signing. */
                r_from_k(&expected_r, group, k);
                CHECK(r == expected_r);
                CHECK((k * s) % order == (i + r * j) % order ||
                      (k * (EXHAUSTIVE_TEST_ORDER - s)) % order == (i + r * j) % order);

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
void test_exhaustive_recovery_sign(const rustsecp256k1_v0_1_2_context *ctx, const rustsecp256k1_v0_1_2_ge *group, int order) {
    int i, j, k;

    /* Loop */
    for (i = 1; i < order; i++) {  /* message */
        for (j = 1; j < order; j++) {  /* key */
            for (k = 1; k < order; k++) {  /* nonce */
                const int starting_k = k;
                rustsecp256k1_v0_1_2_fe r_dot_y_normalized;
                rustsecp256k1_v0_1_2_ecdsa_recoverable_signature rsig;
                rustsecp256k1_v0_1_2_ecdsa_signature sig;
                rustsecp256k1_v0_1_2_scalar sk, msg, r, s, expected_r;
                unsigned char sk32[32], msg32[32];
                int expected_recid;
                int recid;
                rustsecp256k1_v0_1_2_scalar_set_int(&msg, i);
                rustsecp256k1_v0_1_2_scalar_set_int(&sk, j);
                rustsecp256k1_v0_1_2_scalar_get_b32(sk32, &sk);
                rustsecp256k1_v0_1_2_scalar_get_b32(msg32, &msg);

                rustsecp256k1_v0_1_2_ecdsa_sign_recoverable(ctx, &rsig, msg32, sk32, rustsecp256k1_v0_1_2_nonce_function_smallint, &k);

                /* Check directly */
                rustsecp256k1_v0_1_2_ecdsa_recoverable_signature_load(ctx, &r, &s, &recid, &rsig);
                r_from_k(&expected_r, group, k);
                CHECK(r == expected_r);
                CHECK((k * s) % order == (i + r * j) % order ||
                      (k * (EXHAUSTIVE_TEST_ORDER - s)) % order == (i + r * j) % order);
                /* In computing the recid, there is an overflow condition that is disabled in
                 * scalar_low_impl.h `rustsecp256k1_v0_1_2_scalar_set_b32` because almost every r.y value
                 * will exceed the group order, and our signing code always holds out for r
                 * values that don't overflow, so with a proper overflow check the tests would
                 * loop indefinitely. */
                r_dot_y_normalized = group[k].y;
                rustsecp256k1_v0_1_2_fe_normalize(&r_dot_y_normalized);
                /* Also the recovery id is flipped depending if we hit the low-s branch */
                if ((k * s) % order == (i + r * j) % order) {
                    expected_recid = rustsecp256k1_v0_1_2_fe_is_odd(&r_dot_y_normalized) ? 1 : 0;
                } else {
                    expected_recid = rustsecp256k1_v0_1_2_fe_is_odd(&r_dot_y_normalized) ? 0 : 1;
                }
                CHECK(recid == expected_recid);

                /* Convert to a standard sig then check */
                rustsecp256k1_v0_1_2_ecdsa_recoverable_signature_convert(ctx, &sig, &rsig);
                rustsecp256k1_v0_1_2_ecdsa_signature_load(ctx, &r, &s, &sig);
                /* Note that we compute expected_r *after* signing -- this is important
                 * because our nonce-computing function function might change k during
                 * signing. */
                r_from_k(&expected_r, group, k);
                CHECK(r == expected_r);
                CHECK((k * s) % order == (i + r * j) % order ||
                      (k * (EXHAUSTIVE_TEST_ORDER - s)) % order == (i + r * j) % order);

                /* Overflow means we've tried every possible nonce */
                if (k < starting_k) {
                    break;
                }
            }
        }
    }
}

void test_exhaustive_recovery_verify(const rustsecp256k1_v0_1_2_context *ctx, const rustsecp256k1_v0_1_2_ge *group, int order) {
    /* This is essentially a copy of test_exhaustive_verify, with recovery added */
    int s, r, msg, key;
    for (s = 1; s < order; s++) {
        for (r = 1; r < order; r++) {
            for (msg = 1; msg < order; msg++) {
                for (key = 1; key < order; key++) {
                    rustsecp256k1_v0_1_2_ge nonconst_ge;
                    rustsecp256k1_v0_1_2_ecdsa_recoverable_signature rsig;
                    rustsecp256k1_v0_1_2_ecdsa_signature sig;
                    rustsecp256k1_v0_1_2_pubkey pk;
                    rustsecp256k1_v0_1_2_scalar sk_s, msg_s, r_s, s_s;
                    rustsecp256k1_v0_1_2_scalar s_times_k_s, msg_plus_r_times_sk_s;
                    int recid = 0;
                    int k, should_verify;
                    unsigned char msg32[32];

                    rustsecp256k1_v0_1_2_scalar_set_int(&s_s, s);
                    rustsecp256k1_v0_1_2_scalar_set_int(&r_s, r);
                    rustsecp256k1_v0_1_2_scalar_set_int(&msg_s, msg);
                    rustsecp256k1_v0_1_2_scalar_set_int(&sk_s, key);
                    rustsecp256k1_v0_1_2_scalar_get_b32(msg32, &msg_s);

                    /* Verify by hand */
                    /* Run through every k value that gives us this r and check that *one* works.
                     * Note there could be none, there could be multiple, ECDSA is weird. */
                    should_verify = 0;
                    for (k = 0; k < order; k++) {
                        rustsecp256k1_v0_1_2_scalar check_x_s;
                        r_from_k(&check_x_s, group, k);
                        if (r_s == check_x_s) {
                            rustsecp256k1_v0_1_2_scalar_set_int(&s_times_k_s, k);
                            rustsecp256k1_v0_1_2_scalar_mul(&s_times_k_s, &s_times_k_s, &s_s);
                            rustsecp256k1_v0_1_2_scalar_mul(&msg_plus_r_times_sk_s, &r_s, &sk_s);
                            rustsecp256k1_v0_1_2_scalar_add(&msg_plus_r_times_sk_s, &msg_plus_r_times_sk_s, &msg_s);
                            should_verify |= rustsecp256k1_v0_1_2_scalar_eq(&s_times_k_s, &msg_plus_r_times_sk_s);
                        }
                    }
                    /* nb we have a "high s" rule */
                    should_verify &= !rustsecp256k1_v0_1_2_scalar_is_high(&s_s);

                    /* We would like to try recovering the pubkey and checking that it matches,
                     * but pubkey recovery is impossible in the exhaustive tests (the reason
                     * being that there are 12 nonzero r values, 12 nonzero points, and no
                     * overlap between the sets, so there are no valid signatures). */

                    /* Verify by converting to a standard signature and calling verify */
                    rustsecp256k1_v0_1_2_ecdsa_recoverable_signature_save(&rsig, &r_s, &s_s, recid);
                    rustsecp256k1_v0_1_2_ecdsa_recoverable_signature_convert(ctx, &sig, &rsig);
                    memcpy(&nonconst_ge, &group[sk_s], sizeof(nonconst_ge));
                    rustsecp256k1_v0_1_2_pubkey_save(&pk, &nonconst_ge);
                    CHECK(should_verify ==
                          rustsecp256k1_v0_1_2_ecdsa_verify(ctx, &sig, msg32, &pk));
                }
            }
        }
    }
}
#endif

int main(void) {
    int i;
    rustsecp256k1_v0_1_2_gej groupj[EXHAUSTIVE_TEST_ORDER];
    rustsecp256k1_v0_1_2_ge group[EXHAUSTIVE_TEST_ORDER];

    /* Build context */
    rustsecp256k1_v0_1_2_context *ctx = rustsecp256k1_v0_1_2_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* TODO set z = 1, then do num_tests runs with random z values */

    /* Generate the entire group */
    rustsecp256k1_v0_1_2_gej_set_infinity(&groupj[0]);
    rustsecp256k1_v0_1_2_ge_set_gej(&group[0], &groupj[0]);
    for (i = 1; i < EXHAUSTIVE_TEST_ORDER; i++) {
        /* Set a different random z-value for each Jacobian point */
        rustsecp256k1_v0_1_2_fe z;
        random_fe(&z);

        rustsecp256k1_v0_1_2_gej_add_ge(&groupj[i], &groupj[i - 1], &rustsecp256k1_v0_1_2_ge_const_g);
        rustsecp256k1_v0_1_2_ge_set_gej(&group[i], &groupj[i]);
        rustsecp256k1_v0_1_2_gej_rescale(&groupj[i], &z);

        /* Verify against ecmult_gen */
        {
            rustsecp256k1_v0_1_2_scalar scalar_i;
            rustsecp256k1_v0_1_2_gej generatedj;
            rustsecp256k1_v0_1_2_ge generated;

            rustsecp256k1_v0_1_2_scalar_set_int(&scalar_i, i);
            rustsecp256k1_v0_1_2_ecmult_gen(&ctx->ecmult_gen_ctx, &generatedj, &scalar_i);
            rustsecp256k1_v0_1_2_ge_set_gej(&generated, &generatedj);

            CHECK(group[i].infinity == 0);
            CHECK(generated.infinity == 0);
            CHECK(rustsecp256k1_v0_1_2_fe_equal_var(&generated.x, &group[i].x));
            CHECK(rustsecp256k1_v0_1_2_fe_equal_var(&generated.y, &group[i].y));
        }
    }

    /* Run the tests */
#ifdef USE_ENDOMORPHISM
    test_exhaustive_endomorphism(group, EXHAUSTIVE_TEST_ORDER);
#endif
    test_exhaustive_addition(group, groupj, EXHAUSTIVE_TEST_ORDER);
    test_exhaustive_ecmult(ctx, group, groupj, EXHAUSTIVE_TEST_ORDER);
    test_exhaustive_ecmult_multi(ctx, group, EXHAUSTIVE_TEST_ORDER);
    test_exhaustive_sign(ctx, group, EXHAUSTIVE_TEST_ORDER);
    test_exhaustive_verify(ctx, group, EXHAUSTIVE_TEST_ORDER);

#ifdef ENABLE_MODULE_RECOVERY
    test_exhaustive_recovery_sign(ctx, group, EXHAUSTIVE_TEST_ORDER);
    test_exhaustive_recovery_verify(ctx, group, EXHAUSTIVE_TEST_ORDER);
#endif

    rustsecp256k1_v0_1_2_context_destroy(ctx);
    return 0;
}

