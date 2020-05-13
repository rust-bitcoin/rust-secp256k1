/**********************************************************************
 * Copyright (c) 2013, 2014, 2015 Pieter Wuille, Gregory Maxwell      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_ECMULT_GEN_IMPL_H
#define SECP256K1_ECMULT_GEN_IMPL_H

#include "util.h"
#include "scalar.h"
#include "group.h"
#include "ecmult_gen.h"
#include "hash_impl.h"
#ifdef USE_ECMULT_STATIC_PRECOMPUTATION
#include "ecmult_static_context.h"
#endif

#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    static const size_t SECP256K1_ECMULT_GEN_CONTEXT_PREALLOCATED_SIZE = ROUND_TO_ALIGN(sizeof(*((rustsecp256k1_v0_1_2_ecmult_gen_context*) NULL)->prec));
#else
    static const size_t SECP256K1_ECMULT_GEN_CONTEXT_PREALLOCATED_SIZE = 0;
#endif

static void rustsecp256k1_v0_1_2_ecmult_gen_context_init(rustsecp256k1_v0_1_2_ecmult_gen_context *ctx) {
    ctx->prec = NULL;
}

static void rustsecp256k1_v0_1_2_ecmult_gen_context_build(rustsecp256k1_v0_1_2_ecmult_gen_context *ctx, void **prealloc) {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    rustsecp256k1_v0_1_2_ge prec[ECMULT_GEN_PREC_N * ECMULT_GEN_PREC_G];
    rustsecp256k1_v0_1_2_gej gj;
    rustsecp256k1_v0_1_2_gej nums_gej;
    int i, j;
    size_t const prealloc_size = SECP256K1_ECMULT_GEN_CONTEXT_PREALLOCATED_SIZE;
    void* const base = *prealloc;
#endif

    if (ctx->prec != NULL) {
        return;
    }
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    ctx->prec = (rustsecp256k1_v0_1_2_ge_storage (*)[ECMULT_GEN_PREC_N][ECMULT_GEN_PREC_G])manual_alloc(prealloc, prealloc_size, base, prealloc_size);

    /* get the generator */
    rustsecp256k1_v0_1_2_gej_set_ge(&gj, &rustsecp256k1_v0_1_2_ge_const_g);

    /* Construct a group element with no known corresponding scalar (nothing up my sleeve). */
    {
        static const unsigned char nums_b32[33] = "The scalar for this x is unknown";
        rustsecp256k1_v0_1_2_fe nums_x;
        rustsecp256k1_v0_1_2_ge nums_ge;
        int r;
        r = rustsecp256k1_v0_1_2_fe_set_b32(&nums_x, nums_b32);
        (void)r;
        VERIFY_CHECK(r);
        r = rustsecp256k1_v0_1_2_ge_set_xo_var(&nums_ge, &nums_x, 0);
        (void)r;
        VERIFY_CHECK(r);
        rustsecp256k1_v0_1_2_gej_set_ge(&nums_gej, &nums_ge);
        /* Add G to make the bits in x uniformly distributed. */
        rustsecp256k1_v0_1_2_gej_add_ge_var(&nums_gej, &nums_gej, &rustsecp256k1_v0_1_2_ge_const_g, NULL);
    }

    /* compute prec. */
    {
        rustsecp256k1_v0_1_2_gej precj[ECMULT_GEN_PREC_N * ECMULT_GEN_PREC_G]; /* Jacobian versions of prec. */
        rustsecp256k1_v0_1_2_gej gbase;
        rustsecp256k1_v0_1_2_gej numsbase;
        gbase = gj; /* PREC_G^j * G */
        numsbase = nums_gej; /* 2^j * nums. */
        for (j = 0; j < ECMULT_GEN_PREC_N; j++) {
            /* Set precj[j*PREC_G .. j*PREC_G+(PREC_G-1)] to (numsbase, numsbase + gbase, ..., numsbase + (PREC_G-1)*gbase). */
            precj[j*ECMULT_GEN_PREC_G] = numsbase;
            for (i = 1; i < ECMULT_GEN_PREC_G; i++) {
                rustsecp256k1_v0_1_2_gej_add_var(&precj[j*ECMULT_GEN_PREC_G + i], &precj[j*ECMULT_GEN_PREC_G + i - 1], &gbase, NULL);
            }
            /* Multiply gbase by PREC_G. */
            for (i = 0; i < ECMULT_GEN_PREC_B; i++) {
                rustsecp256k1_v0_1_2_gej_double_var(&gbase, &gbase, NULL);
            }
            /* Multiply numbase by 2. */
            rustsecp256k1_v0_1_2_gej_double_var(&numsbase, &numsbase, NULL);
            if (j == ECMULT_GEN_PREC_N - 2) {
                /* In the last iteration, numsbase is (1 - 2^j) * nums instead. */
                rustsecp256k1_v0_1_2_gej_neg(&numsbase, &numsbase);
                rustsecp256k1_v0_1_2_gej_add_var(&numsbase, &numsbase, &nums_gej, NULL);
            }
        }
        rustsecp256k1_v0_1_2_ge_set_all_gej_var(prec, precj, ECMULT_GEN_PREC_N * ECMULT_GEN_PREC_G);
    }
    for (j = 0; j < ECMULT_GEN_PREC_N; j++) {
        for (i = 0; i < ECMULT_GEN_PREC_G; i++) {
            rustsecp256k1_v0_1_2_ge_to_storage(&(*ctx->prec)[j][i], &prec[j*ECMULT_GEN_PREC_G + i]);
        }
    }
#else
    (void)prealloc;
    ctx->prec = (rustsecp256k1_v0_1_2_ge_storage (*)[ECMULT_GEN_PREC_N][ECMULT_GEN_PREC_G])rustsecp256k1_v0_1_2_ecmult_static_context;
#endif
    rustsecp256k1_v0_1_2_ecmult_gen_blind(ctx, NULL);
}

static int rustsecp256k1_v0_1_2_ecmult_gen_context_is_built(const rustsecp256k1_v0_1_2_ecmult_gen_context* ctx) {
    return ctx->prec != NULL;
}

static void rustsecp256k1_v0_1_2_ecmult_gen_context_finalize_memcpy(rustsecp256k1_v0_1_2_ecmult_gen_context *dst, const rustsecp256k1_v0_1_2_ecmult_gen_context *src) {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    if (src->prec != NULL) {
        /* We cast to void* first to suppress a -Wcast-align warning. */
        dst->prec = (rustsecp256k1_v0_1_2_ge_storage (*)[ECMULT_GEN_PREC_N][ECMULT_GEN_PREC_G])(void*)((unsigned char*)dst + ((unsigned char*)src->prec - (unsigned char*)src));
    }
#else
    (void)dst, (void)src;
#endif
}

static void rustsecp256k1_v0_1_2_ecmult_gen_context_clear(rustsecp256k1_v0_1_2_ecmult_gen_context *ctx) {
    rustsecp256k1_v0_1_2_scalar_clear(&ctx->blind);
    rustsecp256k1_v0_1_2_gej_clear(&ctx->initial);
    ctx->prec = NULL;
}

static void rustsecp256k1_v0_1_2_ecmult_gen(const rustsecp256k1_v0_1_2_ecmult_gen_context *ctx, rustsecp256k1_v0_1_2_gej *r, const rustsecp256k1_v0_1_2_scalar *gn) {
    rustsecp256k1_v0_1_2_ge add;
    rustsecp256k1_v0_1_2_ge_storage adds;
    rustsecp256k1_v0_1_2_scalar gnb;
    int bits;
    int i, j;
    memset(&adds, 0, sizeof(adds));
    *r = ctx->initial;
    /* Blind scalar/point multiplication by computing (n-b)G + bG instead of nG. */
    rustsecp256k1_v0_1_2_scalar_add(&gnb, gn, &ctx->blind);
    add.infinity = 0;
    for (j = 0; j < ECMULT_GEN_PREC_N; j++) {
        bits = rustsecp256k1_v0_1_2_scalar_get_bits(&gnb, j * ECMULT_GEN_PREC_B, ECMULT_GEN_PREC_B);
        for (i = 0; i < ECMULT_GEN_PREC_G; i++) {
            /** This uses a conditional move to avoid any secret data in array indexes.
             *   _Any_ use of secret indexes has been demonstrated to result in timing
             *   sidechannels, even when the cache-line access patterns are uniform.
             *  See also:
             *   "A word of warning", CHES 2013 Rump Session, by Daniel J. Bernstein and Peter Schwabe
             *    (https://cryptojedi.org/peter/data/chesrump-20130822.pdf) and
             *   "Cache Attacks and Countermeasures: the Case of AES", RSA 2006,
             *    by Dag Arne Osvik, Adi Shamir, and Eran Tromer
             *    (http://www.tau.ac.il/~tromer/papers/cache.pdf)
             */
            rustsecp256k1_v0_1_2_ge_storage_cmov(&adds, &(*ctx->prec)[j][i], i == bits);
        }
        rustsecp256k1_v0_1_2_ge_from_storage(&add, &adds);
        rustsecp256k1_v0_1_2_gej_add_ge(r, r, &add);
    }
    bits = 0;
    rustsecp256k1_v0_1_2_ge_clear(&add);
    rustsecp256k1_v0_1_2_scalar_clear(&gnb);
}

/* Setup blinding values for rustsecp256k1_v0_1_2_ecmult_gen. */
static void rustsecp256k1_v0_1_2_ecmult_gen_blind(rustsecp256k1_v0_1_2_ecmult_gen_context *ctx, const unsigned char *seed32) {
    rustsecp256k1_v0_1_2_scalar b;
    rustsecp256k1_v0_1_2_gej gb;
    rustsecp256k1_v0_1_2_fe s;
    unsigned char nonce32[32];
    rustsecp256k1_v0_1_2_rfc6979_hmac_sha256 rng;
    int overflow;
    unsigned char keydata[64] = {0};
    if (seed32 == NULL) {
        /* When seed is NULL, reset the initial point and blinding value. */
        rustsecp256k1_v0_1_2_gej_set_ge(&ctx->initial, &rustsecp256k1_v0_1_2_ge_const_g);
        rustsecp256k1_v0_1_2_gej_neg(&ctx->initial, &ctx->initial);
        rustsecp256k1_v0_1_2_scalar_set_int(&ctx->blind, 1);
    }
    /* The prior blinding value (if not reset) is chained forward by including it in the hash. */
    rustsecp256k1_v0_1_2_scalar_get_b32(nonce32, &ctx->blind);
    /** Using a CSPRNG allows a failure free interface, avoids needing large amounts of random data,
     *   and guards against weak or adversarial seeds.  This is a simpler and safer interface than
     *   asking the caller for blinding values directly and expecting them to retry on failure.
     */
    memcpy(keydata, nonce32, 32);
    if (seed32 != NULL) {
        memcpy(keydata + 32, seed32, 32);
    }
    rustsecp256k1_v0_1_2_rfc6979_hmac_sha256_initialize(&rng, keydata, seed32 ? 64 : 32);
    memset(keydata, 0, sizeof(keydata));
    /* Accept unobservably small non-uniformity. */
    rustsecp256k1_v0_1_2_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
    overflow = !rustsecp256k1_v0_1_2_fe_set_b32(&s, nonce32);
    overflow |= rustsecp256k1_v0_1_2_fe_is_zero(&s);
    rustsecp256k1_v0_1_2_fe_cmov(&s, &rustsecp256k1_v0_1_2_fe_one, overflow);
    /* Randomize the projection to defend against multiplier sidechannels. */
    rustsecp256k1_v0_1_2_gej_rescale(&ctx->initial, &s);
    rustsecp256k1_v0_1_2_fe_clear(&s);
    rustsecp256k1_v0_1_2_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
    rustsecp256k1_v0_1_2_scalar_set_b32(&b, nonce32, NULL);
    /* A blinding value of 0 works, but would undermine the projection hardening. */
    rustsecp256k1_v0_1_2_scalar_cmov(&b, &rustsecp256k1_v0_1_2_scalar_one, rustsecp256k1_v0_1_2_scalar_is_zero(&b));
    rustsecp256k1_v0_1_2_rfc6979_hmac_sha256_finalize(&rng);
    memset(nonce32, 0, 32);
    rustsecp256k1_v0_1_2_ecmult_gen(ctx, &gb, &b);
    rustsecp256k1_v0_1_2_scalar_negate(&b, &b);
    ctx->blind = b;
    ctx->initial = gb;
    rustsecp256k1_v0_1_2_scalar_clear(&b);
    rustsecp256k1_v0_1_2_gej_clear(&gb);
}

#endif /* SECP256K1_ECMULT_GEN_IMPL_H */
