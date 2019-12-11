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
    static const size_t SECP256K1_ECMULT_GEN_CONTEXT_PREALLOCATED_SIZE = ROUND_TO_ALIGN(sizeof(*((rustsecp256k1_v0_1_1_ecmult_gen_context*) NULL)->prec));
#else
    static const size_t SECP256K1_ECMULT_GEN_CONTEXT_PREALLOCATED_SIZE = 0;
#endif

static void rustsecp256k1_v0_1_1_ecmult_gen_context_init(rustsecp256k1_v0_1_1_ecmult_gen_context *ctx) {
    ctx->prec = NULL;
}

static void rustsecp256k1_v0_1_1_ecmult_gen_context_build(rustsecp256k1_v0_1_1_ecmult_gen_context *ctx, void **prealloc) {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    rustsecp256k1_v0_1_1_ge prec[1024];
    rustsecp256k1_v0_1_1_gej gj;
    rustsecp256k1_v0_1_1_gej nums_gej;
    int i, j;
    size_t const prealloc_size = SECP256K1_ECMULT_GEN_CONTEXT_PREALLOCATED_SIZE;
    void* const base = *prealloc;
#endif

    if (ctx->prec != NULL) {
        return;
    }
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    ctx->prec = (rustsecp256k1_v0_1_1_ge_storage (*)[64][16])manual_alloc(prealloc, prealloc_size, base, prealloc_size);

    /* get the generator */
    rustsecp256k1_v0_1_1_gej_set_ge(&gj, &rustsecp256k1_v0_1_1_ge_const_g);

    /* Construct a group element with no known corresponding scalar (nothing up my sleeve). */
    {
        static const unsigned char nums_b32[33] = "The scalar for this x is unknown";
        rustsecp256k1_v0_1_1_fe nums_x;
        rustsecp256k1_v0_1_1_ge nums_ge;
        int r;
        r = rustsecp256k1_v0_1_1_fe_set_b32(&nums_x, nums_b32);
        (void)r;
        VERIFY_CHECK(r);
        r = rustsecp256k1_v0_1_1_ge_set_xo_var(&nums_ge, &nums_x, 0);
        (void)r;
        VERIFY_CHECK(r);
        rustsecp256k1_v0_1_1_gej_set_ge(&nums_gej, &nums_ge);
        /* Add G to make the bits in x uniformly distributed. */
        rustsecp256k1_v0_1_1_gej_add_ge_var(&nums_gej, &nums_gej, &rustsecp256k1_v0_1_1_ge_const_g, NULL);
    }

    /* compute prec. */
    {
        rustsecp256k1_v0_1_1_gej precj[1024]; /* Jacobian versions of prec. */
        rustsecp256k1_v0_1_1_gej gbase;
        rustsecp256k1_v0_1_1_gej numsbase;
        gbase = gj; /* 16^j * G */
        numsbase = nums_gej; /* 2^j * nums. */
        for (j = 0; j < 64; j++) {
            /* Set precj[j*16 .. j*16+15] to (numsbase, numsbase + gbase, ..., numsbase + 15*gbase). */
            precj[j*16] = numsbase;
            for (i = 1; i < 16; i++) {
                rustsecp256k1_v0_1_1_gej_add_var(&precj[j*16 + i], &precj[j*16 + i - 1], &gbase, NULL);
            }
            /* Multiply gbase by 16. */
            for (i = 0; i < 4; i++) {
                rustsecp256k1_v0_1_1_gej_double_var(&gbase, &gbase, NULL);
            }
            /* Multiply numbase by 2. */
            rustsecp256k1_v0_1_1_gej_double_var(&numsbase, &numsbase, NULL);
            if (j == 62) {
                /* In the last iteration, numsbase is (1 - 2^j) * nums instead. */
                rustsecp256k1_v0_1_1_gej_neg(&numsbase, &numsbase);
                rustsecp256k1_v0_1_1_gej_add_var(&numsbase, &numsbase, &nums_gej, NULL);
            }
        }
        rustsecp256k1_v0_1_1_ge_set_all_gej_var(prec, precj, 1024);
    }
    for (j = 0; j < 64; j++) {
        for (i = 0; i < 16; i++) {
            rustsecp256k1_v0_1_1_ge_to_storage(&(*ctx->prec)[j][i], &prec[j*16 + i]);
        }
    }
#else
    (void)prealloc;
    ctx->prec = (rustsecp256k1_v0_1_1_ge_storage (*)[64][16])rustsecp256k1_v0_1_1_ecmult_static_context;
#endif
    rustsecp256k1_v0_1_1_ecmult_gen_blind(ctx, NULL);
}

static int rustsecp256k1_v0_1_1_ecmult_gen_context_is_built(const rustsecp256k1_v0_1_1_ecmult_gen_context* ctx) {
    return ctx->prec != NULL;
}

static void rustsecp256k1_v0_1_1_ecmult_gen_context_finalize_memcpy(rustsecp256k1_v0_1_1_ecmult_gen_context *dst, const rustsecp256k1_v0_1_1_ecmult_gen_context *src) {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    if (src->prec != NULL) {
        /* We cast to void* first to suppress a -Wcast-align warning. */
        dst->prec = (rustsecp256k1_v0_1_1_ge_storage (*)[64][16])(void*)((unsigned char*)dst + ((unsigned char*)src->prec - (unsigned char*)src));
    }
#else
    (void)dst, (void)src;
#endif
}

static void rustsecp256k1_v0_1_1_ecmult_gen_context_clear(rustsecp256k1_v0_1_1_ecmult_gen_context *ctx) {
    rustsecp256k1_v0_1_1_scalar_clear(&ctx->blind);
    rustsecp256k1_v0_1_1_gej_clear(&ctx->initial);
    ctx->prec = NULL;
}

static void rustsecp256k1_v0_1_1_ecmult_gen(const rustsecp256k1_v0_1_1_ecmult_gen_context *ctx, rustsecp256k1_v0_1_1_gej *r, const rustsecp256k1_v0_1_1_scalar *gn) {
    rustsecp256k1_v0_1_1_ge add;
    rustsecp256k1_v0_1_1_ge_storage adds;
    rustsecp256k1_v0_1_1_scalar gnb;
    int bits;
    int i, j;
    memset(&adds, 0, sizeof(adds));
    *r = ctx->initial;
    /* Blind scalar/point multiplication by computing (n-b)G + bG instead of nG. */
    rustsecp256k1_v0_1_1_scalar_add(&gnb, gn, &ctx->blind);
    add.infinity = 0;
    for (j = 0; j < 64; j++) {
        bits = rustsecp256k1_v0_1_1_scalar_get_bits(&gnb, j * 4, 4);
        for (i = 0; i < 16; i++) {
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
            rustsecp256k1_v0_1_1_ge_storage_cmov(&adds, &(*ctx->prec)[j][i], i == bits);
        }
        rustsecp256k1_v0_1_1_ge_from_storage(&add, &adds);
        rustsecp256k1_v0_1_1_gej_add_ge(r, r, &add);
    }
    bits = 0;
    rustsecp256k1_v0_1_1_ge_clear(&add);
    rustsecp256k1_v0_1_1_scalar_clear(&gnb);
}

/* Setup blinding values for rustsecp256k1_v0_1_1_ecmult_gen. */
static void rustsecp256k1_v0_1_1_ecmult_gen_blind(rustsecp256k1_v0_1_1_ecmult_gen_context *ctx, const unsigned char *seed32) {
    rustsecp256k1_v0_1_1_scalar b;
    rustsecp256k1_v0_1_1_gej gb;
    rustsecp256k1_v0_1_1_fe s;
    unsigned char nonce32[32];
    rustsecp256k1_v0_1_1_rfc6979_hmac_sha256 rng;
    int retry;
    unsigned char keydata[64] = {0};
    if (seed32 == NULL) {
        /* When seed is NULL, reset the initial point and blinding value. */
        rustsecp256k1_v0_1_1_gej_set_ge(&ctx->initial, &rustsecp256k1_v0_1_1_ge_const_g);
        rustsecp256k1_v0_1_1_gej_neg(&ctx->initial, &ctx->initial);
        rustsecp256k1_v0_1_1_scalar_set_int(&ctx->blind, 1);
    }
    /* The prior blinding value (if not reset) is chained forward by including it in the hash. */
    rustsecp256k1_v0_1_1_scalar_get_b32(nonce32, &ctx->blind);
    /** Using a CSPRNG allows a failure free interface, avoids needing large amounts of random data,
     *   and guards against weak or adversarial seeds.  This is a simpler and safer interface than
     *   asking the caller for blinding values directly and expecting them to retry on failure.
     */
    memcpy(keydata, nonce32, 32);
    if (seed32 != NULL) {
        memcpy(keydata + 32, seed32, 32);
    }
    rustsecp256k1_v0_1_1_rfc6979_hmac_sha256_initialize(&rng, keydata, seed32 ? 64 : 32);
    memset(keydata, 0, sizeof(keydata));
    /* Retry for out of range results to achieve uniformity. */
    do {
        rustsecp256k1_v0_1_1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
        retry = !rustsecp256k1_v0_1_1_fe_set_b32(&s, nonce32);
        retry |= rustsecp256k1_v0_1_1_fe_is_zero(&s);
    } while (retry); /* This branch true is cryptographically unreachable. Requires sha256_hmac output > Fp. */
    /* Randomize the projection to defend against multiplier sidechannels. */
    rustsecp256k1_v0_1_1_gej_rescale(&ctx->initial, &s);
    rustsecp256k1_v0_1_1_fe_clear(&s);
    do {
        rustsecp256k1_v0_1_1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
        rustsecp256k1_v0_1_1_scalar_set_b32(&b, nonce32, &retry);
        /* A blinding value of 0 works, but would undermine the projection hardening. */
        retry |= rustsecp256k1_v0_1_1_scalar_is_zero(&b);
    } while (retry); /* This branch true is cryptographically unreachable. Requires sha256_hmac output > order. */
    rustsecp256k1_v0_1_1_rfc6979_hmac_sha256_finalize(&rng);
    memset(nonce32, 0, 32);
    rustsecp256k1_v0_1_1_ecmult_gen(ctx, &gb, &b);
    rustsecp256k1_v0_1_1_scalar_negate(&b, &b);
    ctx->blind = b;
    ctx->initial = gb;
    rustsecp256k1_v0_1_1_scalar_clear(&b);
    rustsecp256k1_v0_1_1_gej_clear(&gb);
}

#endif /* SECP256K1_ECMULT_GEN_IMPL_H */
