/**********************************************************************
 * Copyright (c) 2013, 2014, 2017 Pieter Wuille, Andrew Poelstra      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_ECMULT_H
#define SECP256K1_ECMULT_H

#include "num.h"
#include "group.h"
#include "scalar.h"
#include "scratch.h"

typedef struct {
    /* For accelerating the computation of a*P + b*G: */
    rustsecp256k1_v0_1_2_ge_storage (*pre_g)[];    /* odd multiples of the generator */
#ifdef USE_ENDOMORPHISM
    rustsecp256k1_v0_1_2_ge_storage (*pre_g_128)[]; /* odd multiples of 2^128*generator */
#endif
} rustsecp256k1_v0_1_2_ecmult_context;

static const size_t SECP256K1_ECMULT_CONTEXT_PREALLOCATED_SIZE;
static void rustsecp256k1_v0_1_2_ecmult_context_init(rustsecp256k1_v0_1_2_ecmult_context *ctx);
static void rustsecp256k1_v0_1_2_ecmult_context_build(rustsecp256k1_v0_1_2_ecmult_context *ctx, void **prealloc);
static void rustsecp256k1_v0_1_2_ecmult_context_finalize_memcpy(rustsecp256k1_v0_1_2_ecmult_context *dst, const rustsecp256k1_v0_1_2_ecmult_context *src);
static void rustsecp256k1_v0_1_2_ecmult_context_clear(rustsecp256k1_v0_1_2_ecmult_context *ctx);
static int rustsecp256k1_v0_1_2_ecmult_context_is_built(const rustsecp256k1_v0_1_2_ecmult_context *ctx);

/** Double multiply: R = na*A + ng*G */
static void rustsecp256k1_v0_1_2_ecmult(const rustsecp256k1_v0_1_2_ecmult_context *ctx, rustsecp256k1_v0_1_2_gej *r, const rustsecp256k1_v0_1_2_gej *a, const rustsecp256k1_v0_1_2_scalar *na, const rustsecp256k1_v0_1_2_scalar *ng);

typedef int (rustsecp256k1_v0_1_2_ecmult_multi_callback)(rustsecp256k1_v0_1_2_scalar *sc, rustsecp256k1_v0_1_2_ge *pt, size_t idx, void *data);

/**
 * Multi-multiply: R = inp_g_sc * G + sum_i ni * Ai.
 * Chooses the right algorithm for a given number of points and scratch space
 * size. Resets and overwrites the given scratch space. If the points do not
 * fit in the scratch space the algorithm is repeatedly run with batches of
 * points. If no scratch space is given then a simple algorithm is used that
 * simply multiplies the points with the corresponding scalars and adds them up.
 * Returns: 1 on success (including when inp_g_sc is NULL and n is 0)
 *          0 if there is not enough scratch space for a single point or
 *          callback returns 0
 */
static int rustsecp256k1_v0_1_2_ecmult_multi_var(const rustsecp256k1_v0_1_2_callback* error_callback, const rustsecp256k1_v0_1_2_ecmult_context *ctx, rustsecp256k1_v0_1_2_scratch *scratch, rustsecp256k1_v0_1_2_gej *r, const rustsecp256k1_v0_1_2_scalar *inp_g_sc, rustsecp256k1_v0_1_2_ecmult_multi_callback cb, void *cbdata, size_t n);

#endif /* SECP256K1_ECMULT_H */
