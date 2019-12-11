/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_ECMULT_GEN_H
#define SECP256K1_ECMULT_GEN_H

#include "scalar.h"
#include "group.h"

typedef struct {
    /* For accelerating the computation of a*G:
     * To harden against timing attacks, use the following mechanism:
     * * Break up the multiplicand into groups of 4 bits, called n_0, n_1, n_2, ..., n_63.
     * * Compute sum(n_i * 16^i * G + U_i, i=0..63), where:
     *   * U_i = U * 2^i (for i=0..62)
     *   * U_i = U * (1-2^63) (for i=63)
     *   where U is a point with no known corresponding scalar. Note that sum(U_i, i=0..63) = 0.
     * For each i, and each of the 16 possible values of n_i, (n_i * 16^i * G + U_i) is
     * precomputed (call it prec(i, n_i)). The formula now becomes sum(prec(i, n_i), i=0..63).
     * None of the resulting prec group elements have a known scalar, and neither do any of
     * the intermediate sums while computing a*G.
     */
    rustsecp256k1_v0_1_1_ge_storage (*prec)[64][16]; /* prec[j][i] = 16^j * i * G + U_i */
    rustsecp256k1_v0_1_1_scalar blind;
    rustsecp256k1_v0_1_1_gej initial;
} rustsecp256k1_v0_1_1_ecmult_gen_context;

static const size_t SECP256K1_ECMULT_GEN_CONTEXT_PREALLOCATED_SIZE;
static void rustsecp256k1_v0_1_1_ecmult_gen_context_init(rustsecp256k1_v0_1_1_ecmult_gen_context* ctx);
static void rustsecp256k1_v0_1_1_ecmult_gen_context_build(rustsecp256k1_v0_1_1_ecmult_gen_context* ctx, void **prealloc);
static void rustsecp256k1_v0_1_1_ecmult_gen_context_finalize_memcpy(rustsecp256k1_v0_1_1_ecmult_gen_context *dst, const rustsecp256k1_v0_1_1_ecmult_gen_context* src);
static void rustsecp256k1_v0_1_1_ecmult_gen_context_clear(rustsecp256k1_v0_1_1_ecmult_gen_context* ctx);
static int rustsecp256k1_v0_1_1_ecmult_gen_context_is_built(const rustsecp256k1_v0_1_1_ecmult_gen_context* ctx);

/** Multiply with the generator: R = a*G */
static void rustsecp256k1_v0_1_1_ecmult_gen(const rustsecp256k1_v0_1_1_ecmult_gen_context* ctx, rustsecp256k1_v0_1_1_gej *r, const rustsecp256k1_v0_1_1_scalar *a);

static void rustsecp256k1_v0_1_1_ecmult_gen_blind(rustsecp256k1_v0_1_1_ecmult_gen_context *ctx, const unsigned char *seed32);

#endif /* SECP256K1_ECMULT_GEN_H */
