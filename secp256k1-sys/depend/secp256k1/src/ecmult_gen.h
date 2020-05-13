/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_ECMULT_GEN_H
#define SECP256K1_ECMULT_GEN_H

#include "scalar.h"
#include "group.h"

#if ECMULT_GEN_PREC_BITS != 2 && ECMULT_GEN_PREC_BITS != 4 && ECMULT_GEN_PREC_BITS != 8
#  error "Set ECMULT_GEN_PREC_BITS to 2, 4 or 8."
#endif
#define ECMULT_GEN_PREC_B ECMULT_GEN_PREC_BITS
#define ECMULT_GEN_PREC_G (1 << ECMULT_GEN_PREC_B)
#define ECMULT_GEN_PREC_N (256 / ECMULT_GEN_PREC_B)

typedef struct {
    /* For accelerating the computation of a*G:
     * To harden against timing attacks, use the following mechanism:
     * * Break up the multiplicand into groups of PREC_B bits, called n_0, n_1, n_2, ..., n_(PREC_N-1).
     * * Compute sum(n_i * (PREC_G)^i * G + U_i, i=0 ... PREC_N-1), where:
     *   * U_i = U * 2^i, for i=0 ... PREC_N-2
     *   * U_i = U * (1-2^(PREC_N-1)), for i=PREC_N-1
     *   where U is a point with no known corresponding scalar. Note that sum(U_i, i=0 ... PREC_N-1) = 0.
     * For each i, and each of the PREC_G possible values of n_i, (n_i * (PREC_G)^i * G + U_i) is
     * precomputed (call it prec(i, n_i)). The formula now becomes sum(prec(i, n_i), i=0 ... PREC_N-1).
     * None of the resulting prec group elements have a known scalar, and neither do any of
     * the intermediate sums while computing a*G.
     */
    rustsecp256k1_v0_1_2_ge_storage (*prec)[ECMULT_GEN_PREC_N][ECMULT_GEN_PREC_G]; /* prec[j][i] = (PREC_G)^j * i * G + U_i */
    rustsecp256k1_v0_1_2_scalar blind;
    rustsecp256k1_v0_1_2_gej initial;
} rustsecp256k1_v0_1_2_ecmult_gen_context;

static const size_t SECP256K1_ECMULT_GEN_CONTEXT_PREALLOCATED_SIZE;
static void rustsecp256k1_v0_1_2_ecmult_gen_context_init(rustsecp256k1_v0_1_2_ecmult_gen_context* ctx);
static void rustsecp256k1_v0_1_2_ecmult_gen_context_build(rustsecp256k1_v0_1_2_ecmult_gen_context* ctx, void **prealloc);
static void rustsecp256k1_v0_1_2_ecmult_gen_context_finalize_memcpy(rustsecp256k1_v0_1_2_ecmult_gen_context *dst, const rustsecp256k1_v0_1_2_ecmult_gen_context* src);
static void rustsecp256k1_v0_1_2_ecmult_gen_context_clear(rustsecp256k1_v0_1_2_ecmult_gen_context* ctx);
static int rustsecp256k1_v0_1_2_ecmult_gen_context_is_built(const rustsecp256k1_v0_1_2_ecmult_gen_context* ctx);

/** Multiply with the generator: R = a*G */
static void rustsecp256k1_v0_1_2_ecmult_gen(const rustsecp256k1_v0_1_2_ecmult_gen_context* ctx, rustsecp256k1_v0_1_2_gej *r, const rustsecp256k1_v0_1_2_scalar *a);

static void rustsecp256k1_v0_1_2_ecmult_gen_blind(rustsecp256k1_v0_1_2_ecmult_gen_context *ctx, const unsigned char *seed32);

#endif /* SECP256K1_ECMULT_GEN_H */
