/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECMULT_GEN_H
#define SECP256K1_ECMULT_GEN_H

#include "scalar.h"
#include "group.h"

#ifndef ECMULT_GEN_PREC_BITS
#  define ECMULT_GEN_PREC_BITS 4
#  ifdef DEBUG_CONFIG
#     pragma message DEBUG_CONFIG_MSG("ECMULT_GEN_PREC_BITS undefined, assuming default value")
#  endif
#endif

#ifdef DEBUG_CONFIG
#  pragma message DEBUG_CONFIG_DEF(ECMULT_GEN_PREC_BITS)
#endif

#if ECMULT_GEN_PREC_BITS != 2 && ECMULT_GEN_PREC_BITS != 4 && ECMULT_GEN_PREC_BITS != 8
#  error "Set ECMULT_GEN_PREC_BITS to 2, 4 or 8."
#endif

#define ECMULT_GEN_PREC_G(bits) (1 << bits)
#define ECMULT_GEN_PREC_N(bits) (256 / bits)

typedef struct {
    /* Whether the context has been built. */
    int built;

    /* Blinding values used when computing (n-b)G + bG. */
    rustsecp256k1_v0_10_0_scalar blind; /* -b */
    rustsecp256k1_v0_10_0_gej initial;  /* bG */
} rustsecp256k1_v0_10_0_ecmult_gen_context;

static void rustsecp256k1_v0_10_0_ecmult_gen_context_build(rustsecp256k1_v0_10_0_ecmult_gen_context* ctx);
static void rustsecp256k1_v0_10_0_ecmult_gen_context_clear(rustsecp256k1_v0_10_0_ecmult_gen_context* ctx);

/** Multiply with the generator: R = a*G */
static void rustsecp256k1_v0_10_0_ecmult_gen(const rustsecp256k1_v0_10_0_ecmult_gen_context* ctx, rustsecp256k1_v0_10_0_gej *r, const rustsecp256k1_v0_10_0_scalar *a);

static void rustsecp256k1_v0_10_0_ecmult_gen_blind(rustsecp256k1_v0_10_0_ecmult_gen_context *ctx, const unsigned char *seed32);

#endif /* SECP256K1_ECMULT_GEN_H */
