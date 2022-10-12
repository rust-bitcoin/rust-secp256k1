/***********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECMULT_CONST_H
#define SECP256K1_ECMULT_CONST_H

#include "scalar.h"
#include "group.h"

/**
 * Multiply: R = q*A (in constant-time)
 * Here `bits` should be set to the maximum bitlength of the _absolute value_ of `q`, plus
 * one because we internally sometimes add 2 to the number during the WNAF conversion.
 * A must not be infinity.
 */
static void rustsecp256k1_v0_6_1_ecmult_const(rustsecp256k1_v0_6_1_gej *r, const rustsecp256k1_v0_6_1_ge *a, const rustsecp256k1_v0_6_1_scalar *q, int bits);

#endif /* SECP256K1_ECMULT_CONST_H */
