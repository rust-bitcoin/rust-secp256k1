/***********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_SCALAR_H
#define SECP256K1_SCALAR_H

#include "util.h"

#if defined(EXHAUSTIVE_TEST_ORDER)
#include "scalar_low.h"
#elif defined(SECP256K1_WIDEMUL_INT128)
#include "scalar_4x64.h"
#elif defined(SECP256K1_WIDEMUL_INT64)
#include "scalar_8x32.h"
#else
#error "Please select wide multiplication implementation"
#endif

/** Clear a scalar to prevent the leak of sensitive data. */
static void rustsecp256k1_v0_9_2_scalar_clear(rustsecp256k1_v0_9_2_scalar *r);

/** Access bits from a scalar. All requested bits must belong to the same 32-bit limb. */
static unsigned int rustsecp256k1_v0_9_2_scalar_get_bits(const rustsecp256k1_v0_9_2_scalar *a, unsigned int offset, unsigned int count);

/** Access bits from a scalar. Not constant time. */
static unsigned int rustsecp256k1_v0_9_2_scalar_get_bits_var(const rustsecp256k1_v0_9_2_scalar *a, unsigned int offset, unsigned int count);

/** Set a scalar from a big endian byte array. The scalar will be reduced modulo group order `n`.
 * In:      bin:        pointer to a 32-byte array.
 * Out:     r:          scalar to be set.
 *          overflow:   non-zero if the scalar was bigger or equal to `n` before reduction, zero otherwise (can be NULL).
 */
static void rustsecp256k1_v0_9_2_scalar_set_b32(rustsecp256k1_v0_9_2_scalar *r, const unsigned char *bin, int *overflow);

/** Set a scalar from a big endian byte array and returns 1 if it is a valid
 *  seckey and 0 otherwise. */
static int rustsecp256k1_v0_9_2_scalar_set_b32_seckey(rustsecp256k1_v0_9_2_scalar *r, const unsigned char *bin);

/** Set a scalar to an unsigned integer. */
static void rustsecp256k1_v0_9_2_scalar_set_int(rustsecp256k1_v0_9_2_scalar *r, unsigned int v);

/** Convert a scalar to a byte array. */
static void rustsecp256k1_v0_9_2_scalar_get_b32(unsigned char *bin, const rustsecp256k1_v0_9_2_scalar* a);

/** Add two scalars together (modulo the group order). Returns whether it overflowed. */
static int rustsecp256k1_v0_9_2_scalar_add(rustsecp256k1_v0_9_2_scalar *r, const rustsecp256k1_v0_9_2_scalar *a, const rustsecp256k1_v0_9_2_scalar *b);

/** Conditionally add a power of two to a scalar. The result is not allowed to overflow. */
static void rustsecp256k1_v0_9_2_scalar_cadd_bit(rustsecp256k1_v0_9_2_scalar *r, unsigned int bit, int flag);

/** Multiply two scalars (modulo the group order). */
static void rustsecp256k1_v0_9_2_scalar_mul(rustsecp256k1_v0_9_2_scalar *r, const rustsecp256k1_v0_9_2_scalar *a, const rustsecp256k1_v0_9_2_scalar *b);

/** Shift a scalar right by some amount strictly between 0 and 16, returning
 *  the low bits that were shifted off */
static int rustsecp256k1_v0_9_2_scalar_shr_int(rustsecp256k1_v0_9_2_scalar *r, int n);

/** Compute the inverse of a scalar (modulo the group order). */
static void rustsecp256k1_v0_9_2_scalar_inverse(rustsecp256k1_v0_9_2_scalar *r, const rustsecp256k1_v0_9_2_scalar *a);

/** Compute the inverse of a scalar (modulo the group order), without constant-time guarantee. */
static void rustsecp256k1_v0_9_2_scalar_inverse_var(rustsecp256k1_v0_9_2_scalar *r, const rustsecp256k1_v0_9_2_scalar *a);

/** Compute the complement of a scalar (modulo the group order). */
static void rustsecp256k1_v0_9_2_scalar_negate(rustsecp256k1_v0_9_2_scalar *r, const rustsecp256k1_v0_9_2_scalar *a);

/** Check whether a scalar equals zero. */
static int rustsecp256k1_v0_9_2_scalar_is_zero(const rustsecp256k1_v0_9_2_scalar *a);

/** Check whether a scalar equals one. */
static int rustsecp256k1_v0_9_2_scalar_is_one(const rustsecp256k1_v0_9_2_scalar *a);

/** Check whether a scalar, considered as an nonnegative integer, is even. */
static int rustsecp256k1_v0_9_2_scalar_is_even(const rustsecp256k1_v0_9_2_scalar *a);

/** Check whether a scalar is higher than the group order divided by 2. */
static int rustsecp256k1_v0_9_2_scalar_is_high(const rustsecp256k1_v0_9_2_scalar *a);

/** Conditionally negate a number, in constant time.
 * Returns -1 if the number was negated, 1 otherwise */
static int rustsecp256k1_v0_9_2_scalar_cond_negate(rustsecp256k1_v0_9_2_scalar *a, int flag);

/** Compare two scalars. */
static int rustsecp256k1_v0_9_2_scalar_eq(const rustsecp256k1_v0_9_2_scalar *a, const rustsecp256k1_v0_9_2_scalar *b);

/** Find r1 and r2 such that r1+r2*2^128 = k. */
static void rustsecp256k1_v0_9_2_scalar_split_128(rustsecp256k1_v0_9_2_scalar *r1, rustsecp256k1_v0_9_2_scalar *r2, const rustsecp256k1_v0_9_2_scalar *k);
/** Find r1 and r2 such that r1+r2*lambda = k, where r1 and r2 or their
 *  negations are maximum 128 bits long (see rustsecp256k1_v0_9_2_ge_mul_lambda). It is
 *  required that r1, r2, and k all point to different objects. */
static void rustsecp256k1_v0_9_2_scalar_split_lambda(rustsecp256k1_v0_9_2_scalar * SECP256K1_RESTRICT r1, rustsecp256k1_v0_9_2_scalar * SECP256K1_RESTRICT r2, const rustsecp256k1_v0_9_2_scalar * SECP256K1_RESTRICT k);

/** Multiply a and b (without taking the modulus!), divide by 2**shift, and round to the nearest integer. Shift must be at least 256. */
static void rustsecp256k1_v0_9_2_scalar_mul_shift_var(rustsecp256k1_v0_9_2_scalar *r, const rustsecp256k1_v0_9_2_scalar *a, const rustsecp256k1_v0_9_2_scalar *b, unsigned int shift);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time.  Both *r and *a must be initialized.*/
static void rustsecp256k1_v0_9_2_scalar_cmov(rustsecp256k1_v0_9_2_scalar *r, const rustsecp256k1_v0_9_2_scalar *a, int flag);

/** Check invariants on a scalar (no-op unless VERIFY is enabled). */
static void rustsecp256k1_v0_9_2_scalar_verify(const rustsecp256k1_v0_9_2_scalar *r);

#endif /* SECP256K1_SCALAR_H */
