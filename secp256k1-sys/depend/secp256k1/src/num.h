/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_NUM_H
#define SECP256K1_NUM_H

#ifndef USE_NUM_NONE

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#if defined(USE_NUM_GMP)
#include "num_gmp.h"
#else
#error "Please select num implementation"
#endif

/** Copy a number. */
static void rustsecp256k1_v0_1_2_num_copy(rustsecp256k1_v0_1_2_num *r, const rustsecp256k1_v0_1_2_num *a);

/** Convert a number's absolute value to a binary big-endian string.
 *  There must be enough place. */
static void rustsecp256k1_v0_1_2_num_get_bin(unsigned char *r, unsigned int rlen, const rustsecp256k1_v0_1_2_num *a);

/** Set a number to the value of a binary big-endian string. */
static void rustsecp256k1_v0_1_2_num_set_bin(rustsecp256k1_v0_1_2_num *r, const unsigned char *a, unsigned int alen);

/** Compute a modular inverse. The input must be less than the modulus. */
static void rustsecp256k1_v0_1_2_num_mod_inverse(rustsecp256k1_v0_1_2_num *r, const rustsecp256k1_v0_1_2_num *a, const rustsecp256k1_v0_1_2_num *m);

/** Compute the jacobi symbol (a|b). b must be positive and odd. */
static int rustsecp256k1_v0_1_2_num_jacobi(const rustsecp256k1_v0_1_2_num *a, const rustsecp256k1_v0_1_2_num *b);

/** Compare the absolute value of two numbers. */
static int rustsecp256k1_v0_1_2_num_cmp(const rustsecp256k1_v0_1_2_num *a, const rustsecp256k1_v0_1_2_num *b);

/** Test whether two number are equal (including sign). */
static int rustsecp256k1_v0_1_2_num_eq(const rustsecp256k1_v0_1_2_num *a, const rustsecp256k1_v0_1_2_num *b);

/** Add two (signed) numbers. */
static void rustsecp256k1_v0_1_2_num_add(rustsecp256k1_v0_1_2_num *r, const rustsecp256k1_v0_1_2_num *a, const rustsecp256k1_v0_1_2_num *b);

/** Subtract two (signed) numbers. */
static void rustsecp256k1_v0_1_2_num_sub(rustsecp256k1_v0_1_2_num *r, const rustsecp256k1_v0_1_2_num *a, const rustsecp256k1_v0_1_2_num *b);

/** Multiply two (signed) numbers. */
static void rustsecp256k1_v0_1_2_num_mul(rustsecp256k1_v0_1_2_num *r, const rustsecp256k1_v0_1_2_num *a, const rustsecp256k1_v0_1_2_num *b);

/** Replace a number by its remainder modulo m. M's sign is ignored. The result is a number between 0 and m-1,
    even if r was negative. */
static void rustsecp256k1_v0_1_2_num_mod(rustsecp256k1_v0_1_2_num *r, const rustsecp256k1_v0_1_2_num *m);

/** Right-shift the passed number by bits bits. */
static void rustsecp256k1_v0_1_2_num_shift(rustsecp256k1_v0_1_2_num *r, int bits);

/** Check whether a number is zero. */
static int rustsecp256k1_v0_1_2_num_is_zero(const rustsecp256k1_v0_1_2_num *a);

/** Check whether a number is one. */
static int rustsecp256k1_v0_1_2_num_is_one(const rustsecp256k1_v0_1_2_num *a);

/** Check whether a number is strictly negative. */
static int rustsecp256k1_v0_1_2_num_is_neg(const rustsecp256k1_v0_1_2_num *a);

/** Change a number's sign. */
static void rustsecp256k1_v0_1_2_num_negate(rustsecp256k1_v0_1_2_num *r);

#endif

#endif /* SECP256K1_NUM_H */
