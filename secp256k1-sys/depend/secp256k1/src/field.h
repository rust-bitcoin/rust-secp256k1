/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_FIELD_H
#define SECP256K1_FIELD_H

#include "util.h"

/* This file defines the generic interface for working with rustsecp256k1_v0_10_0_fe
 * objects, which represent field elements (integers modulo 2^256 - 2^32 - 977).
 *
 * The actual definition of the rustsecp256k1_v0_10_0_fe type depends on the chosen field
 * implementation; see the field_5x52.h and field_10x26.h files for details.
 *
 * All rustsecp256k1_v0_10_0_fe objects have implicit properties that determine what
 * operations are permitted on it. These are purely a function of what
 * rustsecp256k1_v0_10_0_fe_ operations are applied on it, generally (implicitly) fixed at
 * compile time, and do not depend on the chosen field implementation. Despite
 * that, what these properties actually entail for the field representation
 * values depends on the chosen field implementation. These properties are:
 * - magnitude: an integer in [0,32]
 * - normalized: 0 or 1; normalized=1 implies magnitude <= 1.
 *
 * In VERIFY mode, they are materialized explicitly as fields in the struct,
 * allowing run-time verification of these properties. In that case, the field
 * implementation also provides a rustsecp256k1_v0_10_0_fe_verify routine to verify that
 * these fields match the run-time value and perform internal consistency
 * checks. */
#ifdef VERIFY
#  define SECP256K1_FE_VERIFY_FIELDS \
    int magnitude; \
    int normalized;
#else
#  define SECP256K1_FE_VERIFY_FIELDS
#endif

#if defined(SECP256K1_WIDEMUL_INT128)
#include "field_5x52.h"
#elif defined(SECP256K1_WIDEMUL_INT64)
#include "field_10x26.h"
#else
#error "Please select wide multiplication implementation"
#endif

#ifdef VERIFY
/* Magnitude and normalized value for constants. */
#define SECP256K1_FE_VERIFY_CONST(d7, d6, d5, d4, d3, d2, d1, d0) \
    /* Magnitude is 0 for constant 0; 1 otherwise. */ \
    , (((d7) | (d6) | (d5) | (d4) | (d3) | (d2) | (d1) | (d0)) != 0) \
    /* Normalized is 1 unless sum(d_i<<(32*i) for i=0..7) exceeds field modulus. */ \
    , (!(((d7) & (d6) & (d5) & (d4) & (d3) & (d2)) == 0xfffffffful && ((d1) == 0xfffffffful || ((d1) == 0xfffffffe && (d0 >= 0xfffffc2f)))))
#else
#define SECP256K1_FE_VERIFY_CONST(d7, d6, d5, d4, d3, d2, d1, d0)
#endif

/** This expands to an initializer for a rustsecp256k1_v0_10_0_fe valued sum((i*32) * d_i, i=0..7) mod p.
 *
 * It has magnitude 1, unless d_i are all 0, in which case the magnitude is 0.
 * It is normalized, unless sum(2^(i*32) * d_i, i=0..7) >= p.
 *
 * SECP256K1_FE_CONST_INNER is provided by the implementation.
 */
#define SECP256K1_FE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0)) SECP256K1_FE_VERIFY_CONST((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0)) }

static const rustsecp256k1_v0_10_0_fe rustsecp256k1_v0_10_0_fe_one = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1);
static const rustsecp256k1_v0_10_0_fe rustsecp256k1_v0_10_0_const_beta = SECP256K1_FE_CONST(
    0x7ae96a2bul, 0x657c0710ul, 0x6e64479eul, 0xac3434e9ul,
    0x9cf04975ul, 0x12f58995ul, 0xc1396c28ul, 0x719501eeul
);

#ifndef VERIFY
/* In non-VERIFY mode, we #define the fe operations to be identical to their
 * internal field implementation, to avoid the potential overhead of a
 * function call (even though presumably inlinable). */
#  define rustsecp256k1_v0_10_0_fe_normalize rustsecp256k1_v0_10_0_fe_impl_normalize
#  define rustsecp256k1_v0_10_0_fe_normalize_weak rustsecp256k1_v0_10_0_fe_impl_normalize_weak
#  define rustsecp256k1_v0_10_0_fe_normalize_var rustsecp256k1_v0_10_0_fe_impl_normalize_var
#  define rustsecp256k1_v0_10_0_fe_normalizes_to_zero rustsecp256k1_v0_10_0_fe_impl_normalizes_to_zero
#  define rustsecp256k1_v0_10_0_fe_normalizes_to_zero_var rustsecp256k1_v0_10_0_fe_impl_normalizes_to_zero_var
#  define rustsecp256k1_v0_10_0_fe_set_int rustsecp256k1_v0_10_0_fe_impl_set_int
#  define rustsecp256k1_v0_10_0_fe_clear rustsecp256k1_v0_10_0_fe_impl_clear
#  define rustsecp256k1_v0_10_0_fe_is_zero rustsecp256k1_v0_10_0_fe_impl_is_zero
#  define rustsecp256k1_v0_10_0_fe_is_odd rustsecp256k1_v0_10_0_fe_impl_is_odd
#  define rustsecp256k1_v0_10_0_fe_cmp_var rustsecp256k1_v0_10_0_fe_impl_cmp_var
#  define rustsecp256k1_v0_10_0_fe_set_b32_mod rustsecp256k1_v0_10_0_fe_impl_set_b32_mod
#  define rustsecp256k1_v0_10_0_fe_set_b32_limit rustsecp256k1_v0_10_0_fe_impl_set_b32_limit
#  define rustsecp256k1_v0_10_0_fe_get_b32 rustsecp256k1_v0_10_0_fe_impl_get_b32
#  define rustsecp256k1_v0_10_0_fe_negate_unchecked rustsecp256k1_v0_10_0_fe_impl_negate_unchecked
#  define rustsecp256k1_v0_10_0_fe_mul_int_unchecked rustsecp256k1_v0_10_0_fe_impl_mul_int_unchecked
#  define rustsecp256k1_v0_10_0_fe_add rustsecp256k1_v0_10_0_fe_impl_add
#  define rustsecp256k1_v0_10_0_fe_mul rustsecp256k1_v0_10_0_fe_impl_mul
#  define rustsecp256k1_v0_10_0_fe_sqr rustsecp256k1_v0_10_0_fe_impl_sqr
#  define rustsecp256k1_v0_10_0_fe_cmov rustsecp256k1_v0_10_0_fe_impl_cmov
#  define rustsecp256k1_v0_10_0_fe_to_storage rustsecp256k1_v0_10_0_fe_impl_to_storage
#  define rustsecp256k1_v0_10_0_fe_from_storage rustsecp256k1_v0_10_0_fe_impl_from_storage
#  define rustsecp256k1_v0_10_0_fe_inv rustsecp256k1_v0_10_0_fe_impl_inv
#  define rustsecp256k1_v0_10_0_fe_inv_var rustsecp256k1_v0_10_0_fe_impl_inv_var
#  define rustsecp256k1_v0_10_0_fe_get_bounds rustsecp256k1_v0_10_0_fe_impl_get_bounds
#  define rustsecp256k1_v0_10_0_fe_half rustsecp256k1_v0_10_0_fe_impl_half
#  define rustsecp256k1_v0_10_0_fe_add_int rustsecp256k1_v0_10_0_fe_impl_add_int
#  define rustsecp256k1_v0_10_0_fe_is_square_var rustsecp256k1_v0_10_0_fe_impl_is_square_var
#endif /* !defined(VERIFY) */

/** Normalize a field element.
 *
 * On input, r must be a valid field element.
 * On output, r represents the same value but has normalized=1 and magnitude=1.
 */
static void rustsecp256k1_v0_10_0_fe_normalize(rustsecp256k1_v0_10_0_fe *r);

/** Give a field element magnitude 1.
 *
 * On input, r must be a valid field element.
 * On output, r represents the same value but has magnitude=1. Normalized is unchanged.
 */
static void rustsecp256k1_v0_10_0_fe_normalize_weak(rustsecp256k1_v0_10_0_fe *r);

/** Normalize a field element, without constant-time guarantee.
 *
 * Identical in behavior to rustsecp256k1_v0_10_0_fe_normalize, but not constant time in r.
 */
static void rustsecp256k1_v0_10_0_fe_normalize_var(rustsecp256k1_v0_10_0_fe *r);

/** Determine whether r represents field element 0.
 *
 * On input, r must be a valid field element.
 * Returns whether r = 0 (mod p).
 */
static int rustsecp256k1_v0_10_0_fe_normalizes_to_zero(const rustsecp256k1_v0_10_0_fe *r);

/** Determine whether r represents field element 0, without constant-time guarantee.
 *
 * Identical in behavior to rustsecp256k1_v0_10_0_normalizes_to_zero, but not constant time in r.
 */
static int rustsecp256k1_v0_10_0_fe_normalizes_to_zero_var(const rustsecp256k1_v0_10_0_fe *r);

/** Set a field element to an integer in range [0,0x7FFF].
 *
 * On input, r does not need to be initialized, a must be in [0,0x7FFF].
 * On output, r represents value a, is normalized and has magnitude (a!=0).
 */
static void rustsecp256k1_v0_10_0_fe_set_int(rustsecp256k1_v0_10_0_fe *r, int a);

/** Set a field element to 0.
 *
 * On input, a does not need to be initialized.
 * On output, a represents 0, is normalized and has magnitude 0.
 */
static void rustsecp256k1_v0_10_0_fe_clear(rustsecp256k1_v0_10_0_fe *a);

/** Determine whether a represents field element 0.
 *
 * On input, a must be a valid normalized field element.
 * Returns whether a = 0 (mod p).
 *
 * This behaves identical to rustsecp256k1_v0_10_0_normalizes_to_zero{,_var}, but requires
 * normalized input (and is much faster).
 */
static int rustsecp256k1_v0_10_0_fe_is_zero(const rustsecp256k1_v0_10_0_fe *a);

/** Determine whether a (mod p) is odd.
 *
 * On input, a must be a valid normalized field element.
 * Returns (int(a) mod p) & 1.
 */
static int rustsecp256k1_v0_10_0_fe_is_odd(const rustsecp256k1_v0_10_0_fe *a);

/** Determine whether two field elements are equal.
 *
 * On input, a and b must be valid field elements with magnitudes not exceeding
 * 1 and 31, respectively.
 * Returns a = b (mod p).
 */
static int rustsecp256k1_v0_10_0_fe_equal(const rustsecp256k1_v0_10_0_fe *a, const rustsecp256k1_v0_10_0_fe *b);

/** Compare the values represented by 2 field elements, without constant-time guarantee.
 *
 * On input, a and b must be valid normalized field elements.
 * Returns 1 if a > b, -1 if a < b, and 0 if a = b (comparisons are done as integers
 * in range 0..p-1).
 */
static int rustsecp256k1_v0_10_0_fe_cmp_var(const rustsecp256k1_v0_10_0_fe *a, const rustsecp256k1_v0_10_0_fe *b);

/** Set a field element equal to the element represented by a provided 32-byte big endian value
 * interpreted modulo p.
 *
 * On input, r does not need to be initialized. a must be a pointer to an initialized 32-byte array.
 * On output, r = a (mod p). It will have magnitude 1, and not be normalized.
 */
static void rustsecp256k1_v0_10_0_fe_set_b32_mod(rustsecp256k1_v0_10_0_fe *r, const unsigned char *a);

/** Set a field element equal to a provided 32-byte big endian value, checking for overflow.
 *
 * On input, r does not need to be initialized. a must be a pointer to an initialized 32-byte array.
 * On output, r = a if (a < p), it will be normalized with magnitude 1, and 1 is returned.
 * If a >= p, 0 is returned, and r will be made invalid (and must not be used without overwriting).
 */
static int rustsecp256k1_v0_10_0_fe_set_b32_limit(rustsecp256k1_v0_10_0_fe *r, const unsigned char *a);

/** Convert a field element to 32-byte big endian byte array.
 * On input, a must be a valid normalized field element, and r a pointer to a 32-byte array.
 * On output, r = a (mod p).
 */
static void rustsecp256k1_v0_10_0_fe_get_b32(unsigned char *r, const rustsecp256k1_v0_10_0_fe *a);

/** Negate a field element.
 *
 * On input, r does not need to be initialized. a must be a valid field element with
 * magnitude not exceeding m. m must be an integer constant expression in [0,31].
 * Performs {r = -a}.
 * On output, r will not be normalized, and will have magnitude m+1.
 */
#define rustsecp256k1_v0_10_0_fe_negate(r, a, m) ASSERT_INT_CONST_AND_DO(m, rustsecp256k1_v0_10_0_fe_negate_unchecked(r, a, m))

/** Like rustsecp256k1_v0_10_0_fe_negate_unchecked but m is not checked to be an integer constant expression.
 *
 * Should not be called directly outside of tests.
 */
static void rustsecp256k1_v0_10_0_fe_negate_unchecked(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a, int m);

/** Add a small integer to a field element.
 *
 * Performs {r += a}. The magnitude of r increases by 1, and normalized is cleared.
 * a must be in range [0,0x7FFF].
 */
static void rustsecp256k1_v0_10_0_fe_add_int(rustsecp256k1_v0_10_0_fe *r, int a);

/** Multiply a field element with a small integer.
 *
 * On input, r must be a valid field element. a must be an integer constant expression in [0,32].
 * The magnitude of r times a must not exceed 32.
 * Performs {r *= a}.
 * On output, r's magnitude is multiplied by a, and r will not be normalized.
 */
#define rustsecp256k1_v0_10_0_fe_mul_int(r, a) ASSERT_INT_CONST_AND_DO(a, rustsecp256k1_v0_10_0_fe_mul_int_unchecked(r, a))

/** Like rustsecp256k1_v0_10_0_fe_mul_int but a is not checked to be an integer constant expression.
 * 
 * Should not be called directly outside of tests.
 */
static void rustsecp256k1_v0_10_0_fe_mul_int_unchecked(rustsecp256k1_v0_10_0_fe *r, int a);

/** Increment a field element by another.
 *
 * On input, r and a must be valid field elements, not necessarily normalized.
 * The sum of their magnitudes must not exceed 32.
 * Performs {r += a}.
 * On output, r will not be normalized, and will have magnitude incremented by a's.
 */
static void rustsecp256k1_v0_10_0_fe_add(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a);

/** Multiply two field elements.
 *
 * On input, a and b must be valid field elements; r does not need to be initialized.
 * r and a may point to the same object, but neither can be equal to b. The magnitudes
 * of a and b must not exceed 8.
 * Performs {r = a * b}
 * On output, r will have magnitude 1, but won't be normalized.
 */
static void rustsecp256k1_v0_10_0_fe_mul(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a, const rustsecp256k1_v0_10_0_fe * SECP256K1_RESTRICT b);

/** Square a field element.
 *
 * On input, a must be a valid field element; r does not need to be initialized. The magnitude
 * of a must not exceed 8.
 * Performs {r = a**2}
 * On output, r will have magnitude 1, but won't be normalized.
 */
static void rustsecp256k1_v0_10_0_fe_sqr(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a);

/** Compute a square root of a field element.
 *
 * On input, a must be a valid field element with magnitude<=8; r need not be initialized.
 * If sqrt(a) exists, performs {r = sqrt(a)} and returns 1.
 * Otherwise, sqrt(-a) exists. The function performs {r = sqrt(-a)} and returns 0.
 * The resulting value represented by r will be a square itself.
 * Variables r and a must not point to the same object.
 * On output, r will have magnitude 1 but will not be normalized.
 */
static int rustsecp256k1_v0_10_0_fe_sqrt(rustsecp256k1_v0_10_0_fe * SECP256K1_RESTRICT r, const rustsecp256k1_v0_10_0_fe * SECP256K1_RESTRICT a);

/** Compute the modular inverse of a field element.
 *
 * On input, a must be a valid field element; r need not be initialized.
 * Performs {r = a**(p-2)} (which maps 0 to 0, and every other element to its
 * inverse).
 * On output, r will have magnitude (a.magnitude != 0) and be normalized.
 */
static void rustsecp256k1_v0_10_0_fe_inv(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a);

/** Compute the modular inverse of a field element, without constant-time guarantee.
 *
 * Behaves identically to rustsecp256k1_v0_10_0_fe_inv, but is not constant-time in a.
 */
static void rustsecp256k1_v0_10_0_fe_inv_var(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a);

/** Convert a field element to rustsecp256k1_v0_10_0_fe_storage.
 *
 * On input, a must be a valid normalized field element.
 * Performs {r = a}.
 */
static void rustsecp256k1_v0_10_0_fe_to_storage(rustsecp256k1_v0_10_0_fe_storage *r, const rustsecp256k1_v0_10_0_fe *a);

/** Convert a field element back from rustsecp256k1_v0_10_0_fe_storage.
 *
 * On input, r need not be initialized.
 * Performs {r = a}.
 * On output, r will be normalized and will have magnitude 1.
 */
static void rustsecp256k1_v0_10_0_fe_from_storage(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe_storage *a);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time.  Both *r and *a must be initialized.*/
static void rustsecp256k1_v0_10_0_fe_storage_cmov(rustsecp256k1_v0_10_0_fe_storage *r, const rustsecp256k1_v0_10_0_fe_storage *a, int flag);

/** Conditionally move a field element in constant time.
 *
 * On input, both r and a must be valid field elements. Flag must be 0 or 1.
 * Performs {r = flag ? a : r}.
 *
 * On output, r's magnitude will be the maximum of both input magnitudes.
 * It will be normalized if and only if both inputs were normalized.
 */
static void rustsecp256k1_v0_10_0_fe_cmov(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a, int flag);

/** Halve the value of a field element modulo the field prime in constant-time.
 *
 * On input, r must be a valid field element.
 * On output, r will be normalized and have magnitude floor(m/2) + 1 where m is
 * the magnitude of r on input.
 */
static void rustsecp256k1_v0_10_0_fe_half(rustsecp256k1_v0_10_0_fe *r);

/** Sets r to a field element with magnitude m, normalized if (and only if) m==0.
 *  The value is chosen so that it is likely to trigger edge cases related to
 *  internal overflows. */
static void rustsecp256k1_v0_10_0_fe_get_bounds(rustsecp256k1_v0_10_0_fe *r, int m);

/** Determine whether a is a square (modulo p).
 *
 * On input, a must be a valid field element.
 */
static int rustsecp256k1_v0_10_0_fe_is_square_var(const rustsecp256k1_v0_10_0_fe *a);

/** Check invariants on a field element (no-op unless VERIFY is enabled). */
static void rustsecp256k1_v0_10_0_fe_verify(const rustsecp256k1_v0_10_0_fe *a);
#define SECP256K1_FE_VERIFY(a) rustsecp256k1_v0_10_0_fe_verify(a)

/** Check that magnitude of a is at most m (no-op unless VERIFY is enabled). */
static void rustsecp256k1_v0_10_0_fe_verify_magnitude(const rustsecp256k1_v0_10_0_fe *a, int m);
#define SECP256K1_FE_VERIFY_MAGNITUDE(a, m) rustsecp256k1_v0_10_0_fe_verify_magnitude(a, m)

#endif /* SECP256K1_FIELD_H */
