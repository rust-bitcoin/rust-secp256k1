/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_FIELD_H
#define SECP256K1_FIELD_H

/** Field element module.
 *
 *  Field elements can be represented in several ways, but code accessing
 *  it (and implementations) need to take certain properties into account:
 *  - Each field element can be normalized or not.
 *  - Each field element has a magnitude, which represents how far away
 *    its representation is away from normalization. Normalized elements
 *    always have a magnitude of 1, but a magnitude of 1 doesn't imply
 *    normality.
 */

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#if defined(USE_FIELD_10X26)
#include "field_10x26.h"
#elif defined(USE_FIELD_5X52)
#include "field_5x52.h"
#else
#error "Please select field implementation"
#endif

#include "util.h"

/** Normalize a field element. This brings the field element to a canonical representation, reduces
 *  its magnitude to 1, and reduces it modulo field size `p`.
 */
static void rustsecp256k1_v0_1_2_fe_normalize(rustsecp256k1_v0_1_2_fe *r);

/** Weakly normalize a field element: reduce its magnitude to 1, but don't fully normalize. */
static void rustsecp256k1_v0_1_2_fe_normalize_weak(rustsecp256k1_v0_1_2_fe *r);

/** Normalize a field element, without constant-time guarantee. */
static void rustsecp256k1_v0_1_2_fe_normalize_var(rustsecp256k1_v0_1_2_fe *r);

/** Verify whether a field element represents zero i.e. would normalize to a zero value. The field
 *  implementation may optionally normalize the input, but this should not be relied upon. */
static int rustsecp256k1_v0_1_2_fe_normalizes_to_zero(rustsecp256k1_v0_1_2_fe *r);

/** Verify whether a field element represents zero i.e. would normalize to a zero value. The field
 *  implementation may optionally normalize the input, but this should not be relied upon. */
static int rustsecp256k1_v0_1_2_fe_normalizes_to_zero_var(rustsecp256k1_v0_1_2_fe *r);

/** Set a field element equal to a small integer. Resulting field element is normalized. */
static void rustsecp256k1_v0_1_2_fe_set_int(rustsecp256k1_v0_1_2_fe *r, int a);

/** Sets a field element equal to zero, initializing all fields. */
static void rustsecp256k1_v0_1_2_fe_clear(rustsecp256k1_v0_1_2_fe *a);

/** Verify whether a field element is zero. Requires the input to be normalized. */
static int rustsecp256k1_v0_1_2_fe_is_zero(const rustsecp256k1_v0_1_2_fe *a);

/** Check the "oddness" of a field element. Requires the input to be normalized. */
static int rustsecp256k1_v0_1_2_fe_is_odd(const rustsecp256k1_v0_1_2_fe *a);

/** Compare two field elements. Requires magnitude-1 inputs. */
static int rustsecp256k1_v0_1_2_fe_equal(const rustsecp256k1_v0_1_2_fe *a, const rustsecp256k1_v0_1_2_fe *b);

/** Same as rustsecp256k1_v0_1_2_fe_equal, but may be variable time. */
static int rustsecp256k1_v0_1_2_fe_equal_var(const rustsecp256k1_v0_1_2_fe *a, const rustsecp256k1_v0_1_2_fe *b);

/** Compare two field elements. Requires both inputs to be normalized */
static int rustsecp256k1_v0_1_2_fe_cmp_var(const rustsecp256k1_v0_1_2_fe *a, const rustsecp256k1_v0_1_2_fe *b);

/** Set a field element equal to 32-byte big endian value. If successful, the resulting field element is normalized. */
static int rustsecp256k1_v0_1_2_fe_set_b32(rustsecp256k1_v0_1_2_fe *r, const unsigned char *a);

/** Convert a field element to a 32-byte big endian value. Requires the input to be normalized */
static void rustsecp256k1_v0_1_2_fe_get_b32(unsigned char *r, const rustsecp256k1_v0_1_2_fe *a);

/** Set a field element equal to the additive inverse of another. Takes a maximum magnitude of the input
 *  as an argument. The magnitude of the output is one higher. */
static void rustsecp256k1_v0_1_2_fe_negate(rustsecp256k1_v0_1_2_fe *r, const rustsecp256k1_v0_1_2_fe *a, int m);

/** Multiplies the passed field element with a small integer constant. Multiplies the magnitude by that
 *  small integer. */
static void rustsecp256k1_v0_1_2_fe_mul_int(rustsecp256k1_v0_1_2_fe *r, int a);

/** Adds a field element to another. The result has the sum of the inputs' magnitudes as magnitude. */
static void rustsecp256k1_v0_1_2_fe_add(rustsecp256k1_v0_1_2_fe *r, const rustsecp256k1_v0_1_2_fe *a);

/** Sets a field element to be the product of two others. Requires the inputs' magnitudes to be at most 8.
 *  The output magnitude is 1 (but not guaranteed to be normalized). */
static void rustsecp256k1_v0_1_2_fe_mul(rustsecp256k1_v0_1_2_fe *r, const rustsecp256k1_v0_1_2_fe *a, const rustsecp256k1_v0_1_2_fe * SECP256K1_RESTRICT b);

/** Sets a field element to be the square of another. Requires the input's magnitude to be at most 8.
 *  The output magnitude is 1 (but not guaranteed to be normalized). */
static void rustsecp256k1_v0_1_2_fe_sqr(rustsecp256k1_v0_1_2_fe *r, const rustsecp256k1_v0_1_2_fe *a);

/** If a has a square root, it is computed in r and 1 is returned. If a does not
 *  have a square root, the root of its negation is computed and 0 is returned.
 *  The input's magnitude can be at most 8. The output magnitude is 1 (but not
 *  guaranteed to be normalized). The result in r will always be a square
 *  itself. */
static int rustsecp256k1_v0_1_2_fe_sqrt(rustsecp256k1_v0_1_2_fe *r, const rustsecp256k1_v0_1_2_fe *a);

/** Checks whether a field element is a quadratic residue. */
static int rustsecp256k1_v0_1_2_fe_is_quad_var(const rustsecp256k1_v0_1_2_fe *a);

/** Sets a field element to be the (modular) inverse of another. Requires the input's magnitude to be
 *  at most 8. The output magnitude is 1 (but not guaranteed to be normalized). */
static void rustsecp256k1_v0_1_2_fe_inv(rustsecp256k1_v0_1_2_fe *r, const rustsecp256k1_v0_1_2_fe *a);

/** Potentially faster version of rustsecp256k1_v0_1_2_fe_inv, without constant-time guarantee. */
static void rustsecp256k1_v0_1_2_fe_inv_var(rustsecp256k1_v0_1_2_fe *r, const rustsecp256k1_v0_1_2_fe *a);

/** Calculate the (modular) inverses of a batch of field elements. Requires the inputs' magnitudes to be
 *  at most 8. The output magnitudes are 1 (but not guaranteed to be normalized). The inputs and
 *  outputs must not overlap in memory. */
static void rustsecp256k1_v0_1_2_fe_inv_all_var(rustsecp256k1_v0_1_2_fe *r, const rustsecp256k1_v0_1_2_fe *a, size_t len);

/** Convert a field element to the storage type. */
static void rustsecp256k1_v0_1_2_fe_to_storage(rustsecp256k1_v0_1_2_fe_storage *r, const rustsecp256k1_v0_1_2_fe *a);

/** Convert a field element back from the storage type. */
static void rustsecp256k1_v0_1_2_fe_from_storage(rustsecp256k1_v0_1_2_fe *r, const rustsecp256k1_v0_1_2_fe_storage *a);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time. */
static void rustsecp256k1_v0_1_2_fe_storage_cmov(rustsecp256k1_v0_1_2_fe_storage *r, const rustsecp256k1_v0_1_2_fe_storage *a, int flag);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time. */
static void rustsecp256k1_v0_1_2_fe_cmov(rustsecp256k1_v0_1_2_fe *r, const rustsecp256k1_v0_1_2_fe *a, int flag);

#endif /* SECP256K1_FIELD_H */
