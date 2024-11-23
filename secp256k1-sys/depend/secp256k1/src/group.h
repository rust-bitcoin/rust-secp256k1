/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_GROUP_H
#define SECP256K1_GROUP_H

#include "field.h"

/** A group element in affine coordinates on the secp256k1 curve,
 *  or occasionally on an isomorphic curve of the form y^2 = x^3 + 7*t^6.
 *  Note: For exhaustive test mode, secp256k1 is replaced by a small subgroup of a different curve.
 */
typedef struct {
    rustsecp256k1_v0_11_fe x;
    rustsecp256k1_v0_11_fe y;
    int infinity; /* whether this represents the point at infinity */
} rustsecp256k1_v0_11_ge;

#define SECP256K1_GE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), 0}
#define SECP256K1_GE_CONST_INFINITY {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), 1}

/** A group element of the secp256k1 curve, in jacobian coordinates.
 *  Note: For exhastive test mode, secp256k1 is replaced by a small subgroup of a different curve.
 */
typedef struct {
    rustsecp256k1_v0_11_fe x; /* actual X: x/z^2 */
    rustsecp256k1_v0_11_fe y; /* actual Y: y/z^3 */
    rustsecp256k1_v0_11_fe z;
    int infinity; /* whether this represents the point at infinity */
} rustsecp256k1_v0_11_gej;

#define SECP256K1_GEJ_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), 0}
#define SECP256K1_GEJ_CONST_INFINITY {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), 1}

typedef struct {
    rustsecp256k1_v0_11_fe_storage x;
    rustsecp256k1_v0_11_fe_storage y;
} rustsecp256k1_v0_11_ge_storage;

#define SECP256K1_GE_STORAGE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_STORAGE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_STORAGE_CONST((i),(j),(k),(l),(m),(n),(o),(p))}

#define SECP256K1_GE_STORAGE_CONST_GET(t) SECP256K1_FE_STORAGE_CONST_GET(t.x), SECP256K1_FE_STORAGE_CONST_GET(t.y)

/** Maximum allowed magnitudes for group element coordinates
 *  in affine (x, y) and jacobian (x, y, z) representation. */
#define SECP256K1_GE_X_MAGNITUDE_MAX  4
#define SECP256K1_GE_Y_MAGNITUDE_MAX  3
#define SECP256K1_GEJ_X_MAGNITUDE_MAX 4
#define SECP256K1_GEJ_Y_MAGNITUDE_MAX 4
#define SECP256K1_GEJ_Z_MAGNITUDE_MAX 1

/** Set a group element equal to the point with given X and Y coordinates */
static void rustsecp256k1_v0_11_ge_set_xy(rustsecp256k1_v0_11_ge *r, const rustsecp256k1_v0_11_fe *x, const rustsecp256k1_v0_11_fe *y);

/** Set a group element (affine) equal to the point with the given X coordinate, and given oddness
 *  for Y. Return value indicates whether the result is valid. */
static int rustsecp256k1_v0_11_ge_set_xo_var(rustsecp256k1_v0_11_ge *r, const rustsecp256k1_v0_11_fe *x, int odd);

/** Determine whether x is a valid X coordinate on the curve. */
static int rustsecp256k1_v0_11_ge_x_on_curve_var(const rustsecp256k1_v0_11_fe *x);

/** Determine whether fraction xn/xd is a valid X coordinate on the curve (xd != 0). */
static int rustsecp256k1_v0_11_ge_x_frac_on_curve_var(const rustsecp256k1_v0_11_fe *xn, const rustsecp256k1_v0_11_fe *xd);

/** Check whether a group element is the point at infinity. */
static int rustsecp256k1_v0_11_ge_is_infinity(const rustsecp256k1_v0_11_ge *a);

/** Check whether a group element is valid (i.e., on the curve). */
static int rustsecp256k1_v0_11_ge_is_valid_var(const rustsecp256k1_v0_11_ge *a);

/** Set r equal to the inverse of a (i.e., mirrored around the X axis) */
static void rustsecp256k1_v0_11_ge_neg(rustsecp256k1_v0_11_ge *r, const rustsecp256k1_v0_11_ge *a);

/** Set a group element equal to another which is given in jacobian coordinates. Constant time. */
static void rustsecp256k1_v0_11_ge_set_gej(rustsecp256k1_v0_11_ge *r, rustsecp256k1_v0_11_gej *a);

/** Set a group element equal to another which is given in jacobian coordinates. */
static void rustsecp256k1_v0_11_ge_set_gej_var(rustsecp256k1_v0_11_ge *r, rustsecp256k1_v0_11_gej *a);

/** Set a batch of group elements equal to the inputs given in jacobian coordinates */
static void rustsecp256k1_v0_11_ge_set_all_gej_var(rustsecp256k1_v0_11_ge *r, const rustsecp256k1_v0_11_gej *a, size_t len);

/** Bring a batch of inputs to the same global z "denominator", based on ratios between
 *  (omitted) z coordinates of adjacent elements.
 *
 *  Although the elements a[i] are _ge rather than _gej, they actually represent elements
 *  in Jacobian coordinates with their z coordinates omitted.
 *
 *  Using the notation z(b) to represent the omitted z coordinate of b, the array zr of
 *  z coordinate ratios must satisfy zr[i] == z(a[i]) / z(a[i-1]) for 0 < 'i' < len.
 *  The zr[0] value is unused.
 *
 *  This function adjusts the coordinates of 'a' in place so that for all 'i', z(a[i]) == z(a[len-1]).
 *  In other words, the initial value of z(a[len-1]) becomes the global z "denominator". Only the
 *  a[i].x and a[i].y coordinates are explicitly modified; the adjustment of the omitted z coordinate is
 *  implicit.
 *
 *  The coordinates of the final element a[len-1] are not changed.
 */
static void rustsecp256k1_v0_11_ge_table_set_globalz(size_t len, rustsecp256k1_v0_11_ge *a, const rustsecp256k1_v0_11_fe *zr);

/** Check two group elements (affine) for equality in variable time. */
static int rustsecp256k1_v0_11_ge_eq_var(const rustsecp256k1_v0_11_ge *a, const rustsecp256k1_v0_11_ge *b);

/** Set a group element (affine) equal to the point at infinity. */
static void rustsecp256k1_v0_11_ge_set_infinity(rustsecp256k1_v0_11_ge *r);

/** Set a group element (jacobian) equal to the point at infinity. */
static void rustsecp256k1_v0_11_gej_set_infinity(rustsecp256k1_v0_11_gej *r);

/** Set a group element (jacobian) equal to another which is given in affine coordinates. */
static void rustsecp256k1_v0_11_gej_set_ge(rustsecp256k1_v0_11_gej *r, const rustsecp256k1_v0_11_ge *a);

/** Check two group elements (jacobian) for equality in variable time. */
static int rustsecp256k1_v0_11_gej_eq_var(const rustsecp256k1_v0_11_gej *a, const rustsecp256k1_v0_11_gej *b);

/** Check two group elements (jacobian and affine) for equality in variable time. */
static int rustsecp256k1_v0_11_gej_eq_ge_var(const rustsecp256k1_v0_11_gej *a, const rustsecp256k1_v0_11_ge *b);

/** Compare the X coordinate of a group element (jacobian).
  * The magnitude of the group element's X coordinate must not exceed 31. */
static int rustsecp256k1_v0_11_gej_eq_x_var(const rustsecp256k1_v0_11_fe *x, const rustsecp256k1_v0_11_gej *a);

/** Set r equal to the inverse of a (i.e., mirrored around the X axis) */
static void rustsecp256k1_v0_11_gej_neg(rustsecp256k1_v0_11_gej *r, const rustsecp256k1_v0_11_gej *a);

/** Check whether a group element is the point at infinity. */
static int rustsecp256k1_v0_11_gej_is_infinity(const rustsecp256k1_v0_11_gej *a);

/** Set r equal to the double of a. Constant time. */
static void rustsecp256k1_v0_11_gej_double(rustsecp256k1_v0_11_gej *r, const rustsecp256k1_v0_11_gej *a);

/** Set r equal to the double of a. If rzr is not-NULL this sets *rzr such that r->z == a->z * *rzr (where infinity means an implicit z = 0). */
static void rustsecp256k1_v0_11_gej_double_var(rustsecp256k1_v0_11_gej *r, const rustsecp256k1_v0_11_gej *a, rustsecp256k1_v0_11_fe *rzr);

/** Set r equal to the sum of a and b. If rzr is non-NULL this sets *rzr such that r->z == a->z * *rzr (a cannot be infinity in that case). */
static void rustsecp256k1_v0_11_gej_add_var(rustsecp256k1_v0_11_gej *r, const rustsecp256k1_v0_11_gej *a, const rustsecp256k1_v0_11_gej *b, rustsecp256k1_v0_11_fe *rzr);

/** Set r equal to the sum of a and b (with b given in affine coordinates, and not infinity). */
static void rustsecp256k1_v0_11_gej_add_ge(rustsecp256k1_v0_11_gej *r, const rustsecp256k1_v0_11_gej *a, const rustsecp256k1_v0_11_ge *b);

/** Set r equal to the sum of a and b (with b given in affine coordinates). This is more efficient
    than rustsecp256k1_v0_11_gej_add_var. It is identical to rustsecp256k1_v0_11_gej_add_ge but without constant-time
    guarantee, and b is allowed to be infinity. If rzr is non-NULL this sets *rzr such that r->z == a->z * *rzr (a cannot be infinity in that case). */
static void rustsecp256k1_v0_11_gej_add_ge_var(rustsecp256k1_v0_11_gej *r, const rustsecp256k1_v0_11_gej *a, const rustsecp256k1_v0_11_ge *b, rustsecp256k1_v0_11_fe *rzr);

/** Set r equal to the sum of a and b (with the inverse of b's Z coordinate passed as bzinv). */
static void rustsecp256k1_v0_11_gej_add_zinv_var(rustsecp256k1_v0_11_gej *r, const rustsecp256k1_v0_11_gej *a, const rustsecp256k1_v0_11_ge *b, const rustsecp256k1_v0_11_fe *bzinv);

/** Set r to be equal to lambda times a, where lambda is chosen in a way such that this is very fast. */
static void rustsecp256k1_v0_11_ge_mul_lambda(rustsecp256k1_v0_11_ge *r, const rustsecp256k1_v0_11_ge *a);

/** Clear a rustsecp256k1_v0_11_gej to prevent leaking sensitive information. */
static void rustsecp256k1_v0_11_gej_clear(rustsecp256k1_v0_11_gej *r);

/** Clear a rustsecp256k1_v0_11_ge to prevent leaking sensitive information. */
static void rustsecp256k1_v0_11_ge_clear(rustsecp256k1_v0_11_ge *r);

/** Convert a group element to the storage type. */
static void rustsecp256k1_v0_11_ge_to_storage(rustsecp256k1_v0_11_ge_storage *r, const rustsecp256k1_v0_11_ge *a);

/** Convert a group element back from the storage type. */
static void rustsecp256k1_v0_11_ge_from_storage(rustsecp256k1_v0_11_ge *r, const rustsecp256k1_v0_11_ge_storage *a);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time.  Both *r and *a must be initialized.*/
static void rustsecp256k1_v0_11_gej_cmov(rustsecp256k1_v0_11_gej *r, const rustsecp256k1_v0_11_gej *a, int flag);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time.  Both *r and *a must be initialized.*/
static void rustsecp256k1_v0_11_ge_storage_cmov(rustsecp256k1_v0_11_ge_storage *r, const rustsecp256k1_v0_11_ge_storage *a, int flag);

/** Rescale a jacobian point by b which must be non-zero. Constant-time. */
static void rustsecp256k1_v0_11_gej_rescale(rustsecp256k1_v0_11_gej *r, const rustsecp256k1_v0_11_fe *b);

/** Convert a group element that is not infinity to a 64-byte array. The output
 *  array is platform-dependent. */
static void rustsecp256k1_v0_11_ge_to_bytes(unsigned char *buf, const rustsecp256k1_v0_11_ge *a);

/** Convert a 64-byte array into group element. This function assumes that the
 *  provided buffer correctly encodes a group element. */
static void rustsecp256k1_v0_11_ge_from_bytes(rustsecp256k1_v0_11_ge *r, const unsigned char *buf);

/** Convert a group element (that is allowed to be infinity) to a 64-byte
 *  array. The output array is platform-dependent. */
static void rustsecp256k1_v0_11_ge_to_bytes_ext(unsigned char *data, const rustsecp256k1_v0_11_ge *ge);

/** Convert a 64-byte array into a group element. This function assumes that the
 *  provided buffer is the output of rustsecp256k1_v0_11_ge_to_bytes_ext. */
static void rustsecp256k1_v0_11_ge_from_bytes_ext(rustsecp256k1_v0_11_ge *ge, const unsigned char *data);

/** Determine if a point (which is assumed to be on the curve) is in the correct (sub)group of the curve.
 *
 * In normal mode, the used group is secp256k1, which has cofactor=1 meaning that every point on the curve is in the
 * group, and this function returns always true.
 *
 * When compiling in exhaustive test mode, a slightly different curve equation is used, leading to a group with a
 * (very) small subgroup, and that subgroup is what is used for all cryptographic operations. In that mode, this
 * function checks whether a point that is on the curve is in fact also in that subgroup.
 */
static int rustsecp256k1_v0_11_ge_is_in_correct_subgroup(const rustsecp256k1_v0_11_ge* ge);

/** Check invariants on an affine group element (no-op unless VERIFY is enabled). */
static void rustsecp256k1_v0_11_ge_verify(const rustsecp256k1_v0_11_ge *a);
#define SECP256K1_GE_VERIFY(a) rustsecp256k1_v0_11_ge_verify(a)

/** Check invariants on a Jacobian group element (no-op unless VERIFY is enabled). */
static void rustsecp256k1_v0_11_gej_verify(const rustsecp256k1_v0_11_gej *a);
#define SECP256K1_GEJ_VERIFY(a) rustsecp256k1_v0_11_gej_verify(a)

#endif /* SECP256K1_GROUP_H */
