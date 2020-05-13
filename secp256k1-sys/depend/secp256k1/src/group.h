/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_GROUP_H
#define SECP256K1_GROUP_H

#include "num.h"
#include "field.h"

/** A group element of the secp256k1 curve, in affine coordinates. */
typedef struct {
    rustsecp256k1_v0_1_2_fe x;
    rustsecp256k1_v0_1_2_fe y;
    int infinity; /* whether this represents the point at infinity */
} rustsecp256k1_v0_1_2_ge;

#define SECP256K1_GE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), 0}
#define SECP256K1_GE_CONST_INFINITY {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), 1}

/** A group element of the secp256k1 curve, in jacobian coordinates. */
typedef struct {
    rustsecp256k1_v0_1_2_fe x; /* actual X: x/z^2 */
    rustsecp256k1_v0_1_2_fe y; /* actual Y: y/z^3 */
    rustsecp256k1_v0_1_2_fe z;
    int infinity; /* whether this represents the point at infinity */
} rustsecp256k1_v0_1_2_gej;

#define SECP256K1_GEJ_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), 0}
#define SECP256K1_GEJ_CONST_INFINITY {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), 1}

typedef struct {
    rustsecp256k1_v0_1_2_fe_storage x;
    rustsecp256k1_v0_1_2_fe_storage y;
} rustsecp256k1_v0_1_2_ge_storage;

#define SECP256K1_GE_STORAGE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_STORAGE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_STORAGE_CONST((i),(j),(k),(l),(m),(n),(o),(p))}

#define SECP256K1_GE_STORAGE_CONST_GET(t) SECP256K1_FE_STORAGE_CONST_GET(t.x), SECP256K1_FE_STORAGE_CONST_GET(t.y)

/** Set a group element equal to the point with given X and Y coordinates */
static void rustsecp256k1_v0_1_2_ge_set_xy(rustsecp256k1_v0_1_2_ge *r, const rustsecp256k1_v0_1_2_fe *x, const rustsecp256k1_v0_1_2_fe *y);

/** Set a group element (affine) equal to the point with the given X coordinate
 *  and a Y coordinate that is a quadratic residue modulo p. The return value
 *  is true iff a coordinate with the given X coordinate exists.
 */
static int rustsecp256k1_v0_1_2_ge_set_xquad(rustsecp256k1_v0_1_2_ge *r, const rustsecp256k1_v0_1_2_fe *x);

/** Set a group element (affine) equal to the point with the given X coordinate, and given oddness
 *  for Y. Return value indicates whether the result is valid. */
static int rustsecp256k1_v0_1_2_ge_set_xo_var(rustsecp256k1_v0_1_2_ge *r, const rustsecp256k1_v0_1_2_fe *x, int odd);

/** Check whether a group element is the point at infinity. */
static int rustsecp256k1_v0_1_2_ge_is_infinity(const rustsecp256k1_v0_1_2_ge *a);

/** Check whether a group element is valid (i.e., on the curve). */
static int rustsecp256k1_v0_1_2_ge_is_valid_var(const rustsecp256k1_v0_1_2_ge *a);

static void rustsecp256k1_v0_1_2_ge_neg(rustsecp256k1_v0_1_2_ge *r, const rustsecp256k1_v0_1_2_ge *a);

/** Set a group element equal to another which is given in jacobian coordinates */
static void rustsecp256k1_v0_1_2_ge_set_gej(rustsecp256k1_v0_1_2_ge *r, rustsecp256k1_v0_1_2_gej *a);

/** Set a batch of group elements equal to the inputs given in jacobian coordinates */
static void rustsecp256k1_v0_1_2_ge_set_all_gej_var(rustsecp256k1_v0_1_2_ge *r, const rustsecp256k1_v0_1_2_gej *a, size_t len);

/** Bring a batch inputs given in jacobian coordinates (with known z-ratios) to
 *  the same global z "denominator". zr must contain the known z-ratios such
 *  that mul(a[i].z, zr[i+1]) == a[i+1].z. zr[0] is ignored. The x and y
 *  coordinates of the result are stored in r, the common z coordinate is
 *  stored in globalz. */
static void rustsecp256k1_v0_1_2_ge_globalz_set_table_gej(size_t len, rustsecp256k1_v0_1_2_ge *r, rustsecp256k1_v0_1_2_fe *globalz, const rustsecp256k1_v0_1_2_gej *a, const rustsecp256k1_v0_1_2_fe *zr);

/** Set a group element (affine) equal to the point at infinity. */
static void rustsecp256k1_v0_1_2_ge_set_infinity(rustsecp256k1_v0_1_2_ge *r);

/** Set a group element (jacobian) equal to the point at infinity. */
static void rustsecp256k1_v0_1_2_gej_set_infinity(rustsecp256k1_v0_1_2_gej *r);

/** Set a group element (jacobian) equal to another which is given in affine coordinates. */
static void rustsecp256k1_v0_1_2_gej_set_ge(rustsecp256k1_v0_1_2_gej *r, const rustsecp256k1_v0_1_2_ge *a);

/** Compare the X coordinate of a group element (jacobian). */
static int rustsecp256k1_v0_1_2_gej_eq_x_var(const rustsecp256k1_v0_1_2_fe *x, const rustsecp256k1_v0_1_2_gej *a);

/** Set r equal to the inverse of a (i.e., mirrored around the X axis) */
static void rustsecp256k1_v0_1_2_gej_neg(rustsecp256k1_v0_1_2_gej *r, const rustsecp256k1_v0_1_2_gej *a);

/** Check whether a group element is the point at infinity. */
static int rustsecp256k1_v0_1_2_gej_is_infinity(const rustsecp256k1_v0_1_2_gej *a);

/** Check whether a group element's y coordinate is a quadratic residue. */
static int rustsecp256k1_v0_1_2_gej_has_quad_y_var(const rustsecp256k1_v0_1_2_gej *a);

/** Set r equal to the double of a, a cannot be infinity. Constant time. */
static void rustsecp256k1_v0_1_2_gej_double_nonzero(rustsecp256k1_v0_1_2_gej *r, const rustsecp256k1_v0_1_2_gej *a);

/** Set r equal to the double of a. If rzr is not-NULL this sets *rzr such that r->z == a->z * *rzr (where infinity means an implicit z = 0). */
static void rustsecp256k1_v0_1_2_gej_double_var(rustsecp256k1_v0_1_2_gej *r, const rustsecp256k1_v0_1_2_gej *a, rustsecp256k1_v0_1_2_fe *rzr);

/** Set r equal to the sum of a and b. If rzr is non-NULL this sets *rzr such that r->z == a->z * *rzr (a cannot be infinity in that case). */
static void rustsecp256k1_v0_1_2_gej_add_var(rustsecp256k1_v0_1_2_gej *r, const rustsecp256k1_v0_1_2_gej *a, const rustsecp256k1_v0_1_2_gej *b, rustsecp256k1_v0_1_2_fe *rzr);

/** Set r equal to the sum of a and b (with b given in affine coordinates, and not infinity). */
static void rustsecp256k1_v0_1_2_gej_add_ge(rustsecp256k1_v0_1_2_gej *r, const rustsecp256k1_v0_1_2_gej *a, const rustsecp256k1_v0_1_2_ge *b);

/** Set r equal to the sum of a and b (with b given in affine coordinates). This is more efficient
    than rustsecp256k1_v0_1_2_gej_add_var. It is identical to rustsecp256k1_v0_1_2_gej_add_ge but without constant-time
    guarantee, and b is allowed to be infinity. If rzr is non-NULL this sets *rzr such that r->z == a->z * *rzr (a cannot be infinity in that case). */
static void rustsecp256k1_v0_1_2_gej_add_ge_var(rustsecp256k1_v0_1_2_gej *r, const rustsecp256k1_v0_1_2_gej *a, const rustsecp256k1_v0_1_2_ge *b, rustsecp256k1_v0_1_2_fe *rzr);

/** Set r equal to the sum of a and b (with the inverse of b's Z coordinate passed as bzinv). */
static void rustsecp256k1_v0_1_2_gej_add_zinv_var(rustsecp256k1_v0_1_2_gej *r, const rustsecp256k1_v0_1_2_gej *a, const rustsecp256k1_v0_1_2_ge *b, const rustsecp256k1_v0_1_2_fe *bzinv);

#ifdef USE_ENDOMORPHISM
/** Set r to be equal to lambda times a, where lambda is chosen in a way such that this is very fast. */
static void rustsecp256k1_v0_1_2_ge_mul_lambda(rustsecp256k1_v0_1_2_ge *r, const rustsecp256k1_v0_1_2_ge *a);
#endif

/** Clear a rustsecp256k1_v0_1_2_gej to prevent leaking sensitive information. */
static void rustsecp256k1_v0_1_2_gej_clear(rustsecp256k1_v0_1_2_gej *r);

/** Clear a rustsecp256k1_v0_1_2_ge to prevent leaking sensitive information. */
static void rustsecp256k1_v0_1_2_ge_clear(rustsecp256k1_v0_1_2_ge *r);

/** Convert a group element to the storage type. */
static void rustsecp256k1_v0_1_2_ge_to_storage(rustsecp256k1_v0_1_2_ge_storage *r, const rustsecp256k1_v0_1_2_ge *a);

/** Convert a group element back from the storage type. */
static void rustsecp256k1_v0_1_2_ge_from_storage(rustsecp256k1_v0_1_2_ge *r, const rustsecp256k1_v0_1_2_ge_storage *a);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time. */
static void rustsecp256k1_v0_1_2_ge_storage_cmov(rustsecp256k1_v0_1_2_ge_storage *r, const rustsecp256k1_v0_1_2_ge_storage *a, int flag);

/** Rescale a jacobian point by b which must be non-zero. Constant-time. */
static void rustsecp256k1_v0_1_2_gej_rescale(rustsecp256k1_v0_1_2_gej *r, const rustsecp256k1_v0_1_2_fe *b);

#endif /* SECP256K1_GROUP_H */
