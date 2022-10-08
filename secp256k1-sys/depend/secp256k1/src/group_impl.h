/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_GROUP_IMPL_H
#define SECP256K1_GROUP_IMPL_H

#include "field.h"
#include "group.h"

#define SECP256K1_G_ORDER_13 SECP256K1_GE_CONST(\
    0xc3459c3d, 0x35326167, 0xcd86cce8, 0x07a2417f,\
    0x5b8bd567, 0xde8538ee, 0x0d507b0c, 0xd128f5bb,\
    0x8e467fec, 0xcd30000a, 0x6cc1184e, 0x25d382c2,\
    0xa2f4494e, 0x2fbe9abc, 0x8b64abac, 0xd005fb24\
)
#define SECP256K1_G_ORDER_199 SECP256K1_GE_CONST(\
    0x226e653f, 0xc8df7744, 0x9bacbf12, 0x7d1dcbf9,\
    0x87f05b2a, 0xe7edbd28, 0x1f564575, 0xc48dcf18,\
    0xa13872c2, 0xe933bb17, 0x5d9ffd5b, 0xb5b6e10c,\
    0x57fe3c00, 0xbaaaa15a, 0xe003ec3e, 0x9c269bae\
)
/** Generator for secp256k1, value 'g' defined in
 *  "Standards for Efficient Cryptography" (SEC2) 2.7.1.
 */
#define SECP256K1_G SECP256K1_GE_CONST(\
    0x79BE667EUL, 0xF9DCBBACUL, 0x55A06295UL, 0xCE870B07UL,\
    0x029BFCDBUL, 0x2DCE28D9UL, 0x59F2815BUL, 0x16F81798UL,\
    0x483ADA77UL, 0x26A3C465UL, 0x5DA4FBFCUL, 0x0E1108A8UL,\
    0xFD17B448UL, 0xA6855419UL, 0x9C47D08FUL, 0xFB10D4B8UL\
)
/* These exhaustive group test orders and generators are chosen such that:
 * - The field size is equal to that of secp256k1, so field code is the same.
 * - The curve equation is of the form y^2=x^3+B for some constant B.
 * - The subgroup has a generator 2*P, where P.x=1.
 * - The subgroup has size less than 1000 to permit exhaustive testing.
 * - The subgroup admits an endomorphism of the form lambda*(x,y) == (beta*x,y).
 *
 * These parameters are generated using sage/gen_exhaustive_groups.sage.
 */
#if defined(EXHAUSTIVE_TEST_ORDER)
#  if EXHAUSTIVE_TEST_ORDER == 13
static const rustsecp256k1_v0_6_1_ge rustsecp256k1_v0_6_1_ge_const_g = SECP256K1_G_ORDER_13;

static const rustsecp256k1_v0_6_1_fe rustsecp256k1_v0_6_1_fe_const_b = SECP256K1_FE_CONST(
    0x3d3486b2, 0x159a9ca5, 0xc75638be, 0xb23a69bc,
    0x946a45ab, 0x24801247, 0xb4ed2b8e, 0x26b6a417
);
#  elif EXHAUSTIVE_TEST_ORDER == 199
static const rustsecp256k1_v0_6_1_ge rustsecp256k1_v0_6_1_ge_const_g = SECP256K1_G_ORDER_199;

static const rustsecp256k1_v0_6_1_fe rustsecp256k1_v0_6_1_fe_const_b = SECP256K1_FE_CONST(
    0x2cca28fa, 0xfc614b80, 0x2a3db42b, 0x00ba00b1,
    0xbea8d943, 0xdace9ab2, 0x9536daea, 0x0074defb
);
#  else
#    error No known generator for the specified exhaustive test group order.
#  endif
#else
static const rustsecp256k1_v0_6_1_ge rustsecp256k1_v0_6_1_ge_const_g = SECP256K1_G;

static const rustsecp256k1_v0_6_1_fe rustsecp256k1_v0_6_1_fe_const_b = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 7);
#endif

static void rustsecp256k1_v0_6_1_ge_set_gej_zinv(rustsecp256k1_v0_6_1_ge *r, const rustsecp256k1_v0_6_1_gej *a, const rustsecp256k1_v0_6_1_fe *zi) {
    rustsecp256k1_v0_6_1_fe zi2;
    rustsecp256k1_v0_6_1_fe zi3;
    VERIFY_CHECK(!a->infinity);
    rustsecp256k1_v0_6_1_fe_sqr(&zi2, zi);
    rustsecp256k1_v0_6_1_fe_mul(&zi3, &zi2, zi);
    rustsecp256k1_v0_6_1_fe_mul(&r->x, &a->x, &zi2);
    rustsecp256k1_v0_6_1_fe_mul(&r->y, &a->y, &zi3);
    r->infinity = a->infinity;
}

static void rustsecp256k1_v0_6_1_ge_set_xy(rustsecp256k1_v0_6_1_ge *r, const rustsecp256k1_v0_6_1_fe *x, const rustsecp256k1_v0_6_1_fe *y) {
    r->infinity = 0;
    r->x = *x;
    r->y = *y;
}

static int rustsecp256k1_v0_6_1_ge_is_infinity(const rustsecp256k1_v0_6_1_ge *a) {
    return a->infinity;
}

static void rustsecp256k1_v0_6_1_ge_neg(rustsecp256k1_v0_6_1_ge *r, const rustsecp256k1_v0_6_1_ge *a) {
    *r = *a;
    rustsecp256k1_v0_6_1_fe_normalize_weak(&r->y);
    rustsecp256k1_v0_6_1_fe_negate(&r->y, &r->y, 1);
}

static void rustsecp256k1_v0_6_1_ge_set_gej(rustsecp256k1_v0_6_1_ge *r, rustsecp256k1_v0_6_1_gej *a) {
    rustsecp256k1_v0_6_1_fe z2, z3;
    r->infinity = a->infinity;
    rustsecp256k1_v0_6_1_fe_inv(&a->z, &a->z);
    rustsecp256k1_v0_6_1_fe_sqr(&z2, &a->z);
    rustsecp256k1_v0_6_1_fe_mul(&z3, &a->z, &z2);
    rustsecp256k1_v0_6_1_fe_mul(&a->x, &a->x, &z2);
    rustsecp256k1_v0_6_1_fe_mul(&a->y, &a->y, &z3);
    rustsecp256k1_v0_6_1_fe_set_int(&a->z, 1);
    r->x = a->x;
    r->y = a->y;
}

static void rustsecp256k1_v0_6_1_ge_set_gej_var(rustsecp256k1_v0_6_1_ge *r, rustsecp256k1_v0_6_1_gej *a) {
    rustsecp256k1_v0_6_1_fe z2, z3;
    if (a->infinity) {
        rustsecp256k1_v0_6_1_ge_set_infinity(r);
        return;
    }
    rustsecp256k1_v0_6_1_fe_inv_var(&a->z, &a->z);
    rustsecp256k1_v0_6_1_fe_sqr(&z2, &a->z);
    rustsecp256k1_v0_6_1_fe_mul(&z3, &a->z, &z2);
    rustsecp256k1_v0_6_1_fe_mul(&a->x, &a->x, &z2);
    rustsecp256k1_v0_6_1_fe_mul(&a->y, &a->y, &z3);
    rustsecp256k1_v0_6_1_fe_set_int(&a->z, 1);
    rustsecp256k1_v0_6_1_ge_set_xy(r, &a->x, &a->y);
}

static void rustsecp256k1_v0_6_1_ge_set_all_gej_var(rustsecp256k1_v0_6_1_ge *r, const rustsecp256k1_v0_6_1_gej *a, size_t len) {
    rustsecp256k1_v0_6_1_fe u;
    size_t i;
    size_t last_i = SIZE_MAX;

    for (i = 0; i < len; i++) {
        if (a[i].infinity) {
            rustsecp256k1_v0_6_1_ge_set_infinity(&r[i]);
        } else {
            /* Use destination's x coordinates as scratch space */
            if (last_i == SIZE_MAX) {
                r[i].x = a[i].z;
            } else {
                rustsecp256k1_v0_6_1_fe_mul(&r[i].x, &r[last_i].x, &a[i].z);
            }
            last_i = i;
        }
    }
    if (last_i == SIZE_MAX) {
        return;
    }
    rustsecp256k1_v0_6_1_fe_inv_var(&u, &r[last_i].x);

    i = last_i;
    while (i > 0) {
        i--;
        if (!a[i].infinity) {
            rustsecp256k1_v0_6_1_fe_mul(&r[last_i].x, &r[i].x, &u);
            rustsecp256k1_v0_6_1_fe_mul(&u, &u, &a[last_i].z);
            last_i = i;
        }
    }
    VERIFY_CHECK(!a[last_i].infinity);
    r[last_i].x = u;

    for (i = 0; i < len; i++) {
        if (!a[i].infinity) {
            rustsecp256k1_v0_6_1_ge_set_gej_zinv(&r[i], &a[i], &r[i].x);
        }
    }
}

static void rustsecp256k1_v0_6_1_ge_globalz_set_table_gej(size_t len, rustsecp256k1_v0_6_1_ge *r, rustsecp256k1_v0_6_1_fe *globalz, const rustsecp256k1_v0_6_1_gej *a, const rustsecp256k1_v0_6_1_fe *zr) {
    size_t i = len - 1;
    rustsecp256k1_v0_6_1_fe zs;

    if (len > 0) {
        /* The z of the final point gives us the "global Z" for the table. */
        r[i].x = a[i].x;
        r[i].y = a[i].y;
        /* Ensure all y values are in weak normal form for fast negation of points */
        rustsecp256k1_v0_6_1_fe_normalize_weak(&r[i].y);
        *globalz = a[i].z;
        r[i].infinity = 0;
        zs = zr[i];

        /* Work our way backwards, using the z-ratios to scale the x/y values. */
        while (i > 0) {
            if (i != len - 1) {
                rustsecp256k1_v0_6_1_fe_mul(&zs, &zs, &zr[i]);
            }
            i--;
            rustsecp256k1_v0_6_1_ge_set_gej_zinv(&r[i], &a[i], &zs);
        }
    }
}

static void rustsecp256k1_v0_6_1_gej_set_infinity(rustsecp256k1_v0_6_1_gej *r) {
    r->infinity = 1;
    rustsecp256k1_v0_6_1_fe_clear(&r->x);
    rustsecp256k1_v0_6_1_fe_clear(&r->y);
    rustsecp256k1_v0_6_1_fe_clear(&r->z);
}

static void rustsecp256k1_v0_6_1_ge_set_infinity(rustsecp256k1_v0_6_1_ge *r) {
    r->infinity = 1;
    rustsecp256k1_v0_6_1_fe_clear(&r->x);
    rustsecp256k1_v0_6_1_fe_clear(&r->y);
}

static void rustsecp256k1_v0_6_1_gej_clear(rustsecp256k1_v0_6_1_gej *r) {
    r->infinity = 0;
    rustsecp256k1_v0_6_1_fe_clear(&r->x);
    rustsecp256k1_v0_6_1_fe_clear(&r->y);
    rustsecp256k1_v0_6_1_fe_clear(&r->z);
}

static void rustsecp256k1_v0_6_1_ge_clear(rustsecp256k1_v0_6_1_ge *r) {
    r->infinity = 0;
    rustsecp256k1_v0_6_1_fe_clear(&r->x);
    rustsecp256k1_v0_6_1_fe_clear(&r->y);
}

static int rustsecp256k1_v0_6_1_ge_set_xo_var(rustsecp256k1_v0_6_1_ge *r, const rustsecp256k1_v0_6_1_fe *x, int odd) {
    rustsecp256k1_v0_6_1_fe x2, x3;
    r->x = *x;
    rustsecp256k1_v0_6_1_fe_sqr(&x2, x);
    rustsecp256k1_v0_6_1_fe_mul(&x3, x, &x2);
    r->infinity = 0;
    rustsecp256k1_v0_6_1_fe_add(&x3, &rustsecp256k1_v0_6_1_fe_const_b);
    if (!rustsecp256k1_v0_6_1_fe_sqrt(&r->y, &x3)) {
        return 0;
    }
    rustsecp256k1_v0_6_1_fe_normalize_var(&r->y);
    if (rustsecp256k1_v0_6_1_fe_is_odd(&r->y) != odd) {
        rustsecp256k1_v0_6_1_fe_negate(&r->y, &r->y, 1);
    }
    return 1;

}

static void rustsecp256k1_v0_6_1_gej_set_ge(rustsecp256k1_v0_6_1_gej *r, const rustsecp256k1_v0_6_1_ge *a) {
   r->infinity = a->infinity;
   r->x = a->x;
   r->y = a->y;
   rustsecp256k1_v0_6_1_fe_set_int(&r->z, 1);
}

static int rustsecp256k1_v0_6_1_gej_eq_x_var(const rustsecp256k1_v0_6_1_fe *x, const rustsecp256k1_v0_6_1_gej *a) {
    rustsecp256k1_v0_6_1_fe r, r2;
    VERIFY_CHECK(!a->infinity);
    rustsecp256k1_v0_6_1_fe_sqr(&r, &a->z); rustsecp256k1_v0_6_1_fe_mul(&r, &r, x);
    r2 = a->x; rustsecp256k1_v0_6_1_fe_normalize_weak(&r2);
    return rustsecp256k1_v0_6_1_fe_equal_var(&r, &r2);
}

static void rustsecp256k1_v0_6_1_gej_neg(rustsecp256k1_v0_6_1_gej *r, const rustsecp256k1_v0_6_1_gej *a) {
    r->infinity = a->infinity;
    r->x = a->x;
    r->y = a->y;
    r->z = a->z;
    rustsecp256k1_v0_6_1_fe_normalize_weak(&r->y);
    rustsecp256k1_v0_6_1_fe_negate(&r->y, &r->y, 1);
}

static int rustsecp256k1_v0_6_1_gej_is_infinity(const rustsecp256k1_v0_6_1_gej *a) {
    return a->infinity;
}

static int rustsecp256k1_v0_6_1_ge_is_valid_var(const rustsecp256k1_v0_6_1_ge *a) {
    rustsecp256k1_v0_6_1_fe y2, x3;
    if (a->infinity) {
        return 0;
    }
    /* y^2 = x^3 + 7 */
    rustsecp256k1_v0_6_1_fe_sqr(&y2, &a->y);
    rustsecp256k1_v0_6_1_fe_sqr(&x3, &a->x); rustsecp256k1_v0_6_1_fe_mul(&x3, &x3, &a->x);
    rustsecp256k1_v0_6_1_fe_add(&x3, &rustsecp256k1_v0_6_1_fe_const_b);
    rustsecp256k1_v0_6_1_fe_normalize_weak(&x3);
    return rustsecp256k1_v0_6_1_fe_equal_var(&y2, &x3);
}

static SECP256K1_INLINE void rustsecp256k1_v0_6_1_gej_double(rustsecp256k1_v0_6_1_gej *r, const rustsecp256k1_v0_6_1_gej *a) {
    /* Operations: 3 mul, 4 sqr, 0 normalize, 12 mul_int/add/negate.
     *
     * Note that there is an implementation described at
     *     https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
     * which trades a multiply for a square, but in practice this is actually slower,
     * mainly because it requires more normalizations.
     */
    rustsecp256k1_v0_6_1_fe t1,t2,t3,t4;

    r->infinity = a->infinity;

    rustsecp256k1_v0_6_1_fe_mul(&r->z, &a->z, &a->y);
    rustsecp256k1_v0_6_1_fe_mul_int(&r->z, 2);       /* Z' = 2*Y*Z (2) */
    rustsecp256k1_v0_6_1_fe_sqr(&t1, &a->x);
    rustsecp256k1_v0_6_1_fe_mul_int(&t1, 3);         /* T1 = 3*X^2 (3) */
    rustsecp256k1_v0_6_1_fe_sqr(&t2, &t1);           /* T2 = 9*X^4 (1) */
    rustsecp256k1_v0_6_1_fe_sqr(&t3, &a->y);
    rustsecp256k1_v0_6_1_fe_mul_int(&t3, 2);         /* T3 = 2*Y^2 (2) */
    rustsecp256k1_v0_6_1_fe_sqr(&t4, &t3);
    rustsecp256k1_v0_6_1_fe_mul_int(&t4, 2);         /* T4 = 8*Y^4 (2) */
    rustsecp256k1_v0_6_1_fe_mul(&t3, &t3, &a->x);    /* T3 = 2*X*Y^2 (1) */
    r->x = t3;
    rustsecp256k1_v0_6_1_fe_mul_int(&r->x, 4);       /* X' = 8*X*Y^2 (4) */
    rustsecp256k1_v0_6_1_fe_negate(&r->x, &r->x, 4); /* X' = -8*X*Y^2 (5) */
    rustsecp256k1_v0_6_1_fe_add(&r->x, &t2);         /* X' = 9*X^4 - 8*X*Y^2 (6) */
    rustsecp256k1_v0_6_1_fe_negate(&t2, &t2, 1);     /* T2 = -9*X^4 (2) */
    rustsecp256k1_v0_6_1_fe_mul_int(&t3, 6);         /* T3 = 12*X*Y^2 (6) */
    rustsecp256k1_v0_6_1_fe_add(&t3, &t2);           /* T3 = 12*X*Y^2 - 9*X^4 (8) */
    rustsecp256k1_v0_6_1_fe_mul(&r->y, &t1, &t3);    /* Y' = 36*X^3*Y^2 - 27*X^6 (1) */
    rustsecp256k1_v0_6_1_fe_negate(&t2, &t4, 2);     /* T2 = -8*Y^4 (3) */
    rustsecp256k1_v0_6_1_fe_add(&r->y, &t2);         /* Y' = 36*X^3*Y^2 - 27*X^6 - 8*Y^4 (4) */
}

static void rustsecp256k1_v0_6_1_gej_double_var(rustsecp256k1_v0_6_1_gej *r, const rustsecp256k1_v0_6_1_gej *a, rustsecp256k1_v0_6_1_fe *rzr) {
    /** For secp256k1, 2Q is infinity if and only if Q is infinity. This is because if 2Q = infinity,
     *  Q must equal -Q, or that Q.y == -(Q.y), or Q.y is 0. For a point on y^2 = x^3 + 7 to have
     *  y=0, x^3 must be -7 mod p. However, -7 has no cube root mod p.
     *
     *  Having said this, if this function receives a point on a sextic twist, e.g. by
     *  a fault attack, it is possible for y to be 0. This happens for y^2 = x^3 + 6,
     *  since -6 does have a cube root mod p. For this point, this function will not set
     *  the infinity flag even though the point doubles to infinity, and the result
     *  point will be gibberish (z = 0 but infinity = 0).
     */
    if (a->infinity) {
        rustsecp256k1_v0_6_1_gej_set_infinity(r);
        if (rzr != NULL) {
            rustsecp256k1_v0_6_1_fe_set_int(rzr, 1);
        }
        return;
    }

    if (rzr != NULL) {
        *rzr = a->y;
        rustsecp256k1_v0_6_1_fe_normalize_weak(rzr);
        rustsecp256k1_v0_6_1_fe_mul_int(rzr, 2);
    }

    rustsecp256k1_v0_6_1_gej_double(r, a);
}

static void rustsecp256k1_v0_6_1_gej_add_var(rustsecp256k1_v0_6_1_gej *r, const rustsecp256k1_v0_6_1_gej *a, const rustsecp256k1_v0_6_1_gej *b, rustsecp256k1_v0_6_1_fe *rzr) {
    /* Operations: 12 mul, 4 sqr, 2 normalize, 12 mul_int/add/negate */
    rustsecp256k1_v0_6_1_fe z22, z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;

    if (a->infinity) {
        VERIFY_CHECK(rzr == NULL);
        *r = *b;
        return;
    }

    if (b->infinity) {
        if (rzr != NULL) {
            rustsecp256k1_v0_6_1_fe_set_int(rzr, 1);
        }
        *r = *a;
        return;
    }

    r->infinity = 0;
    rustsecp256k1_v0_6_1_fe_sqr(&z22, &b->z);
    rustsecp256k1_v0_6_1_fe_sqr(&z12, &a->z);
    rustsecp256k1_v0_6_1_fe_mul(&u1, &a->x, &z22);
    rustsecp256k1_v0_6_1_fe_mul(&u2, &b->x, &z12);
    rustsecp256k1_v0_6_1_fe_mul(&s1, &a->y, &z22); rustsecp256k1_v0_6_1_fe_mul(&s1, &s1, &b->z);
    rustsecp256k1_v0_6_1_fe_mul(&s2, &b->y, &z12); rustsecp256k1_v0_6_1_fe_mul(&s2, &s2, &a->z);
    rustsecp256k1_v0_6_1_fe_negate(&h, &u1, 1); rustsecp256k1_v0_6_1_fe_add(&h, &u2);
    rustsecp256k1_v0_6_1_fe_negate(&i, &s1, 1); rustsecp256k1_v0_6_1_fe_add(&i, &s2);
    if (rustsecp256k1_v0_6_1_fe_normalizes_to_zero_var(&h)) {
        if (rustsecp256k1_v0_6_1_fe_normalizes_to_zero_var(&i)) {
            rustsecp256k1_v0_6_1_gej_double_var(r, a, rzr);
        } else {
            if (rzr != NULL) {
                rustsecp256k1_v0_6_1_fe_set_int(rzr, 0);
            }
            rustsecp256k1_v0_6_1_gej_set_infinity(r);
        }
        return;
    }
    rustsecp256k1_v0_6_1_fe_sqr(&i2, &i);
    rustsecp256k1_v0_6_1_fe_sqr(&h2, &h);
    rustsecp256k1_v0_6_1_fe_mul(&h3, &h, &h2);
    rustsecp256k1_v0_6_1_fe_mul(&h, &h, &b->z);
    if (rzr != NULL) {
        *rzr = h;
    }
    rustsecp256k1_v0_6_1_fe_mul(&r->z, &a->z, &h);
    rustsecp256k1_v0_6_1_fe_mul(&t, &u1, &h2);
    r->x = t; rustsecp256k1_v0_6_1_fe_mul_int(&r->x, 2); rustsecp256k1_v0_6_1_fe_add(&r->x, &h3); rustsecp256k1_v0_6_1_fe_negate(&r->x, &r->x, 3); rustsecp256k1_v0_6_1_fe_add(&r->x, &i2);
    rustsecp256k1_v0_6_1_fe_negate(&r->y, &r->x, 5); rustsecp256k1_v0_6_1_fe_add(&r->y, &t); rustsecp256k1_v0_6_1_fe_mul(&r->y, &r->y, &i);
    rustsecp256k1_v0_6_1_fe_mul(&h3, &h3, &s1); rustsecp256k1_v0_6_1_fe_negate(&h3, &h3, 1);
    rustsecp256k1_v0_6_1_fe_add(&r->y, &h3);
}

static void rustsecp256k1_v0_6_1_gej_add_ge_var(rustsecp256k1_v0_6_1_gej *r, const rustsecp256k1_v0_6_1_gej *a, const rustsecp256k1_v0_6_1_ge *b, rustsecp256k1_v0_6_1_fe *rzr) {
    /* 8 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
    rustsecp256k1_v0_6_1_fe z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;
    if (a->infinity) {
        VERIFY_CHECK(rzr == NULL);
        rustsecp256k1_v0_6_1_gej_set_ge(r, b);
        return;
    }
    if (b->infinity) {
        if (rzr != NULL) {
            rustsecp256k1_v0_6_1_fe_set_int(rzr, 1);
        }
        *r = *a;
        return;
    }
    r->infinity = 0;

    rustsecp256k1_v0_6_1_fe_sqr(&z12, &a->z);
    u1 = a->x; rustsecp256k1_v0_6_1_fe_normalize_weak(&u1);
    rustsecp256k1_v0_6_1_fe_mul(&u2, &b->x, &z12);
    s1 = a->y; rustsecp256k1_v0_6_1_fe_normalize_weak(&s1);
    rustsecp256k1_v0_6_1_fe_mul(&s2, &b->y, &z12); rustsecp256k1_v0_6_1_fe_mul(&s2, &s2, &a->z);
    rustsecp256k1_v0_6_1_fe_negate(&h, &u1, 1); rustsecp256k1_v0_6_1_fe_add(&h, &u2);
    rustsecp256k1_v0_6_1_fe_negate(&i, &s1, 1); rustsecp256k1_v0_6_1_fe_add(&i, &s2);
    if (rustsecp256k1_v0_6_1_fe_normalizes_to_zero_var(&h)) {
        if (rustsecp256k1_v0_6_1_fe_normalizes_to_zero_var(&i)) {
            rustsecp256k1_v0_6_1_gej_double_var(r, a, rzr);
        } else {
            if (rzr != NULL) {
                rustsecp256k1_v0_6_1_fe_set_int(rzr, 0);
            }
            rustsecp256k1_v0_6_1_gej_set_infinity(r);
        }
        return;
    }
    rustsecp256k1_v0_6_1_fe_sqr(&i2, &i);
    rustsecp256k1_v0_6_1_fe_sqr(&h2, &h);
    rustsecp256k1_v0_6_1_fe_mul(&h3, &h, &h2);
    if (rzr != NULL) {
        *rzr = h;
    }
    rustsecp256k1_v0_6_1_fe_mul(&r->z, &a->z, &h);
    rustsecp256k1_v0_6_1_fe_mul(&t, &u1, &h2);
    r->x = t; rustsecp256k1_v0_6_1_fe_mul_int(&r->x, 2); rustsecp256k1_v0_6_1_fe_add(&r->x, &h3); rustsecp256k1_v0_6_1_fe_negate(&r->x, &r->x, 3); rustsecp256k1_v0_6_1_fe_add(&r->x, &i2);
    rustsecp256k1_v0_6_1_fe_negate(&r->y, &r->x, 5); rustsecp256k1_v0_6_1_fe_add(&r->y, &t); rustsecp256k1_v0_6_1_fe_mul(&r->y, &r->y, &i);
    rustsecp256k1_v0_6_1_fe_mul(&h3, &h3, &s1); rustsecp256k1_v0_6_1_fe_negate(&h3, &h3, 1);
    rustsecp256k1_v0_6_1_fe_add(&r->y, &h3);
}

static void rustsecp256k1_v0_6_1_gej_add_zinv_var(rustsecp256k1_v0_6_1_gej *r, const rustsecp256k1_v0_6_1_gej *a, const rustsecp256k1_v0_6_1_ge *b, const rustsecp256k1_v0_6_1_fe *bzinv) {
    /* 9 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
    rustsecp256k1_v0_6_1_fe az, z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;

    if (b->infinity) {
        *r = *a;
        return;
    }
    if (a->infinity) {
        rustsecp256k1_v0_6_1_fe bzinv2, bzinv3;
        r->infinity = b->infinity;
        rustsecp256k1_v0_6_1_fe_sqr(&bzinv2, bzinv);
        rustsecp256k1_v0_6_1_fe_mul(&bzinv3, &bzinv2, bzinv);
        rustsecp256k1_v0_6_1_fe_mul(&r->x, &b->x, &bzinv2);
        rustsecp256k1_v0_6_1_fe_mul(&r->y, &b->y, &bzinv3);
        rustsecp256k1_v0_6_1_fe_set_int(&r->z, 1);
        return;
    }
    r->infinity = 0;

    /** We need to calculate (rx,ry,rz) = (ax,ay,az) + (bx,by,1/bzinv). Due to
     *  secp256k1's isomorphism we can multiply the Z coordinates on both sides
     *  by bzinv, and get: (rx,ry,rz*bzinv) = (ax,ay,az*bzinv) + (bx,by,1).
     *  This means that (rx,ry,rz) can be calculated as
     *  (ax,ay,az*bzinv) + (bx,by,1), when not applying the bzinv factor to rz.
     *  The variable az below holds the modified Z coordinate for a, which is used
     *  for the computation of rx and ry, but not for rz.
     */
    rustsecp256k1_v0_6_1_fe_mul(&az, &a->z, bzinv);

    rustsecp256k1_v0_6_1_fe_sqr(&z12, &az);
    u1 = a->x; rustsecp256k1_v0_6_1_fe_normalize_weak(&u1);
    rustsecp256k1_v0_6_1_fe_mul(&u2, &b->x, &z12);
    s1 = a->y; rustsecp256k1_v0_6_1_fe_normalize_weak(&s1);
    rustsecp256k1_v0_6_1_fe_mul(&s2, &b->y, &z12); rustsecp256k1_v0_6_1_fe_mul(&s2, &s2, &az);
    rustsecp256k1_v0_6_1_fe_negate(&h, &u1, 1); rustsecp256k1_v0_6_1_fe_add(&h, &u2);
    rustsecp256k1_v0_6_1_fe_negate(&i, &s1, 1); rustsecp256k1_v0_6_1_fe_add(&i, &s2);
    if (rustsecp256k1_v0_6_1_fe_normalizes_to_zero_var(&h)) {
        if (rustsecp256k1_v0_6_1_fe_normalizes_to_zero_var(&i)) {
            rustsecp256k1_v0_6_1_gej_double_var(r, a, NULL);
        } else {
            rustsecp256k1_v0_6_1_gej_set_infinity(r);
        }
        return;
    }
    rustsecp256k1_v0_6_1_fe_sqr(&i2, &i);
    rustsecp256k1_v0_6_1_fe_sqr(&h2, &h);
    rustsecp256k1_v0_6_1_fe_mul(&h3, &h, &h2);
    r->z = a->z; rustsecp256k1_v0_6_1_fe_mul(&r->z, &r->z, &h);
    rustsecp256k1_v0_6_1_fe_mul(&t, &u1, &h2);
    r->x = t; rustsecp256k1_v0_6_1_fe_mul_int(&r->x, 2); rustsecp256k1_v0_6_1_fe_add(&r->x, &h3); rustsecp256k1_v0_6_1_fe_negate(&r->x, &r->x, 3); rustsecp256k1_v0_6_1_fe_add(&r->x, &i2);
    rustsecp256k1_v0_6_1_fe_negate(&r->y, &r->x, 5); rustsecp256k1_v0_6_1_fe_add(&r->y, &t); rustsecp256k1_v0_6_1_fe_mul(&r->y, &r->y, &i);
    rustsecp256k1_v0_6_1_fe_mul(&h3, &h3, &s1); rustsecp256k1_v0_6_1_fe_negate(&h3, &h3, 1);
    rustsecp256k1_v0_6_1_fe_add(&r->y, &h3);
}


static void rustsecp256k1_v0_6_1_gej_add_ge(rustsecp256k1_v0_6_1_gej *r, const rustsecp256k1_v0_6_1_gej *a, const rustsecp256k1_v0_6_1_ge *b) {
    /* Operations: 7 mul, 5 sqr, 4 normalize, 21 mul_int/add/negate/cmov */
    static const rustsecp256k1_v0_6_1_fe fe_1 = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1);
    rustsecp256k1_v0_6_1_fe zz, u1, u2, s1, s2, t, tt, m, n, q, rr;
    rustsecp256k1_v0_6_1_fe m_alt, rr_alt;
    int infinity, degenerate;
    VERIFY_CHECK(!b->infinity);
    VERIFY_CHECK(a->infinity == 0 || a->infinity == 1);

    /** In:
     *    Eric Brier and Marc Joye, Weierstrass Elliptic Curves and Side-Channel Attacks.
     *    In D. Naccache and P. Paillier, Eds., Public Key Cryptography, vol. 2274 of Lecture Notes in Computer Science, pages 335-345. Springer-Verlag, 2002.
     *  we find as solution for a unified addition/doubling formula:
     *    lambda = ((x1 + x2)^2 - x1 * x2 + a) / (y1 + y2), with a = 0 for secp256k1's curve equation.
     *    x3 = lambda^2 - (x1 + x2)
     *    2*y3 = lambda * (x1 + x2 - 2 * x3) - (y1 + y2).
     *
     *  Substituting x_i = Xi / Zi^2 and yi = Yi / Zi^3, for i=1,2,3, gives:
     *    U1 = X1*Z2^2, U2 = X2*Z1^2
     *    S1 = Y1*Z2^3, S2 = Y2*Z1^3
     *    Z = Z1*Z2
     *    T = U1+U2
     *    M = S1+S2
     *    Q = T*M^2
     *    R = T^2-U1*U2
     *    X3 = 4*(R^2-Q)
     *    Y3 = 4*(R*(3*Q-2*R^2)-M^4)
     *    Z3 = 2*M*Z
     *  (Note that the paper uses xi = Xi / Zi and yi = Yi / Zi instead.)
     *
     *  This formula has the benefit of being the same for both addition
     *  of distinct points and doubling. However, it breaks down in the
     *  case that either point is infinity, or that y1 = -y2. We handle
     *  these cases in the following ways:
     *
     *    - If b is infinity we simply bail by means of a VERIFY_CHECK.
     *
     *    - If a is infinity, we detect this, and at the end of the
     *      computation replace the result (which will be meaningless,
     *      but we compute to be constant-time) with b.x : b.y : 1.
     *
     *    - If a = -b, we have y1 = -y2, which is a degenerate case.
     *      But here the answer is infinity, so we simply set the
     *      infinity flag of the result, overriding the computed values
     *      without even needing to cmov.
     *
     *    - If y1 = -y2 but x1 != x2, which does occur thanks to certain
     *      properties of our curve (specifically, 1 has nontrivial cube
     *      roots in our field, and the curve equation has no x coefficient)
     *      then the answer is not infinity but also not given by the above
     *      equation. In this case, we cmov in place an alternate expression
     *      for lambda. Specifically (y1 - y2)/(x1 - x2). Where both these
     *      expressions for lambda are defined, they are equal, and can be
     *      obtained from each other by multiplication by (y1 + y2)/(y1 + y2)
     *      then substitution of x^3 + 7 for y^2 (using the curve equation).
     *      For all pairs of nonzero points (a, b) at least one is defined,
     *      so this covers everything.
     */

    rustsecp256k1_v0_6_1_fe_sqr(&zz, &a->z);                       /* z = Z1^2 */
    u1 = a->x; rustsecp256k1_v0_6_1_fe_normalize_weak(&u1);        /* u1 = U1 = X1*Z2^2 (1) */
    rustsecp256k1_v0_6_1_fe_mul(&u2, &b->x, &zz);                  /* u2 = U2 = X2*Z1^2 (1) */
    s1 = a->y; rustsecp256k1_v0_6_1_fe_normalize_weak(&s1);        /* s1 = S1 = Y1*Z2^3 (1) */
    rustsecp256k1_v0_6_1_fe_mul(&s2, &b->y, &zz);                  /* s2 = Y2*Z1^2 (1) */
    rustsecp256k1_v0_6_1_fe_mul(&s2, &s2, &a->z);                  /* s2 = S2 = Y2*Z1^3 (1) */
    t = u1; rustsecp256k1_v0_6_1_fe_add(&t, &u2);                  /* t = T = U1+U2 (2) */
    m = s1; rustsecp256k1_v0_6_1_fe_add(&m, &s2);                  /* m = M = S1+S2 (2) */
    rustsecp256k1_v0_6_1_fe_sqr(&rr, &t);                          /* rr = T^2 (1) */
    rustsecp256k1_v0_6_1_fe_negate(&m_alt, &u2, 1);                /* Malt = -X2*Z1^2 */
    rustsecp256k1_v0_6_1_fe_mul(&tt, &u1, &m_alt);                 /* tt = -U1*U2 (2) */
    rustsecp256k1_v0_6_1_fe_add(&rr, &tt);                         /* rr = R = T^2-U1*U2 (3) */
    /** If lambda = R/M = 0/0 we have a problem (except in the "trivial"
     *  case that Z = z1z2 = 0, and this is special-cased later on). */
    degenerate = rustsecp256k1_v0_6_1_fe_normalizes_to_zero(&m) &
                 rustsecp256k1_v0_6_1_fe_normalizes_to_zero(&rr);
    /* This only occurs when y1 == -y2 and x1^3 == x2^3, but x1 != x2.
     * This means either x1 == beta*x2 or beta*x1 == x2, where beta is
     * a nontrivial cube root of one. In either case, an alternate
     * non-indeterminate expression for lambda is (y1 - y2)/(x1 - x2),
     * so we set R/M equal to this. */
    rr_alt = s1;
    rustsecp256k1_v0_6_1_fe_mul_int(&rr_alt, 2);       /* rr = Y1*Z2^3 - Y2*Z1^3 (2) */
    rustsecp256k1_v0_6_1_fe_add(&m_alt, &u1);          /* Malt = X1*Z2^2 - X2*Z1^2 */

    rustsecp256k1_v0_6_1_fe_cmov(&rr_alt, &rr, !degenerate);
    rustsecp256k1_v0_6_1_fe_cmov(&m_alt, &m, !degenerate);
    /* Now Ralt / Malt = lambda and is guaranteed not to be 0/0.
     * From here on out Ralt and Malt represent the numerator
     * and denominator of lambda; R and M represent the explicit
     * expressions x1^2 + x2^2 + x1x2 and y1 + y2. */
    rustsecp256k1_v0_6_1_fe_sqr(&n, &m_alt);                       /* n = Malt^2 (1) */
    rustsecp256k1_v0_6_1_fe_mul(&q, &n, &t);                       /* q = Q = T*Malt^2 (1) */
    /* These two lines use the observation that either M == Malt or M == 0,
     * so M^3 * Malt is either Malt^4 (which is computed by squaring), or
     * zero (which is "computed" by cmov). So the cost is one squaring
     * versus two multiplications. */
    rustsecp256k1_v0_6_1_fe_sqr(&n, &n);
    rustsecp256k1_v0_6_1_fe_cmov(&n, &m, degenerate);              /* n = M^3 * Malt (2) */
    rustsecp256k1_v0_6_1_fe_sqr(&t, &rr_alt);                      /* t = Ralt^2 (1) */
    rustsecp256k1_v0_6_1_fe_mul(&r->z, &a->z, &m_alt);             /* r->z = Malt*Z (1) */
    infinity = rustsecp256k1_v0_6_1_fe_normalizes_to_zero(&r->z) & ~a->infinity;
    rustsecp256k1_v0_6_1_fe_mul_int(&r->z, 2);                     /* r->z = Z3 = 2*Malt*Z (2) */
    rustsecp256k1_v0_6_1_fe_negate(&q, &q, 1);                     /* q = -Q (2) */
    rustsecp256k1_v0_6_1_fe_add(&t, &q);                           /* t = Ralt^2-Q (3) */
    rustsecp256k1_v0_6_1_fe_normalize_weak(&t);
    r->x = t;                                           /* r->x = Ralt^2-Q (1) */
    rustsecp256k1_v0_6_1_fe_mul_int(&t, 2);                        /* t = 2*x3 (2) */
    rustsecp256k1_v0_6_1_fe_add(&t, &q);                           /* t = 2*x3 - Q: (4) */
    rustsecp256k1_v0_6_1_fe_mul(&t, &t, &rr_alt);                  /* t = Ralt*(2*x3 - Q) (1) */
    rustsecp256k1_v0_6_1_fe_add(&t, &n);                           /* t = Ralt*(2*x3 - Q) + M^3*Malt (3) */
    rustsecp256k1_v0_6_1_fe_negate(&r->y, &t, 3);                  /* r->y = Ralt*(Q - 2x3) - M^3*Malt (4) */
    rustsecp256k1_v0_6_1_fe_normalize_weak(&r->y);
    rustsecp256k1_v0_6_1_fe_mul_int(&r->x, 4);                     /* r->x = X3 = 4*(Ralt^2-Q) */
    rustsecp256k1_v0_6_1_fe_mul_int(&r->y, 4);                     /* r->y = Y3 = 4*Ralt*(Q - 2x3) - 4*M^3*Malt (4) */

    /** In case a->infinity == 1, replace r with (b->x, b->y, 1). */
    rustsecp256k1_v0_6_1_fe_cmov(&r->x, &b->x, a->infinity);
    rustsecp256k1_v0_6_1_fe_cmov(&r->y, &b->y, a->infinity);
    rustsecp256k1_v0_6_1_fe_cmov(&r->z, &fe_1, a->infinity);
    r->infinity = infinity;
}

static void rustsecp256k1_v0_6_1_gej_rescale(rustsecp256k1_v0_6_1_gej *r, const rustsecp256k1_v0_6_1_fe *s) {
    /* Operations: 4 mul, 1 sqr */
    rustsecp256k1_v0_6_1_fe zz;
    VERIFY_CHECK(!rustsecp256k1_v0_6_1_fe_is_zero(s));
    rustsecp256k1_v0_6_1_fe_sqr(&zz, s);
    rustsecp256k1_v0_6_1_fe_mul(&r->x, &r->x, &zz);                /* r->x *= s^2 */
    rustsecp256k1_v0_6_1_fe_mul(&r->y, &r->y, &zz);
    rustsecp256k1_v0_6_1_fe_mul(&r->y, &r->y, s);                  /* r->y *= s^3 */
    rustsecp256k1_v0_6_1_fe_mul(&r->z, &r->z, s);                  /* r->z *= s   */
}

static void rustsecp256k1_v0_6_1_ge_to_storage(rustsecp256k1_v0_6_1_ge_storage *r, const rustsecp256k1_v0_6_1_ge *a) {
    rustsecp256k1_v0_6_1_fe x, y;
    VERIFY_CHECK(!a->infinity);
    x = a->x;
    rustsecp256k1_v0_6_1_fe_normalize(&x);
    y = a->y;
    rustsecp256k1_v0_6_1_fe_normalize(&y);
    rustsecp256k1_v0_6_1_fe_to_storage(&r->x, &x);
    rustsecp256k1_v0_6_1_fe_to_storage(&r->y, &y);
}

static void rustsecp256k1_v0_6_1_ge_from_storage(rustsecp256k1_v0_6_1_ge *r, const rustsecp256k1_v0_6_1_ge_storage *a) {
    rustsecp256k1_v0_6_1_fe_from_storage(&r->x, &a->x);
    rustsecp256k1_v0_6_1_fe_from_storage(&r->y, &a->y);
    r->infinity = 0;
}

static SECP256K1_INLINE void rustsecp256k1_v0_6_1_gej_cmov(rustsecp256k1_v0_6_1_gej *r, const rustsecp256k1_v0_6_1_gej *a, int flag) {
    rustsecp256k1_v0_6_1_fe_cmov(&r->x, &a->x, flag);
    rustsecp256k1_v0_6_1_fe_cmov(&r->y, &a->y, flag);
    rustsecp256k1_v0_6_1_fe_cmov(&r->z, &a->z, flag);

    r->infinity ^= (r->infinity ^ a->infinity) & flag;
}

static SECP256K1_INLINE void rustsecp256k1_v0_6_1_ge_storage_cmov(rustsecp256k1_v0_6_1_ge_storage *r, const rustsecp256k1_v0_6_1_ge_storage *a, int flag) {
    rustsecp256k1_v0_6_1_fe_storage_cmov(&r->x, &a->x, flag);
    rustsecp256k1_v0_6_1_fe_storage_cmov(&r->y, &a->y, flag);
}

static void rustsecp256k1_v0_6_1_ge_mul_lambda(rustsecp256k1_v0_6_1_ge *r, const rustsecp256k1_v0_6_1_ge *a) {
    static const rustsecp256k1_v0_6_1_fe beta = SECP256K1_FE_CONST(
        0x7ae96a2bul, 0x657c0710ul, 0x6e64479eul, 0xac3434e9ul,
        0x9cf04975ul, 0x12f58995ul, 0xc1396c28ul, 0x719501eeul
    );
    *r = *a;
    rustsecp256k1_v0_6_1_fe_mul(&r->x, &r->x, &beta);
}

static int rustsecp256k1_v0_6_1_ge_is_in_correct_subgroup(const rustsecp256k1_v0_6_1_ge* ge) {
#ifdef EXHAUSTIVE_TEST_ORDER
    rustsecp256k1_v0_6_1_gej out;
    int i;

    /* A very simple EC multiplication ladder that avoids a dependency on ecmult. */
    rustsecp256k1_v0_6_1_gej_set_infinity(&out);
    for (i = 0; i < 32; ++i) {
        rustsecp256k1_v0_6_1_gej_double_var(&out, &out, NULL);
        if ((((uint32_t)EXHAUSTIVE_TEST_ORDER) >> (31 - i)) & 1) {
            rustsecp256k1_v0_6_1_gej_add_ge_var(&out, &out, ge, NULL);
        }
    }
    return rustsecp256k1_v0_6_1_gej_is_infinity(&out);
#else
    (void)ge;
    /* The real secp256k1 group has cofactor 1, so the subgroup is the entire curve. */
    return 1;
#endif
}

#endif /* SECP256K1_GROUP_IMPL_H */
