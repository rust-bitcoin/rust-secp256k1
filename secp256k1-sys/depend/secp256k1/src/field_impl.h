/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_FIELD_IMPL_H
#define SECP256K1_FIELD_IMPL_H

#include "field.h"
#include "util.h"

#if defined(SECP256K1_WIDEMUL_INT128)
#include "field_5x52_impl.h"
#elif defined(SECP256K1_WIDEMUL_INT64)
#include "field_10x26_impl.h"
#else
#error "Please select wide multiplication implementation"
#endif

SECP256K1_INLINE static int rustsecp256k1_v0_10_0_fe_equal(const rustsecp256k1_v0_10_0_fe *a, const rustsecp256k1_v0_10_0_fe *b) {
    rustsecp256k1_v0_10_0_fe na;
    SECP256K1_FE_VERIFY(a);
    SECP256K1_FE_VERIFY(b);
    SECP256K1_FE_VERIFY_MAGNITUDE(a, 1);
    SECP256K1_FE_VERIFY_MAGNITUDE(b, 31);

    rustsecp256k1_v0_10_0_fe_negate(&na, a, 1);
    rustsecp256k1_v0_10_0_fe_add(&na, b);
    return rustsecp256k1_v0_10_0_fe_normalizes_to_zero(&na);
}

static int rustsecp256k1_v0_10_0_fe_sqrt(rustsecp256k1_v0_10_0_fe * SECP256K1_RESTRICT r, const rustsecp256k1_v0_10_0_fe * SECP256K1_RESTRICT a) {
    /** Given that p is congruent to 3 mod 4, we can compute the square root of
     *  a mod p as the (p+1)/4'th power of a.
     *
     *  As (p+1)/4 is an even number, it will have the same result for a and for
     *  (-a). Only one of these two numbers actually has a square root however,
     *  so we test at the end by squaring and comparing to the input.
     *  Also because (p+1)/4 is an even number, the computed square root is
     *  itself always a square (a ** ((p+1)/4) is the square of a ** ((p+1)/8)).
     */
    rustsecp256k1_v0_10_0_fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;
    int j, ret;

    VERIFY_CHECK(r != a);
    SECP256K1_FE_VERIFY(a);
    SECP256K1_FE_VERIFY_MAGNITUDE(a, 8);

    /** The binary representation of (p + 1)/4 has 3 blocks of 1s, with lengths in
     *  { 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
     *  1, [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
     */

    rustsecp256k1_v0_10_0_fe_sqr(&x2, a);
    rustsecp256k1_v0_10_0_fe_mul(&x2, &x2, a);

    rustsecp256k1_v0_10_0_fe_sqr(&x3, &x2);
    rustsecp256k1_v0_10_0_fe_mul(&x3, &x3, a);

    x6 = x3;
    for (j=0; j<3; j++) {
        rustsecp256k1_v0_10_0_fe_sqr(&x6, &x6);
    }
    rustsecp256k1_v0_10_0_fe_mul(&x6, &x6, &x3);

    x9 = x6;
    for (j=0; j<3; j++) {
        rustsecp256k1_v0_10_0_fe_sqr(&x9, &x9);
    }
    rustsecp256k1_v0_10_0_fe_mul(&x9, &x9, &x3);

    x11 = x9;
    for (j=0; j<2; j++) {
        rustsecp256k1_v0_10_0_fe_sqr(&x11, &x11);
    }
    rustsecp256k1_v0_10_0_fe_mul(&x11, &x11, &x2);

    x22 = x11;
    for (j=0; j<11; j++) {
        rustsecp256k1_v0_10_0_fe_sqr(&x22, &x22);
    }
    rustsecp256k1_v0_10_0_fe_mul(&x22, &x22, &x11);

    x44 = x22;
    for (j=0; j<22; j++) {
        rustsecp256k1_v0_10_0_fe_sqr(&x44, &x44);
    }
    rustsecp256k1_v0_10_0_fe_mul(&x44, &x44, &x22);

    x88 = x44;
    for (j=0; j<44; j++) {
        rustsecp256k1_v0_10_0_fe_sqr(&x88, &x88);
    }
    rustsecp256k1_v0_10_0_fe_mul(&x88, &x88, &x44);

    x176 = x88;
    for (j=0; j<88; j++) {
        rustsecp256k1_v0_10_0_fe_sqr(&x176, &x176);
    }
    rustsecp256k1_v0_10_0_fe_mul(&x176, &x176, &x88);

    x220 = x176;
    for (j=0; j<44; j++) {
        rustsecp256k1_v0_10_0_fe_sqr(&x220, &x220);
    }
    rustsecp256k1_v0_10_0_fe_mul(&x220, &x220, &x44);

    x223 = x220;
    for (j=0; j<3; j++) {
        rustsecp256k1_v0_10_0_fe_sqr(&x223, &x223);
    }
    rustsecp256k1_v0_10_0_fe_mul(&x223, &x223, &x3);

    /* The final result is then assembled using a sliding window over the blocks. */

    t1 = x223;
    for (j=0; j<23; j++) {
        rustsecp256k1_v0_10_0_fe_sqr(&t1, &t1);
    }
    rustsecp256k1_v0_10_0_fe_mul(&t1, &t1, &x22);
    for (j=0; j<6; j++) {
        rustsecp256k1_v0_10_0_fe_sqr(&t1, &t1);
    }
    rustsecp256k1_v0_10_0_fe_mul(&t1, &t1, &x2);
    rustsecp256k1_v0_10_0_fe_sqr(&t1, &t1);
    rustsecp256k1_v0_10_0_fe_sqr(r, &t1);

    /* Check that a square root was actually calculated */

    rustsecp256k1_v0_10_0_fe_sqr(&t1, r);
    ret = rustsecp256k1_v0_10_0_fe_equal(&t1, a);

#ifdef VERIFY
    if (!ret) {
        rustsecp256k1_v0_10_0_fe_negate(&t1, &t1, 1);
        rustsecp256k1_v0_10_0_fe_normalize_var(&t1);
        VERIFY_CHECK(rustsecp256k1_v0_10_0_fe_equal(&t1, a));
    }
#endif
    return ret;
}

#ifndef VERIFY
static void rustsecp256k1_v0_10_0_fe_verify(const rustsecp256k1_v0_10_0_fe *a) { (void)a; }
static void rustsecp256k1_v0_10_0_fe_verify_magnitude(const rustsecp256k1_v0_10_0_fe *a, int m) { (void)a; (void)m; }
#else
static void rustsecp256k1_v0_10_0_fe_impl_verify(const rustsecp256k1_v0_10_0_fe *a);
static void rustsecp256k1_v0_10_0_fe_verify(const rustsecp256k1_v0_10_0_fe *a) {
    /* Magnitude between 0 and 32. */
    SECP256K1_FE_VERIFY_MAGNITUDE(a, 32);
    /* Normalized is 0 or 1. */
    VERIFY_CHECK((a->normalized == 0) || (a->normalized == 1));
    /* If normalized, magnitude must be 0 or 1. */
    if (a->normalized) SECP256K1_FE_VERIFY_MAGNITUDE(a, 1);
    /* Invoke implementation-specific checks. */
    rustsecp256k1_v0_10_0_fe_impl_verify(a);
}

static void rustsecp256k1_v0_10_0_fe_verify_magnitude(const rustsecp256k1_v0_10_0_fe *a, int m) {
    VERIFY_CHECK(m >= 0);
    VERIFY_CHECK(m <= 32);
    VERIFY_CHECK(a->magnitude <= m);
}

static void rustsecp256k1_v0_10_0_fe_impl_normalize(rustsecp256k1_v0_10_0_fe *r);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_normalize(rustsecp256k1_v0_10_0_fe *r) {
    SECP256K1_FE_VERIFY(r);

    rustsecp256k1_v0_10_0_fe_impl_normalize(r);
    r->magnitude = 1;
    r->normalized = 1;

    SECP256K1_FE_VERIFY(r);
}

static void rustsecp256k1_v0_10_0_fe_impl_normalize_weak(rustsecp256k1_v0_10_0_fe *r);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_normalize_weak(rustsecp256k1_v0_10_0_fe *r) {
    SECP256K1_FE_VERIFY(r);

    rustsecp256k1_v0_10_0_fe_impl_normalize_weak(r);
    r->magnitude = 1;

    SECP256K1_FE_VERIFY(r);
}

static void rustsecp256k1_v0_10_0_fe_impl_normalize_var(rustsecp256k1_v0_10_0_fe *r);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_normalize_var(rustsecp256k1_v0_10_0_fe *r) {
    SECP256K1_FE_VERIFY(r);

    rustsecp256k1_v0_10_0_fe_impl_normalize_var(r);
    r->magnitude = 1;
    r->normalized = 1;

    SECP256K1_FE_VERIFY(r);
}

static int rustsecp256k1_v0_10_0_fe_impl_normalizes_to_zero(const rustsecp256k1_v0_10_0_fe *r);
SECP256K1_INLINE static int rustsecp256k1_v0_10_0_fe_normalizes_to_zero(const rustsecp256k1_v0_10_0_fe *r) {
    SECP256K1_FE_VERIFY(r);

    return rustsecp256k1_v0_10_0_fe_impl_normalizes_to_zero(r);
}

static int rustsecp256k1_v0_10_0_fe_impl_normalizes_to_zero_var(const rustsecp256k1_v0_10_0_fe *r);
SECP256K1_INLINE static int rustsecp256k1_v0_10_0_fe_normalizes_to_zero_var(const rustsecp256k1_v0_10_0_fe *r) {
    SECP256K1_FE_VERIFY(r);

    return rustsecp256k1_v0_10_0_fe_impl_normalizes_to_zero_var(r);
}

static void rustsecp256k1_v0_10_0_fe_impl_set_int(rustsecp256k1_v0_10_0_fe *r, int a);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_set_int(rustsecp256k1_v0_10_0_fe *r, int a) {
    VERIFY_CHECK(0 <= a && a <= 0x7FFF);

    rustsecp256k1_v0_10_0_fe_impl_set_int(r, a);
    r->magnitude = (a != 0);
    r->normalized = 1;

    SECP256K1_FE_VERIFY(r);
}

static void rustsecp256k1_v0_10_0_fe_impl_add_int(rustsecp256k1_v0_10_0_fe *r, int a);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_add_int(rustsecp256k1_v0_10_0_fe *r, int a) {
    VERIFY_CHECK(0 <= a && a <= 0x7FFF);
    SECP256K1_FE_VERIFY(r);

    rustsecp256k1_v0_10_0_fe_impl_add_int(r, a);
    r->magnitude += 1;
    r->normalized = 0;

    SECP256K1_FE_VERIFY(r);
}

static void rustsecp256k1_v0_10_0_fe_impl_clear(rustsecp256k1_v0_10_0_fe *a);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_clear(rustsecp256k1_v0_10_0_fe *a) {
    a->magnitude = 0;
    a->normalized = 1;
    rustsecp256k1_v0_10_0_fe_impl_clear(a);

    SECP256K1_FE_VERIFY(a);
}

static int rustsecp256k1_v0_10_0_fe_impl_is_zero(const rustsecp256k1_v0_10_0_fe *a);
SECP256K1_INLINE static int rustsecp256k1_v0_10_0_fe_is_zero(const rustsecp256k1_v0_10_0_fe *a) {
    SECP256K1_FE_VERIFY(a);
    VERIFY_CHECK(a->normalized);

    return rustsecp256k1_v0_10_0_fe_impl_is_zero(a);
}

static int rustsecp256k1_v0_10_0_fe_impl_is_odd(const rustsecp256k1_v0_10_0_fe *a);
SECP256K1_INLINE static int rustsecp256k1_v0_10_0_fe_is_odd(const rustsecp256k1_v0_10_0_fe *a) {
    SECP256K1_FE_VERIFY(a);
    VERIFY_CHECK(a->normalized);

    return rustsecp256k1_v0_10_0_fe_impl_is_odd(a);
}

static int rustsecp256k1_v0_10_0_fe_impl_cmp_var(const rustsecp256k1_v0_10_0_fe *a, const rustsecp256k1_v0_10_0_fe *b);
SECP256K1_INLINE static int rustsecp256k1_v0_10_0_fe_cmp_var(const rustsecp256k1_v0_10_0_fe *a, const rustsecp256k1_v0_10_0_fe *b) {
    SECP256K1_FE_VERIFY(a);
    SECP256K1_FE_VERIFY(b);
    VERIFY_CHECK(a->normalized);
    VERIFY_CHECK(b->normalized);

    return rustsecp256k1_v0_10_0_fe_impl_cmp_var(a, b);
}

static void rustsecp256k1_v0_10_0_fe_impl_set_b32_mod(rustsecp256k1_v0_10_0_fe *r, const unsigned char *a);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_set_b32_mod(rustsecp256k1_v0_10_0_fe *r, const unsigned char *a) {
    rustsecp256k1_v0_10_0_fe_impl_set_b32_mod(r, a);
    r->magnitude = 1;
    r->normalized = 0;

    SECP256K1_FE_VERIFY(r);
}

static int rustsecp256k1_v0_10_0_fe_impl_set_b32_limit(rustsecp256k1_v0_10_0_fe *r, const unsigned char *a);
SECP256K1_INLINE static int rustsecp256k1_v0_10_0_fe_set_b32_limit(rustsecp256k1_v0_10_0_fe *r, const unsigned char *a) {
    if (rustsecp256k1_v0_10_0_fe_impl_set_b32_limit(r, a)) {
        r->magnitude = 1;
        r->normalized = 1;
        SECP256K1_FE_VERIFY(r);
        return 1;
    } else {
        /* Mark the output field element as invalid. */
        r->magnitude = -1;
        return 0;
    }
}

static void rustsecp256k1_v0_10_0_fe_impl_get_b32(unsigned char *r, const rustsecp256k1_v0_10_0_fe *a);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_get_b32(unsigned char *r, const rustsecp256k1_v0_10_0_fe *a) {
    SECP256K1_FE_VERIFY(a);
    VERIFY_CHECK(a->normalized);

    rustsecp256k1_v0_10_0_fe_impl_get_b32(r, a);
}

static void rustsecp256k1_v0_10_0_fe_impl_negate_unchecked(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a, int m);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_negate_unchecked(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a, int m) {
    SECP256K1_FE_VERIFY(a);
    VERIFY_CHECK(m >= 0 && m <= 31);
    SECP256K1_FE_VERIFY_MAGNITUDE(a, m);

    rustsecp256k1_v0_10_0_fe_impl_negate_unchecked(r, a, m);
    r->magnitude = m + 1;
    r->normalized = 0;

    SECP256K1_FE_VERIFY(r);
}

static void rustsecp256k1_v0_10_0_fe_impl_mul_int_unchecked(rustsecp256k1_v0_10_0_fe *r, int a);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_mul_int_unchecked(rustsecp256k1_v0_10_0_fe *r, int a) {
    SECP256K1_FE_VERIFY(r);

    VERIFY_CHECK(a >= 0 && a <= 32);
    VERIFY_CHECK(a*r->magnitude <= 32);
    rustsecp256k1_v0_10_0_fe_impl_mul_int_unchecked(r, a);
    r->magnitude *= a;
    r->normalized = 0;

    SECP256K1_FE_VERIFY(r);
}

static void rustsecp256k1_v0_10_0_fe_impl_add(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_add(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a) {
    SECP256K1_FE_VERIFY(r);
    SECP256K1_FE_VERIFY(a);
    VERIFY_CHECK(r->magnitude + a->magnitude <= 32);

    rustsecp256k1_v0_10_0_fe_impl_add(r, a);
    r->magnitude += a->magnitude;
    r->normalized = 0;

    SECP256K1_FE_VERIFY(r);
}

static void rustsecp256k1_v0_10_0_fe_impl_mul(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a, const rustsecp256k1_v0_10_0_fe * SECP256K1_RESTRICT b);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_mul(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a, const rustsecp256k1_v0_10_0_fe * SECP256K1_RESTRICT b) {
    SECP256K1_FE_VERIFY(a);
    SECP256K1_FE_VERIFY(b);
    SECP256K1_FE_VERIFY_MAGNITUDE(a, 8);
    SECP256K1_FE_VERIFY_MAGNITUDE(b, 8);
    VERIFY_CHECK(r != b);
    VERIFY_CHECK(a != b);

    rustsecp256k1_v0_10_0_fe_impl_mul(r, a, b);
    r->magnitude = 1;
    r->normalized = 0;

    SECP256K1_FE_VERIFY(r);
}

static void rustsecp256k1_v0_10_0_fe_impl_sqr(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_sqr(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a) {
    SECP256K1_FE_VERIFY(a);
    SECP256K1_FE_VERIFY_MAGNITUDE(a, 8);

    rustsecp256k1_v0_10_0_fe_impl_sqr(r, a);
    r->magnitude = 1;
    r->normalized = 0;

    SECP256K1_FE_VERIFY(r);
}

static void rustsecp256k1_v0_10_0_fe_impl_cmov(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a, int flag);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_cmov(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *a, int flag) {
    VERIFY_CHECK(flag == 0 || flag == 1);
    SECP256K1_FE_VERIFY(a);
    SECP256K1_FE_VERIFY(r);

    rustsecp256k1_v0_10_0_fe_impl_cmov(r, a, flag);
    if (a->magnitude > r->magnitude) r->magnitude = a->magnitude;
    if (!a->normalized) r->normalized = 0;

    SECP256K1_FE_VERIFY(r);
}

static void rustsecp256k1_v0_10_0_fe_impl_to_storage(rustsecp256k1_v0_10_0_fe_storage *r, const rustsecp256k1_v0_10_0_fe *a);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_to_storage(rustsecp256k1_v0_10_0_fe_storage *r, const rustsecp256k1_v0_10_0_fe *a) {
    SECP256K1_FE_VERIFY(a);
    VERIFY_CHECK(a->normalized);

    rustsecp256k1_v0_10_0_fe_impl_to_storage(r, a);
}

static void rustsecp256k1_v0_10_0_fe_impl_from_storage(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe_storage *a);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_from_storage(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe_storage *a) {
    rustsecp256k1_v0_10_0_fe_impl_from_storage(r, a);
    r->magnitude = 1;
    r->normalized = 1;

    SECP256K1_FE_VERIFY(r);
}

static void rustsecp256k1_v0_10_0_fe_impl_inv(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *x);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_inv(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *x) {
    int input_is_zero = rustsecp256k1_v0_10_0_fe_normalizes_to_zero(x);
    SECP256K1_FE_VERIFY(x);

    rustsecp256k1_v0_10_0_fe_impl_inv(r, x);
    r->magnitude = x->magnitude > 0;
    r->normalized = 1;

    VERIFY_CHECK(rustsecp256k1_v0_10_0_fe_normalizes_to_zero(r) == input_is_zero);
    SECP256K1_FE_VERIFY(r);
}

static void rustsecp256k1_v0_10_0_fe_impl_inv_var(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *x);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_inv_var(rustsecp256k1_v0_10_0_fe *r, const rustsecp256k1_v0_10_0_fe *x) {
    int input_is_zero = rustsecp256k1_v0_10_0_fe_normalizes_to_zero(x);
    SECP256K1_FE_VERIFY(x);

    rustsecp256k1_v0_10_0_fe_impl_inv_var(r, x);
    r->magnitude = x->magnitude > 0;
    r->normalized = 1;

    VERIFY_CHECK(rustsecp256k1_v0_10_0_fe_normalizes_to_zero(r) == input_is_zero);
    SECP256K1_FE_VERIFY(r);
}

static int rustsecp256k1_v0_10_0_fe_impl_is_square_var(const rustsecp256k1_v0_10_0_fe *x);
SECP256K1_INLINE static int rustsecp256k1_v0_10_0_fe_is_square_var(const rustsecp256k1_v0_10_0_fe *x) {
    int ret;
    rustsecp256k1_v0_10_0_fe tmp = *x, sqrt;
    SECP256K1_FE_VERIFY(x);

    ret = rustsecp256k1_v0_10_0_fe_impl_is_square_var(x);
    rustsecp256k1_v0_10_0_fe_normalize_weak(&tmp);
    VERIFY_CHECK(ret == rustsecp256k1_v0_10_0_fe_sqrt(&sqrt, &tmp));
    return ret;
}

static void rustsecp256k1_v0_10_0_fe_impl_get_bounds(rustsecp256k1_v0_10_0_fe* r, int m);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_get_bounds(rustsecp256k1_v0_10_0_fe* r, int m) {
    VERIFY_CHECK(m >= 0);
    VERIFY_CHECK(m <= 32);

    rustsecp256k1_v0_10_0_fe_impl_get_bounds(r, m);
    r->magnitude = m;
    r->normalized = (m == 0);

    SECP256K1_FE_VERIFY(r);
}

static void rustsecp256k1_v0_10_0_fe_impl_half(rustsecp256k1_v0_10_0_fe *r);
SECP256K1_INLINE static void rustsecp256k1_v0_10_0_fe_half(rustsecp256k1_v0_10_0_fe *r) {
    SECP256K1_FE_VERIFY(r);
    SECP256K1_FE_VERIFY_MAGNITUDE(r, 31);

    rustsecp256k1_v0_10_0_fe_impl_half(r);
    r->magnitude = (r->magnitude >> 1) + 1;
    r->normalized = 0;

    SECP256K1_FE_VERIFY(r);
}

#endif /* defined(VERIFY) */

#endif /* SECP256K1_FIELD_IMPL_H */
