/**********************************************************************
 * Copyright (c) 2015 Pieter Wuille, Andrew Poelstra                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_ECMULT_CONST_IMPL_H
#define SECP256K1_ECMULT_CONST_IMPL_H

#include "scalar.h"
#include "group.h"
#include "ecmult_const.h"
#include "ecmult_impl.h"

/* This is like `ECMULT_TABLE_GET_GE` but is constant time */
#define ECMULT_CONST_TABLE_GET_GE(r,pre,n,w) do { \
    int m; \
    /* Extract the sign-bit for a constant time absolute-value. */ \
    int mask = (n) >> (sizeof(n) * CHAR_BIT - 1); \
    int abs_n = ((n) + mask) ^ mask; \
    int idx_n = abs_n >> 1; \
    rustsecp256k1_v0_1_2_fe neg_y; \
    VERIFY_CHECK(((n) & 1) == 1); \
    VERIFY_CHECK((n) >= -((1 << ((w)-1)) - 1)); \
    VERIFY_CHECK((n) <=  ((1 << ((w)-1)) - 1)); \
    VERIFY_SETUP(rustsecp256k1_v0_1_2_fe_clear(&(r)->x)); \
    VERIFY_SETUP(rustsecp256k1_v0_1_2_fe_clear(&(r)->y)); \
    for (m = 0; m < ECMULT_TABLE_SIZE(w); m++) { \
        /* This loop is used to avoid secret data in array indices. See
         * the comment in ecmult_gen_impl.h for rationale. */ \
        rustsecp256k1_v0_1_2_fe_cmov(&(r)->x, &(pre)[m].x, m == idx_n); \
        rustsecp256k1_v0_1_2_fe_cmov(&(r)->y, &(pre)[m].y, m == idx_n); \
    } \
    (r)->infinity = 0; \
    rustsecp256k1_v0_1_2_fe_negate(&neg_y, &(r)->y, 1); \
    rustsecp256k1_v0_1_2_fe_cmov(&(r)->y, &neg_y, (n) != abs_n); \
} while(0)


/** Convert a number to WNAF notation.
 *  The number becomes represented by sum(2^{wi} * wnaf[i], i=0..WNAF_SIZE(w)+1) - return_val.
 *  It has the following guarantees:
 *  - each wnaf[i] an odd integer between -(1 << w) and (1 << w)
 *  - each wnaf[i] is nonzero
 *  - the number of words set is always WNAF_SIZE(w) + 1
 *
 *  Adapted from `The Width-w NAF Method Provides Small Memory and Fast Elliptic Scalar
 *  Multiplications Secure against Side Channel Attacks`, Okeya and Tagaki. M. Joye (Ed.)
 *  CT-RSA 2003, LNCS 2612, pp. 328-443, 2003. Springer-Verlag Berlin Heidelberg 2003
 *
 *  Numbers reference steps of `Algorithm SPA-resistant Width-w NAF with Odd Scalar` on pp. 335
 */
static int rustsecp256k1_v0_1_2_wnaf_const(int *wnaf, const rustsecp256k1_v0_1_2_scalar *scalar, int w, int size) {
    int global_sign;
    int skew = 0;
    int word = 0;

    /* 1 2 3 */
    int u_last;
    int u;

    int flip;
    int bit;
    rustsecp256k1_v0_1_2_scalar s;
    int not_neg_one;

    VERIFY_CHECK(w > 0);
    VERIFY_CHECK(size > 0);

    /* Note that we cannot handle even numbers by negating them to be odd, as is
     * done in other implementations, since if our scalars were specified to have
     * width < 256 for performance reasons, their negations would have width 256
     * and we'd lose any performance benefit. Instead, we use a technique from
     * Section 4.2 of the Okeya/Tagaki paper, which is to add either 1 (for even)
     * or 2 (for odd) to the number we are encoding, returning a skew value indicating
     * this, and having the caller compensate after doing the multiplication.
     *
     * In fact, we _do_ want to negate numbers to minimize their bit-lengths (and in
     * particular, to ensure that the outputs from the endomorphism-split fit into
     * 128 bits). If we negate, the parity of our number flips, inverting which of
     * {1, 2} we want to add to the scalar when ensuring that it's odd. Further
     * complicating things, -1 interacts badly with `rustsecp256k1_v0_1_2_scalar_cadd_bit` and
     * we need to special-case it in this logic. */
    flip = rustsecp256k1_v0_1_2_scalar_is_high(scalar);
    /* We add 1 to even numbers, 2 to odd ones, noting that negation flips parity */
    bit = flip ^ !rustsecp256k1_v0_1_2_scalar_is_even(scalar);
    /* We check for negative one, since adding 2 to it will cause an overflow */
    rustsecp256k1_v0_1_2_scalar_negate(&s, scalar);
    not_neg_one = !rustsecp256k1_v0_1_2_scalar_is_one(&s);
    s = *scalar;
    rustsecp256k1_v0_1_2_scalar_cadd_bit(&s, bit, not_neg_one);
    /* If we had negative one, flip == 1, s.d[0] == 0, bit == 1, so caller expects
     * that we added two to it and flipped it. In fact for -1 these operations are
     * identical. We only flipped, but since skewing is required (in the sense that
     * the skew must be 1 or 2, never zero) and flipping is not, we need to change
     * our flags to claim that we only skewed. */
    global_sign = rustsecp256k1_v0_1_2_scalar_cond_negate(&s, flip);
    global_sign *= not_neg_one * 2 - 1;
    skew = 1 << bit;

    /* 4 */
    u_last = rustsecp256k1_v0_1_2_scalar_shr_int(&s, w);
    do {
        int sign;
        int even;

        /* 4.1 4.4 */
        u = rustsecp256k1_v0_1_2_scalar_shr_int(&s, w);
        /* 4.2 */
        even = ((u & 1) == 0);
        sign = 2 * (u_last > 0) - 1;
        u += sign * even;
        u_last -= sign * even * (1 << w);

        /* 4.3, adapted for global sign change */
        wnaf[word++] = u_last * global_sign;

        u_last = u;
    } while (word * w < size);
    wnaf[word] = u * global_sign;

    VERIFY_CHECK(rustsecp256k1_v0_1_2_scalar_is_zero(&s));
    VERIFY_CHECK(word == WNAF_SIZE_BITS(size, w));
    return skew;
}

static void rustsecp256k1_v0_1_2_ecmult_const(rustsecp256k1_v0_1_2_gej *r, const rustsecp256k1_v0_1_2_ge *a, const rustsecp256k1_v0_1_2_scalar *scalar, int size) {
    rustsecp256k1_v0_1_2_ge pre_a[ECMULT_TABLE_SIZE(WINDOW_A)];
    rustsecp256k1_v0_1_2_ge tmpa;
    rustsecp256k1_v0_1_2_fe Z;

    int skew_1;
#ifdef USE_ENDOMORPHISM
    rustsecp256k1_v0_1_2_ge pre_a_lam[ECMULT_TABLE_SIZE(WINDOW_A)];
    int wnaf_lam[1 + WNAF_SIZE(WINDOW_A - 1)];
    int skew_lam;
    rustsecp256k1_v0_1_2_scalar q_1, q_lam;
#endif
    int wnaf_1[1 + WNAF_SIZE(WINDOW_A - 1)];

    int i;

    /* build wnaf representation for q. */
    int rsize = size;
#ifdef USE_ENDOMORPHISM
    if (size > 128) {
        rsize = 128;
        /* split q into q_1 and q_lam (where q = q_1 + q_lam*lambda, and q_1 and q_lam are ~128 bit) */
        rustsecp256k1_v0_1_2_scalar_split_lambda(&q_1, &q_lam, scalar);
        skew_1   = rustsecp256k1_v0_1_2_wnaf_const(wnaf_1,   &q_1,   WINDOW_A - 1, 128);
        skew_lam = rustsecp256k1_v0_1_2_wnaf_const(wnaf_lam, &q_lam, WINDOW_A - 1, 128);
    } else
#endif
    {
        skew_1   = rustsecp256k1_v0_1_2_wnaf_const(wnaf_1, scalar, WINDOW_A - 1, size);
#ifdef USE_ENDOMORPHISM
        skew_lam = 0;
#endif
    }

    /* Calculate odd multiples of a.
     * All multiples are brought to the same Z 'denominator', which is stored
     * in Z. Due to secp256k1' isomorphism we can do all operations pretending
     * that the Z coordinate was 1, use affine addition formulae, and correct
     * the Z coordinate of the result once at the end.
     */
    rustsecp256k1_v0_1_2_gej_set_ge(r, a);
    rustsecp256k1_v0_1_2_ecmult_odd_multiples_table_globalz_windowa(pre_a, &Z, r);
    for (i = 0; i < ECMULT_TABLE_SIZE(WINDOW_A); i++) {
        rustsecp256k1_v0_1_2_fe_normalize_weak(&pre_a[i].y);
    }
#ifdef USE_ENDOMORPHISM
    if (size > 128) {
        for (i = 0; i < ECMULT_TABLE_SIZE(WINDOW_A); i++) {
            rustsecp256k1_v0_1_2_ge_mul_lambda(&pre_a_lam[i], &pre_a[i]);
        }

    }
#endif

    /* first loop iteration (separated out so we can directly set r, rather
     * than having it start at infinity, get doubled several times, then have
     * its new value added to it) */
    i = wnaf_1[WNAF_SIZE_BITS(rsize, WINDOW_A - 1)];
    VERIFY_CHECK(i != 0);
    ECMULT_CONST_TABLE_GET_GE(&tmpa, pre_a, i, WINDOW_A);
    rustsecp256k1_v0_1_2_gej_set_ge(r, &tmpa);
#ifdef USE_ENDOMORPHISM
    if (size > 128) {
        i = wnaf_lam[WNAF_SIZE_BITS(rsize, WINDOW_A - 1)];
        VERIFY_CHECK(i != 0);
        ECMULT_CONST_TABLE_GET_GE(&tmpa, pre_a_lam, i, WINDOW_A);
        rustsecp256k1_v0_1_2_gej_add_ge(r, r, &tmpa);
    }
#endif
    /* remaining loop iterations */
    for (i = WNAF_SIZE_BITS(rsize, WINDOW_A - 1) - 1; i >= 0; i--) {
        int n;
        int j;
        for (j = 0; j < WINDOW_A - 1; ++j) {
            rustsecp256k1_v0_1_2_gej_double_nonzero(r, r);
        }

        n = wnaf_1[i];
        ECMULT_CONST_TABLE_GET_GE(&tmpa, pre_a, n, WINDOW_A);
        VERIFY_CHECK(n != 0);
        rustsecp256k1_v0_1_2_gej_add_ge(r, r, &tmpa);
#ifdef USE_ENDOMORPHISM
        if (size > 128) {
            n = wnaf_lam[i];
            ECMULT_CONST_TABLE_GET_GE(&tmpa, pre_a_lam, n, WINDOW_A);
            VERIFY_CHECK(n != 0);
            rustsecp256k1_v0_1_2_gej_add_ge(r, r, &tmpa);
        }
#endif
    }

    rustsecp256k1_v0_1_2_fe_mul(&r->z, &r->z, &Z);

    {
        /* Correct for wNAF skew */
        rustsecp256k1_v0_1_2_ge correction = *a;
        rustsecp256k1_v0_1_2_ge_storage correction_1_stor;
#ifdef USE_ENDOMORPHISM
        rustsecp256k1_v0_1_2_ge_storage correction_lam_stor;
#endif
        rustsecp256k1_v0_1_2_ge_storage a2_stor;
        rustsecp256k1_v0_1_2_gej tmpj;
        rustsecp256k1_v0_1_2_gej_set_ge(&tmpj, &correction);
        rustsecp256k1_v0_1_2_gej_double_var(&tmpj, &tmpj, NULL);
        rustsecp256k1_v0_1_2_ge_set_gej(&correction, &tmpj);
        rustsecp256k1_v0_1_2_ge_to_storage(&correction_1_stor, a);
#ifdef USE_ENDOMORPHISM
        if (size > 128) {
            rustsecp256k1_v0_1_2_ge_to_storage(&correction_lam_stor, a);
        }
#endif
        rustsecp256k1_v0_1_2_ge_to_storage(&a2_stor, &correction);

        /* For odd numbers this is 2a (so replace it), for even ones a (so no-op) */
        rustsecp256k1_v0_1_2_ge_storage_cmov(&correction_1_stor, &a2_stor, skew_1 == 2);
#ifdef USE_ENDOMORPHISM
        if (size > 128) {
            rustsecp256k1_v0_1_2_ge_storage_cmov(&correction_lam_stor, &a2_stor, skew_lam == 2);
        }
#endif

        /* Apply the correction */
        rustsecp256k1_v0_1_2_ge_from_storage(&correction, &correction_1_stor);
        rustsecp256k1_v0_1_2_ge_neg(&correction, &correction);
        rustsecp256k1_v0_1_2_gej_add_ge(r, r, &correction);

#ifdef USE_ENDOMORPHISM
        if (size > 128) {
            rustsecp256k1_v0_1_2_ge_from_storage(&correction, &correction_lam_stor);
            rustsecp256k1_v0_1_2_ge_neg(&correction, &correction);
            rustsecp256k1_v0_1_2_ge_mul_lambda(&correction, &correction);
            rustsecp256k1_v0_1_2_gej_add_ge(r, r, &correction);
        }
#endif
    }
}

#endif /* SECP256K1_ECMULT_CONST_IMPL_H */
