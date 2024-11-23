/***********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_SCALAR_REPR_IMPL_H
#define SECP256K1_SCALAR_REPR_IMPL_H

#include "checkmem.h"
#include "scalar.h"
#include "util.h"

#include <string.h>

SECP256K1_INLINE static int rustsecp256k1_v0_11_scalar_is_even(const rustsecp256k1_v0_11_scalar *a) {
    SECP256K1_SCALAR_VERIFY(a);

    return !(*a & 1);
}

SECP256K1_INLINE static void rustsecp256k1_v0_11_scalar_set_int(rustsecp256k1_v0_11_scalar *r, unsigned int v) {
    *r = v % EXHAUSTIVE_TEST_ORDER;

    SECP256K1_SCALAR_VERIFY(r);
}

SECP256K1_INLINE static uint32_t rustsecp256k1_v0_11_scalar_get_bits_limb32(const rustsecp256k1_v0_11_scalar *a, unsigned int offset, unsigned int count) {
    SECP256K1_SCALAR_VERIFY(a);

    VERIFY_CHECK(count > 0 && count <= 32);
    if (offset < 32) {
        return (*a >> offset) & (0xFFFFFFFF >> (32 - count));
    } else {
        return 0;
    }
}

SECP256K1_INLINE static uint32_t rustsecp256k1_v0_11_scalar_get_bits_var(const rustsecp256k1_v0_11_scalar *a, unsigned int offset, unsigned int count) {
    SECP256K1_SCALAR_VERIFY(a);

    return rustsecp256k1_v0_11_scalar_get_bits_limb32(a, offset, count);
}

SECP256K1_INLINE static int rustsecp256k1_v0_11_scalar_check_overflow(const rustsecp256k1_v0_11_scalar *a) { return *a >= EXHAUSTIVE_TEST_ORDER; }

static int rustsecp256k1_v0_11_scalar_add(rustsecp256k1_v0_11_scalar *r, const rustsecp256k1_v0_11_scalar *a, const rustsecp256k1_v0_11_scalar *b) {
    SECP256K1_SCALAR_VERIFY(a);
    SECP256K1_SCALAR_VERIFY(b);

    *r = (*a + *b) % EXHAUSTIVE_TEST_ORDER;

    SECP256K1_SCALAR_VERIFY(r);
    return *r < *b;
}

static void rustsecp256k1_v0_11_scalar_cadd_bit(rustsecp256k1_v0_11_scalar *r, unsigned int bit, int flag) {
    SECP256K1_SCALAR_VERIFY(r);

    if (flag && bit < 32)
        *r += ((uint32_t)1 << bit);

    SECP256K1_SCALAR_VERIFY(r);
    VERIFY_CHECK(bit < 32);
    /* Verify that adding (1 << bit) will not overflow any in-range scalar *r by overflowing the underlying uint32_t. */
    VERIFY_CHECK(((uint32_t)1 << bit) - 1 <= UINT32_MAX - EXHAUSTIVE_TEST_ORDER);
}

static void rustsecp256k1_v0_11_scalar_set_b32(rustsecp256k1_v0_11_scalar *r, const unsigned char *b32, int *overflow) {
    int i;
    int over = 0;
    *r = 0;
    for (i = 0; i < 32; i++) {
        *r = (*r * 0x100) + b32[i];
        if (*r >= EXHAUSTIVE_TEST_ORDER) {
            over = 1;
            *r %= EXHAUSTIVE_TEST_ORDER;
        }
    }
    if (overflow) *overflow = over;

    SECP256K1_SCALAR_VERIFY(r);
}

static void rustsecp256k1_v0_11_scalar_get_b32(unsigned char *bin, const rustsecp256k1_v0_11_scalar* a) {
    SECP256K1_SCALAR_VERIFY(a);

    memset(bin, 0, 32);
    bin[28] = *a >> 24; bin[29] = *a >> 16; bin[30] = *a >> 8; bin[31] = *a;
}

SECP256K1_INLINE static int rustsecp256k1_v0_11_scalar_is_zero(const rustsecp256k1_v0_11_scalar *a) {
    SECP256K1_SCALAR_VERIFY(a);

    return *a == 0;
}

static void rustsecp256k1_v0_11_scalar_negate(rustsecp256k1_v0_11_scalar *r, const rustsecp256k1_v0_11_scalar *a) {
    SECP256K1_SCALAR_VERIFY(a);

    if (*a == 0) {
        *r = 0;
    } else {
        *r = EXHAUSTIVE_TEST_ORDER - *a;
    }

    SECP256K1_SCALAR_VERIFY(r);
}

SECP256K1_INLINE static int rustsecp256k1_v0_11_scalar_is_one(const rustsecp256k1_v0_11_scalar *a) {
    SECP256K1_SCALAR_VERIFY(a);

    return *a == 1;
}

static int rustsecp256k1_v0_11_scalar_is_high(const rustsecp256k1_v0_11_scalar *a) {
    SECP256K1_SCALAR_VERIFY(a);

    return *a > EXHAUSTIVE_TEST_ORDER / 2;
}

static int rustsecp256k1_v0_11_scalar_cond_negate(rustsecp256k1_v0_11_scalar *r, int flag) {
    SECP256K1_SCALAR_VERIFY(r);

    if (flag) rustsecp256k1_v0_11_scalar_negate(r, r);

    SECP256K1_SCALAR_VERIFY(r);
    return flag ? -1 : 1;
}

static void rustsecp256k1_v0_11_scalar_mul(rustsecp256k1_v0_11_scalar *r, const rustsecp256k1_v0_11_scalar *a, const rustsecp256k1_v0_11_scalar *b) {
    SECP256K1_SCALAR_VERIFY(a);
    SECP256K1_SCALAR_VERIFY(b);

    *r = (*a * *b) % EXHAUSTIVE_TEST_ORDER;

    SECP256K1_SCALAR_VERIFY(r);
}

static void rustsecp256k1_v0_11_scalar_split_128(rustsecp256k1_v0_11_scalar *r1, rustsecp256k1_v0_11_scalar *r2, const rustsecp256k1_v0_11_scalar *a) {
    SECP256K1_SCALAR_VERIFY(a);

    *r1 = *a;
    *r2 = 0;

    SECP256K1_SCALAR_VERIFY(r1);
    SECP256K1_SCALAR_VERIFY(r2);
}

SECP256K1_INLINE static int rustsecp256k1_v0_11_scalar_eq(const rustsecp256k1_v0_11_scalar *a, const rustsecp256k1_v0_11_scalar *b) {
    SECP256K1_SCALAR_VERIFY(a);
    SECP256K1_SCALAR_VERIFY(b);

    return *a == *b;
}

static SECP256K1_INLINE void rustsecp256k1_v0_11_scalar_cmov(rustsecp256k1_v0_11_scalar *r, const rustsecp256k1_v0_11_scalar *a, int flag) {
    uint32_t mask0, mask1;
    volatile int vflag = flag;
    SECP256K1_SCALAR_VERIFY(a);
    SECP256K1_CHECKMEM_CHECK_VERIFY(r, sizeof(*r));

    mask0 = vflag + ~((uint32_t)0);
    mask1 = ~mask0;
    *r = (*r & mask0) | (*a & mask1);

    SECP256K1_SCALAR_VERIFY(r);
}

static void rustsecp256k1_v0_11_scalar_inverse(rustsecp256k1_v0_11_scalar *r, const rustsecp256k1_v0_11_scalar *x) {
    int i;
    uint32_t res = 0;
    SECP256K1_SCALAR_VERIFY(x);

    for (i = 0; i < EXHAUSTIVE_TEST_ORDER; i++) {
        if ((i * *x) % EXHAUSTIVE_TEST_ORDER == 1) {
            res = i;
            break;
        }
    }

    /* If this VERIFY_CHECK triggers we were given a noninvertible scalar (and thus
     * have a composite group order; fix it in exhaustive_tests.c). */
    VERIFY_CHECK(res != 0);
    *r = res;

    SECP256K1_SCALAR_VERIFY(r);
}

static void rustsecp256k1_v0_11_scalar_inverse_var(rustsecp256k1_v0_11_scalar *r, const rustsecp256k1_v0_11_scalar *x) {
    SECP256K1_SCALAR_VERIFY(x);

    rustsecp256k1_v0_11_scalar_inverse(r, x);

    SECP256K1_SCALAR_VERIFY(r);
}

static void rustsecp256k1_v0_11_scalar_half(rustsecp256k1_v0_11_scalar *r, const rustsecp256k1_v0_11_scalar *a) {
    SECP256K1_SCALAR_VERIFY(a);

    *r = (*a + ((-(uint32_t)(*a & 1)) & EXHAUSTIVE_TEST_ORDER)) >> 1;

    SECP256K1_SCALAR_VERIFY(r);
}

#endif /* SECP256K1_SCALAR_REPR_IMPL_H */
