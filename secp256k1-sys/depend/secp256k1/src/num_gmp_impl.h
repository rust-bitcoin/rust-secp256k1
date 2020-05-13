/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_NUM_REPR_IMPL_H
#define SECP256K1_NUM_REPR_IMPL_H

#include <string.h>
#include <stdlib.h>
#include <gmp.h>

#include "util.h"
#include "num.h"

#ifdef VERIFY
static void rustsecp256k1_v0_1_2_num_sanity(const rustsecp256k1_v0_1_2_num *a) {
    VERIFY_CHECK(a->limbs == 1 || (a->limbs > 1 && a->data[a->limbs-1] != 0));
}
#else
#define rustsecp256k1_v0_1_2_num_sanity(a) do { } while(0)
#endif

static void rustsecp256k1_v0_1_2_num_copy(rustsecp256k1_v0_1_2_num *r, const rustsecp256k1_v0_1_2_num *a) {
    *r = *a;
}

static void rustsecp256k1_v0_1_2_num_get_bin(unsigned char *r, unsigned int rlen, const rustsecp256k1_v0_1_2_num *a) {
    unsigned char tmp[65];
    int len = 0;
    int shift = 0;
    if (a->limbs>1 || a->data[0] != 0) {
        len = mpn_get_str(tmp, 256, (mp_limb_t*)a->data, a->limbs);
    }
    while (shift < len && tmp[shift] == 0) shift++;
    VERIFY_CHECK(len-shift <= (int)rlen);
    memset(r, 0, rlen - len + shift);
    if (len > shift) {
        memcpy(r + rlen - len + shift, tmp + shift, len - shift);
    }
    memset(tmp, 0, sizeof(tmp));
}

static void rustsecp256k1_v0_1_2_num_set_bin(rustsecp256k1_v0_1_2_num *r, const unsigned char *a, unsigned int alen) {
    int len;
    VERIFY_CHECK(alen > 0);
    VERIFY_CHECK(alen <= 64);
    len = mpn_set_str(r->data, a, alen, 256);
    if (len == 0) {
        r->data[0] = 0;
        len = 1;
    }
    VERIFY_CHECK(len <= NUM_LIMBS*2);
    r->limbs = len;
    r->neg = 0;
    while (r->limbs > 1 && r->data[r->limbs-1]==0) {
        r->limbs--;
    }
}

static void rustsecp256k1_v0_1_2_num_add_abs(rustsecp256k1_v0_1_2_num *r, const rustsecp256k1_v0_1_2_num *a, const rustsecp256k1_v0_1_2_num *b) {
    mp_limb_t c = mpn_add(r->data, a->data, a->limbs, b->data, b->limbs);
    r->limbs = a->limbs;
    if (c != 0) {
        VERIFY_CHECK(r->limbs < 2*NUM_LIMBS);
        r->data[r->limbs++] = c;
    }
}

static void rustsecp256k1_v0_1_2_num_sub_abs(rustsecp256k1_v0_1_2_num *r, const rustsecp256k1_v0_1_2_num *a, const rustsecp256k1_v0_1_2_num *b) {
    mp_limb_t c = mpn_sub(r->data, a->data, a->limbs, b->data, b->limbs);
    (void)c;
    VERIFY_CHECK(c == 0);
    r->limbs = a->limbs;
    while (r->limbs > 1 && r->data[r->limbs-1]==0) {
        r->limbs--;
    }
}

static void rustsecp256k1_v0_1_2_num_mod(rustsecp256k1_v0_1_2_num *r, const rustsecp256k1_v0_1_2_num *m) {
    rustsecp256k1_v0_1_2_num_sanity(r);
    rustsecp256k1_v0_1_2_num_sanity(m);

    if (r->limbs >= m->limbs) {
        mp_limb_t t[2*NUM_LIMBS];
        mpn_tdiv_qr(t, r->data, 0, r->data, r->limbs, m->data, m->limbs);
        memset(t, 0, sizeof(t));
        r->limbs = m->limbs;
        while (r->limbs > 1 && r->data[r->limbs-1]==0) {
            r->limbs--;
        }
    }

    if (r->neg && (r->limbs > 1 || r->data[0] != 0)) {
        rustsecp256k1_v0_1_2_num_sub_abs(r, m, r);
        r->neg = 0;
    }
}

static void rustsecp256k1_v0_1_2_num_mod_inverse(rustsecp256k1_v0_1_2_num *r, const rustsecp256k1_v0_1_2_num *a, const rustsecp256k1_v0_1_2_num *m) {
    int i;
    mp_limb_t g[NUM_LIMBS+1];
    mp_limb_t u[NUM_LIMBS+1];
    mp_limb_t v[NUM_LIMBS+1];
    mp_size_t sn;
    mp_size_t gn;
    rustsecp256k1_v0_1_2_num_sanity(a);
    rustsecp256k1_v0_1_2_num_sanity(m);

    /** mpn_gcdext computes: (G,S) = gcdext(U,V), where
     *  * G = gcd(U,V)
     *  * G = U*S + V*T
     *  * U has equal or more limbs than V, and V has no padding
     *  If we set U to be (a padded version of) a, and V = m:
     *    G = a*S + m*T
     *    G = a*S mod m
     *  Assuming G=1:
     *    S = 1/a mod m
     */
    VERIFY_CHECK(m->limbs <= NUM_LIMBS);
    VERIFY_CHECK(m->data[m->limbs-1] != 0);
    for (i = 0; i < m->limbs; i++) {
        u[i] = (i < a->limbs) ? a->data[i] : 0;
        v[i] = m->data[i];
    }
    sn = NUM_LIMBS+1;
    gn = mpn_gcdext(g, r->data, &sn, u, m->limbs, v, m->limbs);
    (void)gn;
    VERIFY_CHECK(gn == 1);
    VERIFY_CHECK(g[0] == 1);
    r->neg = a->neg ^ m->neg;
    if (sn < 0) {
        mpn_sub(r->data, m->data, m->limbs, r->data, -sn);
        r->limbs = m->limbs;
        while (r->limbs > 1 && r->data[r->limbs-1]==0) {
            r->limbs--;
        }
    } else {
        r->limbs = sn;
    }
    memset(g, 0, sizeof(g));
    memset(u, 0, sizeof(u));
    memset(v, 0, sizeof(v));
}

static int rustsecp256k1_v0_1_2_num_jacobi(const rustsecp256k1_v0_1_2_num *a, const rustsecp256k1_v0_1_2_num *b) {
    int ret;
    mpz_t ga, gb;
    rustsecp256k1_v0_1_2_num_sanity(a);
    rustsecp256k1_v0_1_2_num_sanity(b);
    VERIFY_CHECK(!b->neg && (b->limbs > 0) && (b->data[0] & 1));

    mpz_inits(ga, gb, NULL);

    mpz_import(gb, b->limbs, -1, sizeof(mp_limb_t), 0, 0, b->data);
    mpz_import(ga, a->limbs, -1, sizeof(mp_limb_t), 0, 0, a->data);
    if (a->neg) {
        mpz_neg(ga, ga);
    }

    ret = mpz_jacobi(ga, gb);

    mpz_clears(ga, gb, NULL);

    return ret;
}

static int rustsecp256k1_v0_1_2_num_is_one(const rustsecp256k1_v0_1_2_num *a) {
    return (a->limbs == 1 && a->data[0] == 1);
}

static int rustsecp256k1_v0_1_2_num_is_zero(const rustsecp256k1_v0_1_2_num *a) {
    return (a->limbs == 1 && a->data[0] == 0);
}

static int rustsecp256k1_v0_1_2_num_is_neg(const rustsecp256k1_v0_1_2_num *a) {
    return (a->limbs > 1 || a->data[0] != 0) && a->neg;
}

static int rustsecp256k1_v0_1_2_num_cmp(const rustsecp256k1_v0_1_2_num *a, const rustsecp256k1_v0_1_2_num *b) {
    if (a->limbs > b->limbs) {
        return 1;
    }
    if (a->limbs < b->limbs) {
        return -1;
    }
    return mpn_cmp(a->data, b->data, a->limbs);
}

static int rustsecp256k1_v0_1_2_num_eq(const rustsecp256k1_v0_1_2_num *a, const rustsecp256k1_v0_1_2_num *b) {
    if (a->limbs > b->limbs) {
        return 0;
    }
    if (a->limbs < b->limbs) {
        return 0;
    }
    if ((a->neg && !rustsecp256k1_v0_1_2_num_is_zero(a)) != (b->neg && !rustsecp256k1_v0_1_2_num_is_zero(b))) {
        return 0;
    }
    return mpn_cmp(a->data, b->data, a->limbs) == 0;
}

static void rustsecp256k1_v0_1_2_num_subadd(rustsecp256k1_v0_1_2_num *r, const rustsecp256k1_v0_1_2_num *a, const rustsecp256k1_v0_1_2_num *b, int bneg) {
    if (!(b->neg ^ bneg ^ a->neg)) { /* a and b have the same sign */
        r->neg = a->neg;
        if (a->limbs >= b->limbs) {
            rustsecp256k1_v0_1_2_num_add_abs(r, a, b);
        } else {
            rustsecp256k1_v0_1_2_num_add_abs(r, b, a);
        }
    } else {
        if (rustsecp256k1_v0_1_2_num_cmp(a, b) > 0) {
            r->neg = a->neg;
            rustsecp256k1_v0_1_2_num_sub_abs(r, a, b);
        } else {
            r->neg = b->neg ^ bneg;
            rustsecp256k1_v0_1_2_num_sub_abs(r, b, a);
        }
    }
}

static void rustsecp256k1_v0_1_2_num_add(rustsecp256k1_v0_1_2_num *r, const rustsecp256k1_v0_1_2_num *a, const rustsecp256k1_v0_1_2_num *b) {
    rustsecp256k1_v0_1_2_num_sanity(a);
    rustsecp256k1_v0_1_2_num_sanity(b);
    rustsecp256k1_v0_1_2_num_subadd(r, a, b, 0);
}

static void rustsecp256k1_v0_1_2_num_sub(rustsecp256k1_v0_1_2_num *r, const rustsecp256k1_v0_1_2_num *a, const rustsecp256k1_v0_1_2_num *b) {
    rustsecp256k1_v0_1_2_num_sanity(a);
    rustsecp256k1_v0_1_2_num_sanity(b);
    rustsecp256k1_v0_1_2_num_subadd(r, a, b, 1);
}

static void rustsecp256k1_v0_1_2_num_mul(rustsecp256k1_v0_1_2_num *r, const rustsecp256k1_v0_1_2_num *a, const rustsecp256k1_v0_1_2_num *b) {
    mp_limb_t tmp[2*NUM_LIMBS+1];
    rustsecp256k1_v0_1_2_num_sanity(a);
    rustsecp256k1_v0_1_2_num_sanity(b);

    VERIFY_CHECK(a->limbs + b->limbs <= 2*NUM_LIMBS+1);
    if ((a->limbs==1 && a->data[0]==0) || (b->limbs==1 && b->data[0]==0)) {
        r->limbs = 1;
        r->neg = 0;
        r->data[0] = 0;
        return;
    }
    if (a->limbs >= b->limbs) {
        mpn_mul(tmp, a->data, a->limbs, b->data, b->limbs);
    } else {
        mpn_mul(tmp, b->data, b->limbs, a->data, a->limbs);
    }
    r->limbs = a->limbs + b->limbs;
    if (r->limbs > 1 && tmp[r->limbs - 1]==0) {
        r->limbs--;
    }
    VERIFY_CHECK(r->limbs <= 2*NUM_LIMBS);
    mpn_copyi(r->data, tmp, r->limbs);
    r->neg = a->neg ^ b->neg;
    memset(tmp, 0, sizeof(tmp));
}

static void rustsecp256k1_v0_1_2_num_shift(rustsecp256k1_v0_1_2_num *r, int bits) {
    if (bits % GMP_NUMB_BITS) {
        /* Shift within limbs. */
        mpn_rshift(r->data, r->data, r->limbs, bits % GMP_NUMB_BITS);
    }
    if (bits >= GMP_NUMB_BITS) {
        int i;
        /* Shift full limbs. */
        for (i = 0; i < r->limbs; i++) {
            int index = i + (bits / GMP_NUMB_BITS);
            if (index < r->limbs && index < 2*NUM_LIMBS) {
                r->data[i] = r->data[index];
            } else {
                r->data[i] = 0;
            }
        }
    }
    while (r->limbs>1 && r->data[r->limbs-1]==0) {
        r->limbs--;
    }
}

static void rustsecp256k1_v0_1_2_num_negate(rustsecp256k1_v0_1_2_num *r) {
    r->neg ^= 1;
}

#endif /* SECP256K1_NUM_REPR_IMPL_H */
