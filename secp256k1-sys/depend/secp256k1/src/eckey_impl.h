/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECKEY_IMPL_H
#define SECP256K1_ECKEY_IMPL_H

#include "eckey.h"

#include "util.h"
#include "scalar.h"
#include "field.h"
#include "group.h"
#include "ecmult_gen.h"

static int rustsecp256k1_v0_13_eckey_pubkey_parse(rustsecp256k1_v0_13_ge *elem, const unsigned char *pub, size_t size) {
    if (size == 33 && (pub[0] == SECP256K1_TAG_PUBKEY_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_ODD)) {
        rustsecp256k1_v0_13_fe x;
        return rustsecp256k1_v0_13_fe_set_b32_limit(&x, pub+1) && rustsecp256k1_v0_13_ge_set_xo_var(elem, &x, pub[0] == SECP256K1_TAG_PUBKEY_ODD);
    } else if (size == 65 && (pub[0] == SECP256K1_TAG_PUBKEY_UNCOMPRESSED || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD)) {
        rustsecp256k1_v0_13_fe x, y;
        if (!rustsecp256k1_v0_13_fe_set_b32_limit(&x, pub+1) || !rustsecp256k1_v0_13_fe_set_b32_limit(&y, pub+33)) {
            return 0;
        }
        rustsecp256k1_v0_13_ge_set_xy(elem, &x, &y);
        if ((pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD) &&
            rustsecp256k1_v0_13_fe_is_odd(&y) != (pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD)) {
            return 0;
        }
        return rustsecp256k1_v0_13_ge_is_valid_var(elem);
    } else {
        return 0;
    }
}

static void rustsecp256k1_v0_13_eckey_pubkey_serialize33(rustsecp256k1_v0_13_ge *elem, unsigned char *pub33) {
    VERIFY_CHECK(!rustsecp256k1_v0_13_ge_is_infinity(elem));

    rustsecp256k1_v0_13_fe_normalize_var(&elem->x);
    rustsecp256k1_v0_13_fe_normalize_var(&elem->y);
    pub33[0] = rustsecp256k1_v0_13_fe_is_odd(&elem->y) ? SECP256K1_TAG_PUBKEY_ODD : SECP256K1_TAG_PUBKEY_EVEN;
    rustsecp256k1_v0_13_fe_get_b32(&pub33[1], &elem->x);
}

static void rustsecp256k1_v0_13_eckey_pubkey_serialize65(rustsecp256k1_v0_13_ge *elem, unsigned char *pub65) {
    VERIFY_CHECK(!rustsecp256k1_v0_13_ge_is_infinity(elem));

    rustsecp256k1_v0_13_fe_normalize_var(&elem->x);
    rustsecp256k1_v0_13_fe_normalize_var(&elem->y);
    pub65[0] = SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
    rustsecp256k1_v0_13_fe_get_b32(&pub65[1], &elem->x);
    rustsecp256k1_v0_13_fe_get_b32(&pub65[33], &elem->y);
}

static int rustsecp256k1_v0_13_eckey_privkey_tweak_add(rustsecp256k1_v0_13_scalar *key, const rustsecp256k1_v0_13_scalar *tweak) {
    rustsecp256k1_v0_13_scalar_add(key, key, tweak);
    return !rustsecp256k1_v0_13_scalar_is_zero(key);
}

static int rustsecp256k1_v0_13_eckey_pubkey_tweak_add(rustsecp256k1_v0_13_ge *key, const rustsecp256k1_v0_13_scalar *tweak) {
    rustsecp256k1_v0_13_gej pt;
    rustsecp256k1_v0_13_gej_set_ge(&pt, key);
    rustsecp256k1_v0_13_ecmult(&pt, &pt, &rustsecp256k1_v0_13_scalar_one, tweak);

    if (rustsecp256k1_v0_13_gej_is_infinity(&pt)) {
        return 0;
    }
    rustsecp256k1_v0_13_ge_set_gej(key, &pt);
    return 1;
}

static int rustsecp256k1_v0_13_eckey_privkey_tweak_mul(rustsecp256k1_v0_13_scalar *key, const rustsecp256k1_v0_13_scalar *tweak) {
    int ret;
    ret = !rustsecp256k1_v0_13_scalar_is_zero(tweak);

    rustsecp256k1_v0_13_scalar_mul(key, key, tweak);
    return ret;
}

static int rustsecp256k1_v0_13_eckey_pubkey_tweak_mul(rustsecp256k1_v0_13_ge *key, const rustsecp256k1_v0_13_scalar *tweak) {
    rustsecp256k1_v0_13_gej pt;
    if (rustsecp256k1_v0_13_scalar_is_zero(tweak)) {
        return 0;
    }

    rustsecp256k1_v0_13_gej_set_ge(&pt, key);
    rustsecp256k1_v0_13_ecmult(&pt, &pt, tweak, &rustsecp256k1_v0_13_scalar_zero);
    rustsecp256k1_v0_13_ge_set_gej(key, &pt);
    return 1;
}

#endif /* SECP256K1_ECKEY_IMPL_H */
