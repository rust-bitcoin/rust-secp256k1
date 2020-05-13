/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_ECKEY_IMPL_H
#define SECP256K1_ECKEY_IMPL_H

#include "eckey.h"

#include "scalar.h"
#include "field.h"
#include "group.h"
#include "ecmult_gen.h"

static int rustsecp256k1_v0_1_2_eckey_pubkey_parse(rustsecp256k1_v0_1_2_ge *elem, const unsigned char *pub, size_t size) {
    if (size == 33 && (pub[0] == SECP256K1_TAG_PUBKEY_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_ODD)) {
        rustsecp256k1_v0_1_2_fe x;
        return rustsecp256k1_v0_1_2_fe_set_b32(&x, pub+1) && rustsecp256k1_v0_1_2_ge_set_xo_var(elem, &x, pub[0] == SECP256K1_TAG_PUBKEY_ODD);
    } else if (size == 65 && (pub[0] == SECP256K1_TAG_PUBKEY_UNCOMPRESSED || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD)) {
        rustsecp256k1_v0_1_2_fe x, y;
        if (!rustsecp256k1_v0_1_2_fe_set_b32(&x, pub+1) || !rustsecp256k1_v0_1_2_fe_set_b32(&y, pub+33)) {
            return 0;
        }
        rustsecp256k1_v0_1_2_ge_set_xy(elem, &x, &y);
        if ((pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD) &&
            rustsecp256k1_v0_1_2_fe_is_odd(&y) != (pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD)) {
            return 0;
        }
        return rustsecp256k1_v0_1_2_ge_is_valid_var(elem);
    } else {
        return 0;
    }
}

static int rustsecp256k1_v0_1_2_eckey_pubkey_serialize(rustsecp256k1_v0_1_2_ge *elem, unsigned char *pub, size_t *size, int compressed) {
    if (rustsecp256k1_v0_1_2_ge_is_infinity(elem)) {
        return 0;
    }
    rustsecp256k1_v0_1_2_fe_normalize_var(&elem->x);
    rustsecp256k1_v0_1_2_fe_normalize_var(&elem->y);
    rustsecp256k1_v0_1_2_fe_get_b32(&pub[1], &elem->x);
    if (compressed) {
        *size = 33;
        pub[0] = rustsecp256k1_v0_1_2_fe_is_odd(&elem->y) ? SECP256K1_TAG_PUBKEY_ODD : SECP256K1_TAG_PUBKEY_EVEN;
    } else {
        *size = 65;
        pub[0] = SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
        rustsecp256k1_v0_1_2_fe_get_b32(&pub[33], &elem->y);
    }
    return 1;
}

static int rustsecp256k1_v0_1_2_eckey_privkey_tweak_add(rustsecp256k1_v0_1_2_scalar *key, const rustsecp256k1_v0_1_2_scalar *tweak) {
    rustsecp256k1_v0_1_2_scalar_add(key, key, tweak);
    return !rustsecp256k1_v0_1_2_scalar_is_zero(key);
}

static int rustsecp256k1_v0_1_2_eckey_pubkey_tweak_add(const rustsecp256k1_v0_1_2_ecmult_context *ctx, rustsecp256k1_v0_1_2_ge *key, const rustsecp256k1_v0_1_2_scalar *tweak) {
    rustsecp256k1_v0_1_2_gej pt;
    rustsecp256k1_v0_1_2_scalar one;
    rustsecp256k1_v0_1_2_gej_set_ge(&pt, key);
    rustsecp256k1_v0_1_2_scalar_set_int(&one, 1);
    rustsecp256k1_v0_1_2_ecmult(ctx, &pt, &pt, &one, tweak);

    if (rustsecp256k1_v0_1_2_gej_is_infinity(&pt)) {
        return 0;
    }
    rustsecp256k1_v0_1_2_ge_set_gej(key, &pt);
    return 1;
}

static int rustsecp256k1_v0_1_2_eckey_privkey_tweak_mul(rustsecp256k1_v0_1_2_scalar *key, const rustsecp256k1_v0_1_2_scalar *tweak) {
    int ret;
    ret = !rustsecp256k1_v0_1_2_scalar_is_zero(tweak);

    rustsecp256k1_v0_1_2_scalar_mul(key, key, tweak);
    return ret;
}

static int rustsecp256k1_v0_1_2_eckey_pubkey_tweak_mul(const rustsecp256k1_v0_1_2_ecmult_context *ctx, rustsecp256k1_v0_1_2_ge *key, const rustsecp256k1_v0_1_2_scalar *tweak) {
    rustsecp256k1_v0_1_2_scalar zero;
    rustsecp256k1_v0_1_2_gej pt;
    if (rustsecp256k1_v0_1_2_scalar_is_zero(tweak)) {
        return 0;
    }

    rustsecp256k1_v0_1_2_scalar_set_int(&zero, 0);
    rustsecp256k1_v0_1_2_gej_set_ge(&pt, key);
    rustsecp256k1_v0_1_2_ecmult(ctx, &pt, &pt, tweak, &zero);
    rustsecp256k1_v0_1_2_ge_set_gej(key, &pt);
    return 1;
}

#endif /* SECP256K1_ECKEY_IMPL_H */
