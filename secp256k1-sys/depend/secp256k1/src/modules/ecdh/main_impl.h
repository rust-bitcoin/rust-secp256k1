/***********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ECDH_MAIN_H
#define SECP256K1_MODULE_ECDH_MAIN_H

#include "../../../include/secp256k1_ecdh.h"
#include "../../ecmult_const_impl.h"

static int ecdh_hash_function_sha256(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    unsigned char version = (y32[31] & 0x01) | 0x02;
    rustsecp256k1_v0_9_2_sha256 sha;
    (void)data;

    rustsecp256k1_v0_9_2_sha256_initialize(&sha);
    rustsecp256k1_v0_9_2_sha256_write(&sha, &version, 1);
    rustsecp256k1_v0_9_2_sha256_write(&sha, x32, 32);
    rustsecp256k1_v0_9_2_sha256_finalize(&sha, output);

    return 1;
}

const rustsecp256k1_v0_9_2_ecdh_hash_function rustsecp256k1_v0_9_2_ecdh_hash_function_sha256 = ecdh_hash_function_sha256;
const rustsecp256k1_v0_9_2_ecdh_hash_function rustsecp256k1_v0_9_2_ecdh_hash_function_default = ecdh_hash_function_sha256;

int rustsecp256k1_v0_9_2_ecdh(const rustsecp256k1_v0_9_2_context* ctx, unsigned char *output, const rustsecp256k1_v0_9_2_pubkey *point, const unsigned char *scalar, rustsecp256k1_v0_9_2_ecdh_hash_function hashfp, void *data) {
    int ret = 0;
    int overflow = 0;
    rustsecp256k1_v0_9_2_gej res;
    rustsecp256k1_v0_9_2_ge pt;
    rustsecp256k1_v0_9_2_scalar s;
    unsigned char x[32];
    unsigned char y[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(point != NULL);
    ARG_CHECK(scalar != NULL);

    if (hashfp == NULL) {
        hashfp = rustsecp256k1_v0_9_2_ecdh_hash_function_default;
    }

    rustsecp256k1_v0_9_2_pubkey_load(ctx, &pt, point);
    rustsecp256k1_v0_9_2_scalar_set_b32(&s, scalar, &overflow);

    overflow |= rustsecp256k1_v0_9_2_scalar_is_zero(&s);
    rustsecp256k1_v0_9_2_scalar_cmov(&s, &rustsecp256k1_v0_9_2_scalar_one, overflow);

    rustsecp256k1_v0_9_2_ecmult_const(&res, &pt, &s);
    rustsecp256k1_v0_9_2_ge_set_gej(&pt, &res);

    /* Compute a hash of the point */
    rustsecp256k1_v0_9_2_fe_normalize(&pt.x);
    rustsecp256k1_v0_9_2_fe_normalize(&pt.y);
    rustsecp256k1_v0_9_2_fe_get_b32(x, &pt.x);
    rustsecp256k1_v0_9_2_fe_get_b32(y, &pt.y);

    ret = hashfp(output, x, y, data);

    memset(x, 0, 32);
    memset(y, 0, 32);
    rustsecp256k1_v0_9_2_scalar_clear(&s);

    return !!ret & !overflow;
}

#endif /* SECP256K1_MODULE_ECDH_MAIN_H */
