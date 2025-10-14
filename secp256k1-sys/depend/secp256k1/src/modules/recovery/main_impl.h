/***********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                               *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_RECOVERY_MAIN_H
#define SECP256K1_MODULE_RECOVERY_MAIN_H

#include "../../../include/secp256k1_recovery.h"

static void rustsecp256k1_v0_12_ecdsa_recoverable_signature_load(const rustsecp256k1_v0_12_context* ctx, rustsecp256k1_v0_12_scalar* r, rustsecp256k1_v0_12_scalar* s, int* recid, const rustsecp256k1_v0_12_ecdsa_recoverable_signature* sig) {
    (void)ctx;
    if (sizeof(rustsecp256k1_v0_12_scalar) == 32) {
        /* When the rustsecp256k1_v0_12_scalar type is exactly 32 byte, use its
         * representation inside rustsecp256k1_v0_12_ecdsa_signature, as conversion is very fast.
         * Note that rustsecp256k1_v0_12_ecdsa_signature_save must use the same representation. */
        memcpy(r, &sig->data[0], 32);
        memcpy(s, &sig->data[32], 32);
    } else {
        rustsecp256k1_v0_12_scalar_set_b32(r, &sig->data[0], NULL);
        rustsecp256k1_v0_12_scalar_set_b32(s, &sig->data[32], NULL);
    }
    *recid = sig->data[64];
}

static void rustsecp256k1_v0_12_ecdsa_recoverable_signature_save(rustsecp256k1_v0_12_ecdsa_recoverable_signature* sig, const rustsecp256k1_v0_12_scalar* r, const rustsecp256k1_v0_12_scalar* s, int recid) {
    if (sizeof(rustsecp256k1_v0_12_scalar) == 32) {
        memcpy(&sig->data[0], r, 32);
        memcpy(&sig->data[32], s, 32);
    } else {
        rustsecp256k1_v0_12_scalar_get_b32(&sig->data[0], r);
        rustsecp256k1_v0_12_scalar_get_b32(&sig->data[32], s);
    }
    sig->data[64] = recid;
}

int rustsecp256k1_v0_12_ecdsa_recoverable_signature_parse_compact(const rustsecp256k1_v0_12_context* ctx, rustsecp256k1_v0_12_ecdsa_recoverable_signature* sig, const unsigned char *input64, int recid) {
    rustsecp256k1_v0_12_scalar r, s;
    int ret = 1;
    int overflow = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input64 != NULL);
    ARG_CHECK(recid >= 0 && recid <= 3);

    rustsecp256k1_v0_12_scalar_set_b32(&r, &input64[0], &overflow);
    ret &= !overflow;
    rustsecp256k1_v0_12_scalar_set_b32(&s, &input64[32], &overflow);
    ret &= !overflow;
    if (ret) {
        rustsecp256k1_v0_12_ecdsa_recoverable_signature_save(sig, &r, &s, recid);
    } else {
        memset(sig, 0, sizeof(*sig));
    }
    return ret;
}

int rustsecp256k1_v0_12_ecdsa_recoverable_signature_serialize_compact(const rustsecp256k1_v0_12_context* ctx, unsigned char *output64, int *recid, const rustsecp256k1_v0_12_ecdsa_recoverable_signature* sig) {
    rustsecp256k1_v0_12_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output64 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(recid != NULL);

    rustsecp256k1_v0_12_ecdsa_recoverable_signature_load(ctx, &r, &s, recid, sig);
    rustsecp256k1_v0_12_scalar_get_b32(&output64[0], &r);
    rustsecp256k1_v0_12_scalar_get_b32(&output64[32], &s);
    return 1;
}

int rustsecp256k1_v0_12_ecdsa_recoverable_signature_convert(const rustsecp256k1_v0_12_context* ctx, rustsecp256k1_v0_12_ecdsa_signature* sig, const rustsecp256k1_v0_12_ecdsa_recoverable_signature* sigin) {
    rustsecp256k1_v0_12_scalar r, s;
    int recid;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(sigin != NULL);

    rustsecp256k1_v0_12_ecdsa_recoverable_signature_load(ctx, &r, &s, &recid, sigin);
    rustsecp256k1_v0_12_ecdsa_signature_save(sig, &r, &s);
    return 1;
}

static int rustsecp256k1_v0_12_ecdsa_sig_recover(const rustsecp256k1_v0_12_scalar *sigr, const rustsecp256k1_v0_12_scalar* sigs, rustsecp256k1_v0_12_ge *pubkey, const rustsecp256k1_v0_12_scalar *message, int recid) {
    unsigned char brx[32];
    rustsecp256k1_v0_12_fe fx;
    rustsecp256k1_v0_12_ge x;
    rustsecp256k1_v0_12_gej xj;
    rustsecp256k1_v0_12_scalar rn, u1, u2;
    rustsecp256k1_v0_12_gej qj;
    int r;

    if (rustsecp256k1_v0_12_scalar_is_zero(sigr) || rustsecp256k1_v0_12_scalar_is_zero(sigs)) {
        return 0;
    }

    rustsecp256k1_v0_12_scalar_get_b32(brx, sigr);
    r = rustsecp256k1_v0_12_fe_set_b32_limit(&fx, brx);
    (void)r;
    VERIFY_CHECK(r); /* brx comes from a scalar, so is less than the order; certainly less than p */
    if (recid & 2) {
        if (rustsecp256k1_v0_12_fe_cmp_var(&fx, &rustsecp256k1_v0_12_ecdsa_const_p_minus_order) >= 0) {
            return 0;
        }
        rustsecp256k1_v0_12_fe_add(&fx, &rustsecp256k1_v0_12_ecdsa_const_order_as_fe);
    }
    if (!rustsecp256k1_v0_12_ge_set_xo_var(&x, &fx, recid & 1)) {
        return 0;
    }
    rustsecp256k1_v0_12_gej_set_ge(&xj, &x);
    rustsecp256k1_v0_12_scalar_inverse_var(&rn, sigr);
    rustsecp256k1_v0_12_scalar_mul(&u1, &rn, message);
    rustsecp256k1_v0_12_scalar_negate(&u1, &u1);
    rustsecp256k1_v0_12_scalar_mul(&u2, &rn, sigs);
    rustsecp256k1_v0_12_ecmult(&qj, &xj, &u2, &u1);
    rustsecp256k1_v0_12_ge_set_gej_var(pubkey, &qj);
    return !rustsecp256k1_v0_12_gej_is_infinity(&qj);
}

int rustsecp256k1_v0_12_ecdsa_sign_recoverable(const rustsecp256k1_v0_12_context* ctx, rustsecp256k1_v0_12_ecdsa_recoverable_signature *signature, const unsigned char *msghash32, const unsigned char *seckey, rustsecp256k1_v0_12_nonce_function noncefp, const void* noncedata) {
    rustsecp256k1_v0_12_scalar r, s;
    int ret, recid;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1_v0_12_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msghash32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(seckey != NULL);

    ret = rustsecp256k1_v0_12_ecdsa_sign_inner(ctx, &r, &s, &recid, msghash32, seckey, noncefp, noncedata);
    rustsecp256k1_v0_12_ecdsa_recoverable_signature_save(signature, &r, &s, recid);
    return ret;
}

int rustsecp256k1_v0_12_ecdsa_recover(const rustsecp256k1_v0_12_context* ctx, rustsecp256k1_v0_12_pubkey *pubkey, const rustsecp256k1_v0_12_ecdsa_recoverable_signature *signature, const unsigned char *msghash32) {
    rustsecp256k1_v0_12_ge q;
    rustsecp256k1_v0_12_scalar r, s;
    rustsecp256k1_v0_12_scalar m;
    int recid;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(msghash32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(pubkey != NULL);

    rustsecp256k1_v0_12_ecdsa_recoverable_signature_load(ctx, &r, &s, &recid, signature);
    VERIFY_CHECK(recid >= 0 && recid < 4);  /* should have been caught in parse_compact */
    rustsecp256k1_v0_12_scalar_set_b32(&m, msghash32, NULL);
    if (rustsecp256k1_v0_12_ecdsa_sig_recover(&r, &s, &q, &m, recid)) {
        rustsecp256k1_v0_12_pubkey_save(pubkey, &q);
        return 1;
    } else {
        memset(pubkey, 0, sizeof(*pubkey));
        return 0;
    }
}

#endif /* SECP256K1_MODULE_RECOVERY_MAIN_H */
