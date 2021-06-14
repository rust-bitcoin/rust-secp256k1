/***********************************************************************
 * Copyright (c) 2018-2020 Andrew Poelstra, Jonas Nick                 *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORRSIG_MAIN_H
#define SECP256K1_MODULE_SCHNORRSIG_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_schnorrsig.h"
#include "../../hash.h"

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/nonce")||SHA256("BIP0340/nonce"). */
static void rustsecp256k1_v0_4_1_nonce_function_bip340_sha256_tagged(rustsecp256k1_v0_4_1_sha256 *sha) {
    rustsecp256k1_v0_4_1_sha256_initialize(sha);
    sha->s[0] = 0x46615b35ul;
    sha->s[1] = 0xf4bfbff7ul;
    sha->s[2] = 0x9f8dc671ul;
    sha->s[3] = 0x83627ab3ul;
    sha->s[4] = 0x60217180ul;
    sha->s[5] = 0x57358661ul;
    sha->s[6] = 0x21a29e54ul;
    sha->s[7] = 0x68b07b4cul;

    sha->bytes = 64;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/aux")||SHA256("BIP0340/aux"). */
static void rustsecp256k1_v0_4_1_nonce_function_bip340_sha256_tagged_aux(rustsecp256k1_v0_4_1_sha256 *sha) {
    rustsecp256k1_v0_4_1_sha256_initialize(sha);
    sha->s[0] = 0x24dd3219ul;
    sha->s[1] = 0x4eba7e70ul;
    sha->s[2] = 0xca0fabb9ul;
    sha->s[3] = 0x0fa3166dul;
    sha->s[4] = 0x3afbe4b1ul;
    sha->s[5] = 0x4c44df97ul;
    sha->s[6] = 0x4aac2739ul;
    sha->s[7] = 0x249e850aul;

    sha->bytes = 64;
}

/* algo16 argument for nonce_function_bip340 to derive the nonce exactly as stated in BIP-340
 * by using the correct tagged hash function. */
static const unsigned char bip340_algo16[16] = "BIP0340/nonce\0\0\0";

static int nonce_function_bip340(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *xonly_pk32, const unsigned char *algo16, void *data) {
    rustsecp256k1_v0_4_1_sha256 sha;
    unsigned char masked_key[32];
    int i;

    if (algo16 == NULL) {
        return 0;
    }

    if (data != NULL) {
        rustsecp256k1_v0_4_1_nonce_function_bip340_sha256_tagged_aux(&sha);
        rustsecp256k1_v0_4_1_sha256_write(&sha, data, 32);
        rustsecp256k1_v0_4_1_sha256_finalize(&sha, masked_key);
        for (i = 0; i < 32; i++) {
            masked_key[i] ^= key32[i];
        }
    }

    /* Tag the hash with algo16 which is important to avoid nonce reuse across
     * algorithms. If this nonce function is used in BIP-340 signing as defined
     * in the spec, an optimized tagging implementation is used. */
    if (rustsecp256k1_v0_4_1_memcmp_var(algo16, bip340_algo16, 16) == 0) {
        rustsecp256k1_v0_4_1_nonce_function_bip340_sha256_tagged(&sha);
    } else {
        int algo16_len = 16;
        /* Remove terminating null bytes */
        while (algo16_len > 0 && !algo16[algo16_len - 1]) {
            algo16_len--;
        }
        rustsecp256k1_v0_4_1_sha256_initialize_tagged(&sha, algo16, algo16_len);
    }

    /* Hash (masked-)key||pk||msg using the tagged hash as per the spec */
    if (data != NULL) {
        rustsecp256k1_v0_4_1_sha256_write(&sha, masked_key, 32);
    } else {
        rustsecp256k1_v0_4_1_sha256_write(&sha, key32, 32);
    }
    rustsecp256k1_v0_4_1_sha256_write(&sha, xonly_pk32, 32);
    rustsecp256k1_v0_4_1_sha256_write(&sha, msg32, 32);
    rustsecp256k1_v0_4_1_sha256_finalize(&sha, nonce32);
    return 1;
}

const rustsecp256k1_v0_4_1_nonce_function_hardened rustsecp256k1_v0_4_1_nonce_function_bip340 = nonce_function_bip340;

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/challenge")||SHA256("BIP0340/challenge"). */
static void rustsecp256k1_v0_4_1_schnorrsig_sha256_tagged(rustsecp256k1_v0_4_1_sha256 *sha) {
    rustsecp256k1_v0_4_1_sha256_initialize(sha);
    sha->s[0] = 0x9cecba11ul;
    sha->s[1] = 0x23925381ul;
    sha->s[2] = 0x11679112ul;
    sha->s[3] = 0xd1627e0ful;
    sha->s[4] = 0x97c87550ul;
    sha->s[5] = 0x003cc765ul;
    sha->s[6] = 0x90f61164ul;
    sha->s[7] = 0x33e9b66aul;
    sha->bytes = 64;
}

static void rustsecp256k1_v0_4_1_schnorrsig_challenge(rustsecp256k1_v0_4_1_scalar* e, const unsigned char *r32, const unsigned char *msg32, const unsigned char *pubkey32)
{
    unsigned char buf[32];
    rustsecp256k1_v0_4_1_sha256 sha;

    /* tagged hash(r.x, pk.x, msg32) */
    rustsecp256k1_v0_4_1_schnorrsig_sha256_tagged(&sha);
    rustsecp256k1_v0_4_1_sha256_write(&sha, r32, 32);
    rustsecp256k1_v0_4_1_sha256_write(&sha, pubkey32, 32);
    rustsecp256k1_v0_4_1_sha256_write(&sha, msg32, 32);
    rustsecp256k1_v0_4_1_sha256_finalize(&sha, buf);
    /* Set scalar e to the challenge hash modulo the curve order as per
     * BIP340. */
    rustsecp256k1_v0_4_1_scalar_set_b32(e, buf, NULL);
}

int rustsecp256k1_v0_4_1_schnorrsig_sign(const rustsecp256k1_v0_4_1_context* ctx, unsigned char *sig64, const unsigned char *msg32, const rustsecp256k1_v0_4_1_keypair *keypair, rustsecp256k1_v0_4_1_nonce_function_hardened noncefp, void *ndata) {
    rustsecp256k1_v0_4_1_scalar sk;
    rustsecp256k1_v0_4_1_scalar e;
    rustsecp256k1_v0_4_1_scalar k;
    rustsecp256k1_v0_4_1_gej rj;
    rustsecp256k1_v0_4_1_ge pk;
    rustsecp256k1_v0_4_1_ge r;
    unsigned char buf[32] = { 0 };
    unsigned char pk_buf[32];
    unsigned char seckey[32];
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1_v0_4_1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(keypair != NULL);

    if (noncefp == NULL) {
        noncefp = rustsecp256k1_v0_4_1_nonce_function_bip340;
    }

    ret &= rustsecp256k1_v0_4_1_keypair_load(ctx, &sk, &pk, keypair);
    /* Because we are signing for a x-only pubkey, the secret key is negated
     * before signing if the point corresponding to the secret key does not
     * have an even Y. */
    if (rustsecp256k1_v0_4_1_fe_is_odd(&pk.y)) {
        rustsecp256k1_v0_4_1_scalar_negate(&sk, &sk);
    }

    rustsecp256k1_v0_4_1_scalar_get_b32(seckey, &sk);
    rustsecp256k1_v0_4_1_fe_get_b32(pk_buf, &pk.x);
    ret &= !!noncefp(buf, msg32, seckey, pk_buf, bip340_algo16, ndata);
    rustsecp256k1_v0_4_1_scalar_set_b32(&k, buf, NULL);
    ret &= !rustsecp256k1_v0_4_1_scalar_is_zero(&k);
    rustsecp256k1_v0_4_1_scalar_cmov(&k, &rustsecp256k1_v0_4_1_scalar_one, !ret);

    rustsecp256k1_v0_4_1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &k);
    rustsecp256k1_v0_4_1_ge_set_gej(&r, &rj);

    /* We declassify r to allow using it as a branch point. This is fine
     * because r is not a secret. */
    rustsecp256k1_v0_4_1_declassify(ctx, &r, sizeof(r));
    rustsecp256k1_v0_4_1_fe_normalize_var(&r.y);
    if (rustsecp256k1_v0_4_1_fe_is_odd(&r.y)) {
        rustsecp256k1_v0_4_1_scalar_negate(&k, &k);
    }
    rustsecp256k1_v0_4_1_fe_normalize_var(&r.x);
    rustsecp256k1_v0_4_1_fe_get_b32(&sig64[0], &r.x);

    rustsecp256k1_v0_4_1_schnorrsig_challenge(&e, &sig64[0], msg32, pk_buf);
    rustsecp256k1_v0_4_1_scalar_mul(&e, &e, &sk);
    rustsecp256k1_v0_4_1_scalar_add(&e, &e, &k);
    rustsecp256k1_v0_4_1_scalar_get_b32(&sig64[32], &e);

    rustsecp256k1_v0_4_1_memczero(sig64, 64, !ret);
    rustsecp256k1_v0_4_1_scalar_clear(&k);
    rustsecp256k1_v0_4_1_scalar_clear(&sk);
    memset(seckey, 0, sizeof(seckey));

    return ret;
}

int rustsecp256k1_v0_4_1_schnorrsig_verify(const rustsecp256k1_v0_4_1_context* ctx, const unsigned char *sig64, const unsigned char *msg32, const rustsecp256k1_v0_4_1_xonly_pubkey *pubkey) {
    rustsecp256k1_v0_4_1_scalar s;
    rustsecp256k1_v0_4_1_scalar e;
    rustsecp256k1_v0_4_1_gej rj;
    rustsecp256k1_v0_4_1_ge pk;
    rustsecp256k1_v0_4_1_gej pkj;
    rustsecp256k1_v0_4_1_fe rx;
    rustsecp256k1_v0_4_1_ge r;
    unsigned char buf[32];
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rustsecp256k1_v0_4_1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(pubkey != NULL);

    if (!rustsecp256k1_v0_4_1_fe_set_b32(&rx, &sig64[0])) {
        return 0;
    }

    rustsecp256k1_v0_4_1_scalar_set_b32(&s, &sig64[32], &overflow);
    if (overflow) {
        return 0;
    }

    if (!rustsecp256k1_v0_4_1_xonly_pubkey_load(ctx, &pk, pubkey)) {
        return 0;
    }

    /* Compute e. */
    rustsecp256k1_v0_4_1_fe_get_b32(buf, &pk.x);
    rustsecp256k1_v0_4_1_schnorrsig_challenge(&e, &sig64[0], msg32, buf);

    /* Compute rj =  s*G + (-e)*pkj */
    rustsecp256k1_v0_4_1_scalar_negate(&e, &e);
    rustsecp256k1_v0_4_1_gej_set_ge(&pkj, &pk);
    rustsecp256k1_v0_4_1_ecmult(&ctx->ecmult_ctx, &rj, &pkj, &e, &s);

    rustsecp256k1_v0_4_1_ge_set_gej_var(&r, &rj);
    if (rustsecp256k1_v0_4_1_ge_is_infinity(&r)) {
        return 0;
    }

    rustsecp256k1_v0_4_1_fe_normalize_var(&r.y);
    return !rustsecp256k1_v0_4_1_fe_is_odd(&r.y) &&
           rustsecp256k1_v0_4_1_fe_equal_var(&rx, &r.x);
}

#endif
