/***********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_HASH_H
#define SECP256K1_HASH_H

#include <stdlib.h>
#include <stdint.h>

typedef struct {
    uint32_t s[8];
    unsigned char buf[64];
    uint64_t bytes;
} rustsecp256k1_v0_12_sha256;

static void rustsecp256k1_v0_12_sha256_initialize(rustsecp256k1_v0_12_sha256 *hash);
static void rustsecp256k1_v0_12_sha256_write(rustsecp256k1_v0_12_sha256 *hash, const unsigned char *data, size_t size);
static void rustsecp256k1_v0_12_sha256_finalize(rustsecp256k1_v0_12_sha256 *hash, unsigned char *out32);
static void rustsecp256k1_v0_12_sha256_clear(rustsecp256k1_v0_12_sha256 *hash);

typedef struct {
    rustsecp256k1_v0_12_sha256 inner, outer;
} rustsecp256k1_v0_12_hmac_sha256;

static void rustsecp256k1_v0_12_hmac_sha256_initialize(rustsecp256k1_v0_12_hmac_sha256 *hash, const unsigned char *key, size_t size);
static void rustsecp256k1_v0_12_hmac_sha256_write(rustsecp256k1_v0_12_hmac_sha256 *hash, const unsigned char *data, size_t size);
static void rustsecp256k1_v0_12_hmac_sha256_finalize(rustsecp256k1_v0_12_hmac_sha256 *hash, unsigned char *out32);
static void rustsecp256k1_v0_12_hmac_sha256_clear(rustsecp256k1_v0_12_hmac_sha256 *hash);

typedef struct {
    unsigned char v[32];
    unsigned char k[32];
    int retry;
} rustsecp256k1_v0_12_rfc6979_hmac_sha256;

static void rustsecp256k1_v0_12_rfc6979_hmac_sha256_initialize(rustsecp256k1_v0_12_rfc6979_hmac_sha256 *rng, const unsigned char *key, size_t keylen);
static void rustsecp256k1_v0_12_rfc6979_hmac_sha256_generate(rustsecp256k1_v0_12_rfc6979_hmac_sha256 *rng, unsigned char *out, size_t outlen);
static void rustsecp256k1_v0_12_rfc6979_hmac_sha256_finalize(rustsecp256k1_v0_12_rfc6979_hmac_sha256 *rng);
static void rustsecp256k1_v0_12_rfc6979_hmac_sha256_clear(rustsecp256k1_v0_12_rfc6979_hmac_sha256 *rng);

#endif /* SECP256K1_HASH_H */
