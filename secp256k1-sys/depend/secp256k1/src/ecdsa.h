/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECDSA_H
#define SECP256K1_ECDSA_H

#include <stddef.h>

#include "scalar.h"
#include "group.h"
#include "ecmult.h"

static int rustsecp256k1_v0_10_0_ecdsa_sig_parse(rustsecp256k1_v0_10_0_scalar *r, rustsecp256k1_v0_10_0_scalar *s, const unsigned char *sig, size_t size);
static int rustsecp256k1_v0_10_0_ecdsa_sig_serialize(unsigned char *sig, size_t *size, const rustsecp256k1_v0_10_0_scalar *r, const rustsecp256k1_v0_10_0_scalar *s);
static int rustsecp256k1_v0_10_0_ecdsa_sig_verify(const rustsecp256k1_v0_10_0_scalar* r, const rustsecp256k1_v0_10_0_scalar* s, const rustsecp256k1_v0_10_0_ge *pubkey, const rustsecp256k1_v0_10_0_scalar *message);
static int rustsecp256k1_v0_10_0_ecdsa_sig_sign(const rustsecp256k1_v0_10_0_ecmult_gen_context *ctx, rustsecp256k1_v0_10_0_scalar* r, rustsecp256k1_v0_10_0_scalar* s, const rustsecp256k1_v0_10_0_scalar *seckey, const rustsecp256k1_v0_10_0_scalar *message, const rustsecp256k1_v0_10_0_scalar *nonce, int *recid);

#endif /* SECP256K1_ECDSA_H */
