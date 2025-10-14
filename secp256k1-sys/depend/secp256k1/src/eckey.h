/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECKEY_H
#define SECP256K1_ECKEY_H

#include <stddef.h>

#include "group.h"
#include "scalar.h"
#include "ecmult.h"
#include "ecmult_gen.h"

static int rustsecp256k1_v0_12_eckey_pubkey_parse(rustsecp256k1_v0_12_ge *elem, const unsigned char *pub, size_t size);
static int rustsecp256k1_v0_12_eckey_pubkey_serialize(rustsecp256k1_v0_12_ge *elem, unsigned char *pub, size_t *size, int compressed);

static int rustsecp256k1_v0_12_eckey_privkey_tweak_add(rustsecp256k1_v0_12_scalar *key, const rustsecp256k1_v0_12_scalar *tweak);
static int rustsecp256k1_v0_12_eckey_pubkey_tweak_add(rustsecp256k1_v0_12_ge *key, const rustsecp256k1_v0_12_scalar *tweak);
static int rustsecp256k1_v0_12_eckey_privkey_tweak_mul(rustsecp256k1_v0_12_scalar *key, const rustsecp256k1_v0_12_scalar *tweak);
static int rustsecp256k1_v0_12_eckey_pubkey_tweak_mul(rustsecp256k1_v0_12_ge *key, const rustsecp256k1_v0_12_scalar *tweak);

#endif /* SECP256K1_ECKEY_H */
