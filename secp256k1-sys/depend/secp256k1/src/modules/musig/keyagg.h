/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_MUSIG_KEYAGG_H
#define SECP256K1_MODULE_MUSIG_KEYAGG_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_musig.h"

#include "../../group.h"
#include "../../scalar.h"

typedef struct {
    rustsecp256k1_v0_11_ge pk;
    /* If there is no "second" public key, second_pk is set to the point at
     * infinity */
    rustsecp256k1_v0_11_ge second_pk;
    unsigned char pks_hash[32];
    /* tweak is identical to value tacc[v] in the specification. */
    rustsecp256k1_v0_11_scalar tweak;
    /* parity_acc corresponds to (1 - gacc[v])/2 in the spec. So if gacc[v] is
     * -1, parity_acc is 1. Otherwise, parity_acc is 0. */
    int parity_acc;
} rustsecp256k1_v0_11_keyagg_cache_internal;

static int rustsecp256k1_v0_11_keyagg_cache_load(const rustsecp256k1_v0_11_context* ctx, rustsecp256k1_v0_11_keyagg_cache_internal *cache_i, const rustsecp256k1_v0_11_musig_keyagg_cache *cache);

static void rustsecp256k1_v0_11_musig_keyaggcoef(rustsecp256k1_v0_11_scalar *r, const rustsecp256k1_v0_11_keyagg_cache_internal *cache_i, rustsecp256k1_v0_11_ge *pk);

#endif
