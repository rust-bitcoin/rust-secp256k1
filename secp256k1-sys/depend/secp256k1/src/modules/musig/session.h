/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_MUSIG_SESSION_H
#define SECP256K1_MODULE_MUSIG_SESSION_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_musig.h"

#include "../../scalar.h"

typedef struct {
    int fin_nonce_parity;
    unsigned char fin_nonce[32];
    rustsecp256k1_v0_12_scalar noncecoef;
    rustsecp256k1_v0_12_scalar challenge;
    rustsecp256k1_v0_12_scalar s_part;
} rustsecp256k1_v0_12_musig_session_internal;

static int rustsecp256k1_v0_12_musig_session_load(const rustsecp256k1_v0_12_context* ctx, rustsecp256k1_v0_12_musig_session_internal *session_i, const rustsecp256k1_v0_12_musig_session *session);

#endif
