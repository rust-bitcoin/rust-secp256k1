/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_TESTUTIL_H
#define SECP256K1_TESTUTIL_H

#include "field.h"
#include "testrand.h"
#include "util.h"

static void random_fe(rustsecp256k1_v0_10_0_fe *x) {
    unsigned char bin[32];
    do {
        rustsecp256k1_v0_10_0_testrand256(bin);
        if (rustsecp256k1_v0_10_0_fe_set_b32_limit(x, bin)) {
            return;
        }
    } while(1);
}

static void random_fe_non_zero(rustsecp256k1_v0_10_0_fe *nz) {
    do {
        random_fe(nz);
    } while (rustsecp256k1_v0_10_0_fe_is_zero(nz));
}

#endif /* SECP256K1_TESTUTIL_H */
