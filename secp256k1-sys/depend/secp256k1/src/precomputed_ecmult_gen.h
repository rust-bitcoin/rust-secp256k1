/*********************************************************************************
 * Copyright (c) 2013, 2014, 2015, 2021 Thomas Daede, Cory Fields, Pieter Wuille *
 * Distributed under the MIT software license, see the accompanying              *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.          *
 *********************************************************************************/

#ifndef SECP256K1_PRECOMPUTED_ECMULT_GEN_H
#define SECP256K1_PRECOMPUTED_ECMULT_GEN_H

#ifdef __cplusplus
extern "C" {
#endif

#include "group.h"
#include "ecmult_gen.h"
#ifdef EXHAUSTIVE_TEST_ORDER
static rustsecp256k1_v0_12_ge_storage rustsecp256k1_v0_12_ecmult_gen_prec_table[COMB_BLOCKS][COMB_POINTS];
#else
extern const rustsecp256k1_v0_12_ge_storage rustsecp256k1_v0_12_ecmult_gen_prec_table[COMB_BLOCKS][COMB_POINTS];
#endif /* defined(EXHAUSTIVE_TEST_ORDER) */

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_PRECOMPUTED_ECMULT_GEN_H */
