/***********************************************************************
 * Copyright (c) Pieter Wuille, Gregory Maxwell                        *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECMULT_GEN_COMPUTE_TABLE_H
#define SECP256K1_ECMULT_GEN_COMPUTE_TABLE_H

#include "ecmult_gen.h"

static void rustsecp256k1_v0_12_ecmult_gen_compute_table(rustsecp256k1_v0_12_ge_storage* table, const rustsecp256k1_v0_12_ge* gen, int blocks, int teeth, int spacing);

#endif /* SECP256K1_ECMULT_GEN_COMPUTE_TABLE_H */
