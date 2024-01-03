/*****************************************************************************************************
 * Copyright (c) 2013, 2014, 2017, 2021 Pieter Wuille, Andrew Poelstra, Jonas Nick, Russell O'Connor *
 * Distributed under the MIT software license, see the accompanying                                  *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.                              *
 *****************************************************************************************************/

#ifndef SECP256K1_ECMULT_COMPUTE_TABLE_H
#define SECP256K1_ECMULT_COMPUTE_TABLE_H

/* Construct table of all odd multiples of gen in range 1..(2**(window_g-1)-1). */
static void rustsecp256k1_v0_9_2_ecmult_compute_table(rustsecp256k1_v0_9_2_ge_storage* table, int window_g, const rustsecp256k1_v0_9_2_gej* gen);

/* Like rustsecp256k1_v0_9_2_ecmult_compute_table, but one for both gen and gen*2^128. */
static void rustsecp256k1_v0_9_2_ecmult_compute_two_tables(rustsecp256k1_v0_9_2_ge_storage* table, rustsecp256k1_v0_9_2_ge_storage* table_128, int window_g, const rustsecp256k1_v0_9_2_ge* gen);

#endif /* SECP256K1_ECMULT_COMPUTE_TABLE_H */
