/*****************************************************************************************************
 * Copyright (c) 2013, 2014, 2017, 2021 Pieter Wuille, Andrew Poelstra, Jonas Nick, Russell O'Connor *
 * Distributed under the MIT software license, see the accompanying                                  *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.                              *
 *****************************************************************************************************/

#ifndef SECP256K1_ECMULT_COMPUTE_TABLE_IMPL_H
#define SECP256K1_ECMULT_COMPUTE_TABLE_IMPL_H

#include "ecmult_compute_table.h"
#include "group_impl.h"
#include "field_impl.h"
#include "ecmult.h"
#include "util.h"

static void rustsecp256k1_v0_11_ecmult_compute_table(rustsecp256k1_v0_11_ge_storage* table, int window_g, const rustsecp256k1_v0_11_gej* gen) {
    rustsecp256k1_v0_11_gej gj;
    rustsecp256k1_v0_11_ge ge, dgen;
    int j;

    gj = *gen;
    rustsecp256k1_v0_11_ge_set_gej_var(&ge, &gj);
    rustsecp256k1_v0_11_ge_to_storage(&table[0], &ge);

    rustsecp256k1_v0_11_gej_double_var(&gj, gen, NULL);
    rustsecp256k1_v0_11_ge_set_gej_var(&dgen, &gj);

    for (j = 1; j < ECMULT_TABLE_SIZE(window_g); ++j) {
        rustsecp256k1_v0_11_gej_set_ge(&gj, &ge);
        rustsecp256k1_v0_11_gej_add_ge_var(&gj, &gj, &dgen, NULL);
        rustsecp256k1_v0_11_ge_set_gej_var(&ge, &gj);
        rustsecp256k1_v0_11_ge_to_storage(&table[j], &ge);
    }
}

/* Like rustsecp256k1_v0_11_ecmult_compute_table, but one for both gen and gen*2^128. */
static void rustsecp256k1_v0_11_ecmult_compute_two_tables(rustsecp256k1_v0_11_ge_storage* table, rustsecp256k1_v0_11_ge_storage* table_128, int window_g, const rustsecp256k1_v0_11_ge* gen) {
    rustsecp256k1_v0_11_gej gj;
    int i;

    rustsecp256k1_v0_11_gej_set_ge(&gj, gen);
    rustsecp256k1_v0_11_ecmult_compute_table(table, window_g, &gj);
    for (i = 0; i < 128; ++i) {
        rustsecp256k1_v0_11_gej_double_var(&gj, &gj, NULL);
    }
    rustsecp256k1_v0_11_ecmult_compute_table(table_128, window_g, &gj);
}

#endif /* SECP256K1_ECMULT_COMPUTE_TABLE_IMPL_H */
