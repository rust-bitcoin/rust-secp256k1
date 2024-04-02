/***********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_SCRATCH_IMPL_H
#define SECP256K1_SCRATCH_IMPL_H

#include "util.h"
#include "scratch.h"

static size_t rustsecp256k1_v0_10_0_scratch_checkpoint(const rustsecp256k1_v0_10_0_callback* error_callback, const rustsecp256k1_v0_10_0_scratch* scratch) {
    if (rustsecp256k1_v0_10_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        rustsecp256k1_v0_10_0_callback_call(error_callback, "invalid scratch space");
        return 0;
    }
    return scratch->alloc_size;
}

static void rustsecp256k1_v0_10_0_scratch_apply_checkpoint(const rustsecp256k1_v0_10_0_callback* error_callback, rustsecp256k1_v0_10_0_scratch* scratch, size_t checkpoint) {
    if (rustsecp256k1_v0_10_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        rustsecp256k1_v0_10_0_callback_call(error_callback, "invalid scratch space");
        return;
    }
    if (checkpoint > scratch->alloc_size) {
        rustsecp256k1_v0_10_0_callback_call(error_callback, "invalid checkpoint");
        return;
    }
    scratch->alloc_size = checkpoint;
}

static size_t rustsecp256k1_v0_10_0_scratch_max_allocation(const rustsecp256k1_v0_10_0_callback* error_callback, const rustsecp256k1_v0_10_0_scratch* scratch, size_t objects) {
    if (rustsecp256k1_v0_10_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        rustsecp256k1_v0_10_0_callback_call(error_callback, "invalid scratch space");
        return 0;
    }
    /* Ensure that multiplication will not wrap around */
    if (ALIGNMENT > 1 && objects > SIZE_MAX/(ALIGNMENT - 1)) {
        return 0;
    }
    if (scratch->max_size - scratch->alloc_size <= objects * (ALIGNMENT - 1)) {
        return 0;
    }
    return scratch->max_size - scratch->alloc_size - objects * (ALIGNMENT - 1);
}

static void *rustsecp256k1_v0_10_0_scratch_alloc(const rustsecp256k1_v0_10_0_callback* error_callback, rustsecp256k1_v0_10_0_scratch* scratch, size_t size) {
    void *ret;
    size_t rounded_size;

    rounded_size = ROUND_TO_ALIGN(size);
    /* Check that rounding did not wrap around */
    if (rounded_size < size) {
        return NULL;
    }
    size = rounded_size;

    if (rustsecp256k1_v0_10_0_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        rustsecp256k1_v0_10_0_callback_call(error_callback, "invalid scratch space");
        return NULL;
    }

    if (size > scratch->max_size - scratch->alloc_size) {
        return NULL;
    }
    ret = (void *) ((char *) scratch->data + scratch->alloc_size);
    memset(ret, 0, size);
    scratch->alloc_size += size;

    return ret;
}

#endif
