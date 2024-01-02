/***********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_SCRATCH_H
#define SECP256K1_SCRATCH_H

/* The typedef is used internally; the struct name is used in the public API
 * (where it is exposed as a different typedef) */
typedef struct rustsecp256k1_v0_9_2_scratch_space_struct {
    /** guard against interpreting this object as other types */
    unsigned char magic[8];
    /** actual allocated data */
    void *data;
    /** amount that has been allocated (i.e. `data + offset` is the next
     *  available pointer)  */
    size_t alloc_size;
    /** maximum size available to allocate */
    size_t max_size;
} rustsecp256k1_v0_9_2_scratch;

static rustsecp256k1_v0_9_2_scratch* rustsecp256k1_v0_9_2_scratch_create(const rustsecp256k1_v0_9_2_callback* error_callback, size_t max_size);

static void rustsecp256k1_v0_9_2_scratch_destroy(const rustsecp256k1_v0_9_2_callback* error_callback, rustsecp256k1_v0_9_2_scratch* scratch);

/** Returns an opaque object used to "checkpoint" a scratch space. Used
 *  with `rustsecp256k1_v0_9_2_scratch_apply_checkpoint` to undo allocations. */
static size_t rustsecp256k1_v0_9_2_scratch_checkpoint(const rustsecp256k1_v0_9_2_callback* error_callback, const rustsecp256k1_v0_9_2_scratch* scratch);

/** Applies a check point received from `rustsecp256k1_v0_9_2_scratch_checkpoint`,
 *  undoing all allocations since that point. */
static void rustsecp256k1_v0_9_2_scratch_apply_checkpoint(const rustsecp256k1_v0_9_2_callback* error_callback, rustsecp256k1_v0_9_2_scratch* scratch, size_t checkpoint);

/** Returns the maximum allocation the scratch space will allow */
static size_t rustsecp256k1_v0_9_2_scratch_max_allocation(const rustsecp256k1_v0_9_2_callback* error_callback, const rustsecp256k1_v0_9_2_scratch* scratch, size_t n_objects);

/** Returns a pointer into the most recently allocated frame, or NULL if there is insufficient available space */
static void *rustsecp256k1_v0_9_2_scratch_alloc(const rustsecp256k1_v0_9_2_callback* error_callback, rustsecp256k1_v0_9_2_scratch* scratch, size_t n);

#endif
