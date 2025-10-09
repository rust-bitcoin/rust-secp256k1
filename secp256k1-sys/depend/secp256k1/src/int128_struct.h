#ifndef SECP256K1_INT128_STRUCT_H
#define SECP256K1_INT128_STRUCT_H

#include <stdint.h>
#include "util.h"

typedef struct {
  uint64_t lo;
  uint64_t hi;
} rustsecp256k1_v0_12_uint128;

typedef rustsecp256k1_v0_12_uint128 rustsecp256k1_v0_12_int128;

#endif
