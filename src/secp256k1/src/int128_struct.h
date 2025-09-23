#ifndef SECP256K1_INT128_STRUCT_H
#define SECP256K1_INT128_STRUCT_H

#include "util.h"
#include <stdint.h>

typedef struct {
    uint64_t lo;
    uint64_t hi;
} secp256k1_uint128;

typedef secp256k1_uint128 secp256k1_int128;

#endif
