// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_CACHES_H
#define BITCOIN_KERNEL_CACHES_H

#include <util/byte_units.h>

#include <algorithm>

//! Suggested default amount of cache reserved for the kernel (bytes)
static constexpr size_t DEFAULT_KERNEL_CACHE{450_MiB};
//! Max memory allocated to block tree DB specific cache (bytes)
static constexpr size_t MAX_BLOCK_DB_CACHE{2_MiB};
//! Max memory allocated to coin DB specific cache (bytes)
static constexpr size_t MAX_COINS_DB_CACHE{8_MiB};
//! Max memory allocated to asset DB specific cache (bytes)
static constexpr size_t MAX_ASSET_DB_CACHE{8_MiB};
//! Max memory allocated to signed block DB specific cache (bytes)
static constexpr size_t MAX_SIGNED_BLOCK_DB_CACHE{8_MiB};

namespace kernel {
struct CacheSizes {
    size_t block_tree_db;
    size_t coins_db;
    size_t coins;
    size_t asset_db;
    size_t signed_block_db;

    CacheSizes(size_t total_cache)
    {
        block_tree_db = std::min(total_cache / 8, MAX_BLOCK_DB_CACHE);
        total_cache -= block_tree_db;

        coins_db = std::min(total_cache / 2, MAX_COINS_DB_CACHE);
        total_cache -= coins_db;

        asset_db = std::min(total_cache / 2, MAX_ASSET_DB_CACHE);
        total_cache -= asset_db;

        signed_block_db = std::min(total_cache / 2, MAX_SIGNED_BLOCK_DB_CACHE);
        total_cache -= signed_block_db;
        
        coins = total_cache; // the rest goes to the coins cache
    }
};
} // namespace kernel

#endif // BITCOIN_KERNEL_CACHES_H
