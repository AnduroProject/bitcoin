// Copyright (c) 2015-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_MERKLE_H
#define BITCOIN_CONSENSUS_MERKLE_H

#include <vector>

#include <primitives/block.h>
#include <coordinate/signed_block.h>
#include <uint256.h>

uint256 ComputeMerkleRoot(std::vector<uint256> hashes, bool* mutated = nullptr);


/*
 * Compute the Merkle root of the transactions in a block.
 * *mutated is set to true if a duplicated subtree was found.
 */
uint256 BlockMerkleRoot(const CBlock& block, bool* mutated = nullptr);

/**
 * Compute the raw Merkle root of a block, depending on the input type.
 *
 * @param block     Reference to the CBlock instance for which to compute the Merkle root.
 * @param type      Selector for which data structure to compute the Merkle root from:
 *                  - 0: vtx (transactions) – compute Merkle root over block.vtx
 *                  - 1: pegin – compute Merkle root over block.pegins
 *                  - 3: signedblock – compute Merkle root over block.signed_blocks or equivalent
 *
 * @param mutated   (Optional) Output parameter that will be set to true if a Merkle tree 
 *                  mutation was detected (i.e. duplicate subtrees producing the same hash), 
 *                  otherwise false. If nullptr is passed, the mutation check is skipped.
 *
 * @return          A uint256 representing the Merkle root hash of the selected data.
 *
 * @note
 *  - The mutation flag is useful for detecting Merkle tree malleability issues (as in 
 *    Bitcoin Core’s GetMerkleRoot implementation).
 *  - For type 0 (vtx), this matches the standard Bitcoin block transaction Merkle root.
 *  - For type 1 (pegin), it commits to peg-in transactions relevant to sidechain/federated peg logic.
 *  - For type 3 (signedblock), it commits to signatures or signed block data as defined
 *    by the consensus rules of the system.
 *
 * Example:
 * @code
 *   bool mutated;
 *   uint256 txRoot = BlockRawMerkleRoot(block, 0, &mutated);
 *   uint256 peginRoot = BlockRawMerkleRoot(block, 1);
 * @endcode
 */
uint256 BlockRawMerkleRoot(const CBlock& block, uint16_t type, bool* mutated = nullptr);

/*
 * Compute the Merkle root of the witness transactions in a block.
 * *mutated is set to true if a duplicated subtree was found.
 */
uint256 BlockWitnessMerkleRoot(const CBlock& block, bool* mutated = nullptr);

uint256 SignedBlockMerkleRoot(const SignedBlock& block, bool* mutated = nullptr);

uint256 SignedBlockWitnessMerkleRoot(const SignedBlock& block, bool* mutated = nullptr);

/**
 * Compute merkle path to the specified transaction
 *
 * @param[in] block the block
 * @param[in] position transaction for which to calculate the merkle path (0 is the coinbase)
 *
 * @return merkle path ordered from the deepest
 */
std::vector<uint256> TransactionMerklePath(const CBlock& block, uint32_t position);

#endif // BITCOIN_CONSENSUS_MERKLE_H
