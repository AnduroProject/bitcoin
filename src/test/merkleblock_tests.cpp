// Copyright (c) 2012-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <merkleblock.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <set>
#include <vector>

BOOST_AUTO_TEST_SUITE(merkleblock_tests)

/**
 * Create a CMerkleBlock using a list of txids which will be found in the
 * given block.
 */
BOOST_AUTO_TEST_CASE(merkleblock_construct_from_txids_found)
{
    CBlock block = getBlock13b8a();

    std::set<Txid> txids;

    // Last txn in block.
    Txid txhash1{Txid::FromHex("937790a1a3bfb749a9d248e5a46e7bb9dbe9009917e7aae1149f2d4883e637ea").value()};

    // Second txn in block.
    Txid txhash2{Txid::FromHex("0f2e9924b1e175a5fc55d26f38b1d50a52380eebaa12c6484920a2c7f5065818").value()};

    txids.insert(txhash1);
    txids.insert(txhash2);

    CMerkleBlock merkleBlock(block, block.vtx, txids);

    BOOST_CHECK_EQUAL(merkleBlock.header.GetHash().GetHex(), block.GetHash().GetHex());

    // vMatchedTxn is only used when bloom filter is specified.
    BOOST_CHECK_EQUAL(merkleBlock.vMatchedTxn.size(), 0U);

    std::vector<uint256> vMatched;
    std::vector<unsigned int> vIndex;

    merkleBlock.txn.ExtractMatches(vMatched, vIndex);
    BOOST_CHECK_EQUAL(vMatched.size(), 2U);
}


/**
 * Create a CMerkleBlock using a list of txids which will not be found in the
 * given block.
 */
BOOST_AUTO_TEST_CASE(merkleblock_construct_from_txids_not_found)
{
    CBlock block = getBlock13b8a();

    std::set<Txid> txids2;
    txids2.insert(Txid::FromHex("c0ffee00003bafa802c8aa084379aa98d9fcd632ddc2ed9782b586ec87451f20").value());
    CMerkleBlock merkleBlock(block, txids2);

    BOOST_CHECK_EQUAL(merkleBlock.vMatchedTxn.size(), 0U);

    std::vector<uint256> vMatched;
    std::vector<unsigned int> vIndex;

    merkleBlock.txn.ExtractMatches(vMatched, vIndex);
    BOOST_CHECK_EQUAL(vMatched.size(), 0U);
    BOOST_CHECK_EQUAL(vIndex.size(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
