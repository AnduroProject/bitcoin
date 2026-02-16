#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <consensus/validation.h>
#include <validation.h>
#include <txmempool.h>
#include <policy/policy.h>
#include <node/miner.h>
#include <coordinate/anduro_validator.h>
#include <consensus/merkle.h>
#include <pow.h>
#include <test/util/txmempool.h>
#include <txmempool.h>

BOOST_FIXTURE_TEST_SUITE(asset_transaction_tests, TestingSetup)
// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Create an asset transaction using TestChain100Setup coins
 */
CMutableTransaction CreateAssetTransaction(
    const CTransactionRef& coinbaseTx,
    const std::string& payloadData,
    const std::string& ticker,
    const std::string& headline,
    int32_t assetType,
    int32_t precision
) {
    CMutableTransaction tx;
    
    // Set transaction version for asset transactions
    tx.version = TRANSACTION_COORDINATE_ASSET_CREATE_VERSION;
    
    // Set asset-specific fields
    tx.payloadData = payloadData;
    tx.payload = prepareMessageHash(payloadData);
    tx.ticker = ticker;
    tx.headline = headline;
    tx.assetType = assetType;
    tx.precision = precision;
    
    // Add input from coinbase transaction
    CTxIn txin(coinbaseTx->GetHash(), 0);
    tx.vin.push_back(txin);
    
    // Get the scriptPubKey from the coinbase output
    const CTxDestination coinbaseScript = DecodeDestination("ccrt1qhqr9plud3fk6zlnaf7thes7lyrj2r9qwww7alh");
    const CScript scriptPubKey = GetScriptForDestination(coinbaseScript);
    // CScript scriptPubKey = GetScriptForRawPubKey(coinbaseKey.GetPubKey());
    
    // Output 0: Controller output (zero value)
    CTxOut controllerOut(CAmount(1), scriptPubKey);
    tx.vout.push_back(controllerOut);
    
    // Output 1: Supply output (zero value)
    CTxOut supplyOut(CAmount(10000), scriptPubKey);
    tx.vout.push_back(supplyOut);
    
    // Output 2: Forward output (remaining BTC minus fee)
    CAmount fee = 1000;  // Transaction fee
    CAmount forwardAmount = coinbaseTx->vout[0].nValue - fee;
    CTxOut forwardOut(forwardAmount, scriptPubKey);
    tx.vout.push_back(forwardOut);
    
    return tx;
}

/**
 * Sign the asset transaction using the coinbase key
 */
bool SignTransaction(
    CMutableTransaction& tx,
    const CKey& key,
    const CTransactionRef& prevTx
) {
    // Setup signing provider
    FillableSigningProvider keystore;
    keystore.AddKey(key);
    
    // Sign each input
    for (size_t i = 0; i < tx.vin.size(); i++) {
        const CScript& scriptPubKey = prevTx->vout[tx.vin[i].prevout.n].scriptPubKey;
        const CAmount& amount = prevTx->vout[tx.vin[i].prevout.n].nValue;
        
        SignatureData sigdata = DataFromTransaction(tx, i, prevTx->vout[tx.vin[i].prevout.n]);
        bool isSigned = ProduceSignature(keystore, 
                                       MutableTransactionSignatureCreator(tx, i, amount, SIGHASH_ALL), 
                                       scriptPubKey, 
                                       sigdata);
        
        if (!isSigned) {
            return false;
        }
        
        UpdateInput(tx.vin[i], sigdata);
    }
    
    return true;
}

// ============================================================================
// Test Cases
// ============================================================================

BOOST_FIXTURE_TEST_CASE(fungible_asset_mempool_validation, TestChain100Setup) {
    // Create asset transaction
    CTxMemPool& pool = *Assert(m_node.mempool);
    TestMemPoolEntryHelper entry;
    LOCK2(::cs_main, pool.cs);
    CTransactionRef coinbaseTx = m_coinbase_txns[0];
    
    CMutableTransaction mtx = CreateAssetTransaction(
        coinbaseTx,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "GOLD",
        "Digital Gold Token",
        0,  // Fungible
        8   // 8 decimal precision
    );
    
    // Sign the transaction
    BOOST_CHECK(SignTransaction(mtx, coinbaseKey, coinbaseTx));
    
    // Convert to immutable transaction
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    
    AddToMempool(pool, entry.Time(Now<NodeSeconds>()).FromTx(tx));
    
    // // Verify it's in mempool
    BOOST_CHECK(m_node.mempool->exists(tx->GetHash()));
    
    // // Verify transaction properties
    BOOST_CHECK_EQUAL(tx->version, TRANSACTION_COORDINATE_ASSET_CREATE_VERSION);
    BOOST_CHECK_EQUAL(tx->ticker, "GOLD");
    BOOST_CHECK_EQUAL(tx->assetType, 0);
    BOOST_CHECK_EQUAL(tx->precision, 8);
}

BOOST_FIXTURE_TEST_CASE(non_fungible_asset_mempool_validation, TestChain100Setup) {
    CTxMemPool& pool = *Assert(m_node.mempool);
    TestMemPoolEntryHelper entry;
    LOCK2(::cs_main, pool.cs);

    // Create NFT transaction
    CTransactionRef coinbaseTx = m_coinbase_txns[1];
    
    CMutableTransaction mtx = CreateAssetTransaction(
        coinbaseTx,
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        "NFT001",
        "Rare Digital Artwork",
        1,  // Non-Fungible
        0   // No precision for NFT
    );
    
    // Sign the transaction
    BOOST_CHECK(SignTransaction(mtx, coinbaseKey, coinbaseTx));
    
    // Convert to immutable transaction
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    
    // Submit to mempool
    AddToMempool(pool, entry.Time(Now<NodeSeconds>()).FromTx(tx));
    
    // Verify transaction properties
    BOOST_CHECK_EQUAL(tx->version, TRANSACTION_COORDINATE_ASSET_CREATE_VERSION);
    BOOST_CHECK_EQUAL(tx->ticker, "NFT001");
    BOOST_CHECK_EQUAL(tx->assetType, 1);
    BOOST_CHECK_EQUAL(tx->precision, 0);
}

BOOST_FIXTURE_TEST_CASE(nft_collection_mempool_validation, TestChain100Setup) {
    CTxMemPool& pool = *Assert(m_node.mempool);
    TestMemPoolEntryHelper entry;
     LOCK2(::cs_main, pool.cs);
    // Create NFT collection transaction
    CTransactionRef coinbaseTx = m_coinbase_txns[2];
    
    CMutableTransaction mtx = CreateAssetTransaction(
        coinbaseTx,
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "ARTCOL",
        "Digital Art Collection",
        2,  // Non-Fungible Collection
        0   // No precision for collection
    );
    
    // Sign the transaction
    BOOST_CHECK(SignTransaction(mtx, coinbaseKey, coinbaseTx));
    
    // Convert to immutable transaction
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    
    // Submit to mempool
    AddToMempool(pool, entry.Time(Now<NodeSeconds>()).FromTx(tx));
    
    // Verify transaction properties
    BOOST_CHECK_EQUAL(tx->assetType, 2);
    BOOST_CHECK_EQUAL(tx->precision, 0);
}

BOOST_FIXTURE_TEST_CASE(invalid_precision_rejected_by_mempool, TestChain100Setup) {
    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(::cs_main, pool.cs);
    CTransactionRef coinbaseTx = m_coinbase_txns[3];
    
    CMutableTransaction mtx = CreateAssetTransaction(
        coinbaseTx,
        "1111111111111111111111111111111111111111111111111111111111111111",
        "INVALID",
        "Invalid Precision Token",
        0,  // Fungible
        9   // Invalid: exceeds max precision of 8
    );
    
    // Sign the transaction
    BOOST_CHECK(SignTransaction(mtx, coinbaseKey, coinbaseTx));
    
    // Convert to immutable transaction
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    
    // Submit to mempool - should be rejected by validation
    const auto res = AcceptToMemoryPool((m_node.chainman)->ActiveChainstate(), tx, GetTime(), false, /*test_accept=*/false);
    BOOST_CHECK(res.m_result_type != MempoolAcceptResult::ResultType::VALID);
    
    // Verify it's NOT in mempool
    BOOST_CHECK(!m_node.mempool->exists(tx->GetHash()));
}

BOOST_FIXTURE_TEST_CASE(nft_with_precision_rejected, TestChain100Setup) {
    CTxMemPool& pool = *Assert(m_node.mempool);
    LOCK2(::cs_main, pool.cs);
    // Create NFT with non-zero precision (invalid)
    CTransactionRef coinbaseTx = m_coinbase_txns[4];
    
    CMutableTransaction mtx = CreateAssetTransaction(
        coinbaseTx,
        "2222222222222222222222222222222222222222222222222222222222222222",
        "BADNFT",
        "NFT with Invalid Precision",
        1,  // Non-Fungible
        1   // Invalid: should be 0 for NFT
    );
    
    // Sign the transaction
    BOOST_CHECK(SignTransaction(mtx, coinbaseKey, coinbaseTx));
    
    // Convert to immutable transaction
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    
    // Submit to mempool - should be rejected by validation
    const auto res = AcceptToMemoryPool((m_node.chainman)->ActiveChainstate(), tx, GetTime(), false, /*test_accept=*/false);
    BOOST_CHECK(res.m_result_type != MempoolAcceptResult::ResultType::VALID);
}

BOOST_FIXTURE_TEST_CASE(asset_transaction_consensus_validation, TestChain100Setup) {
   // Create valid asset transaction
    mineBlocks(100);
    LOCK(cs_main);
    CTransactionRef coinbaseTx = m_coinbase_txns[5];
    
    CMutableTransaction mtx = CreateAssetTransaction(
        coinbaseTx,
        "3333333333333333333333333333333333333333333333333333333333333333",
        "SILVER",
        "Digital Silver Token",
        0,  // Fungible
        4   // 4 decimal precision
    );

    LogPrintf("tx details %i \n", mtx.vin.size());
    
    // Sign the transaction
    BOOST_CHECK(SignTransaction(mtx, coinbaseKey, coinbaseTx));

    
    
    CBlock block;
    block = CreateAndProcessBlock({mtx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

    BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() == block.GetHash());
}

BOOST_FIXTURE_TEST_CASE(multiple_asset_types_in_block, TestChain100Setup) {
    mineBlocks(100);
    std::vector<CTransactionRef> assetTxs;
    
    // Create fungible asset
    CMutableTransaction mtx1 = CreateAssetTransaction(
        m_coinbase_txns[6],
        "4444444444444444444444444444444444444444444444444444444444444444",
        "TOKEN1",
        "Test Token 1",
        0, 
        8
    );
    BOOST_CHECK(SignTransaction(mtx1, coinbaseKey, m_coinbase_txns[6]));

    // Create NFT
    CMutableTransaction mtx2 = CreateAssetTransaction(
        m_coinbase_txns[7],
        "5555555555555555555555555555555555555555555555555555555555555555",
        "NFT002",
        "Test NFT 2",
        1, 0
    );
    BOOST_CHECK(SignTransaction(mtx2, coinbaseKey, m_coinbase_txns[7]));
    
    // Create NFT Collection
    CMutableTransaction mtx3 = CreateAssetTransaction(
        m_coinbase_txns[8],
        "6666666666666666666666666666666666666666666666666666666666666666",
        "COL001",
        "Test Collection",
        2, 0
    );
    BOOST_CHECK(SignTransaction(mtx3, coinbaseKey, m_coinbase_txns[8]));
    
    CBlock block;
    block = CreateAndProcessBlock({mtx1, mtx2, mtx3}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    BOOST_CHECK(m_node.chainman->ActiveChain().Tip()->GetBlockHash() == block.GetHash());
}

BOOST_AUTO_TEST_SUITE_END()