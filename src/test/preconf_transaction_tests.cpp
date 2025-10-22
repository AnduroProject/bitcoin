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
#include <validation.h>

BOOST_FIXTURE_TEST_SUITE(preconf_transaction_tests, TestingSetup)

CMutableTransaction CreateNormalTransaction(
    const CTransactionRef& coinbaseTx
) {
    CMutableTransaction tx;
    
    // Set transaction version for asset transactions
    tx.version = 2;
    
    // Add input from coinbase transaction
    CTxIn txin(coinbaseTx->GetHash(), 0);
    tx.vin.push_back(txin);
    
    // Get the scriptPubKey from the coinbase output
    const CTxDestination coinbaseScript = DecodeDestination("ccrt1qhqr9plud3fk6zlnaf7thes7lyrj2r9qwww7alh");
    const CScript scriptPubKey = GetScriptForDestination(coinbaseScript);
    
    // Output 0: Supply output (zero value)
    CTxOut receiverOut(CAmount(5000000), scriptPubKey);
    tx.vout.push_back(receiverOut);
    
    // Output 1: Forward output (remaining BTC minus fee)
    CAmount fee = 1000;  // Transaction fee
    CAmount forwardAmount = coinbaseTx->vout[0].nValue - fee;
    CTxOut forwardOut(forwardAmount, scriptPubKey);
    tx.vout.push_back(forwardOut);
    
    return tx;
}

/**
 * Create an asset transaction using TestChain100Setup coins
 */
CMutableTransaction CreatePreconfTransaction(
    const CTransactionRef& coinbaseTx,
    const CAmount reserve,
    const CScript scriptPubKey
) {
    CMutableTransaction tx;
    
    // Set transaction version for asset transactions
    tx.version = TRANSACTION_PRECONF_VERSION;
    
    // Add input from coinbase transaction
    CTxIn txin(coinbaseTx->GetHash(), 0);
    tx.vin.push_back(txin);
    
    // Get the scriptPubKey from the coinbase output
    const CTxDestination coinbaseScript = DecodeDestination("ccrt1qhqr9plud3fk6zlnaf7thes7lyrj2r9qwww7alh");
    const CScript receiverPubKey = GetScriptForDestination(coinbaseScript);
    
    // Output 0: Controller output (zero value)
    CTxOut reserveOut(reserve, scriptPubKey);
    tx.vout.push_back(reserveOut);
    
    // Output 1: Supply output (zero value)
    CTxOut receiverOut(5000000, receiverPubKey);
    tx.vout.push_back(receiverOut);
    
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

BOOST_FIXTURE_TEST_CASE(create_preconf_transaction, TestChain100Setup) {
    LOCK(cs_main);
    CTransactionRef coinbaseTx = m_coinbase_txns[0];
    CScript scriptPubKey = GetScriptForRawPubKey(coinbaseKey.GetPubKey());

    CMutableTransaction mtx = CreatePreconfTransaction(
        coinbaseTx,
        CAmount(5),
        scriptPubKey
    );

    BOOST_CHECK(SignTransaction(mtx, coinbaseKey, coinbaseTx));

    // Convert to immutable transaction
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(tx, false , true);
    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
}

BOOST_FIXTURE_TEST_CASE(preconf_transaction_invalid_reserve, TestChain100Setup) {
    LOCK(cs_main);
    CTransactionRef coinbaseTx = m_coinbase_txns[0];
    CScript scriptPubKey = GetScriptForRawPubKey(coinbaseKey.GetPubKey());

    CMutableTransaction mtx = CreatePreconfTransaction(
        coinbaseTx,
        CAmount(4),
        scriptPubKey
    );

    BOOST_CHECK(SignTransaction(mtx, coinbaseKey, coinbaseTx));

    // Convert to immutable transaction
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(tx, false , true);
    BOOST_CHECK(result.m_result_type != MempoolAcceptResult::ResultType::VALID);
}


BOOST_FIXTURE_TEST_CASE(preconf_transaction_submit_normal_mempool, TestChain100Setup) {
    LOCK(cs_main);
    CTransactionRef coinbaseTx = m_coinbase_txns[0];
    CScript scriptPubKey = GetScriptForRawPubKey(coinbaseKey.GetPubKey());

    CMutableTransaction mtx = CreatePreconfTransaction(
        coinbaseTx,
        CAmount(5),
        scriptPubKey
    );

    BOOST_CHECK(SignTransaction(mtx, coinbaseKey, coinbaseTx));

    // Convert to immutable transaction
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(tx, false , false);
    BOOST_CHECK(result.m_result_type != MempoolAcceptResult::ResultType::VALID);
}

BOOST_FIXTURE_TEST_CASE(submit_normal_tx_preconf, TestChain100Setup) {
    LOCK(cs_main);
    CTransactionRef coinbaseTx = m_coinbase_txns[0];

    CMutableTransaction mtx = CreateNormalTransaction(
        coinbaseTx
    );

    BOOST_CHECK(SignTransaction(mtx, coinbaseKey, coinbaseTx));

    // Convert to immutable transaction
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(tx, false , true);
    BOOST_CHECK(result.m_result_type != MempoolAcceptResult::ResultType::VALID);
}

BOOST_AUTO_TEST_SUITE_END()