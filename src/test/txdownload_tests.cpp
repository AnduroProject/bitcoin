// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/validation.h>
#include <net_processing.h>
#include <node/txdownloadman_impl.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <array>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(txdownload_tests, TestingSetup)

struct Behaviors {
    bool m_txid_in_rejects;
    bool m_wtxid_in_rejects;
    bool m_txid_in_rejects_recon;
    bool m_wtxid_in_rejects_recon;
    bool m_keep_for_compact;
    bool m_ignore_inv_txid;
    bool m_ignore_inv_wtxid;

    // Constructor. We are passing and casting ints because they are more readable in a table (see expected_behaviors).
    Behaviors(bool txid_rejects, bool wtxid_rejects, bool txid_recon, bool wtxid_recon, bool keep, bool txid_inv, bool wtxid_inv) :
        m_txid_in_rejects(txid_rejects),
        m_wtxid_in_rejects(wtxid_rejects),
        m_txid_in_rejects_recon(txid_recon),
        m_wtxid_in_rejects_recon(wtxid_recon),
        m_keep_for_compact(keep),
        m_ignore_inv_txid(txid_inv),
        m_ignore_inv_wtxid(wtxid_inv)
    {}

    void CheckEqual(const Behaviors& other, bool segwit)
    {
        BOOST_CHECK_EQUAL(other.m_wtxid_in_rejects,       m_wtxid_in_rejects);
        BOOST_CHECK_EQUAL(other.m_wtxid_in_rejects_recon, m_wtxid_in_rejects_recon);
        BOOST_CHECK_EQUAL(other.m_keep_for_compact,       m_keep_for_compact);
        BOOST_CHECK_EQUAL(other.m_ignore_inv_wtxid,       m_ignore_inv_wtxid);

        // false negatives for nonsegwit transactions, since txid == wtxid.
        if (segwit) {
            BOOST_CHECK_EQUAL(other.m_txid_in_rejects,        m_txid_in_rejects);
            BOOST_CHECK_EQUAL(other.m_txid_in_rejects_recon,  m_txid_in_rejects_recon);
            BOOST_CHECK_EQUAL(other.m_ignore_inv_txid,        m_ignore_inv_txid);
        }
    }
};

// Map from failure reason to expected behavior for a segwit tx that fails
// Txid and Wtxid are assumed to be different here. For a nonsegwit transaction, use the wtxid results.
static std::map<TxValidationResult, Behaviors> expected_behaviors{
    {TxValidationResult::TX_CONSENSUS,               {/*txid_rejects*/0,/*wtxid_rejects*/1,/*txid_recon*/0,/*wtxid_recon*/0,/*keep*/1,/*txid_inv*/0,/*wtxid_inv*/1}},
    {TxValidationResult::TX_INPUTS_NOT_STANDARD,     {                1,                 1,              0,               0,        1,            1,             1}},
    {TxValidationResult::TX_NOT_STANDARD,            {                0,                 1,              0,               0,        1,            0,             1}},
    {TxValidationResult::TX_MISSING_INPUTS,          {                0,                 0,              0,               0,        1,            0,             1}},
    {TxValidationResult::TX_PREMATURE_SPEND,         {                0,                 1,              0,               0,        1,            0,             1}},
    {TxValidationResult::TX_WITNESS_MUTATED,         {                0,                 1,              0,               0,        1,            0,             1}},
    {TxValidationResult::TX_WITNESS_STRIPPED,        {                0,                 0,              0,               0,        0,            0,             0}},
    {TxValidationResult::TX_CONFLICT,                {                0,                 1,              0,               0,        1,            0,             1}},
    {TxValidationResult::TX_MEMPOOL_POLICY,          {                0,                 1,              0,               0,        1,            0,             1}},
    {TxValidationResult::TX_NO_MEMPOOL,              {                0,                 1,              0,               0,        1,            0,             1}},
    {TxValidationResult::TX_RECONSIDERABLE,          {                0,                 0,              0,               1,        1,            0,             1}},
    {TxValidationResult::TX_UNKNOWN,                 {                0,                 1,              0,               0,        1,            0,             1}},
};

static bool CheckOrphanBehavior(node::TxDownloadManagerImpl& txdownload_impl, const CTransactionRef& tx, const node::RejectedTxTodo& ret, std::string& err_msg,
                                bool expect_orphan, bool expect_keep, unsigned int expected_parents)
{
    // Missing inputs can never result in a PackageToValidate.
    if (ret.m_package_to_validate.has_value()) {
        err_msg = strprintf("returned a PackageToValidate on missing inputs");
        return false;
    }

    if (expect_orphan != txdownload_impl.m_orphanage->HaveTx(tx->GetWitnessHash())) {
        err_msg = strprintf("unexpectedly %s tx in orphanage", expect_orphan ? "did not find" : "found");
        return false;
    }
    if (expect_keep != ret.m_should_add_extra_compact_tx) {
        err_msg = strprintf("unexpectedly returned %s add to vExtraTxnForCompact", expect_keep ? "should not" : "should");
        return false;
    }
    if (expected_parents != ret.m_unique_parents.size()) {
        err_msg = strprintf("expected %u unique_parents, got %u", expected_parents, ret.m_unique_parents.size());
        return false;
    }
    return true;
}

static CTransactionRef CreatePlaceholderTx(bool segwit)
{
    // Each tx returned from here spends the previous one.
    static Txid prevout_hash{};

    CMutableTransaction mtx;
    mtx.vin.emplace_back(prevout_hash, 0);
    // This makes txid != wtxid
    if (segwit) mtx.vin[0].scriptWitness.stack.push_back({1});
    mtx.vout.emplace_back(CENT, CScript());
    auto ptx = MakeTransactionRef(mtx);
    prevout_hash = ptx->GetHash();
    return ptx;
}

BOOST_FIXTURE_TEST_CASE(tx_rejection_types, TestChain100Setup)
{
    CTxMemPool& pool = *Assert(m_node.mempool);
    CTxMemPool& preconfmempool = *Assert(m_node.preconfmempool);
    FastRandomContext det_rand{true};
    node::TxDownloadOptions DEFAULT_OPTS{pool, preconfmempool, det_rand, true};

    // A new TxDownloadManagerImpl is created for each tx so we can just reuse the same one.
    TxValidationState state;
    NodeId nodeid{0};
    std::chrono::microseconds now{GetTime()};
    node::TxDownloadConnectionInfo connection_info{/*m_preferred=*/false, /*m_relay_permissions=*/false, /*m_wtxid_relay=*/true};

    for (const auto segwit_parent : {true, false}) {
        for (const auto segwit_child : {true, false}) {
            const auto ptx_parent = CreatePlaceholderTx(segwit_parent);
            const auto ptx_child = CreatePlaceholderTx(segwit_child);
            const auto& parent_txid = ptx_parent->GetHash();
            const auto& parent_wtxid = ptx_parent->GetWitnessHash();
            const auto& child_txid = ptx_child->GetHash();
            const auto& child_wtxid = ptx_child->GetWitnessHash();

            for (const auto& [result, expected_behavior] : expected_behaviors) {
                node::TxDownloadManagerImpl txdownload_impl{DEFAULT_OPTS};
                txdownload_impl.ConnectedPeer(nodeid, connection_info);
                // Parent failure
                state.Invalid(result, "");
                const auto& [keep, unique_txids, package_to_validate] = txdownload_impl.MempoolRejectedTx(ptx_parent, state, nodeid, /*first_time_failure=*/true);

                // No distinction between txid and wtxid caching for nonsegwit transactions, so only test these specific
                // behaviors for segwit transactions.
                Behaviors actual_behavior{
                    /*txid_rejects=*/txdownload_impl.RecentRejectsFilter().contains(parent_txid.ToUint256()),
                    /*wtxid_rejects=*/txdownload_impl.RecentRejectsFilter().contains(parent_wtxid.ToUint256()),
                    /*txid_recon=*/txdownload_impl.RecentRejectsReconsiderableFilter().contains(parent_txid.ToUint256()),
                    /*wtxid_recon=*/txdownload_impl.RecentRejectsReconsiderableFilter().contains(parent_wtxid.ToUint256()),
                    /*keep=*/keep,
                    /*txid_inv=*/txdownload_impl.AddTxAnnouncement(nodeid, parent_txid, now),
                    /*wtxid_inv=*/txdownload_impl.AddTxAnnouncement(nodeid, parent_wtxid, now),
                };
                BOOST_TEST_MESSAGE("Testing behavior for " << result << (segwit_parent ? " segwit " : " nonsegwit"));
                actual_behavior.CheckEqual(expected_behavior, /*segwit=*/segwit_parent);

                // Later, a child of this transaction fails for missing inputs
                state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "");
                txdownload_impl.MempoolRejectedTx(ptx_child, state, nodeid, /*first_time_failure=*/true);

                // If parent (by txid) was rejected, child is too.
                const bool parent_txid_rejected{segwit_parent ? expected_behavior.m_txid_in_rejects : expected_behavior.m_wtxid_in_rejects};
                BOOST_CHECK_EQUAL(parent_txid_rejected, txdownload_impl.RecentRejectsFilter().contains(child_txid.ToUint256()));
                BOOST_CHECK_EQUAL(parent_txid_rejected, txdownload_impl.RecentRejectsFilter().contains(child_wtxid.ToUint256()));

                // Unless rejected, the child should be in orphanage.
                BOOST_CHECK_EQUAL(!parent_txid_rejected, txdownload_impl.m_orphanage->HaveTx(ptx_child->GetWitnessHash()));
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
