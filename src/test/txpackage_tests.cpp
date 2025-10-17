// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <key_io.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/random.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <test/util/txmempool.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

using namespace util::hex_literals;

// A fee amount that is above 1sat/vB but below 5sat/vB for most transactions created within these
// unit tests.
static const CAmount low_fee_amt{200};

struct TxPackageTest : TestChain100Setup {
// Create placeholder transactions that have no meaning.
inline CTransactionRef create_placeholder_tx(size_t num_inputs, size_t num_outputs)
{
    CMutableTransaction mtx = CMutableTransaction();
    mtx.vin.resize(num_inputs);
    mtx.vout.resize(num_outputs);
    auto random_script = CScript() << ToByteVector(m_rng.rand256()) << ToByteVector(m_rng.rand256());
    for (size_t i{0}; i < num_inputs; ++i) {
        mtx.vin[i].prevout.hash = Txid::FromUint256(m_rng.rand256());
        mtx.vin[i].prevout.n = 0;
        mtx.vin[i].scriptSig = random_script;
    }
    for (size_t o{0}; o < num_outputs; ++o) {
        mtx.vout[o].nValue = 1 * CENT;
        mtx.vout[o].scriptPubKey = random_script;
    }
    return MakeTransactionRef(mtx);
}
}; // struct TxPackageTest

BOOST_FIXTURE_TEST_SUITE(txpackage_tests, TxPackageTest)

BOOST_AUTO_TEST_CASE(package_hash_tests)
{
    // Random real segwit transaction
    DataStream stream_1{
        "020000000001018eee3117ad6619f59b5ffe82469fac06568b509d6589b08c0cff39f8bb374fb0000000000000fdffffff0200e1f505000000001600149cda0de94e384ca38c057124a489523b4d92637cc0ca4403000000001600141a0a0776e138371bb68034648589f2940fc7e43f0247304402204e96d50850737750de5bfbc797cdac06045657945dc487b5cb83233e77d40f19022010db62f9daa3eecabdb543c81d39636b71e77228f5dbfd3adc66e59b7ab8763101210263f7df4d9b8ba0035e28325e2643b762d97185ff147df713fc58dceb6746544fe8030000"_hex,
    };
    CTransaction tx_1(deserialize, TX_WITH_WITNESS, stream_1);
    CTransactionRef ptx_1{MakeTransactionRef(tx_1)};

    // It's easy to see that wtxids are sorted in lexicographical order:
    Wtxid wtxid_1{Wtxid::FromHex("9b085e188ed1a989d60e8d441ec8411ac8a6a80037e5401c4f60a5e5d6b05e84").value()};
    BOOST_CHECK_EQUAL(tx_1.GetWitnessHash(), wtxid_1);

    // The txids are not (we want to test that sorting and hashing use wtxid, not txid):
    Txid txid_1{Txid::FromHex("0f2e9924b1e175a5fc55d26f38b1d50a52380eebaa12c6484920a2c7f5065818").value()};
    BOOST_CHECK_EQUAL(tx_1.GetHash(), txid_1);

    BOOST_CHECK(txid_1.ToUint256() != wtxid_1.ToUint256());
}

BOOST_AUTO_TEST_CASE(package_sanitization_tests)
{
    // Packages can't have more than 25 transactions.
    Package package_too_many;
    package_too_many.reserve(MAX_PACKAGE_COUNT + 1);
    for (size_t i{0}; i < MAX_PACKAGE_COUNT + 1; ++i) {
        package_too_many.emplace_back(create_placeholder_tx(1, 1));
    }
    PackageValidationState state_too_many;
    BOOST_CHECK(!IsWellFormedPackage(package_too_many, state_too_many, /*require_sorted=*/true));
    BOOST_CHECK_EQUAL(state_too_many.GetResult(), PackageValidationResult::PCKG_POLICY);
    BOOST_CHECK_EQUAL(state_too_many.GetRejectReason(), "package-too-many-transactions");

    // Packages can't have a total weight of more than 404'000WU.
    CTransactionRef large_ptx = create_placeholder_tx(150, 150);
    Package package_too_large;
    auto size_large = GetTransactionWeight(*large_ptx);
    size_t total_weight{0};
    while (total_weight <= MAX_PACKAGE_WEIGHT) {
        package_too_large.push_back(large_ptx);
        total_weight += size_large;
    }
    BOOST_CHECK(package_too_large.size() <= MAX_PACKAGE_COUNT);
    PackageValidationState state_too_large;
    BOOST_CHECK(!IsWellFormedPackage(package_too_large, state_too_large, /*require_sorted=*/true));
    BOOST_CHECK_EQUAL(state_too_large.GetResult(), PackageValidationResult::PCKG_POLICY);
    BOOST_CHECK_EQUAL(state_too_large.GetRejectReason(), "package-too-large");

    // Packages can't contain transactions with the same txid.
    Package package_duplicate_txids_empty;
    for (auto i{0}; i < 3; ++i) {
        CMutableTransaction empty_tx;
        package_duplicate_txids_empty.emplace_back(MakeTransactionRef(empty_tx));
    }
    PackageValidationState state_duplicates;
    BOOST_CHECK(!IsWellFormedPackage(package_duplicate_txids_empty, state_duplicates, /*require_sorted=*/true));
    BOOST_CHECK_EQUAL(state_duplicates.GetResult(), PackageValidationResult::PCKG_POLICY);
    BOOST_CHECK_EQUAL(state_duplicates.GetRejectReason(), "package-contains-duplicates");
    BOOST_CHECK(!IsConsistentPackage(package_duplicate_txids_empty));

    // Packages can't have transactions spending the same prevout
    CMutableTransaction tx_zero_1;
    CMutableTransaction tx_zero_2;
    COutPoint same_prevout{Txid::FromUint256(m_rng.rand256()), 0};
    tx_zero_1.vin.emplace_back(same_prevout);
    tx_zero_2.vin.emplace_back(same_prevout);
    // Different vouts (not the same tx)
    tx_zero_1.vout.emplace_back(CENT, P2WSH_OP_TRUE);
    tx_zero_2.vout.emplace_back(2 * CENT, P2WSH_OP_TRUE);
    Package package_conflicts{MakeTransactionRef(tx_zero_1), MakeTransactionRef(tx_zero_2)};
    BOOST_CHECK(!IsConsistentPackage(package_conflicts));
    // Transactions are considered sorted when they have no dependencies.
    BOOST_CHECK(IsTopoSortedPackage(package_conflicts));
    PackageValidationState state_conflicts;
    BOOST_CHECK(!IsWellFormedPackage(package_conflicts, state_conflicts, /*require_sorted=*/true));
    BOOST_CHECK_EQUAL(state_conflicts.GetResult(), PackageValidationResult::PCKG_POLICY);
    BOOST_CHECK_EQUAL(state_conflicts.GetRejectReason(), "conflict-in-package");

    // IsConsistentPackage only cares about conflicts between transactions, not about a transaction
    // conflicting with itself (i.e. duplicate prevouts in vin).
    CMutableTransaction dup_tx;
    const COutPoint rand_prevout{Txid::FromUint256(m_rng.rand256()), 0};
    dup_tx.vin.emplace_back(rand_prevout);
    dup_tx.vin.emplace_back(rand_prevout);
    Package package_with_dup_tx{MakeTransactionRef(dup_tx)};
    BOOST_CHECK(IsConsistentPackage(package_with_dup_tx));
    package_with_dup_tx.emplace_back(create_placeholder_tx(1, 1));
    BOOST_CHECK(IsConsistentPackage(package_with_dup_tx));
}


BOOST_AUTO_TEST_SUITE_END()
