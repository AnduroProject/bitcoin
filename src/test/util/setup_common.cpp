// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>

#include <addrman.h>
#include <banman.h>
#include <chainparams.h>
#include <common/system.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <init.h>
#include <init/common.h>
#include <interfaces/chain.h>
#include <kernel/mempool_entry.h>
#include <logging.h>
#include <net.h>
#include <net_processing.h>
#include <node/blockstorage.h>
#include <node/chainstate.h>
#include <node/context.h>
#include <node/kernel_notifications.h>
#include <node/mempool_args.h>
#include <node/miner.h>
#include <node/peerman_args.h>
#include <node/warnings.h>
#include <noui.h>
#include <policy/fees.h>
#include <pow.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <rpc/register.h>
#include <rpc/server.h>
#include <scheduler.h>
#include <script/sigcache.h>
#include <streams.h>
#include <test/util/coverage.h>
#include <test/util/net.h>
#include <test/util/random.h>
#include <test/util/txmempool.h>
#include <txdb.h>
#include <txmempool.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <util/fs_helpers.h>
#include <util/rbf.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/task_runner.h>
#include <util/thread.h>
#include <util/threadnames.h>
#include <util/time.h>
#include <util/translation.h>
#include <util/vector.h>
#include <validation.h>
#include <validationinterface.h>
#include <walletinitinterface.h>

#include <algorithm>
#include <future>
#include <functional>
#include <stdexcept>

using namespace util::hex_literals;
using node::ApplyArgsManOptions;
using node::BlockAssembler;
using node::BlockManager;
using node::KernelNotifications;
using node::LoadChainstate;
using node::RegenerateCommitments;
using node::VerifyLoadedChainstate;

const TranslateFn G_TRANSLATION_FUN{nullptr};

constexpr inline auto TEST_DIR_PATH_ELEMENT{"test_common bitcoin"}; // Includes a space to catch possible path escape issues.
/** Random context to get unique temp data dirs. Separate from m_rng, which can be seeded from a const env var */
static FastRandomContext g_rng_temp_path;
static const bool g_rng_temp_path_init{[] {
    // Must be initialized before any SeedRandomForTest
    Assert(!g_used_g_prng);
    (void)g_rng_temp_path.rand64();
    g_used_g_prng = false;
    ResetCoverageCounters(); // The seed strengthen in SeedStartup is not deterministic, so exclude it from coverage counts
    return true;
}()};

struct NetworkSetup
{
    NetworkSetup()
    {
        Assert(SetupNetworking());
    }
};
static NetworkSetup g_networksetup_instance;

void SetupCommonTestArgs(ArgsManager& argsman)
{
    argsman.AddArg("-testdatadir", strprintf("Custom data directory (default: %s<random_string>)", fs::PathToString(fs::temp_directory_path() / TEST_DIR_PATH_ELEMENT / "")),
                   ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
}

/** Test setup failure */
static void ExitFailure(std::string_view str_err)
{
    std::cerr << str_err << std::endl;
    exit(EXIT_FAILURE);
}

BasicTestingSetup::BasicTestingSetup(const ChainType chainType, TestOpts opts)
    : m_args{}
{
    if (!EnableFuzzDeterminism()) {
        SeedRandomForTest(SeedRand::FIXED_SEED);
    }
    m_node.shutdown_signal = &m_interrupt;
    m_node.shutdown_request = [this]{ return m_interrupt(); };
    m_node.args = &gArgs;
    std::vector<const char*> arguments = Cat(
        {
            "dummy",
            "-printtoconsole=0",
            "-logsourcelocations",
            "-logtimemicros",
            "-logthreadnames",
            "-loglevel=trace",
            "-debug",
            "-debugexclude=libevent",
            "-debugexclude=leveldb",
        },
        opts.extra_args);
    if (G_TEST_COMMAND_LINE_ARGUMENTS) {
        arguments = Cat(arguments, G_TEST_COMMAND_LINE_ARGUMENTS());
    }
    util::ThreadRename("test");
    gArgs.ClearPathCache();
    {
        SetupServerArgs(*m_node.args);
        SetupCommonTestArgs(*m_node.args);
        std::string error;
        if (!m_node.args->ParseParameters(arguments.size(), arguments.data(), error)) {
            m_node.args->ClearArgs();
            throw std::runtime_error{error};
        }
    }

    const std::string test_name{G_TEST_GET_FULL_NAME ? G_TEST_GET_FULL_NAME() : ""};
    if (!m_node.args->IsArgSet("-testdatadir")) {
        // To avoid colliding with a leftover prior datadir, and to allow
        // tests, such as the fuzz tests to run in several processes at the
        // same time, add a random element to the path. Keep it small enough to
        // avoid a MAX_PATH violation on Windows.
        const auto rand{HexStr(g_rng_temp_path.randbytes(10))};
        m_path_root = fs::temp_directory_path() / TEST_DIR_PATH_ELEMENT / test_name / rand;
        TryCreateDirectories(m_path_root);
    } else {
        // Custom data directory
        m_has_custom_datadir = true;
        fs::path root_dir{m_node.args->GetPathArg("-testdatadir")};
        if (root_dir.empty()) ExitFailure("-testdatadir argument is empty, please specify a path");

        root_dir = fs::absolute(root_dir);
        m_path_lock = root_dir / TEST_DIR_PATH_ELEMENT / fs::PathFromString(test_name);
        m_path_root = m_path_lock / "datadir";

        // Try to obtain the lock; if unsuccessful don't disturb the existing test.
        TryCreateDirectories(m_path_lock);
        if (util::LockDirectory(m_path_lock, ".lock", /*probe_only=*/false) != util::LockResult::Success) {
            ExitFailure("Cannot obtain a lock on test data lock directory " + fs::PathToString(m_path_lock) + '\n' + "The test executable is probably already running.");
        }

        // Always start with a fresh data directory; this doesn't delete the .lock file located one level above.
        fs::remove_all(m_path_root);
        if (!TryCreateDirectories(m_path_root)) ExitFailure("Cannot create test data directory");

        // Print the test directory name if custom.
        std::cout << "Test directory (will not be deleted): " << m_path_root << std::endl;
    }
    m_args.ForceSetArg("-datadir", fs::PathToString(m_path_root));
    gArgs.ForceSetArg("-datadir", fs::PathToString(m_path_root));

    SelectParams(chainType);
    if (G_TEST_LOG_FUN) LogInstance().PushBackCallback(G_TEST_LOG_FUN);
    InitLogging(*m_node.args);
    AppInitParameterInteraction(*m_node.args);
    LogInstance().StartLogging();
    m_node.warnings = std::make_unique<node::Warnings>();
    m_node.kernel = std::make_unique<kernel::Context>();
    m_node.ecc_context = std::make_unique<ECC_Context>();
    SetupEnvironment();

    m_node.chain = interfaces::MakeChain(m_node);
    static bool noui_connected = false;
    if (!noui_connected) {
        noui_connect();
        noui_connected = true;
    }
}

BasicTestingSetup::~BasicTestingSetup()
{
    m_node.ecc_context.reset();
    m_node.kernel.reset();
    if (!EnableFuzzDeterminism()) {
        SetMockTime(0s); // Reset mocktime for following tests
    }
    LogInstance().DisconnectTestLogger();
    if (m_has_custom_datadir) {
        // Only remove the lock file, preserve the data directory.
        UnlockDirectory(m_path_lock, ".lock");
        fs::remove(m_path_lock / ".lock");
    } else {
        fs::remove_all(m_path_root);
    }
    gArgs.ClearArgs();
}

ChainTestingSetup::ChainTestingSetup(const ChainType chainType, TestOpts opts)
    : BasicTestingSetup(chainType, opts)
{
    const CChainParams& chainparams = Params();

    // A task runner is required to prevent ActivateBestChain
    // from blocking due to queue overrun.
    if (opts.setup_validation_interface) {
        m_node.scheduler = std::make_unique<CScheduler>();
        m_node.scheduler->m_service_thread = std::thread(util::TraceThread, "scheduler", [&] { m_node.scheduler->serviceQueue(); });
        m_node.validation_signals =
            // Use synchronous task runner while fuzzing to avoid non-determinism
            EnableFuzzDeterminism() ?
                std::make_unique<ValidationSignals>(std::make_unique<util::ImmediateTaskRunner>()) :
                std::make_unique<ValidationSignals>(std::make_unique<SerialTaskRunner>(*m_node.scheduler));
        {
            // Ensure deterministic coverage by waiting for m_service_thread to be running
            std::promise<void> promise;
            m_node.scheduler->scheduleFromNow([&promise] { promise.set_value(); }, 0ms);
            promise.get_future().wait();
        }
    }

    bilingual_str error{};

    m_node.mempool = std::make_unique<CTxMemPool>(MemPoolOptionsForTest(m_node), error);
    CTxMemPool::Options mempool_opts = MemPoolOptionsForTest(m_node);
    mempool_opts.is_preconf = true;
    mempool_opts.limits.ancestor_count = 0;
    mempool_opts.limits.descendant_count = 0;
    m_node.preconfmempool = std::make_unique<CTxMemPool>(mempool_opts, error);
    Assert(error.empty());
    m_node.warnings = std::make_unique<node::Warnings>();

    m_node.notifications = std::make_unique<KernelNotifications>(Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings));

    m_make_chainman = [this, &chainparams, opts] {
        Assert(!m_node.chainman);
        ChainstateManager::Options chainman_opts{
            .chainparams = chainparams,
            .datadir = m_args.GetDataDirNet(),
            .check_block_index = 1,
            .notifications = *m_node.notifications,
            .signals = m_node.validation_signals.get(),
            // Use no worker threads while fuzzing to avoid non-determinism
            .worker_threads_num = EnableFuzzDeterminism() ? 0 : 2,
        };
        if (opts.min_validation_cache) {
            chainman_opts.script_execution_cache_bytes = 0;
            chainman_opts.signature_cache_bytes = 0;
        }
        const BlockManager::Options blockman_opts{
            .chainparams = chainman_opts.chainparams,
            .blocks_dir = m_args.GetBlocksDirPath(),
            .notifications = chainman_opts.notifications,
            .block_tree_db_params = DBParams{
                .path = m_args.GetDataDirNet() / "blocks" / "index",
                .cache_bytes = m_kernel_cache_sizes.block_tree_db,
                .memory_only = opts.block_tree_db_in_memory,
                .wipe_data = m_args.GetBoolArg("-reindex", false),
            },
        };
        m_node.chainman = std::make_unique<ChainstateManager>(*Assert(m_node.shutdown_signal), chainman_opts, blockman_opts);
    };
    m_make_chainman();
}

ChainTestingSetup::~ChainTestingSetup()
{
    if (m_node.scheduler) m_node.scheduler->stop();
    if (m_node.validation_signals) m_node.validation_signals->FlushBackgroundCallbacks();
    m_node.connman.reset();
    m_node.banman.reset();
    m_node.addrman.reset();
    m_node.netgroupman.reset();
    m_node.args = nullptr;
    m_node.mempool.reset();
    Assert(!m_node.fee_estimator); // Each test must create a local object, if they wish to use the fee_estimator
    m_node.chainman.reset();
    m_node.validation_signals.reset();
    m_node.scheduler.reset();
}

void ChainTestingSetup::LoadVerifyActivateChainstate()
{
    auto& chainman{*Assert(m_node.chainman)};
    node::ChainstateLoadOptions options;
    options.mempool = Assert(m_node.mempool.get());
    options.coins_db_in_memory = m_coins_db_in_memory;
    options.wipe_chainstate_db = m_args.GetBoolArg("-reindex", false) || m_args.GetBoolArg("-reindex-chainstate", false);
    options.prune = chainman.m_blockman.IsPruneMode();
    options.check_blocks = m_args.GetIntArg("-checkblocks", DEFAULT_CHECKBLOCKS);
    options.check_level = m_args.GetIntArg("-checklevel", DEFAULT_CHECKLEVEL);
    options.require_full_verification = m_args.IsArgSet("-checkblocks") || m_args.IsArgSet("-checklevel");
    auto [status, error] = LoadChainstate(chainman, m_kernel_cache_sizes, options);
    assert(status == node::ChainstateLoadStatus::SUCCESS);

    std::tie(status, error) = VerifyLoadedChainstate(chainman, options);
    assert(status == node::ChainstateLoadStatus::SUCCESS);

    BlockValidationState state;
    if (!chainman.ActiveChainstate().ActivateBestChain(state)) {
        throw std::runtime_error(strprintf("ActivateBestChain failed. (%s)", state.ToString()));
    }
}

TestingSetup::TestingSetup(
    const ChainType chainType,
    TestOpts opts)
    : ChainTestingSetup(chainType, opts)
{
    m_coins_db_in_memory = opts.coins_db_in_memory;
    m_block_tree_db_in_memory = opts.block_tree_db_in_memory;
    // Ideally we'd move all the RPC tests to the functional testing framework
    // instead of unit tests, but for now we need these here.
    RegisterAllCoreRPCCommands(tableRPC);

    LoadVerifyActivateChainstate();

    if (!opts.setup_net) return;

    m_node.netgroupman = std::make_unique<NetGroupManager>(/*asmap=*/std::vector<bool>());
    m_node.addrman = std::make_unique<AddrMan>(*m_node.netgroupman,
                                               /*deterministic=*/false,
                                               m_node.args->GetIntArg("-checkaddrman", 0));
    m_node.banman = std::make_unique<BanMan>(m_args.GetDataDirBase() / "banlist", nullptr, DEFAULT_MISBEHAVING_BANTIME);
    m_node.connman = std::make_unique<ConnmanTestMsg>(0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman, Params()); // Deterministic randomness for tests.
    PeerManager::Options peerman_opts;
    ApplyArgsManOptions(*m_node.args, peerman_opts);
    peerman_opts.deterministic_rng = true;
    m_node.peerman = PeerManager::make(*m_node.connman, *m_node.addrman,
                                       m_node.banman.get(), *m_node.chainman,
                                       *m_node.mempool, *m_node.preconfmempool, *m_node.warnings,
                                       peerman_opts);

    {
        CConnman::Options options;
        options.m_msgproc = m_node.peerman.get();
        m_node.connman->Init(options);
    }
}

TestChain100Setup::TestChain100Setup(
    const ChainType chain_type,
    TestOpts opts)
    : TestingSetup{ChainType::REGTEST, opts}
{
    SetMockTime(1598887952);
    constexpr std::array<unsigned char, 32> vchKey = {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
    coinbaseKey.Set(vchKey.begin(), vchKey.end(), true);

    // Generate a 100-block chain:
    this->mineBlocks(COINBASE_MATURITY);

    {
        LOCK(::cs_main);
        assert(
            m_node.chainman->ActiveChain().Tip()->GetBlockHash().ToString() ==
            "fe56f6334b8b5060eec94c7f93bc4f5e559f350915d3758e69843df2c2a0fa1a");
    }
}

void TestChain100Setup::mineBlocks(int num_blocks)
{
    CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    for (int i = 0; i < num_blocks; i++) {
        std::vector<CMutableTransaction> noTxns;
        CBlock b = CreateAndProcessBlock(noTxns, scriptPubKey);
        SetMockTime(GetTime() + 10);
        m_coinbase_txns.push_back(b.vtx[0]);
    }
}

CBlock TestChain100Setup::CreateBlock(
    const std::vector<CMutableTransaction>& txns,
    const CScript& scriptPubKey,
    Chainstate& chainstate)
{
    BlockAssembler::Options options;
    options.coinbase_output_script = scriptPubKey;
    CBlock block = BlockAssembler{chainstate, nullptr, options}.CreateNewBlock()->block;
    auto& miningHeader = CAuxPow::initAuxPow(block);
    Assert(block.vtx.size() == 1);
    for (const CMutableTransaction& tx : txns) {
        block.vtx.push_back(MakeTransactionRef(tx));
    }
    RegenerateCommitments(block, *Assert(m_node.chainman));

    while (!CheckProofOfWork(miningHeader.GetHash(), block.nBits, m_node.chainman->GetConsensus())) ++miningHeader.nNonce;

    return block;
}

CBlock TestChain100Setup::CreateAndProcessBlock(
    const std::vector<CMutableTransaction>& txns,
    const CScript& scriptPubKey,
    Chainstate* chainstate)
{
    if (!chainstate) {
        chainstate = &Assert(m_node.chainman)->ActiveChainstate();
    }

    CBlock block = this->CreateBlock(txns, scriptPubKey, *chainstate);
    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(block);
    Assert(m_node.chainman)->ProcessNewBlock(shared_pblock, true, true, nullptr);

    return block;
}

std::pair<CMutableTransaction, CAmount> TestChain100Setup::CreateValidTransaction(const std::vector<CTransactionRef>& input_transactions,
                                                                                  const std::vector<COutPoint>& inputs,
                                                                                  int input_height,
                                                                                  const std::vector<CKey>& input_signing_keys,
                                                                                  const std::vector<CTxOut>& outputs,
                                                                                  const std::optional<CFeeRate>& feerate,
                                                                                  const std::optional<uint32_t>& fee_output)
{
    CMutableTransaction mempool_txn;
    mempool_txn.vin.reserve(inputs.size());
    mempool_txn.vout.reserve(outputs.size());

    for (const auto& outpoint : inputs) {
        mempool_txn.vin.emplace_back(outpoint, CScript(), MAX_BIP125_RBF_SEQUENCE);
    }
    mempool_txn.vout = outputs;

    // - Add the signing key to a keystore
    FillableSigningProvider keystore;
    for (const auto& input_signing_key : input_signing_keys) {
        keystore.AddKey(input_signing_key);
    }
    // - Populate a CoinsViewCache with the unspent output
    CCoinsView coins_view;
    CCoinsViewCache coins_cache(&coins_view);
    for (const auto& input_transaction : input_transactions) {
        AddCoins(coins_cache, *input_transaction.get(), input_height);
    }
    // Build Outpoint to Coin map for SignTransaction
    std::map<COutPoint, Coin> input_coins;
    CAmount inputs_amount{0};
    for (const auto& outpoint_to_spend : inputs) {
        // Use GetCoin to properly populate utxo_to_spend
        auto utxo_to_spend{coins_cache.GetCoin(outpoint_to_spend).value()};
        input_coins.insert({outpoint_to_spend, utxo_to_spend});
        inputs_amount += utxo_to_spend.out.nValue;
    }
    // - Default signature hashing type
    int nHashType = SIGHASH_ALL;
    std::map<int, bilingual_str> input_errors;
    assert(SignTransaction(mempool_txn, &keystore, input_coins, nHashType, input_errors));
    CAmount current_fee = inputs_amount - std::accumulate(outputs.begin(), outputs.end(), CAmount(0),
        [](const CAmount& acc, const CTxOut& out) {
        return acc + out.nValue;
    });
    // Deduct fees from fee_output to meet feerate if set
    if (feerate.has_value()) {
        assert(fee_output.has_value());
        assert(fee_output.value() < mempool_txn.vout.size());
        CAmount target_fee = feerate.value().GetFee(GetVirtualTransactionSize(CTransaction{mempool_txn}));
        CAmount deduction = target_fee - current_fee;
        if (deduction > 0) {
            // Only deduct fee if there's anything to deduct. If the caller has put more fees than
            // the target feerate, don't change the fee.
            mempool_txn.vout[fee_output.value()].nValue -= deduction;
            // Re-sign since an output has changed
            input_errors.clear();
            assert(SignTransaction(mempool_txn, &keystore, input_coins, nHashType, input_errors));
            current_fee = target_fee;
        }
    }
    return {mempool_txn, current_fee};
}

CMutableTransaction TestChain100Setup::CreateValidMempoolTransaction(const std::vector<CTransactionRef>& input_transactions,
                                                                     const std::vector<COutPoint>& inputs,
                                                                     int input_height,
                                                                     const std::vector<CKey>& input_signing_keys,
                                                                     const std::vector<CTxOut>& outputs,
                                                                     bool submit)
{
    CMutableTransaction mempool_txn = CreateValidTransaction(input_transactions, inputs, input_height, input_signing_keys, outputs, std::nullopt, std::nullopt).first;
    // If submit=true, add transaction to the mempool.
    if (submit) {
        LOCK(cs_main);
        const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(MakeTransactionRef(mempool_txn));
        assert(result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    }
    return mempool_txn;
}

CMutableTransaction TestChain100Setup::CreateValidMempoolTransaction(CTransactionRef input_transaction,
                                                                     uint32_t input_vout,
                                                                     int input_height,
                                                                     CKey input_signing_key,
                                                                     CScript output_destination,
                                                                     CAmount output_amount,
                                                                     bool submit)
{
    COutPoint input{input_transaction->GetHash(), input_vout};
    CTxOut output{output_amount, output_destination};
    return CreateValidMempoolTransaction(/*input_transactions=*/{input_transaction},
                                         /*inputs=*/{input},
                                         /*input_height=*/input_height,
                                         /*input_signing_keys=*/{input_signing_key},
                                         /*outputs=*/{output},
                                         /*submit=*/submit);
}

std::vector<CTransactionRef> TestChain100Setup::PopulateMempool(FastRandomContext& det_rand, size_t num_transactions, bool submit)
{
    std::vector<CTransactionRef> mempool_transactions;
    std::deque<std::pair<COutPoint, CAmount>> unspent_prevouts;
    std::transform(m_coinbase_txns.begin(), m_coinbase_txns.end(), std::back_inserter(unspent_prevouts),
        [](const auto& tx){ return std::make_pair(COutPoint(tx->GetHash(), 0), tx->vout[0].nValue); });
    while (num_transactions > 0 && !unspent_prevouts.empty()) {
        // The number of inputs and outputs are random, between 1 and 24.
        CMutableTransaction mtx = CMutableTransaction();
        const size_t num_inputs = det_rand.randrange(24) + 1;
        CAmount total_in{0};
        for (size_t n{0}; n < num_inputs; ++n) {
            if (unspent_prevouts.empty()) break;
            const auto& [prevout, amount] = unspent_prevouts.front();
            mtx.vin.emplace_back(prevout, CScript());
            total_in += amount;
            unspent_prevouts.pop_front();
        }
        const size_t num_outputs = det_rand.randrange(24) + 1;
        const CAmount fee = 100 * det_rand.randrange(30);
        const CAmount amount_per_output = (total_in - fee) / num_outputs;
        for (size_t n{0}; n < num_outputs; ++n) {
            CScript spk = CScript() << CScriptNum(num_transactions + n);
            mtx.vout.emplace_back(amount_per_output, spk);
        }
        CTransactionRef ptx = MakeTransactionRef(mtx);
        mempool_transactions.push_back(ptx);
        if (amount_per_output > 3000) {
            // If the value is high enough to fund another transaction + fees, keep track of it so
            // it can be used to build a more complex transaction graph. Insert randomly into
            // unspent_prevouts for extra randomness in the resulting structures.
            for (size_t n{0}; n < num_outputs; ++n) {
                unspent_prevouts.emplace_back(COutPoint(ptx->GetHash(), n), amount_per_output);
                std::swap(unspent_prevouts.back(), unspent_prevouts[det_rand.randrange(unspent_prevouts.size())]);
            }
        }
        if (submit) {
            LOCK2(cs_main, m_node.mempool->cs);
            LockPoints lp;
            auto changeset = m_node.mempool->GetChangeSet();
            changeset->StageAddition(ptx, /*fee=*/(total_in - num_outputs * amount_per_output),
                    /*time=*/0, /*entry_height=*/1, /*entry_sequence=*/0,
                    /*spends_coinbase=*/false, /*sigops_cost=*/4, lp);
            changeset->Apply();
        }
        --num_transactions;
    }
    return mempool_transactions;
}

void TestChain100Setup::MockMempoolMinFee(const CFeeRate& target_feerate)
{
    LOCK2(cs_main, m_node.mempool->cs);
    // Transactions in the mempool will affect the new minimum feerate.
    assert(m_node.mempool->size() == 0);
    // The target feerate cannot be too low...
    // ...otherwise the transaction's feerate will need to be negative.
    assert(target_feerate > m_node.mempool->m_opts.incremental_relay_feerate);
    // ...otherwise this is not meaningful. The feerate policy uses the maximum of both feerates.
    assert(target_feerate > m_node.mempool->m_opts.min_relay_feerate);

    // Manually create an invalid transaction. Manually set the fee in the CTxMemPoolEntry to
    // achieve the exact target feerate.
    CMutableTransaction mtx = CMutableTransaction();
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(m_rng.rand256()), 0});
    mtx.vout.emplace_back(1 * COIN, GetScriptForDestination(WitnessV0ScriptHash(CScript() << OP_TRUE)));
    const auto tx{MakeTransactionRef(mtx)};
    LockPoints lp;
    // The new mempool min feerate is equal to the removed package's feerate + incremental feerate.
    const auto tx_fee = target_feerate.GetFee(GetVirtualTransactionSize(*tx)) -
        m_node.mempool->m_opts.incremental_relay_feerate.GetFee(GetVirtualTransactionSize(*tx));
    {
        auto changeset = m_node.mempool->GetChangeSet();
        changeset->StageAddition(tx, /*fee=*/tx_fee,
                /*time=*/0, /*entry_height=*/1, /*entry_sequence=*/0,
                /*spends_coinbase=*/true, /*sigops_cost=*/1, lp);
        changeset->Apply();
    }
    m_node.mempool->TrimToSize(0);
    assert(m_node.mempool->GetMinFee() == target_feerate);
}
/**
 * @returns a real block (0000000000013b8ab2cd513b0261a14096412195a72a0c4827d229dcc7e0f7af)
 *      with 9 txs.
 */
CBlock getBlock13b8a()
{
    CBlock block;
    DataStream stream{
        "04012222cdf789bda6e1737d3547005ee4b71cb7e62dd6538cc8e7e6155c6e5885ee1cd0beb75dd1781683b65c28a2e18fa589788a90384ee71e0a3c126b1e5428ad52a98f2fc068ffff7f200000000002000000010000000000000000000000000000000000000000000000000000000000000000ffffffff29281bce86e6fe02defd0e6b491f1a3137658be99a9cd4e611de801471dabd1197d60100000000000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000005d886499db05e055438f44e2c3c91aa4ef22f7642370324c83467aa0b4628b2e00000000000000000100000013020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402b07900feffffff030000000000000000160014d78ef1ecf1e10b553366604ecfac4b5d531173ff00000000000000001600143026ae73710e0bd2eb5d86c2853c9dbcc80f5c930000000000000000266a24aa21a9edb0650bad2e5738ca7b426510c988fe0808860890de8622155640952898d9a0de01200000000000000000000000000000000000000000000000000000000000000000af79000002000000000101a00b24434a600557bc23121d63c0e28eec9ed3bd96d54aca42e0bd54379e15f90000000000fdffffff0200e1f5050000000016001453a6bfc3aaab7f21a65cf766b027942048b007da7028830200000000160014ed2b9ea7edaa466d9c0adc3ea145aed922d75e5602463043021f786417caf93ac4f4ca873c8007ecc2734ea36e180c671f1db84853dcf47e680220765e29d86a4f3491a446ac6613a771e8474a5bfd6a992ce126d8a711f19c3e12012103db2a6bf105f56d30dfc8ae1d512066877993f17504fb1716e91c7d1cdda9f2d3af7900000200000000010167fc3d555f452de180b0ba9128564bfe6646cdd73328c3b770c53aefdde8aab10000000000fdffffff02e0ea382301000000160014af83553aca7aeb0ac92fc01f10db3ae00c5f03de00e1f5050000000016001453a6bfc3aaab7f21a65cf766b027942048b007da02473044022060960e16639de5cbe640accdf270d55fdd3f01eda95ee5311891bd680a9ca7ee02207da30e6e02213656c47357070ae1f9a7c089eea5e2608136a54e57ea995358e2012102f783a1a34afe12bbfa25dfb586f67458205e9903ca8834966ec8df6e4db9e7a8af79000002000000000101f04f5759149cec0a8e7b8a225194b9bea5e481848ac58a7a142fa7bf403e93f00000000000fdffffff0200e1f5050000000016001453a6bfc3aaab7f21a65cf766b027942048b007dae0ea38230100000016001405f0b1e132955f32f11ab663a908b87f4f5593fb02473044022045f38e696e3f6699c398de1ed122ad761c812f8077123824829f997b74d28487022049d1e044ae12d27798e303f6aeff1ecddc760ffd73ca9989b21afacd20c4bbed0121026ed1acb1bab70838ccd98d780106a7c1cfaaa31c92ad33a737bf73b7fe9f8926af790000020000000001013f17f3407dac96fc0bb97ff4638b28c17a8b77b0f7e2a5f0d5a87710f55992d00000000000fdffffff0200e1f5050000000016001453a6bfc3aaab7f21a65cf766b027942048b007dae0ea382301000000160014ff12ca37077689e59b19d4e906ce6ac81a25084d02473044022078724cfc7243eefdfff5b9b4e7857d91dbeabf5c019c79017267b07d2eb48831022077f2d46a2757f65acb9b253ace28903d86f2f485b4738b65c5a1859670284a6d012103f34f043b116b4da9e50afffcaebca952dc03cc0764789b1d98635030e9fd1357af79000002000000000101b09c397256c4bdde0df0d3361c0f224f6b06a484bad0c4f74b223b5c55c8a0650000000000fdffffff02e0ea382301000000160014037eddf0ba2fe984289a352e8bb0d14183eb3e6b00e1f5050000000016001453a6bfc3aaab7f21a65cf766b027942048b007da0247304402201c94fcfc210f89773f847781be4c3ef853b4f3759752cd153a868f80453476b702201681ec121c1a13e87907d5d25e252a1e53075ff16fc2e6af196901c1c92e314d01210398042d05078571f9cbed2a0096b24c2cddbe6949068880af19d73e85ef0fcd95af790000020000000001017a8ed5c44e76edf7cc57f2b5570c9b7ebe7892acbd91d2a8dd70ed743193f2f80000000000fdffffff02e0ea38230100000016001409ed2e3890d4d5baa90682ce0112c3e4d47f239d00e1f5050000000016001453a6bfc3aaab7f21a65cf766b027942048b007da024730440220799c37dd51a28c6a12d03fedb37b2719557852e9e3b864302f810be6634d512c02205a246cbac32449566fe3dba2ee84daadc7341c4f0cfdeacea43cfc7883d191fc01210356b1ccee9f9d4709dac0e6b2eebed364c8f4c798ec5ba6cc061a361052cceca96679000002000000000101d295fa64f85f1f27974f0143ad2cbe86e44482117dadd2c7e83ead69177187330000000000fdffffff02e0ea382301000000160014891efee3c8bbaa983fcd2c316aceea37fea60cfc00e1f5050000000016001453a6bfc3aaab7f21a65cf766b027942048b007da02473044022074cb5a034479c8e16d07066bfccb301cbcf11d90df09fd8e936a036f62f6484f02201100da750e12f606f99075e61e5ac474ec70e1b752824e2b3fe17d3db29ff84a0121021be6531bdc77319964d46e63c5069400e8445b1a252290957ffc5be77d24c28faf79000002000000000101a2b4b652026d44c6ccc0f920966ef6e2fa555254ea1fe2bfc8a0d54071b2934d0000000000fdffffff0200e1f5050000000016001453a6bfc3aaab7f21a65cf766b027942048b007dae0ea382301000000160014bb5e729b335bb0974870211b2ee39a78802dbb7d0247304402206a8f4fe9b6876c9e5ebe8e2b652bad940c11821d648486889df65a658f8e6d2202206bc6e4db1cc0cb1ac0a2d42201223692d747983f416bb1c6e0aefcb6f1859aa10121034d3a9e2d44b8f9a37a1ee47d97513e3f1873c733ee7e692c7c2756412f85ef84af790000020000000001018b49501187059881f13eb37bfaa279891e02fc4edb3878395dbe72ce7eb9412c0000000000fdffffff0200e1f5050000000016001453a6bfc3aaab7f21a65cf766b027942048b007da7028830200000000160014ead571872981edc2d260cd4a0b32efda405ac25002473044022000c48bf9f0420d5b79e0d775d26a2854876bc78f86ee5265c751f4a0a96d295d02205c384d21c72c2c0f23f0b3595b749bacfa635e6f657c88533c870eaf6e850692012103db2a6bf105f56d30dfc8ae1d512066877993f17504fb1716e91c7d1cdda9f2d3af7900000200000000010160574cf697d759a45b1630bac5976ddce83571bf8dce2d384b340411839ae9f80000000000fdffffff0200e1f5050000000016001453a6bfc3aaab7f21a65cf766b027942048b007da7028830200000000160014154d587520ee80f746cbc91baeb2e4e6eb62288c02473044022000a6672832ab95e20f25aff9607aec7ee21c8a74f8df531f13e2ea1dda18b24f0220669276bc329b0bde6a0608cf22420a31c29a6e77a3f64b4a5fadd2f95a62d6eb012103db2a6bf105f56d30dfc8ae1d512066877993f17504fb1716e91c7d1cdda9f2d37c79000002000000000101f08ad02011d0b80bb09caea92bf0cdb66e73ce494af66e8cf7c48844ad934c980000000000fdffffff027028830200000000160014b1ca1c60166b2b251d14fc7c77e6d0525b3e580000e1f5050000000016001453a6bfc3aaab7f21a65cf766b027942048b007da02473044022027f780ad2eb0193eb4b8d0f8194d358d2f8b988cbf4753a2df954fe5fe7d842602202080af18626c81904efaa522f164b8e22592365f5f773928e2d4d05f485ebcf1012103db2a6bf105f56d30dfc8ae1d512066877993f17504fb1716e91c7d1cdda9f2d3af79000002000000000101b7ca8dffedbc552863c4c9c7b61291bcb869e6b358dfddd4b2c37ad939a0c2010000000000fdffffff0200e1f5050000000016001453a6bfc3aaab7f21a65cf766b027942048b007dae0ea38230100000016001474a6e0338f985c5956c0e9480e90f8777b840de60247304402204a18a8b8355cecc5788c13d618d6db6f1cea89a813c70562ba8d1330d2f967a102207ac1ffecfe2c9a94e8fa3fc4fb56b49dbdf1920d2c9531a503037a8d0a8c1e7a01210297aaa352ca608da8b8c11d617a49c26155780fb0f073243abacf7d633fb6b717af79000002000000000101575cfed506121e26f2f65a4f38253df6e4cf85e6393e743a9c326cccdad0b7840000000000fdffffff0200e1f5050000000016001453a6bfc3aaab7f21a65cf766b027942048b007dae0ea382301000000160014a546a417a0257abc555e51485e719b4de83202cd0247304402201117c5e5da0b18eb17d09872a632b97454e1001cb5266b1bbf4b37838777857e02202c4648bf4eff97b44b13d57dd49ca067f682ec03d51ca51d21e032392200cd2f0121034d4440966b1ebed945ad558b1ba0897a419c1ae48a6eba83f88a18347eea9bafaf79000002000000000101027c5685592a367867a3749d118b08fe5a57ab8b8e02c88d8154245cd1843adf0000000000fdffffff0200e1f5050000000016001453a6bfc3aaab7f21a65cf766b027942048b007dae0ea382301000000160014e8a2841481f3312d82775cf44d6cb75d21b6fd3b024730440220751d0fa8c05281ab3243dc74df550e6f57a90cbaaa2e852dddee789bc1450cb502205b2b2bfe8855eeaa606268f862318ee5c3fd9294b13fac25e065c085d1d66fe4012103fbe10177df3678086218cd4d7dccb5488e264af9d14afe06a9de04203c47f775af7900000200000000010168b30bfd194b994673408456392c8d8f11dcbdbaa46fb2ad0200eaa16c2ee0b30000000000fdffffff0200e1f5050000000016001453a6bfc3aaab7f21a65cf766b027942048b007dae0ea3823010000001600145d5626c40b9454ad0c2c1e0075396c80daddb3720247304402206bd886be6622b1752f4b69c3b6c7732b480cf815f3869d6cd9c93fddffcab8fa0220375f99ee4f45818c265d6d93b9fb3b193b23b158a91e434eb769bbc89d32e1050121023b25b189670fd75e5376f88dfd02efc8be6751f1e5ab65b935219c4b6165a687af79000002000000000101de4411238995dfeb7f2f5d45c664aa9e44d0996b0a960cd60fe899ace0f85da30000000000fdffffff0200e1f5050000000016001453a6bfc3aaab7f21a65cf766b027942048b007da70288302000000001600146556f0b3f1ce85f374847a0b4b19cb9a1c2231c402473044022065089898c2bd4ca94511773c49fb9502e7d7212cace8b291a3dfba60dc013f6b02204d5df92f780ac9194482ebb39fb72797b0dd04acc2a5e7f9cc2df9e0d326107d012103db2a6bf105f56d30dfc8ae1d512066877993f17504fb1716e91c7d1cdda9f2d3af79000002000000000101f40f0c0c4de946e7061bb769f9cae5274b6e09cd81a4d62c92602e29ea203fc30000000000fdffffff0200e1f5050000000016001453a6bfc3aaab7f21a65cf766b027942048b007dae0ea382301000000160014585ee549a440987bab0120c50a44a35cccb1dcce0247304402204b60b97e957c9e318b353f627acf0696dabd8a556204bf559d826a7b2958fa9c022034ee1d929bc8c3100a2c37d6976d773501ef1d75e5b84b5f9cb820506b393d45012103b06f48a777884ca921dae795e3ce443ff5e746df498acfdb87c2d9ee84aad264af790000020000000001017119c778457622b15db3213c5a82faeaed188c13da8a39a22441d440b823e13b0000000000fdffffff02e0ea3823010000001600147839723bb922e0e8152348eb452f904487457b9000e1f5050000000016001453a6bfc3aaab7f21a65cf766b027942048b007da02473044022070b9b602ec8192ae16d2c13acb94854f2d33b29dc4ac7c611d44326a2028d9b2022020a2e0f21daa732bd6e545afc15f10fe7cae68aede5b839714b71ac49357f43001210311cbddc225ea5e4f3b6d414e04c20a01354f7dc6b02fa74ba4695fc4080b9c1cac790000000000000000000000000000000000000000000000000000000000000000000000000000000000fd640237623232363337353732373236353665373435663631363436343732363537333733323233613232363336333732373433313731363436623738363636343737363433333638373533363333366433373732363633373730363437393631373236623631363833393638376137613634366237323335373136383661333833373739333237373761373037343336373736653634376133373633373337383732333436313339363632323263323236313663366335663662363537393733323233613562323233303333363533303335333936363336333433353333333033353331333333363338333836353337363136323333363533373636333236343337363636343335333236353635363136343330363336363332333633373632333233393335333636353632333133373632333536343633363236343634333533353338363233393338363532323263323233303332333133393634363133373332333933323334333333373339333833353338333133343331333733383631363436343339333733383337333536313631333933303334333336323339333936343635333936353634333236363335333933323633333736313632333736353635333633393337363233383631333636343336333532323263323233303333363233363631333533353339363633303633333136343333333136333633333833383331333036353332363433303333333433343339333133393337333236363631333233333634333933333332333733313338333433313634333833393633363333383332333833303339333136353330333433363635333833313335333332323564376401000000"_hex,
    };
    stream >> TX_WITH_WITNESS(block);
    return block;
}

std::ostream& operator<<(std::ostream& os, const arith_uint256& num)
{
    return os << num.ToString();
}

std::ostream& operator<<(std::ostream& os, const uint160& num)
{
    return os << num.ToString();
}

std::ostream& operator<<(std::ostream& os, const uint256& num)
{
    return os << num.ToString();
}
