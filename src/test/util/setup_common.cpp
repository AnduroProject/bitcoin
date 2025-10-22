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
    m_node.preconfmempool.reset();
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
    options.preconfmempool = Assert(m_node.preconfmempool.get());
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
            "13de00e5967ccb3fa610a312309589d242781144501859497f8bb974b9c0309e");
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
        "04012222ac281b2bb315f055e13f517c239918453ae8d1f2139a7d0e3eed6fc8be7b2a24c4ec874efa6316f2f7d75bf7bd4ad218e4a61e6f26b5433191adb3e781b276e84cebf068ffff7f200000000002000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0000ffffffff03ffffffffffffffff00ffffffffffffffff0000000000000000002928d1f55791f983b98f733d49be76d644ff9d0e632322781dc321131486ddc4576c0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000003c0715c6e3f7f293f97b2e82486b342a9edc012823f9cae427c17834053247470000000000000000070000000b020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff000402e90300feffffff03c817a804000000001600141caf0e4615881ab3cbb724ef5e0328d95be89d5a0000000000000000160014999232388f597e7732c2964ed02ef0ef05236afc0000000000000000266a24aa21a9ed983234c24d2718265206ea5fb28e980615781203296dc4bd4508dd39b1dc11d101200000000000000000000000000000000000000000000000000000000000000000e8030000020000000001018eee3117ad6619f59b5ffe82469fac06568b509d6589b08c0cff39f8bb374fb0000000000000fdffffff0200e1f505000000001600149cda0de94e384ca38c057124a489523b4d92637cc0ca4403000000001600141a0a0776e138371bb68034648589f2940fc7e43f0247304402204e96d50850737750de5bfbc797cdac06045657945dc487b5cb83233e77d40f19022010db62f9daa3eecabdb543c81d39636b71e77228f5dbfd3adc66e59b7ab8763101210263f7df4d9b8ba0035e28325e2643b762d97185ff147df713fc58dceb6746544fe803000002000000000101aec4b91ce2454ae82dcb7c928e424225ca2406333078aaccb469658a40b66dda000000000000fdffffff0200e1f505000000001600149cda0de94e384ca38c057124a489523b4d92637cc0ca4403000000001600146adfd14dffd5ffb3ef641fea24140f8053c8b40002473044022005d8d0843e57925f3f6db8b15654f57e0fde03567773d0945f748fc47accab8202201be7b9e91fe8b7ef1bfa9e8c225ce6058dd459f0bda41ec0aa26abd147f0e81601210263f7df4d9b8ba0035e28325e2643b762d97185ff147df713fc58dceb6746544fe803000002000000000101efeb7daaa390d233a0dc785fb29704aa2738763355d76027fc1165b817923325000000000000fdffffff0200e1f505000000001600149cda0de94e384ca38c057124a489523b4d92637cc0ca4403000000001600148dc79eadb463fcc2bf66b6af573aa60b55aed8d002473044022058407caef36337145902aacbdbb98441e549a080cb35b4824011704b14724c5902207275e6f3eede2959221dcacaff66de6a60c9bcd8f7c437eba8a8ad6d4e2c438f01210263f7df4d9b8ba0035e28325e2643b762d97185ff147df713fc58dceb6746544fe803000002000000000101a01e56b59a76b0b395685feddfecf02456ac422201ae3ffdf2ecc3f30738f64f000000000000fdffffff0200e1f505000000001600149cda0de94e384ca38c057124a489523b4d92637cc0ca4403000000001600143c88a3bf88fbb2349bc892cbdd11e245c528ab2e02473044022027cbc185ab5391c4faf3018df39e8cb6b33e8b6cc008bdfd798c14aac9a8a8f8022066381a7cdda6e73e0db0dd8bca6888694f6c8fb5cb77c04f9d7f3d0dc8e8d55c01210263f7df4d9b8ba0035e28325e2643b762d97185ff147df713fc58dceb6746544fe803000002000000000101616621773d5e98fadd8d66a25650207bc125100c17141db66b250fd1e7e14875000000000000fdffffff0200e1f505000000001600149cda0de94e384ca38c057124a489523b4d92637cc0ca4403000000001600141f3835a8b2c8fd51f96707c75020db87713d98210247304402202537cee1339a856036dff6d017450ca63bfbe9a7928b6bb993f2fb056cdfc0c202201f79decab13393c12cc6e9954a8ae812639edc70a7e06f5e2787ddb4210be6e701210263f7df4d9b8ba0035e28325e2643b762d97185ff147df713fc58dceb6746544fe803000002000000000101870f0f8bab7201b4111bd02a620a48d2b229cae389a51b350fb73155b70021c1000000000000fdffffff0200e1f505000000001600149cda0de94e384ca38c057124a489523b4d92637cc0ca440300000000160014e5cc98b13de51bb3c4a51cd2edc89c3ed5685c270247304402204342a70ebf0964baad8be662bde0f2c1fa2c762e4394c404de123786658d7c45022027dceb557243fad598d8cbe08c8b6b5f7bff6b7731c97d40fa3868ccdc21581701210263f7df4d9b8ba0035e28325e2643b762d97185ff147df713fc58dceb6746544fe803000002000000000101573a00058bcd86aab73f1daf74c81b696e9fbf262e423941a439b0cd85be7920000000000000fdffffff0200e1f505000000001600149cda0de94e384ca38c057124a489523b4d92637cc0ca4403000000001600147128e81815744af06cfa96cfac39fe0b7d7999bb0247304402207434c3ccc5b01bdb4cb9fdb1ace5066fdd12989a2f15760f19439c2ca2e0b7bd02201171df185251b2937573fe7601a31e8c73cf8ef7c545f9608ab887554abba3d101210263f7df4d9b8ba0035e28325e2643b762d97185ff147df713fc58dceb6746544fe8030000020000000001012936d53cb4b268cb26185a261395e1de4e404dff60a2b1f0b6303f25966bde80000000000000fdffffff0200e1f505000000001600149cda0de94e384ca38c057124a489523b4d92637cc0ca440300000000160014aabe527398c89afa39cc9e7253e74169a6472cea02473044022023a3a06aefe43dfb479d629800d23a115b53ea75508cf78567b4b94b3ef8ec600220434bea3a4b00045d46459dd8cf235dc79f359770045b415c3d119a900a71ebce01210263f7df4d9b8ba0035e28325e2643b762d97185ff147df713fc58dceb6746544fe80300000200000000010169f8b8e8fd69fceb3956cab0f39c08506449223f905a4fd5587f2db0222f6935000000000000fdffffff0200e1f505000000001600149cda0de94e384ca38c057124a489523b4d92637cc0ca440300000000160014ead71941725216ae36d9eb115aef1dca81f2fb320247304402207aa43de7c07b377919cca77e2052857f71df3d9a187a2c50313f5e55cdd61412022023043d70795ce58ba1cb9170a2c8379b28c5636a798c8091f70ffc66d42a241e01210263f7df4d9b8ba0035e28325e2643b762d97185ff147df713fc58dceb6746544fe803000002000000000101846e3676ab18c4d256e99257b1c7c7e18b49946119d1ddc9891d09908fcb5baf000000000000fdffffff0200e1f505000000001600149cda0de94e384ca38c057124a489523b4d92637cc0ca4403000000001600143584241d176df2282c0fca00de1df0bc08e5b81d0247304402207f8a0cd08b19255ea278e623d86654b414f7baabc7bcb8ee9752283e9307e8640220199701821066d43ab9bf3068aaa38dfc37bc7bfff4513defd3a28035dd620e0501210263f7df4d9b8ba0035e28325e2643b762d97185ff147df713fc58dceb6746544fe8030000000000000000000000000000000000000000000000000000000000000000000000000000000000fd640237623232363337353732373236353665373435663631363436343732363537333733323233613232363336333732373433313731363436623738363636343737363433333638373533363333366433373732363633373730363437393631373236623631363833393638376137613634366237323335373136383661333833373739333237373761373037343336373736653634376133373633373337383732333436313339363632323263323236313663366335663662363537393733323233613562323233303333363533303335333936363336333433353333333033353331333333363338333836353337363136323333363533373636333236343337363636343335333236353635363136343330363336363332333633373632333233393335333636353632333133373632333536343633363236343634333533353338363233393338363532323263323233303332333133393634363133373332333933323334333333373339333833353338333133343331333733383631363436343339333733383337333536313631333933303334333336323339333936343635333936353634333236363335333933323633333736313632333736353635333633393337363233383631333636343336333532323263323233303333363233363631333533353339363633303633333136343333333136333633333833383331333036353332363433303333333433343339333133393337333236363631333233333634333933333332333733313338333433313634333833393633363333383332333833303339333136353330333433363635333833313335333332323564376401000000"_hex,
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
