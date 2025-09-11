// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <index/txindex.h>
#include <merkleblock.h>
#include <node/blockstorage.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <validation.h>
#include <logging.h>

using node::GetTransaction;

static RPCHelpMan gettxoutproof()
{
    return RPCHelpMan{"gettxoutproof",
        "\nReturns a hex-encoded proof that \"txid\" was included in a block.\n"
        "\nNOTE: By default this function only works sometimes. This is when there is an\n"
        "unspent output in the utxo for this transaction. To make it always work,\n"
        "you need to maintain a transaction index, using the -txindex command line option or\n"
        "specify the block in which the transaction is included manually (by blockhash).\n",
        {
            {"txids", RPCArg::Type::ARR, RPCArg::Optional::NO, "The txids to filter",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A transaction hash"},
                },
            },
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "If specified, looks for txid in the block with this hash"},
            {"type", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "0 - normal transaction \n 1 - signedblock transaction \n 2 - pegin transaction"  },
        },
        RPCResult{
            RPCResult::Type::STR, "data", "A string that is a serialized, hex-encoded data for the proof."
        },
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::set<Txid> setTxids;
            UniValue txids = request.params[0].get_array();
            int transaction_type = request.params[2].isNull() ? 0 : request.params[2].getInt<int>();
            if (txids.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Parameter 'txids' cannot be empty");
            }
            for (unsigned int idx = 0; idx < txids.size(); idx++) {
                auto ret = setTxids.insert(Txid::FromUint256(ParseHashV(txids[idx], "txid")));
                if (!ret.second) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated txid: ") + txids[idx].get_str());
                }
            }

            if((transaction_type == 1 || transaction_type == 2) && request.params[1].isNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Parameter 'block hash' required for signed block and pegin");
            }

            const CBlockIndex* pblockindex = nullptr;
            uint256 hashBlock;
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            
            if(transaction_type == 1 || transaction_type == 2) {
                SignedTxindex signedTxIndex;
                for (const auto& tx : setTxids) {
                    chainman.ActiveChainstate().psignedblocktree->getTxPosition(tx,signedTxIndex);
                    if(signedTxIndex.pos == -1) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid signed block hash");
                    }
                }

                LOCK(cs_main);
                CChain& active_chain = chainman.ActiveChain();
                CBlock block;
                if (!chainman.m_blockman.ReadBlock(block, *active_chain[signedTxIndex.blockIndex])) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "block not found");
                }

                std::vector<CTransactionRef> vtx;
                if(transaction_type == 1) {
                    SignedBlock signed_block;
                    for (const SignedBlock& preconfBlockItem : block.preconfBlock) {
                        if(preconfBlockItem.GetHash() == signedTxIndex.signedBlockHash) {
                            signed_block = preconfBlockItem;
                            break;
                        }
                    }
                    vtx = signed_block.vtx;
                } else {
                    vtx = block.pegins;
                }


                DataStream ssMB{};
                CMerkleBlock mb(block, vtx, setTxids);
                ssMB << mb;
                std::string strHex = HexStr(ssMB);
                return strHex;
            }

            if (!request.params[1].isNull()) {
                LOCK(cs_main);
                hashBlock = ParseHashV(request.params[1], "blockhash");
                pblockindex = chainman.m_blockman.LookupBlockIndex(hashBlock);
                if (!pblockindex) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
                }
            } else {
                LOCK(cs_main);
                Chainstate& active_chainstate = chainman.ActiveChainstate();

                // Loop through txids and try to find which block they're in. Exit loop once a block is found.
                for (const auto& tx : setTxids) {
                    const Coin& coin = AccessByTxid(active_chainstate.CoinsTip(), Txid::FromUint256(tx));
                    if (!coin.IsSpent()) {
                        pblockindex = active_chainstate.m_chain[coin.nHeight];
                        break;
                    }
                }
            }


            // Allow txindex to catch up if we need to query it and before we acquire cs_main.
            if (g_txindex && !pblockindex) {
                g_txindex->BlockUntilSyncedToCurrentChain();
            }

            if (pblockindex == nullptr) {
                const CTransactionRef tx = GetTransaction(/*block_index=*/nullptr, /*mempool=*/nullptr, *setTxids.begin(), hashBlock, chainman.m_blockman);
                if (!tx || hashBlock.IsNull()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not yet in block");
                }

                LOCK(cs_main);
                pblockindex = chainman.m_blockman.LookupBlockIndex(hashBlock);
                if (!pblockindex) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Transaction index corrupt");
                }
            }

            CBlock block;
            if (!chainman.m_blockman.ReadBlock(block, *pblockindex)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
            }

            unsigned int ntxFound = 0;
            for (const auto& tx : block.vtx) {
                if (setTxids.count(tx->GetHash())) {
                    ntxFound++;
                }
            }
            if (ntxFound != setTxids.size()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Not all transactions found in specified or retrieved block");
            }

            DataStream ssMB{};
            CMerkleBlock mb(block, setTxids);
            ssMB << mb;
            std::string strHex = HexStr(ssMB);
            return strHex;
        },
    };
}


static RPCHelpMan verifytxoutproof()
{
    return RPCHelpMan{
        "verifytxoutproof",
        "Verifies that a proof points to a transaction in a block, returning the transaction it commits to\n"
        "and throwing an RPC error if the block is not in our best chain\n",
        {
            {"proof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded proof generated by gettxoutproof"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The txid(s) which the proof commits to, or empty array if the proof cannot be validated."},
            }
        },
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            DataStream ssMB{ParseHexV(request.params[0], "proof")};
            CMerkleBlock merkleBlock;
            ssMB >> merkleBlock;

            UniValue res(UniValue::VARR);

            std::vector<uint256> vMatch;
            std::vector<unsigned int> vIndex;
            merkleBlock.txn.ExtractMatches(vMatch, vIndex);
            // if (merkleBlock.txn.ExtractMatches(vMatch, vIndex) != merkleBlock.header.hashMerkleRoot)
            //     return res;

            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);

            const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(merkleBlock.header.GetHash());
            if (!pindex || !chainman.ActiveChain().Contains(pindex) || pindex->nTx == 0) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");
            }

            // Check if proof is valid, only add results if so
            if (pindex->nTx == merkleBlock.txn.GetNumTransactions()) {
                for (const uint256& hash : vMatch) {
                    res.push_back(hash.GetHex());
                }
            }

            return res;
        },
    };
}


void RegisterTxoutProofRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"blockchain", &gettxoutproof},
        {"blockchain", &verifytxoutproof},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}