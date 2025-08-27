#include <coordinate/coordinate_preconf.h>
#include <core_io.h>
#include <logging.h>
#include <univalue.h>
#include <node/blockstorage.h>
#include <anduro_validator.h>
#include <validation.h>
#include <consensus/merkle.h>
#include <coordinate/invalid_tx.h>
#include <coordinate/coordinate_pegin.h>
#include <undo.h>
#include <merkleblock.h>

using node::BlockManager;

std::vector<CoordinatePreConfSig> coordinatePreConfSig;
std::vector<SignedBlock> finalizedSignedBlocks;
std::vector<SignedBlockPeer> finalizedSignedBlockPeers;

CCoinsView coins_view;
CCoinsViewCache preconfView(&coins_view);
// temporary minfee
CAmount preconfMinFee = 5;

CoordinatePreConfBlock getNextPreConfSigList(ChainstateManager& chainman) {
    uint64_t signedBlockHeight = 0;
    chainman.ActiveChainstate().psignedblocktree->GetLastSignedBlockID(signedBlockHeight);
    LOCK(cs_main);
    CChain& active_chain = chainman.ActiveChain();
    int blockindex = active_chain.Height();

    if(blockindex < 0) {
        CoordinatePreConfBlock result;
        return result;
    }

    CBlock block;
    if (!chainman.m_blockman.ReadBlockFromDisk(block, *CHECK_NONFATAL(active_chain[blockindex]))) {
        LogPrintf("Error reading block from disk at index %d\n", CHECK_NONFATAL(active_chain[blockindex])->GetBlockHash().ToString());
        CoordinatePreConfBlock result;
        return result;
    }
    
    int finalizedStatus = 1;
    auto it = std::find_if(coordinatePreConfSig.begin(), coordinatePreConfSig.end(), 
            [finalizedStatus] (const CoordinatePreConfSig& d) { 
                return (int)d.finalized == finalizedStatus;
            });

    if (it == coordinatePreConfSig.end()) {
        CoordinatePreConfBlock result;
        return result;
    }
    
    CTxMemPool& preconf_pool{*chainman.ActiveChainstate().GetPreConfMempool()};
    CAmount finalFee = nextBlockFee(preconf_pool, signedBlockHeight+1);
    return prepareRefunds(preconf_pool,finalFee, signedBlockHeight+1);
}

CAmount nextBlockFee(CTxMemPool& preconf_pool, uint64_t signedBlockHeight) {
    LOCK(preconf_pool.cs);
    CAmount finalFee = 0;
    for (const CoordinatePreConfSig& coordinatePreConfSigtem : coordinatePreConfSig) {
        if((uint64_t)coordinatePreConfSigtem.blockHeight != signedBlockHeight) {
           continue;
        }
        for (size_t i = 0; i < coordinatePreConfSigtem.txids.size(); i++) {
            if(coordinatePreConfSigtem.txids[i] == uint256::ZERO) {
               continue;
            }
            CTransactionRef tx = preconf_pool.get(coordinatePreConfSigtem.txids[i]);
            if (tx != nullptr) {
                if(finalFee == 0 || finalFee > tx->vout[0].nValue) {
                    finalFee = tx->vout[0].nValue;
                }
            }
        }
    } 
    // check and set preconf fee if mempool size is greator than 1MB
    return preconf_pool.GetTotalTxSize() > DEFAULT_SIGNED_BLOCK_WEIGHT ? finalFee : preconfMinFee;
}

CoordinatePreConfBlock prepareRefunds(CTxMemPool& preconf_pool, CAmount finalFee, uint64_t signedBlockHeight) {
    std::vector<uint256> txids;
    CoordinatePreConfBlock result;
    for (const CoordinatePreConfSig& coordinatePreConfSigtem : coordinatePreConfSig) {    
        if((uint64_t)coordinatePreConfSigtem.blockHeight != signedBlockHeight) {
           continue;
        }
        result.minedBlockHeight = coordinatePreConfSigtem.minedBlockHeight;
        result.witness = coordinatePreConfSigtem.witness;
        for (size_t i = 0; i < coordinatePreConfSigtem.txids.size(); i++) {
            if(coordinatePreConfSigtem.txids[i] != uint256::ZERO) {
                txids.push_back(coordinatePreConfSigtem.txids[i]);
            }
        }
    }
    result.txids = txids;
    result.fee = finalFee;
    return result;
}

bool includePreConfSigWitness(std::vector<CoordinatePreConfSig> preconf, ChainstateManager& chainman) {
    LOCK(cs_main);
    CChain& active_chain = chainman.ActiveChain();
    CTxMemPool& preconf_pool{*chainman.ActiveChainstate().GetPreConfMempool()};
    LOCK(preconf_pool.cs);
    uint64_t signedBlockHeight = 0;
    chainman.ActiveChainstate().psignedblocktree->GetLastSignedBlockID(signedBlockHeight);
    int currentBlockindex = active_chain.Height();
    if(currentBlockindex < 0) {
       return false;
    }
    // check preconf data is empty
    if(preconf.size()==0) {
        LogPrintf("preconf transaction sig empty \n");
        return false;
    }

    // check preconf sign block height is valid   
    if((uint64_t)preconf[0].blockHeight <= signedBlockHeight) {
        LogPrintf("preconf transaction sig has old block height \n");
        return false;
    }

    int blockindex = preconf[0].minedBlockHeight;
    int finalizedStatus = preconf[0].finalized;

    if(finalizedStatus == 1) {
        removePreConfWitness();
    }

    if(blockindex<0) {
          return false;
    }

    if(preconf[0].txids.size() == 0) {
       LogPrintf("preconf transaction not exist \n");
        return false;
    }
    uint256 txid = preconf[0].txids[preconf[0].txids.size()-1];
    std::string federationKey = preconf[0].federationKey;
   
    auto it = std::find_if(coordinatePreConfSig.begin(), coordinatePreConfSig.end(), 
        [txid, federationKey] (const CoordinatePreConfSig& d) { 
            return std::find(d.txids.begin(), d.txids.end(), txid) != d.txids.end() && d.federationKey.compare(federationKey) == 0;
    });
    if (it != coordinatePreConfSig.end()) {
        LogPrintf("preconf transaction list already exist \n");
        return false;
    }
    
    // get block to find the eligible anduro keys to be signed on presigned block
    CBlock block;
    if (!chainman.m_blockman.ReadBlockFromDisk(block, *CHECK_NONFATAL(active_chain[blockindex]))) {
        LogPrintf("Error reading block from disk at index %d\n", CHECK_NONFATAL(active_chain[blockindex])->GetBlockHash().ToString());
    }

    // check txid exist in preconf mempool
    for (const CoordinatePreConfSig& coordinatePreConfSigItem : preconf) {
        UniValue messages(UniValue::VARR);
        for (size_t i = 0; i < coordinatePreConfSigItem.txids.size(); i++){
            UniValue message(UniValue::VOBJ);
            if(coordinatePreConfSigItem.txids[i] != uint256::ZERO) {
                if(!preconf_pool.exists(GenTxid::Txid( coordinatePreConfSigItem.txids[i]))) {
                    LogPrintf("preconf txid not avilable in mempool \n");
                    return false;
                }
                message.pushKV("txid",  coordinatePreConfSigItem.txids[i].ToString());
            } else {
                message.pushKV("txid", "");
            }
            message.pushKV("signed_block_height", coordinatePreConfSigItem.blockHeight);
            message.pushKV("mined_block_height", coordinatePreConfSigItem.minedBlockHeight);
            messages.push_back(message);
        }
        if(finalizedStatus == 1) {
            if(!validateAnduroSignature(coordinatePreConfSigItem.witness,messages.write(),block.currentKeys)) {
                return false;
            }
        } else {
            if(!validatePreconfSignature(coordinatePreConfSigItem.witness,messages.write(),block.currentKeys)) {
                return false;
            }
        }
    }



    for (const CoordinatePreConfSig& preconfItem : preconf) {
        coordinatePreConfSig.push_back(preconfItem);
    }
    
    return true;
}


bool includePreConfBlockFromNetwork(std::vector<SignedBlock> newFinalizedSignedBlocks, ChainstateManager& chainman) {
    for (const SignedBlock& newFinalizedSignedBlock : newFinalizedSignedBlocks) {
        uint64_t nHeight = newFinalizedSignedBlock.nHeight;
        auto it = std::find_if(finalizedSignedBlocks.begin(), finalizedSignedBlocks.end(), 
        [nHeight] (const SignedBlock& d) { 
            return d.nHeight == nHeight;
        });
        if (it == finalizedSignedBlocks.end()) {
            if (!checkSignedBlock(newFinalizedSignedBlock, chainman)) {
                LogPrint(BCLog::NET, "signed block validity failed from network\n");
                continue;
            }
            LOCK(cs_main);
            if (!chainman.ActiveChainstate().ConnectSignedBlock(newFinalizedSignedBlock)) {
                LogPrint(BCLog::NET, "signed block connect failed from network\n");
                continue;
            }
            insertNewSignedBlock(newFinalizedSignedBlock);
        }
    }
    return true;
}

void insertNewSignedBlock(const SignedBlock& newFinalizedSignedBlock) {
    finalizedSignedBlocks.push_back(newFinalizedSignedBlock);
    SignedBlockPeer newPeer;
    newPeer.hash = newFinalizedSignedBlock.GetHash();
    finalizedSignedBlockPeers.push_back(newPeer);
}


void removePreConfWitness() {
    coordinatePreConfSig.clear();
}

void removePreConfFinalizedBlock(uint64_t blockHeight) {
    std::vector<SignedBlock> newFinalizedSignedBlocks;
    std::vector<SignedBlockPeer> newFinalizedSignedBlockPeers;
    for (SignedBlock finalizedSignedBlock : finalizedSignedBlocks) {
        if(static_cast<uint64_t>(finalizedSignedBlock.nHeight) > blockHeight) {
            newFinalizedSignedBlocks.push_back(finalizedSignedBlock);
            SignedBlockPeer newPeer;
            newPeer.hash = finalizedSignedBlock.GetHash();
            newFinalizedSignedBlockPeers.push_back(newPeer);
        }
    }
    finalizedSignedBlocks = newFinalizedSignedBlocks;
    finalizedSignedBlockPeers = newFinalizedSignedBlockPeers;
}
/**
 * This is the function which used to get unbroadcasted preconfirmation signatures
 */
std::vector<CoordinatePreConfSig> getUnBroadcastedPreConfSig() {
    std::vector<CoordinatePreConfSig> sigData;
    for (CoordinatePreConfSig coordinatePreConfSigItem : coordinatePreConfSig) {
        if(!coordinatePreConfSigItem.isBroadcasted) {
            sigData.push_back(coordinatePreConfSigItem);
        } 
    }

    return sigData;
}

/**
 * This is the function which used to get unbroadcasted preconfirmation signed block
 */
std::vector<SignedBlock> getUnBroadcastedPreConfSignedBlock() {
    std::vector<SignedBlock> sigData;
    for (SignedBlockPeer finalizedSignedBlockPeer : finalizedSignedBlockPeers) {
        if(!finalizedSignedBlockPeer.isBroadcasted) {
            for (SignedBlock finalizedSignedBlock : finalizedSignedBlocks) {
                if(finalizedSignedBlockPeer.hash == finalizedSignedBlock.GetHash()) {
                    sigData.push_back(finalizedSignedBlock);
                }
            }
        } 
    }
    return sigData;
}


/**
 * This is the function which used to get all preconfirmation signatures
 */
std::vector<CoordinatePreConfSig> getPreConfSig() {
   return coordinatePreConfSig;
}

/**
 * This is the function which used change status for broadcasted preconf
 */
void updateBroadcastedPreConf(CoordinatePreConfSig& preconfItem, int64_t peerId) {
    for (CoordinatePreConfSig& coordinatePreConfSigItem : coordinatePreConfSig) {
        if(coordinatePreConfSigItem.witness.compare(preconfItem.witness)==0 && !coordinatePreConfSigItem.isBroadcasted) {
            if (std::find(preconfItem.peerList.begin(), preconfItem.peerList.end(), peerId) != preconfItem.peerList.end()) {
                coordinatePreConfSigItem.isBroadcasted = true;
            } else {
                coordinatePreConfSigItem.peerList.push_back(peerId);
            }
            break;
        }
    }
}

/**
 * This is the function which used change status for broadcasted signed block
 */
void updateBroadcastedSignedBlock(SignedBlock& signedBlockItem, int64_t peerId) {
    for (SignedBlockPeer& finalizedSignedBlockPeer : finalizedSignedBlockPeers) {
        if(signedBlockItem.GetHash() == finalizedSignedBlockPeer.hash && !finalizedSignedBlockPeer.isBroadcasted) {
            if (std::find(finalizedSignedBlockPeer.peerList.begin(), finalizedSignedBlockPeer.peerList.end(), peerId) != finalizedSignedBlockPeer.peerList.end()) {
                finalizedSignedBlockPeer.isBroadcasted = true;
            } else {
                finalizedSignedBlockPeer.peerList.push_back(peerId);
            }
            break;
        }
    }
}

/**
 * This is the function which used to get preconf vote information
 */
CAmount getPreConfMinFee() {
   return preconfMinFee;
}

/**
 * This function get new block template for signed block
 */
std::unique_ptr<SignedBlock> CreateNewSignedBlock(ChainstateManager& chainman, uint32_t nTime) {
    LOCK(cs_main);
    std::unique_ptr<SignedBlock> pblocktemplate;
    pblocktemplate.reset(new SignedBlock());
    SignedBlock *block = pblocktemplate.get();

    CCoinsViewCache view(&chainman.ActiveChainstate().CoinsTip());
    uint64_t nIDLast = 0;
    CoordinatePreConfBlock preconfList = getNextPreConfSigList(chainman);
    if(preconfList.witness.compare("")==0) {
        removePreConfWitness();
        LogPrintf("Signed block witness not exist \n");
        return nullptr;
    }

    if(chainman.IsInitialBlockDownload()) {
        LogPrintf("Coordinate is downloading blocks... \n");
        return nullptr;
    }
    chainman.ActiveChainstate().psignedblocktree->GetLastSignedBlockID(nIDLast);
    if(nIDLast > 0) {
        uint256 lastHash;
        chainman.ActiveChainstate().psignedblocktree->GetLastSignedBlockHash(lastHash);
        block->hashPrevSignedBlock = lastHash;
    }
    CTxMemPool& preconf_pool{*chainman.ActiveChainstate().GetPreConfMempool()};
    uint64_t nHeight = nIDLast + 1;
    block->currentFee = preconfList.fee;
    block->nHeight = nHeight;
    block->nTime = nTime;
    block->blockIndex = preconfList.minedBlockHeight;
    block->vtx.resize(preconfList.txids.size() + 1);
    unsigned int i = 1;
    std::vector<CTxOut> coinBaseOuts;

    std::vector<unsigned char> witnessData = ParseHex(preconfList.witness);
    CTxOut witnessOut(0, CScript() << OP_RETURN << witnessData);
    coinBaseOuts.push_back(witnessOut);


    for (const uint256& hash : preconfList.txids) {
        TxMempoolInfo info = preconf_pool.info(GenTxid::Txid(hash));
        if(!info.tx) {
           LogPrintf("Signed block invalid tx \n");
           return nullptr;
        }
        block->vtx[i] = info.tx;
        i = i + 1;
    }
    CAmount federationFee = std::ceil(getPreconfFeeForFederation(block->vtx, block->currentFee) * 0.20);
    CTxOut federationFeeOut(federationFee, getFederationScript(chainman, chainman.ActiveHeight()));
    coinBaseOuts.push_back(federationFeeOut);

    std::vector<unsigned char> witnessMerkleData = ParseHex(SignedBlockWitnessMerkleRoot(*block).ToString());
    CTxOut witnessMerkleOut(0, CScript() << OP_RETURN << witnessMerkleData);
    coinBaseOuts.push_back(witnessMerkleOut);

    CMutableTransaction signedCoinbaseTx;
    signedCoinbaseTx.nVersion = TRANSACTION_PRECONF_VERSION;
    signedCoinbaseTx.vin.resize(1);
    signedCoinbaseTx.vin[0].prevout.SetNull();
    signedCoinbaseTx.vout.resize(coinBaseOuts.size());
    for (size_t i = 0; i < coinBaseOuts.size(); i++)
    {
        signedCoinbaseTx.vout[i] = coinBaseOuts[i];
    }
    block->vtx[0] = MakeTransactionRef(std::move(signedCoinbaseTx));
    block->hashMerkleRoot = SignedBlockMerkleRoot(*block);
    return pblocktemplate;
}

bool checkSignedBlock(const SignedBlock& block, ChainstateManager& chainman) {
    LOCK(cs_main);
    CChain& active_chain = chainman.ActiveChain();
    int blockindex = block.blockIndex;

    // check txid exist in preconf mempool
    UniValue messages(UniValue::VARR);
    //check signature is valid and include to queue
    for (unsigned int i = 0; i < block.vtx.size(); i++) {
        UniValue message(UniValue::VOBJ);
        if(i == 0) {
            message.pushKV("txid", "");
        } else {
            message.pushKV("txid", block.vtx[i]->GetHash().ToString());
        }
        message.pushKV("signed_block_height", block.nHeight);
        message.pushKV("mined_block_height", block.blockIndex);

        messages.push_back(message);
    }
    
    if(blockindex < 0) {
        return false;
    }
    // get block to find the eligible anduro keys to be signed on presigned block
    CBlock minedblock;
    if (!chainman.m_blockman.ReadBlockFromDisk(minedblock, *CHECK_NONFATAL(active_chain[blockindex]))) {
        removePreConfWitness();
        LogPrintf("Error reading block from disk at index %d\n", CHECK_NONFATAL(active_chain[blockindex])->GetBlockHash().ToString());
        return false;
    }
    CTxOut witnessOut = block.vtx[0]->vout[0];
    const std::string witnessStr = ScriptToAsmStr(witnessOut.scriptPubKey).replace(0,10,"");
    CAmount federationFee = std::ceil(getPreconfFeeForFederation(block.vtx, block.currentFee) * 0.20);
    CTxOut federationOut = block.vtx[0]->vout[1];
    if(federationOut.nValue != federationFee) {
        LogPrintf("invalid federation fee included");
        return false;
    }
    
    LogPrintf("validating signed block... \n");
    if(!validateAnduroSignature(witnessStr,messages.write(),minedblock.currentKeys)) {
       removePreConfWitness();
       return false;
    }
    return true;
}

/**
 * This function will get all validate invalid tx details for block
 */
bool validateReconciliationBlock(ChainstateManager& chainman, ReconciliationBlock reconciliationBlock) {
    LOCK(cs_main);
    CChain& active_chain = chainman.ActiveChain();
    int lastHeight = active_chain.Height();
    if(lastHeight < 3 ) {
        return false;
    }

    int currentHeight = lastHeight - 3;
    CBlock prevblock;
    if (!chainman.m_blockman.ReadBlockFromDisk(prevblock, *CHECK_NONFATAL(active_chain[currentHeight]))) {
        return false;
    } 

    if(reconciliationBlock.tx.size() == 0) {
        LogPrintf("no invalid tx available");
        return true;
    }

    std::vector<uint256> preBlockTxs;
    preBlockTxs.resize(prevblock.vtx.size());
    
    std::vector<uint256> reconcileBlockTxs;
    reconcileBlockTxs.resize(prevblock.vtx.size());
    std::vector<uint256> invalidTx;
    for (size_t s = 0; s < prevblock.vtx.size(); s++) {
        preBlockTxs[s] = prevblock.vtx[s]->GetHash();
        auto it = std::find_if(reconciliationBlock.tx.begin(), reconciliationBlock.tx.end(), 
        [s] (const ReconciliationInvalidTx& tx) { 
            return tx.pos == s;
        });
        if (it == reconciliationBlock.tx.end()) {
            reconcileBlockTxs[s].SetNull();
        } else {
            ReconciliationInvalidTx tx = std::move(*it);
            reconcileBlockTxs[s] = tx.txHash;
            invalidTx.push_back(tx.txHash);
        }
    }

    uint256 blockMerkleRoot = ComputeMerkleRoot(preBlockTxs);
    uint256 reconcileMerkleRoot = ComputeMerkleRoot(reconcileBlockTxs);

    if(reconciliationBlock.reconcileMerkleRoot == blockMerkleRoot) {
        LogPrintf("Reconciliation block hash mismatch");
        return false;
    }


    bool isValid = true;
    for (size_t i = 0; i < invalidTx.size(); i++)
    {
        uint256 input = invalidTx[i];

        std::vector<bool> vMatch;
        std::vector<uint256> vHashes;
        std::vector<uint256> rvHashes;
        vMatch.reserve(preBlockTxs.size());
        vHashes.reserve(preBlockTxs.size());
        rvHashes.reserve(preBlockTxs.size());

        for (unsigned int i = 0; i < preBlockTxs.size(); i++)
        {
            const uint256& hash = preBlockTxs[i];
            if(hash == input) {
                vMatch.push_back(true);
            } else {
                vMatch.push_back(false);
            }
            vHashes.push_back(hash);
            rvHashes.push_back(reconcileBlockTxs[i]);
        }

        CPartialMerkleTree txn(vHashes, vMatch);
        CPartialMerkleTree rTxn(rvHashes, vMatch);


        std::vector<uint256> vAvailableMatch;
        std::vector<unsigned int> vAvailableIndex;
        uint256 hashRoot(txn.ExtractMatches(vAvailableMatch, vAvailableIndex));
        if(hashRoot != blockMerkleRoot) {
            LogPrintf("proof belong to block is invalid");
            isValid = false;
            break;
        }

        if (std::find(vAvailableMatch.begin(), vAvailableMatch.end(), input) == vAvailableMatch.end()) {
            isValid = false;
            break;
        }

        std::vector<uint256> rAvailableMatch;
        std::vector<unsigned int> rAvailableIndex;
        uint256 hashReconcile(rTxn.ExtractMatches(rAvailableMatch, rAvailableIndex));
        if(hashReconcile != reconcileMerkleRoot) {
            LogPrintf("proof belong to reconcile block is invalid");
            isValid = false;
            break;
        }
    }
    
    return isValid;
}

/**
 * This function is to get reconsiled block hash
 */
ReconciliationBlock getReconsiledBlock(ChainstateManager& chainman) {
    LOCK(cs_main);

    ReconciliationBlock block;
    CChain& active_chain = chainman.ActiveChain();
    int lastHeight = active_chain.Height();

    if(lastHeight < 3 ) {
        return block;
    }

    int currentHeight = lastHeight - 3;
    if(currentHeight < 0) {
        return block;
    }
    CBlock prevblock;
    if (!chainman.m_blockman.ReadBlockFromDisk(prevblock, *CHECK_NONFATAL(active_chain[currentHeight]))) {
        return block;
    } 

    InvalidTx invalidTxObj;
    chainman.ActiveChainstate().psignedblocktree->GetInvalidTx(currentHeight,invalidTxObj);

    std::vector<uint256> txLeaves;
    txLeaves.resize(prevblock.vtx.size());
    for (size_t s = 0; s < prevblock.vtx.size(); s++) {
        txLeaves[s] = prevblock.vtx[s]->GetHash();
    }
    uint256 blockTxMerkleRoot = ComputeMerkleRoot(txLeaves);

    block.reconcileMerkleRoot = blockTxMerkleRoot;
    block.nTx = prevblock.vtx.size();
    block.tx = invalidTxObj.invalidTxs;

    return block;
}


CAmount getPreconfFeeForBlock(ChainstateManager& chainman, int blockHeight) {
    LOCK(cs_main);
    CChain& active_chain = chainman.ActiveChain();
    if(blockHeight<3) {
        return 0;
    }
    int currentHeight = blockHeight - 3;

    CBlock prevblock;
    if (!chainman.m_blockman.ReadBlockFromDisk(prevblock, *CHECK_NONFATAL(active_chain[currentHeight]))) {
        return 0;
    } 

    CAmount fee = 0;

    for (size_t i = 0; i < prevblock.preconfBlock.size(); i++)
    {  
        SignedBlock block = prevblock.preconfBlock[i];
        for (size_t i = 0; i < block.vtx.size(); i++) {
            if(i==0) {
                continue;
            }
            const CTransactionRef& tx = block.vtx[i];
            fee = fee + (block.currentFee * GetVirtualTransactionSize(*tx));
        }
    }
    return fee;
}

CAmount getPreconfFeeForFederation(std::vector<CTransactionRef> vtx, CAmount currentFee) {
    CAmount fee = 0;
    for (size_t i = 0; i < vtx.size(); i++) {
        if(i==0) {
            continue;
        }
        const CTransactionRef& tx = vtx[i];
        fee = fee + (currentFee * GetVirtualTransactionSize(*tx));
    }
     return fee;
}

CAmount getFeeForBlock(ChainstateManager& chainman, int blockHeight) {
    LOCK(cs_main);
    CChain& active_chain = chainman.ActiveChain();
    if(blockHeight<3) {
        return 0;
    }

    int currentHeight = blockHeight - 3;

    CBlock prevblock;
    if (!chainman.m_blockman.ReadBlockFromDisk(prevblock, *CHECK_NONFATAL(active_chain[currentHeight]))) {
        return 0;
    } 


    CBlockUndo blockUndo;
    if(!chainman.m_blockman.UndoReadFromDisk(blockUndo, *active_chain[currentHeight])) {
       return 0;
    }

    InvalidTx invalidTx;
    chainman.ActiveChainstate().psignedblocktree->GetInvalidTx(currentHeight,invalidTx); 
    CAmount totalFee = 0; 

    for (size_t i = 0; i < prevblock.vtx.size(); ++i) {
        const CTransactionRef& tx = prevblock.vtx.at(i);
        CAmount amt_total_in = 0;
        CAmount amt_total_out = 0;
        if(i > 0) {
            const CTxUndo* txundo = &blockUndo.vtxundo.at(i - 1);
            const bool have_undo = txundo != nullptr;
            if(invalidTx.invalidTxs.size()>0) {
                uint256 invHash = tx->GetHash();
                auto it = std::find_if(invalidTx.invalidTxs.begin(), invalidTx.invalidTxs.end(), 
                [invHash] (const ReconciliationInvalidTx& d) { 
                    return d.txHash == invHash;
                });
                if(it != invalidTx.invalidTxs.end()) {
                    continue;
                }
            }


            for (unsigned int ix = 0; ix < tx->vin.size(); ix++) {
                if (have_undo) {
                    const Coin& prev_coin = txundo->vprevout[ix];
                    const CTxOut& prev_txout = prev_coin.out;
                    if(!(tx->nVersion == TRANSACTION_COORDINATE_ASSET_CREATE_VERSION && prev_coin.IsBitAssetController())) {
                        amt_total_in += prev_txout.nValue;
                    } 
                }
            }

            for (unsigned int ix = 0; ix < tx->vout.size(); ix++) {
                const CTxOut& txout = tx->vout[ix];
                if(tx->nVersion == TRANSACTION_COORDINATE_ASSET_CREATE_VERSION) {
                    if(ix > 1) {
                        amt_total_out += txout.nValue;
                    }
                } else if(tx->nVersion == TRANSACTION_PRECONF_VERSION) {
                    if(ix > 0) {
                        amt_total_out += txout.nValue;
                    }
                } else {
                    amt_total_out += txout.nValue;
                }
            }
        
        }

        totalFee = totalFee + (amt_total_in - amt_total_out);
    }

    for (size_t i = 0; i < prevblock.pegins.size(); ++i) {
        const std::vector<std::vector<unsigned char> >& stack = prevblock.pegins[i]->vin[0].scriptWitness.stack;
        CDataStream stream(stack[2], SER_NETWORK, PROTOCOL_VERSION);
        CAmount value;
        stream >> value;
        const CTransaction& tx = *prevblock.pegins[i];
        CAmount fee = GetVirtualTransactionSize(tx) * PEGIN_FEE;
        totalFee = totalFee + fee;
    }

    if(!MoneyRange(totalFee)) {
        return 0;
    }

    return totalFee;

} 

CScript getMinerScript(ChainstateManager& chainman, int blockHeight) {
    LOCK(cs_main);
    CChain& active_chain = chainman.ActiveChain();
    int currentHeight = blockHeight - 3;
    CScript scriptPubKey;
    CBlock prevblock;

    if(currentHeight < 0) { 
         return scriptPubKey;
    }
    if (!chainman.m_blockman.ReadBlockFromDisk(prevblock, *CHECK_NONFATAL(active_chain[currentHeight]))) {
        return scriptPubKey;
    } 
    return prevblock.vtx[0]->vout[0].scriptPubKey;
}

CScript getFederationScript(ChainstateManager& chainman, int blockHeight) {
    LOCK(cs_main);
    CChain& active_chain = chainman.ActiveChain();
    int currentHeight = blockHeight - 3;
    CScript scriptPubKey;
    if(currentHeight < 0) { 
         return scriptPubKey;
    }

    CBlock prevblock;
    if (!chainman.m_blockman.ReadBlockFromDisk(prevblock, *CHECK_NONFATAL(active_chain[currentHeight]))) {
        return scriptPubKey;
    } 
    std::vector<unsigned char> wData(ParseHex(prevblock.currentKeys));
    const std::string prevWitnessHexStr(wData.begin(), wData.end());
    UniValue witnessVal(UniValue::VOBJ);
    if (!witnessVal.read(prevWitnessHexStr)) {
        LogPrintf("invalid witness params \n");
        return scriptPubKey;
    }
    const CTxDestination coinbaseScript = DecodeDestination(witnessVal.get_obj().find_value("current_address").get_str());
    return GetScriptForDestination(coinbaseScript);
}

/**
 * This is the function which used to get all finalized signed block
 */
std::vector<SignedBlock> getFinalizedSignedBlocks() {
    return finalizedSignedBlocks;
}

CAmount getRefundForPreconfTx(const CTransaction& ptx, CAmount blockFee, CCoinsViewCache& inputs) {
    if(ptx.IsCoinBase()) {
        return 0;
    }
    CAmount refund = 0;
    CAmount fee = blockFee *  GetVirtualTransactionSize(ptx);
    CAmount nValueIn = 0;
    for (unsigned int i = 0; i < ptx.vin.size(); ++i) {
        const COutPoint &prevout = ptx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        if(coin.IsSpent()) {
            continue;
        }
        if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)) {
            continue;
        }
        nValueIn += coin.out.nValue;
    }
    CAmount value_out = 0;
    for (size_t i = 1; i < ptx.vout.size(); ++i) {
        value_out = value_out + ptx.vout[i].nValue;
    }
    if (nValueIn < value_out) { 
        return refund;
    }
    refund = (nValueIn - value_out) - fee;
    if(refund < 0) {
        return 0;
    }
    return refund;
}


CAmount getRefundForPreconfCurrentTx(const CTransaction& ptx, CAmount blockFee, CCoinsViewCache& inputs) {
    if(ptx.IsCoinBase()) {
        return 0;
    }
    const COutPoint &prevout = COutPoint(ptx.GetHash(), 0);
    const Coin& coin = inputs.AccessCoin(prevout);
    if(coin.IsSpent()) {
        return 0;
    }
    return coin.out.nValue;
}
