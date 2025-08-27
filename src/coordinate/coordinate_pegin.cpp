#include <coordinate/coordinate_pegin.h>
#include <common/args.h>
#include <coordinate/coordinate_address.h>
#include <primitives/bitcoin/transaction.h>
#include <primitives/bitcoin/merkleblock.h>
#include <key_io.h>
#include <logging.h>
#include <util/strencodings.h>
#include <univalue.h>
#include <rpc/coordinaterpc.h>

CTxOut getPeginAmount(const std::vector<unsigned char>& bitcoinTx, const std::vector<unsigned char>& bitcoinTxProof, std::string depositAddress) {
    Sidechain::Bitcoin::CTransactionRef pegtx;
    CDataStream pegtx_stream(bitcoinTx, SER_NETWORK, PROTOCOL_VERSION);
    pegtx_stream >> pegtx;
    bool isOutputAvailable = false;
    CAmount value = 0;
    for (size_t i = 0; i < pegtx->vout.size(); i++) {
      CTxDestination fedAddress;
      ExtractDestination(pegtx->vout[i].scriptPubKey, fedAddress);
      std::string fedAddressStr = ParentEncodeDestination(fedAddress);
      if(depositAddress.compare(fedAddressStr) == 0) {
        isOutputAvailable = true;
        value = pegtx->vout[i].nValue;
        break;
      }
    }

    if(!isOutputAvailable || value == 0) {
      return CTxOut();
    }
    std::string userAddressStr = "";
    for (size_t i = 0; i < pegtx->vout.size(); i++) {
        if(pegtx->vout[i].scriptPubKey.IsUnspendable()) {
            std::vector<unsigned char> wData(ParseHex(ExtractOpReturnScript(pegtx->vout[i].scriptPubKey)));
            std::string finalStr(wData.begin(), wData.end());
            if (IsValidDestination(DecodeDestination(finalStr))) {
               userAddressStr = finalStr;
               break;
            } 
        }
    }
    if(userAddressStr.compare("") == 0) {
      LogPrintf("coordinate address is missing \n");
      return CTxOut();
    }
    const CTxDestination coinbaseScript = DecodeDestination(userAddressStr);
    return CTxOut(value, GetScriptForDestination(coinbaseScript));
}

bool hasAddressInRegistry(Chainstate& m_active_chainstate, std::string depositAddress) {
    CoordinateAddress coordinateAddress;
    m_active_chainstate.psignedblocktree->getDepositAddress(depositAddress,coordinateAddress);
    if(coordinateAddress.currentIndex == -1) {
        return false;
    }
    return true;
}

void saveAddressInRegistry(Chainstate& m_active_chainstate, std::string depositAddress) {
    if(!hasAddressInRegistry(m_active_chainstate,depositAddress)) {
      CoordinateAddress coordinateAddress;
      coordinateAddress.currentIndex = 1;
      m_active_chainstate.psignedblocktree->WriteDepositAddress(coordinateAddress, depositAddress);
    }
}

std::string ExtractOpReturnScript(const CScript& script) {
    std::string str;
    opcodetype opcode;
    std::vector<unsigned char> vch;
    CScript::const_iterator pc = script.begin();
    while (pc < script.end()) {
        if (!script.GetOp(pc, opcode, vch)) {
            str = "";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (vch.size() <= static_cast<std::vector<unsigned char>::size_type>(4)) {
                str += strprintf("%d", CScriptNum(vch, false).getint());
            } else {
              str += HexStr(vch);
            }
        } 
    }
    return str;
}

CTxIn buildPeginTxInput(const std::vector<unsigned char>& bitcoinTx, const std::vector<unsigned char>& bitcoinTxProof, std::string depositAddress, CTxOut txOut) {
    Sidechain::Bitcoin::CTransactionRef pegtx;
    CDataStream pegtx_stream(bitcoinTx, SER_NETWORK, PROTOCOL_VERSION);
    pegtx_stream >> pegtx;

    Sidechain::Bitcoin::CMerkleBlock merkle_block;
    CDataStream merkle_block_stream(bitcoinTxProof, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
    merkle_block_stream >> merkle_block;

    uint32_t index = 0;

    for (size_t i = 0; i < pegtx->vout.size(); i++) {
      CTxDestination fedAddress;
      ExtractDestination(pegtx->vout[i].scriptPubKey, fedAddress);
      std::string fedAddressStr = ParentEncodeDestination(fedAddress);
      if(depositAddress.compare(fedAddressStr) == 0) {
        index = i;
        break;
      }
    }

    COutPoint prevOutput = COutPoint(pegtx->GetHash(), index);

    CScriptWitness pegin_witness;
    std::vector<std::vector<unsigned char>>& stack = pegin_witness.stack;

    CScript fedScript = GetScriptForDestination(ParentDecodeDestination(depositAddress));
    stack.push_back(std::vector<unsigned char>(fedScript.begin(), fedScript.end()));

    stack.push_back(std::vector<unsigned char>(txOut.scriptPubKey.begin(), txOut.scriptPubKey.end()));

    std::vector<unsigned char> value_bytes;
    CVectorWriter ss_val(PROTOCOL_VERSION, value_bytes, 0);
    try {
        ss_val << txOut.nValue;
    } catch (...) {
        throw std::ios_base::failure("Amount serialization is invalid.");
    }
    stack.push_back(value_bytes);

    // Strip witness data for proof inclusion since only TXID-covered fields matters
    CDataStream ss_tx(SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
    ss_tx << pegtx;
    const auto* ss_tx_ptr = UCharCast(ss_tx.data());
    std::vector<unsigned char> tx_data_stripped(ss_tx_ptr, ss_tx_ptr + ss_tx.size());
    stack.push_back(tx_data_stripped);

    // Serialize merkle block
    CDataStream ss_txout_proof(SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
    ss_txout_proof << merkle_block;
    const auto* ss_txout_ptr = UCharCast(ss_txout_proof.data());
    std::vector<unsigned char> txout_proof_bytes(ss_txout_ptr, ss_txout_ptr + ss_txout_proof.size());
    stack.push_back(txout_proof_bytes);
    CTxIn ctxIn = CTxIn();
    ctxIn.prevout = prevOutput;
    ctxIn.scriptWitness = pegin_witness;

    return ctxIn;

}


template<typename T>
static bool GetBlockAndTxFromMerkleBlock(uint256& block_hash, uint256& tx_hash, unsigned int& tx_index, T& merkle_block, const std::vector<unsigned char>& merkle_block_raw)
{
    try {
        std::vector<uint256> tx_hashes;
        std::vector<unsigned int> tx_indices;
        CDataStream merkle_block_stream(merkle_block_raw, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
        merkle_block_stream >> merkle_block;
        block_hash = merkle_block.header.GetHash();

        if (!merkle_block_stream.empty()) {
           return false;
        }
        if (merkle_block.txn.ExtractMatches(tx_hashes, tx_indices) != merkle_block.header.hashMerkleRoot || tx_hashes.size() != 1) {
            return false;
        }
        tx_hash = tx_hashes[0];
        tx_index = tx_indices[0];
    } catch (std::exception&) {
        // Invalid encoding of merkle block
        return false;
    }
    return true;
}

template<typename T>
static bool CheckPeginTx(const std::vector<unsigned char>& tx_data, T& pegtx, const COutPoint& prevout, CAmount peginValue, std::string claimAddress, std::string federationAddress)
{
    try {
        CDataStream pegtx_stream(tx_data, SER_NETWORK, PROTOCOL_VERSION);
        pegtx_stream >> pegtx;
        if (!pegtx_stream.empty()) {
            return false;
        }
    } catch (std::exception&) {
        // Invalid encoding of transaction
        return false;
    }

    // Check that transaction matches txid
    if (pegtx->GetHash() != prevout.hash) {
        return false;
    }


    CAmount amount = pegtx->vout[prevout.n].nValue;

    if(amount > peginValue) {
        return false;
    }

    CTxDestination fedAddress;
    CTxDestination userAddress;
    ExtractDestination(pegtx->vout[prevout.n].scriptPubKey, fedAddress);
    std::string fedAddressStr = ParentEncodeDestination(fedAddress);

    if(federationAddress.compare(fedAddressStr) != 0) {
        return false;
    }

    for (size_t i = 0; i < pegtx->vout.size(); i++) {
        if(pegtx->vout[i].scriptPubKey.IsUnspendable()) {
            std::vector<unsigned char> wData(ParseHex(ExtractOpReturnScript(pegtx->vout[i].scriptPubKey)));
            std::string finalStr(wData.begin(), wData.end());
            if (IsValidDestination(DecodeDestination(finalStr))) {
                if(claimAddress.compare(finalStr) != 0) {
                    return false;
                }
           }
           break;
        }
    }
    
    return true;
}



bool IsValidPeginWitness(const CScriptWitness& pegin_witness, const COutPoint& prevout, std::string& err_msg) {

    // Format on stack is as follows:
    // 1) federation address
    // 2) claim address
    // 3) amount
    // 4) serialized transaction - serialized bitcoin transaction
    // 5) txout proof - merkle proof connecting transaction to header

    const std::vector<std::vector<unsigned char> >& stack = pegin_witness.stack;
    // Must include all elements
    if (stack.size() != 5) {
        err_msg = "Not enough stack items.";
        return false;
    }

    CScript fedScript;
    std::string federationAddress;
    try {
        fedScript = CScript(stack[0].begin(), stack[0].end());
        CTxDestination fedAddress;
        ExtractDestination(fedScript, fedAddress);
        federationAddress = ParentEncodeDestination(fedAddress);
    } catch (...) {
        err_msg = "Could not deserialize federation address.";
        return false;
    }

    std::string claimAddress;
    CScript claimScript;
    try {
        claimScript = CScript(stack[1].begin(), stack[1].end());
        CTxDestination claimDetination;
        ExtractDestination(claimScript, claimDetination);
        claimAddress = EncodeDestination(claimDetination);
    } catch (...) {
        err_msg = "Could not deserialize claim address.";
        return false;
    }

    CDataStream stream(stack[2], SER_NETWORK, PROTOCOL_VERSION);
    CAmount value;
    try {
        stream >> value;
    } catch (...) {
        err_msg = "Could not deserialize value.";
        return false;
    }

    if (!MoneyRange(value)) {
        err_msg = "Value was not in valid value range.";
        return false;
    }

    uint256 block_hash;
    uint256 tx_hash;
    int num_txs;
    unsigned int tx_index = 0;
    // Get txout proof
    Sidechain::Bitcoin::CMerkleBlock merkle_block_pow;
    if (!GetBlockAndTxFromMerkleBlock(block_hash, tx_hash, tx_index, merkle_block_pow, stack[4])) {
        err_msg = "Could not extract block and tx from merkleblock.";
        return false;
    }

    if (!CheckParentProofOfWork(block_hash, merkle_block_pow.header.nBits)) {
        err_msg = "Parent proof of work is invalid or insufficient.";
        return false;
    }

    Sidechain::Bitcoin::CTransactionRef pegtx;
    if (!CheckPeginTx(stack[3], pegtx, prevout, value, claimAddress, federationAddress)) {
        err_msg = "Peg-in tx is invalid.";
        return false;
    }

    num_txs = merkle_block_pow.txn.GetNumTransactions();


    // Check that the merkle proof corresponds to the txid
    if (prevout.hash != tx_hash) {
        err_msg = "Merkle proof and txid mismatch.";
        return false;
    }

    // Finally, validate peg-in via rpc call
    if (gArgs.GetBoolArg("-validatepegin", false)) {
        unsigned int required_depth = (unsigned int)COINBASE_MATURITY;
        if (!IsConfirmedBitcoinBlock(block_hash, required_depth, num_txs)) {
            err_msg = "Needs more confirmations.";
            return false;
        }
    }
    return true;
}

bool IsConfirmedBitcoinBlock(const uint256& hash, const int nMinConfirmationDepth, const int nbTxs)
{
    LogPrintf("Checking for confirmed bitcoin block with hash %s, mindepth %d, nbtxs %d\n", hash.ToString().c_str(), nMinConfirmationDepth, nbTxs);
    try {
        UniValue params(UniValue::VARR);
        params.push_back(hash.GetHex());
        UniValue reply = CallMainChainRPC("getblockheader", params);
        UniValue errval = reply.find_value("error");
        if (!errval.isNull()) {
            LogPrintf("WARNING: Got error reply from bitcoind getblockheader: %s\n", errval.write());
            return false;
        }
        UniValue result = reply.find_value("result");
        if (!result.isObject()) {
            LogPrintf("ERROR: bitcoind getblockheader result was malformed (not object): %s\n", result.write());
            return false;
        }

        UniValue confirmations = result.get_obj().find_value("confirmations");
        if (!confirmations.isNum() || confirmations.getInt<int>() < nMinConfirmationDepth) {
            LogPrintf("Insufficient confirmations (got %s, need at least %d).\n", confirmations.write(), nMinConfirmationDepth);
            return false;
        }

        // Only perform extra test if nbTxs has been provided (non-zero).
        if (nbTxs != 0) {
            UniValue nTx = result.get_obj().find_value("nTx");
            if (!nTx.isNum() || nTx.getInt<int>() != nbTxs) {
                LogPrintf("ERROR: Invalid number of transactions in merkle block for %s (got %s, need exactly %d)\n",
                        hash.GetHex(), nTx.write(), nbTxs);
                return false;
            }
        }
    } catch (...) {
        LogPrintf("WARNING: Failure connecting to mainchain daemon RPC; will retry.\n");
        return false;
    }
    return true;
}


bool isPeginFeeValid(const CTransaction& tx) {
    const std::vector<std::vector<unsigned char> >& stack = tx.vin[0].scriptWitness.stack;
    CDataStream stream(stack[2], SER_NETWORK, PROTOCOL_VERSION);
    CAmount value;
    stream >> value;
    CAmount fee = GetVirtualTransactionSize(tx) * PEGIN_FEE;

    if(tx.vout[0].nValue == (value - fee)) {
        return true;
    }
    return false;
}