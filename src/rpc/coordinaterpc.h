// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_COORDINATERPC_H
#define BITCOIN_RPC_COORDINATERPC_H

#include <string>
#include <uint256.h>
#include <consensus/amount.h>

static const char MAINCHAIN_RPC_HOST[] = "127.0.0.1";
static const int MAINCHAIN_RPC_PORT = 19011;
static const char MAINCHAIN_RPC_USER[] = "bitcoin";
static const char MAINCHAIN_RPC_PASS[] = "bitcoin";
static const int MAINCHAIN_HTTP_CLIENT_TIMEOUT=900;

class UniValue;

UniValue CallMainChainRPC(const std::string& strMethod, const UniValue& params);

#endif // BITCOIN_RPC_COORDINATERPC_H
