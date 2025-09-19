// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <compat/compat.h>
#include <net.h>
#include <net_processing.h>
#include <netaddress.h>
#include <netbase.h>
#include <netgroup.h>
#include <node/connection_types.h>
#include <node/protocol_version.h>
#include <protocol.h>
#include <random.h>
#include <test/util/logging.h>
#include <test/util/net.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/chaintype.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

struct LogIPsTestingSetup : public TestingSetup {
    LogIPsTestingSetup()
        : TestingSetup{ChainType::MAIN, {.extra_args = {"-logips"}}} {}
};

BOOST_FIXTURE_TEST_SUITE(net_peer_connection_tests, LogIPsTestingSetup)

static CService ip(uint32_t i)
{
    struct in_addr s;
    s.s_addr = i;
    return CService{CNetAddr{s}, Params().GetDefaultPort()};
}

struct PeerTest : LogIPsTestingSetup {
/** Create a peer and connect to it. If the optional `address` (IP/CJDNS only) isn't passed, a random address is created. */
void AddPeer(NodeId& id, std::vector<CNode*>& nodes, PeerManager& peerman, ConnmanTestMsg& connman, ConnectionType conn_type, bool onion_peer = false, std::optional<std::string> address = std::nullopt)
{
    CAddress addr{};

    if (address.has_value()) {
        addr = CAddress{MaybeFlipIPv6toCJDNS(LookupNumeric(address.value(), Params().GetDefaultPort())), NODE_NONE};
    } else if (onion_peer) {
        auto tor_addr{m_rng.randbytes(ADDR_TORV3_SIZE)};
        BOOST_REQUIRE(addr.SetSpecial(OnionToString(tor_addr)));
    }

    while (!addr.IsLocal() && !addr.IsRoutable()) {
        addr = CAddress{ip(m_rng.randbits(32)), NODE_NONE};
    }

    BOOST_REQUIRE(addr.IsValid());

    const bool inbound_onion{onion_peer && conn_type == ConnectionType::INBOUND};

    nodes.emplace_back(new CNode{++id,
                                 /*sock=*/nullptr,
                                 addr,
                                 /*nKeyedNetGroupIn=*/0,
                                 /*nLocalHostNonceIn=*/0,
                                 CAddress{},
                                 /*addrNameIn=*/"",
                                 conn_type,
                                 /*inbound_onion=*/inbound_onion});
    CNode& node = *nodes.back();
    node.SetCommonVersion(PROTOCOL_VERSION);

    peerman.InitializeNode(node, ServiceFlags(NODE_NETWORK | NODE_WITNESS));
    node.fSuccessfullyConnected = true;

    connman.AddTestNode(node);
}
}; // struct PeerTest

BOOST_AUTO_TEST_SUITE_END()
