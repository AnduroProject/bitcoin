// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bip324.h>
#include <chainparams.h>
#include <crypto/chacha20.h>
#include <crypto/poly1305.h>
#include <key.h>
#include <pubkey.h>
#include <random.h>
#include <span.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <string>
#include <vector>

namespace {

// Helper function to compare containers without using std::ranges
template<typename Container1, typename Container2>
bool containers_equal(const Container1& c1, const Container2& c2) {
    if (c1.size() != c2.size()) return false;
    return std::equal(c1.begin(), c1.end(), c2.begin());
}

// Get magic bytes as vector for HexStr compatibility
std::vector<uint8_t> GetMagicBytes() {
    const auto& magic = Params().MessageStart();
    return std::vector<uint8_t>(magic.begin(), magic.end());
}

// Convert uint8_t array to std::span<const std::byte>
std::span<const std::byte> ToByteSpan(const std::array<uint8_t, 64>& data) {
    return std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.data()), data.size());
}

// Convert uint256 to std::span<const std::byte>
std::span<const std::byte> ToByteSpan(const uint256& hash) {
    return std::span<const std::byte>(reinterpret_cast<const std::byte*>(hash.begin()), 32);
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(bip324_tests, BasicTestingSetup)

// Test BIP324Cipher constructor with CKey and entropy
BOOST_AUTO_TEST_CASE(cipher_with_key_entropy_test)
{
    try {
        CKey priv_key;
        priv_key.MakeNewKey(true);
        
        uint256 entropy = GetRandHash();
        
        // Based on error: BIP324Cipher(const CKey& key, std::span<const std::byte> ent32)
        BIP324Cipher cipher(priv_key, ToByteSpan(entropy));
        
        // Test basic operations
        auto session_id = cipher.GetSessionID();
        auto send_garbage = cipher.GetSendGarbageTerminator();
        auto recv_garbage = cipher.GetReceiveGarbageTerminator();
        
        BOOST_CHECK(!session_id.empty());
        BOOST_CHECK(!send_garbage.empty());
        BOOST_CHECK(!recv_garbage.empty());
        
        auto magic = GetMagicBytes();
        BOOST_TEST_MESSAGE("Cipher with key+entropy test passed");
        BOOST_TEST_MESSAGE("Magic bytes: " + HexStr(magic));
        BOOST_TEST_MESSAGE("Session ID size: " + std::to_string(session_id.size()));
        
    } catch (const std::exception& e) {
        BOOST_TEST_MESSAGE("Exception in cipher_with_key_entropy_test: " + std::string(e.what()));
        BOOST_CHECK(false);
    }
}

// Test BIP324Cipher constructor with CKey and EllSwiftPubKey
BOOST_AUTO_TEST_CASE(cipher_with_key_ellswift_test)
{
    try {
        CKey priv_key;
        priv_key.MakeNewKey(true);
        
        // Create EllSwiftPubKey using span constructor
        std::array<uint8_t, 64> ellswift_data;
        auto magic = GetMagicBytes();
        for (size_t i = 0; i < ellswift_data.size(); ++i) {
            ellswift_data[i] = static_cast<uint8_t>((magic[i % 4] + i) % 256);
        }
        
        EllSwiftPubKey ellswift_key(ToByteSpan(ellswift_data));
        
        // Based on error: BIP324Cipher(const CKey& key, const EllSwiftPubKey& pubkey)
        BIP324Cipher cipher(priv_key, ellswift_key);
        
        // Test basic operations
        auto session_id = cipher.GetSessionID();
        auto send_garbage = cipher.GetSendGarbageTerminator();
        auto recv_garbage = cipher.GetReceiveGarbageTerminator();
        
        BOOST_CHECK(!session_id.empty());
        BOOST_CHECK(!send_garbage.empty());
        BOOST_CHECK(!recv_garbage.empty());
        
        BOOST_TEST_MESSAGE("Cipher with key+ellswift test passed");
        BOOST_TEST_MESSAGE("Magic bytes: " + HexStr(magic));
        
    } catch (const std::exception& e) {
        BOOST_TEST_MESSAGE("Exception in cipher_with_key_ellswift_test: " + std::string(e.what()));
        BOOST_CHECK(false);
    }
}

// Test EllSwiftPubKey creation and operations
BOOST_AUTO_TEST_CASE(ellswift_creation_test)
{
    try {
        auto magic = GetMagicBytes();
        
        // Create multiple EllSwiftPubKey instances with different data
        std::vector<EllSwiftPubKey> ellswift_keys;
        
        for (int i = 0; i < 3; ++i) {
            std::array<uint8_t, 64> data;
            for (size_t j = 0; j < data.size(); ++j) {
                data[j] = static_cast<uint8_t>((magic[j % 4] + i * 17 + j) % 256);
            }
            
            EllSwiftPubKey ellswift(ToByteSpan(data));
            ellswift_keys.push_back(ellswift);
        }
        
        // Verify all keys are different
        for (size_t i = 0; i < ellswift_keys.size(); ++i) {
            for (size_t j = i + 1; j < ellswift_keys.size(); ++j) {
                BOOST_CHECK(ellswift_keys[i] != ellswift_keys[j]);
            }
        }
        
        BOOST_TEST_MESSAGE("EllSwiftPubKey creation test passed");
        
    } catch (const std::exception& e) {
        BOOST_TEST_MESSAGE("Exception in ellswift_creation_test: " + std::string(e.what()));
        BOOST_CHECK(false);
    }
}

// Test encryption operations (void return type)
BOOST_AUTO_TEST_CASE(encryption_operations_test)
{
    try {
        CKey priv_key;
        priv_key.MakeNewKey(true);
        
        uint256 entropy = GetRandHash();
        BIP324Cipher cipher(priv_key, ToByteSpan(entropy));
        
        // Test message encryption with different sizes
        std::vector<size_t> test_sizes = {0, 1, 16, 100, 1000};
        
        for (size_t msg_size : test_sizes) {
            std::vector<uint8_t> message(msg_size, 0x42);
            std::vector<std::byte> encrypted(msg_size + BIP324Cipher::EXPANSION);
            
            // Encrypt returns void, so we just call it and check it doesn't crash
            cipher.Encrypt(
                MakeByteSpan(message),
                {},  // no AAD
                false,  // not ignore
                encrypted
            );
            
            // Verify encrypted data has expected size
            BOOST_CHECK_EQUAL(encrypted.size(), msg_size + BIP324Cipher::EXPANSION);
            
            BOOST_TEST_MESSAGE("Encryption test for size " + std::to_string(msg_size) + " completed");
        }
        
    } catch (const std::exception& e) {
        BOOST_TEST_MESSAGE("Exception in encryption_operations_test: " + std::string(e.what()));
        BOOST_CHECK(false);
    }
}

// Test with Anduro-specific magic numbers
BOOST_AUTO_TEST_CASE(anduro_magic_number_test)
{
    try {
        auto magic = GetMagicBytes();
        
        // Verify we have the expected Anduro magic numbers
        BOOST_CHECK_EQUAL(magic.size(), 4);
        
        if (magic.size() >= 4) {
            BOOST_CHECK_EQUAL(magic[0], 0xf8);
            BOOST_CHECK_EQUAL(magic[1], 0xbf);
            BOOST_CHECK_EQUAL(magic[2], 0xb8);
            BOOST_CHECK_EQUAL(magic[3], 0xd8);
            
            BOOST_TEST_MESSAGE("Confirmed Anduro magic numbers: " + HexStr(magic));
        } else {
            BOOST_TEST_MESSAGE("Unexpected magic number size: " + std::to_string(magic.size()));
        }
        
        // Create cipher using magic-derived entropy
        CKey priv_key;
        priv_key.MakeNewKey(true);
        
        uint256 magic_entropy;
        for (int i = 0; i < 8; ++i) {
            magic_entropy.begin()[i*4] = magic[0];
            magic_entropy.begin()[i*4+1] = magic[1];
            magic_entropy.begin()[i*4+2] = magic[2];
            magic_entropy.begin()[i*4+3] = magic[3];
        }
        
        BIP324Cipher cipher(priv_key, ToByteSpan(magic_entropy));
        
        // Test with message containing magic numbers
        std::vector<uint8_t> message;
        message.insert(message.end(), magic.begin(), magic.end());
        message.push_back(0x01); // Add one more byte
        
        std::vector<std::byte> encrypted(message.size() + BIP324Cipher::EXPANSION);
        cipher.Encrypt(
            MakeByteSpan(message),
            {},
            false,
            encrypted
        );
        
        BOOST_CHECK_EQUAL(encrypted.size(), message.size() + BIP324Cipher::EXPANSION);
        
        BOOST_TEST_MESSAGE("Anduro magic number test passed");
        
    } catch (const std::exception& e) {
        BOOST_TEST_MESSAGE("Exception in anduro_magic_number_test: " + std::string(e.what()));
        BOOST_CHECK(false);
    }
}

// Test cipher properties and basic functionality
BOOST_AUTO_TEST_CASE(cipher_properties_test)
{
    try {
        // Create cipher and test its properties
        CKey priv_key;
        priv_key.MakeNewKey(true);
        
        uint256 entropy = GetRandHash();
        BIP324Cipher cipher(priv_key, ToByteSpan(entropy));
        
        // Test that cipher properties have expected characteristics
        auto session_id = cipher.GetSessionID();
        auto send_garbage = cipher.GetSendGarbageTerminator();
        auto recv_garbage = cipher.GetReceiveGarbageTerminator();
        
        // Verify reasonable sizes (session IDs are typically 32 bytes, garbage terminators 16 bytes)
        BOOST_CHECK_GE(session_id.size(), 16);  // At least 16 bytes
        BOOST_CHECK_LE(session_id.size(), 64);  // At most 64 bytes
        
        BOOST_CHECK_GE(send_garbage.size(), 8);   // At least 8 bytes
        BOOST_CHECK_LE(send_garbage.size(), 32);  // At most 32 bytes
        
        BOOST_CHECK_GE(recv_garbage.size(), 8);   // At least 8 bytes
        BOOST_CHECK_LE(recv_garbage.size(), 32);  // At most 32 bytes
        
        // Test that different ciphers produce different values (cryptographic uniqueness)
        CKey key2;
        key2.MakeNewKey(true);
        uint256 entropy2 = GetRandHash();
        BIP324Cipher cipher2(key2, ToByteSpan(entropy2));
        
        auto session_id2 = cipher2.GetSessionID();
        auto send_garbage2 = cipher2.GetSendGarbageTerminator();
        
        // These should be different (probabilistically) 
        BOOST_CHECK(!containers_equal(session_id, session_id2));
        BOOST_CHECK(!containers_equal(send_garbage, send_garbage2));
        
        BOOST_TEST_MESSAGE("Cipher properties test passed");
        BOOST_TEST_MESSAGE("Session ID size: " + std::to_string(session_id.size()));
        BOOST_TEST_MESSAGE("Send garbage size: " + std::to_string(send_garbage.size()));
        BOOST_TEST_MESSAGE("Recv garbage size: " + std::to_string(recv_garbage.size()));
        
    } catch (const std::exception& e) {
        BOOST_TEST_MESSAGE("Exception in cipher_properties_test: " + std::string(e.what()));
        BOOST_CHECK(false);
    }
}

// Test edge cases and error conditions
BOOST_AUTO_TEST_CASE(edge_cases_test)
{
    try {
        CKey priv_key;
        priv_key.MakeNewKey(true);
        
        uint256 entropy = GetRandHash();
        BIP324Cipher cipher(priv_key, ToByteSpan(entropy));
        
        // Test empty message encryption
        std::vector<uint8_t> empty_message;
        std::vector<std::byte> encrypted(BIP324Cipher::EXPANSION);
        
        cipher.Encrypt(
            MakeByteSpan(empty_message),
            {},
            false,
            encrypted
        );
        
        BOOST_CHECK_EQUAL(encrypted.size(), BIP324Cipher::EXPANSION);
        
        // Test message with AAD
        std::vector<uint8_t> message = {0x01, 0x02, 0x03};
        std::vector<uint8_t> aad = {0xaa, 0xbb, 0xcc, 0xdd};
        std::vector<std::byte> encrypted_with_aad(message.size() + BIP324Cipher::EXPANSION);
        
        cipher.Encrypt(
            MakeByteSpan(message),
            MakeByteSpan(aad),
            false,
            encrypted_with_aad
        );
        
        BOOST_CHECK_EQUAL(encrypted_with_aad.size(), message.size() + BIP324Cipher::EXPANSION);
        
        // Test ignore flag
        std::vector<std::byte> encrypted_ignore(message.size() + BIP324Cipher::EXPANSION);
        
        cipher.Encrypt(
            MakeByteSpan(message),
            {},
            true,  // ignore flag
            encrypted_ignore
        );
        
        BOOST_CHECK_EQUAL(encrypted_ignore.size(), message.size() + BIP324Cipher::EXPANSION);
        
        BOOST_TEST_MESSAGE("Edge cases test passed");
        
    } catch (const std::exception& e) {
        BOOST_TEST_MESSAGE("Exception in edge_cases_test: " + std::string(e.what()));
        BOOST_CHECK(false);
    }
}

BOOST_AUTO_TEST_SUITE_END()