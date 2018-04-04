// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mmr.h>
#include <uint256.h>
#include <util.h>
#include <utilstrencodings.h>
#include <test/test_bitcoin.h>

#include <boost/test/unit_test.hpp>


BOOST_FIXTURE_TEST_SUITE(mmmr_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mmmr_sanity_test)
{
    MMMR mmmr(MakeUnique<MMMRDB>(1 << 20, true));

    uint256 root_hash1 = mmmr.RootHash();
    BOOST_TEST_MESSAGE("Root hash: " << root_hash1.GetHex());

    std::vector<uint256> hashes;
    hashes.reserve(255);
    for (uint i = 0; i < 255; i++) {
        BaseHashWriter<CSHA256> hash_writer(SER_GETHASH, 0);
        hash_writer << i;
        hashes.push_back(hash_writer.GetHash());
    }

    // Add the first 127 leaves.
    for (uint i = 0; i < 127; i++) {
        mmmr.Append({hashes[i]});
    }
    uint256 root_hash2 = mmmr.RootHash();

    // Add 128 more leaves.
    for (uint i = 127; i < 255; i++) {
        mmmr.Append({hashes[i]});
    }
    uint256 root_hash3 = mmmr.RootHash();

    // Remove leaves one by one in forward starting from the front.
    for (uint i = 0; i < 255; i++) {
        mmmr.Remove({i});
    }
    uint256 root_hash4 = mmmr.RootHash();

    // Re-add the removed leaves.
    for (uint i = 0; i < 255; i++) {
        mmmr.Insert({{i, hashes[i]}});
    }
    uint256 root_hash5 = mmmr.RootHash();
    BOOST_CHECK(root_hash3 == root_hash5);

    // Remove leaves one by one in reverse order from the back.
    for (uint i = 0; i < 255; i++) {
        mmmr.Remove({255 - i - 1});
    }
    uint256 root_hash6 = mmmr.RootHash();
    BOOST_CHECK(root_hash4 == root_hash6);

    // Re-add the removed leaves.
    for (uint i = 0; i < 255; i++) {
        mmmr.Insert({{255 - i - 1, hashes[255 - i - 1]}});
    }
    uint256 root_hash7 = mmmr.RootHash();
    BOOST_CHECK(root_hash5 == root_hash7);

    // Rewind to index 127.
    mmmr.Rewind(128);
    uint256 root_hash8 = mmmr.RootHash();
    BOOST_CHECK(root_hash2 == root_hash8);

    // Rewind to index 0.
    mmmr.Rewind(127);
    uint256 root_hash9 = mmmr.RootHash();
    BOOST_CHECK(root_hash1 == root_hash9);
}

BOOST_AUTO_TEST_SUITE_END()
