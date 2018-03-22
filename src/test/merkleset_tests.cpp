// Copyright (c) 2012-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <merkleset.h>
#include <uint256.h>
#include <test/test_bitcoin.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(merkleset_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(merkleset_sanity_test)
{
    MerkleSet merkle_set(/*chunk_size=*/ 1024);

    std::vector<std::pair<uint256, MerkleSet::UpdateOp>> hashes;
    hashes.reserve(256);
    for (int i = 0; i < 5; i++) {
        std::vector<unsigned char> hash_data(32);
        hash_data[0] = static_cast<unsigned char>(i);

        hashes.emplace_back(uint256(hash_data), MerkleSet::UpdateOp::INSERT);
    }

    BOOST_TEST_MESSAGE("Prior root hash: " << merkle_set.RootHash().GetHex());
    merkle_set.Update(std::move(hashes));
    BOOST_TEST_MESSAGE("Post root hash: " << merkle_set.RootHash().GetHex());

    BOOST_FAIL("Just because");
}

BOOST_AUTO_TEST_SUITE_END()
