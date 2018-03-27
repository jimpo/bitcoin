// Copyright (c) 2012-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/sha256.h>
#include <merkleset.h>
#include <uint256.h>
#include <test/test_bitcoin.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(merkleset_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(merkleset_sanity_test)
{
    MerkleSet merkle_set(/*chunk_size=*/ 1520);

    std::vector<uint256> hashes(1000);
    for (uint i = 0; i < hashes.size(); ++i) {
        CSHA256().
            Write(reinterpret_cast<unsigned char*>(&i), sizeof(i)).
            Finalize(hashes[i].begin());
    }

    std::vector<std::pair<uint256, MerkleSet::UpdateOp>> inserts;
    inserts.reserve(hashes.size());
    for (const uint256& hash : hashes) {
        inserts.emplace_back(hash, MerkleSet::UpdateOp::INSERT);
    }

    BOOST_TEST_MESSAGE("Prior root hash: " << merkle_set.RootHash().GetHex());
    merkle_set.Update(std::move(inserts));
    BOOST_TEST_MESSAGE("Post root hash: " << merkle_set.RootHash().GetHex());

    std::vector<std::pair<uint256, MerkleSet::UpdateOp>> removes;
    removes.reserve(hashes.size());
    for (const uint256& hash : hashes) {
        removes.emplace_back(hash, MerkleSet::UpdateOp::REMOVE);
    }

    BOOST_TEST_MESSAGE("Prior root count: " << merkle_set.Count());
    BOOST_TEST_MESSAGE("Prior root hash: " << merkle_set.RootHash().GetHex());
    merkle_set.Update(std::move(removes));
    BOOST_TEST_MESSAGE("Post root hash: " << merkle_set.RootHash().GetHex());
    BOOST_TEST_MESSAGE("Post root count: " << merkle_set.Count());
}

BOOST_AUTO_TEST_SUITE_END()
