// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <test/test_bitcoin.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(chain_mmr_tests)

BOOST_FIXTURE_TEST_CASE(chain_mmr_test, TestChain100Setup)
{
    for (int i = 0; i <= 100; i++) {
        uint256 commitment = chainActive.GenerateMMRCommitment(i);
        for (int j = 0; j <= i; j++) {
            std::vector<uint256> proof = chainActive.GenerateMMRProof(j, i);
            BOOST_CHECK(VerifyChainMMRProof(j, i, chainActive[j]->GetBlockHash(), commitment, proof));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
