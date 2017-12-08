// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/txindex.h>
#include <test/test_bitcoin.h>
#include <utiltime.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(txindex_tests)

BOOST_FIXTURE_TEST_CASE(txindex_initial_sync, TestChain100Setup)
{
    TxIndex txindex(pblocktree);
    txindex.Start();

    // Allow tx index to catch up with the block index.
    constexpr int64_t timeout_ms = 10 * 1000;
    int64_t time_start = GetTimeMillis();
    while (!txindex.BlockUntilSyncedToCurrentChain()) {
        BOOST_REQUIRE(time_start + timeout_ms > GetTimeMillis());
        MilliSleep(100);
    }

    for (const auto& txn : coinbaseTxns) {
        CDiskTxPos postx;
        BOOST_CHECK(txindex.FindTx(txn.GetHash(), postx));
    }

    for (int i = 0; i < 10; i++) {
        CScript coinbase_script_pub_key = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
        std::vector<CMutableTransaction> no_txns;
        const CBlock& block = CreateAndProcessBlock(no_txns, coinbase_script_pub_key);
        const CTransaction& txn = *block.vtx[0];

        const CBlockIndex* pindex;
        {
            LOCK(cs_main);
            auto it = mapBlockIndex.find(block.GetBlockHeader().GetHash());
            BOOST_REQUIRE(it != mapBlockIndex.end());
            pindex = it->second;
        }

        // Would normally get called by the scheduler if it were running.
        std::vector<CTransactionRef> txn_conflicted;
        txindex.BlockConnected(std::make_shared<const CBlock>(block), pindex, txn_conflicted);

        CDiskTxPos actual_postx;
        BOOST_CHECK(txindex.FindTx(txn.GetHash(), actual_postx));
    }
}

BOOST_AUTO_TEST_SUITE_END()
