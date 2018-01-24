// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/test_bitcoin.h>

#include <blockfilter.h>
#include <random.h>
#include <serialize.h>
#include <streams.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(blockfilter_tests)

BOOST_AUTO_TEST_CASE(gcsfilter_test)
{
    std::set<GCSFilter::Element> included_elements, excluded_elements;
    for (int i = 0; i < 100; ++i) {
        GCSFilter::Element rand1(32);
        GetRandBytes(rand1.data(), rand1.size());
        included_elements.insert(std::move(rand1));

        GCSFilter::Element rand2(32);
        GetRandBytes(rand2.data(), rand2.size());
        excluded_elements.insert(std::move(rand2));
    }

    GCSFilter filter(0, 0, 10, included_elements);
    for (const auto& element : included_elements) {
        BOOST_CHECK(filter.Match(element));

        auto insertion = excluded_elements.insert(element);
        BOOST_CHECK(filter.MatchAny(excluded_elements));
        excluded_elements.erase(insertion.first);
    }
}

BOOST_AUTO_TEST_CASE(blockfilter_basic_test)
{
    CBlock block = getBlock13b8a();
    BlockFilter block_filter(BlockFilterType::BASIC, block);
    const GCSFilter& filter = block_filter.GetFilter();

    // TXID of first non-coinbase tx in block.
    const uint256& txid = uint256S("f9fc751cb7dc372406a9f8d738d5e6f8f63bab71986a39cf36ee70ee17036d07");
    GCSFilter::Element txid_element(txid.begin(), txid.end());
    BOOST_CHECK(filter.Match(txid_element));

    // Outpoint spent by first non-coinbase tx in block.
    COutPoint prevout(uint256S("36e8f98c5f5733f88ca00dfa05afd7af5dc34dda802790daba6aa1afcb8c6096"), 0);
    GCSFilter::Element prevout_element;
    CVectorWriter(SER_NETWORK, 0, prevout_element, 0, prevout);
    BOOST_CHECK(filter.Match(prevout_element));

    // P2PKH output script of first non-coinbase tx in block.
    GCSFilter::Element output_script_pushdata(ParseHex("76a914f15d1921f52e4007b146dfa60f369ed2fc393ce288ac"));
    BOOST_CHECK(filter.Match(output_script_pushdata));

    // Filter does match coinbase TXID.
    const uint256& coinbase_txid = block.vtx[0]->GetHash();
    GCSFilter::Element coinbase_txid_element(coinbase_txid.begin(), coinbase_txid.end());
    BOOST_CHECK(filter.Match(coinbase_txid_element));

    // Filter does *not* match coinbase prevout.
    COutPoint coinbase_prevout;
    GCSFilter::Element coinbase_prevout_element;
    CVectorWriter(SER_NETWORK, 0, coinbase_prevout_element, 0, coinbase_prevout);
    BOOST_CHECK(!filter.Match(coinbase_prevout_element));
}

BOOST_AUTO_TEST_SUITE_END()
