// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/blockfilters.json.h>
#include <test/test_bitcoin.h>

#include <clientversion.h>
#include <core_io.h>
#include <gcsfilter.h>
#include <random.h>
#include <serialize.h>
#include <streams.h>
#include <univalue.h>
#include <utilstrencodings.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(gcsfilter_tests)

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

    // Hash160 in P2PKH output of first non-coinbase tx in block.
    GCSFilter::Element output_script_pushdata(ParseHex("f15d1921f52e4007b146dfa60f369ed2fc393ce2"));
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

BOOST_AUTO_TEST_CASE(blockfilter_extended_test)
{
    CBlock block = getBlock13b8a();
    BlockFilter block_filter(BlockFilterType::EXTENDED, block);
    const GCSFilter& filter = block_filter.GetFilter();

    // Pubkey is scriptSig of tx 2 in block.
    GCSFilter::Element pushed_pubkey =
        ParseHex("042b4e8625a96127826915a5b109852636ad0da753c9e1d5606a50480cd0c40f1f8b8d898235e571fe9357d9ec842bc4bba1827daaf4de06d71844d0057707966a");
    BOOST_CHECK(filter.Match(pushed_pubkey));
}

BOOST_AUTO_TEST_CASE(blockfilters_json_test)
{
    UniValue json;
    std::string json_data(json_tests::blockfilters,
                          json_tests::blockfilters + sizeof(json_tests::blockfilters));
    if (!json.read(json_data) || !json.isArray()) {
        BOOST_ERROR("Parse error.");
        return;
    }

    const UniValue& tests = json.get_array();
    for (unsigned int i = 0; i < tests.size(); i++) {
        UniValue test = tests[i];
        std::string strTest = test.write();

        if (test.size() == 1) {
            continue;
        } else if (test.size() != 9) {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }

        unsigned int pos = 0;
        /*int block_height =*/ test[pos++].get_int();
        /*uint256 block_hash =*/ ParseHashUV(test[pos++], "block_hash");
        CBlock block;
        BOOST_REQUIRE(DecodeHexBlk(block, test[pos++].get_str()));
        uint256 prev_filter_header_basic = ParseHashUV(test[pos++], "prev_filter_header_basic");
        uint256 prev_filter_header_ext = ParseHashUV(test[pos++], "prev_filter_header_ext");
        std::vector<unsigned char> filter_basic = ParseHex(test[pos++].get_str());
        std::vector<unsigned char> filter_ext = ParseHex(test[pos++].get_str());
        uint256 filter_header_basic = ParseHashUV(test[pos++], "filter_header_basic");
        uint256 filter_header_ext = ParseHashUV(test[pos++], "filter_header_ext");

        BlockFilter computed_filter_basic(BlockFilterType::BASIC, block);
        BOOST_CHECK(computed_filter_basic.GetFilter().GetEncoded() == filter_basic);

        uint256 computed_header_basic = computed_filter_basic.ComputeHeader(prev_filter_header_basic);
        BOOST_CHECK(computed_header_basic == filter_header_basic);

        BlockFilter computed_filter_ext(BlockFilterType::EXTENDED, block);
        BOOST_CHECK(computed_filter_ext.GetFilter().GetEncoded() == filter_ext);

        uint256 computed_header_ext = computed_filter_ext.ComputeHeader(prev_filter_header_ext);
        BOOST_CHECK(computed_header_ext == filter_header_ext);
    }
}

BOOST_AUTO_TEST_SUITE_END()
