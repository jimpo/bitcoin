// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockfilter.h>
#include <random.h>

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

BOOST_AUTO_TEST_SUITE_END()
