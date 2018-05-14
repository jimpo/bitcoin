// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <random.h>
#include <blockfilter.h>

static void ConstructGCSFilter(benchmark::State& state)
{
    std::set<GCSFilter::Element> elements;
    for (int i = 0; i < 10000; i++) {
        GCSFilter::Element element(32);
        GetRandBytes(element.data(), element.size());
        elements.insert(std::move(element));
    }

    uint64_t siphash_k0 = 0;
    while (state.KeepRunning()) {
        GCSFilter filter(siphash_k0, 0, 20, elements);

        siphash_k0++;
    }
}

static void MatchGCSFilter(benchmark::State& state)
{
    std::set<GCSFilter::Element> elements;
    for (int i = 0; i < 10000; i++) {
        GCSFilter::Element element(32);
        GetRandBytes(element.data(), element.size());
        elements.insert(std::move(element));
    }
    GCSFilter filter(0, 0, 20, elements);

    while (state.KeepRunning()) {
        filter.Match(GCSFilter::Element());
    }
}

BENCHMARK(ConstructGCSFilter, 1000);
BENCHMARK(MatchGCSFilter, 50 * 1000);
