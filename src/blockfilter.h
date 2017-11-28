// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_GCSFILTER_H
#define BITCOIN_GCSFILTER_H

#include <set>
#include <stdint.h>
#include <vector>

#include <primitives/block.h>
#include <serialize.h>
#include <uint256.h>

class GCSFilter
{
public:
    typedef std::vector<unsigned char> Element;

private:
    uint64_t m_siphash_k0;
    uint64_t m_siphash_k1;
    uint8_t m_P;
    uint64_t m_N;
    uint64_t m_F;
    std::vector<unsigned char> m_encoded;

    /** Hash a data element to an integer in the range [0, F). */
    uint64_t HashToRange(const Element& element) const;

    std::vector<uint64_t> BuildHashedSet(const std::set<Element>& elements) const;

public:

    /** Constructs an empty filter. */
    GCSFilter(uint64_t siphash_k0 = 0, uint64_t siphash_k1 = 0, uint8_t logP = 0);

    /** Reconstructs an already-created filter from an encoding. */
    GCSFilter(uint64_t siphash_k0, uint64_t siphash_k1, uint8_t P,
              std::vector<unsigned char> encoded_filter);

    /** Builds a new filter from the params and set of elements. */
    GCSFilter(uint64_t siphash_k0, uint64_t siphash_k1, uint8_t P,
              const std::set<Element>& elements);

    uint64_t GetN() const { return m_N; }
    uint8_t GetP() const { return m_P; }
    const std::vector<unsigned char>& GetEncoded() const { return m_encoded; }

    /**
     * Checks if the element may be in the set. False positives are possible
     * with expected rate P.
     */
    bool Match(const Element& element) const;

    /**
     * Checks if any of the given elements may be in the set. False positives
     * are possible with expected rate P per element checked. This is more
     * efficient that checking Match on multiple elements separately.
     */
    bool MatchAny(const std::set<Element>& elements) const;
};

static constexpr uint8_t BASIC_FILTER_FP_RATE = 20;
static constexpr uint8_t EXTENDED_FILTER_FP_RATE = 20;

enum BlockFilterType : uint8_t
{
    BASIC = 0,
    EXTENDED = 1,
};

/**
 * Complete block filter struct as defined in BIP YYY. Serialization matches
 * payload of "cfilter" messages.
 */
class BlockFilter
{
private:
    BlockFilterType m_filter_type;
    uint256 m_block_hash;
    GCSFilter m_filter;

public:

    BlockFilter(BlockFilterType filter_type, const CBlock& block);

    BlockFilterType GetFilterType() const { return m_filter_type; }

    const GCSFilter& GetFilter() const { return m_filter; }

    uint256 GetHash() const;

    uint256 ComputeHeader(const uint256& prev_header) const;

    template <typename Stream>
    void Serialize(Stream& s) const {
        s << m_block_hash
          << m_filter_type
          << m_filter.GetEncoded();
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        std::vector<unsigned char> encoded_filter;

        s >> m_block_hash
          >> m_filter_type
          >> encoded_filter;

        switch (m_filter_type) {
        case BlockFilterType::BASIC:
            m_filter = GCSFilter(m_block_hash.GetUint64(0), m_block_hash.GetUint64(1),
                                 BASIC_FILTER_FP_RATE, std::move(encoded_filter));
        break;

        case BlockFilterType::EXTENDED:
            m_filter = GCSFilter(m_block_hash.GetUint64(0), m_block_hash.GetUint64(1),
                                 EXTENDED_FILTER_FP_RATE, std::move(encoded_filter));
            break;
        }
    }
};

#endif // BITCOIN_GCSFILTER_H
