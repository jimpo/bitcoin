// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCKFILTER_H
#define BITCOIN_BLOCKFILTER_H

#include <set>
#include <stdint.h>
#include <vector>

#include <serialize.h>
#include <uint256.h>

/**
 * This implements a Golomb-coded set as defined in BIP 158. It is a
 * compact, probabilistic data structure for testing set membership.
 */
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

    /** Helper method used to implement Match and MatchAny */
    bool MatchInternal(const uint64_t* sorted_element_hashes, size_t size) const;

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
     * with probability 2^(-P).
     */
    bool Match(const Element& element) const;

    /**
     * Checks if any of the given elements may be in the set. False positives
     * are possible with probability 2^(-P) per element checked. This is more
     * efficient that checking Match on multiple elements separately.
     */
    bool MatchAny(const std::set<Element>& elements) const;
};

#endif // BITCOIN_BLOCKFILTER_H
