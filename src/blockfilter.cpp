// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockfilter.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>

static constexpr int GCS_SER_TYPE = SER_NETWORK;
static constexpr int GCS_SER_VERSION = 0;

template <typename OStream>
static void GolombRiceEncode(BitStreamWriter<OStream>& bitwriter, uint8_t k, uint64_t n)
{
    // Write quotient as unary-encoded: q 1's followed by one 0.
    uint64_t q = n >> k;
    while (q > 0) {
        int nbits = q <= 64 ? static_cast<int>(q) : 64;
        bitwriter.Write(~0ULL, nbits);
        q -= nbits;
    }
    bitwriter.Write(0, 1);

    // Write the remainder in k bits. Since the remainder is just the bottom
    // k bits of n, there is no need to mask first.
    bitwriter.Write(n, k);
}

template <typename IStream>
static uint64_t GolombRiceDecode(BitStreamReader<IStream>& bitreader, uint8_t k)
{
    // Read unary-encoded quotient: q 1's followed by one 0.
    uint64_t q = 0;
    while (bitreader.Read(1) == 1) {
        q++;
    }

    uint64_t r = bitreader.Read(k);

    return (q << k) + r;
}

// Map a value x that is uniformly distributed in the range [0, 2^64) to a
// value uniformly distributed in [0, n) by returning the upper 64 bits of
// x * n.
//
// See: https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
static uint64_t MapIntoRange(uint64_t x, uint64_t n)
{
    // To perform the calculation on 64-bit numbers without losing the
    // result to overflow, split the numbers into the most significant and
    // least significant 32 bits and perform multiplication piece-wise.
    //
    // See: https://stackoverflow.com/a/26855440
    uint64_t x_hi = x >> 32;
    uint64_t x_lo = x & 0xFFFFFFFF;
    uint64_t n_hi = n >> 32;
    uint64_t n_lo = n & 0xFFFFFFFF;

    uint64_t ac = x_hi * n_hi;
    uint64_t ad = x_hi * n_lo;
    uint64_t bc = x_lo * n_hi;
    uint64_t bd = x_lo * n_lo;

    uint64_t mid34 = (bd >> 32) + (bc & 0xFFFFFFFF) + (ad & 0xFFFFFFFF);
    uint64_t upper64 = ac + (bc >> 32) + (ad >> 32) + (mid34 >> 32);
    return upper64;
}

uint64_t GCSFilter::HashToRange(const Element& element) const
{
    uint64_t hash = CSipHasher(m_siphash_k0, m_siphash_k1)
        .Write(element.data(), element.size())
        .Finalize();
    return MapIntoRange(hash, m_F);
}

std::vector<uint64_t> GCSFilter::BuildHashedSet(const std::set<Element>& elements) const
{
    std::vector<uint64_t> hashed_elements;
    hashed_elements.reserve(elements.size());
    for (const Element& element : elements) {
        hashed_elements.push_back(HashToRange(element));
    }
    std::sort(hashed_elements.begin(), hashed_elements.end());
    return hashed_elements;
}

GCSFilter::GCSFilter(uint64_t siphash_k0, uint64_t siphash_k1, uint8_t P)
    : m_siphash_k0(siphash_k0), m_siphash_k1(siphash_k1), m_P(P), m_N(0), m_F(0)
{
    if (m_P > 32) {
        throw std::invalid_argument("P must be <=32");
    }
}

GCSFilter::GCSFilter(uint64_t siphash_k0, uint64_t siphash_k1, uint8_t P,
                     std::vector<unsigned char> encoded_filter)
    : GCSFilter(siphash_k0, siphash_k1, P)
{
    m_encoded = std::move(encoded_filter);

    CVectorReader stream(GCS_SER_TYPE, GCS_SER_VERSION, m_encoded, 0);

    m_N = ReadCompactSize(stream);
    m_F = m_N << m_P;

    if (m_N >= (1ULL << 32)) {
        throw std::invalid_argument("N must be <2^32");
    }

    // Surface any errors decoding the filter on construction.
    BitStreamReader<CVectorReader> bitreader(stream);
    for (uint64_t i = 0; i < m_N; i++) {
        GolombRiceDecode(bitreader, m_P);
    }
}

GCSFilter::GCSFilter(uint64_t siphash_k0, uint64_t siphash_k1, uint8_t P,
                     const std::set<GCSFilter::Element>& elements)
    : GCSFilter(siphash_k0, siphash_k1, P)
{
    if (elements.size() >= (1ULL << 32)) {
        throw std::invalid_argument("N must be <2^32");
    }

    m_N = elements.size();
    m_F = m_N << m_P;

    CVectorWriter stream(GCS_SER_TYPE, GCS_SER_VERSION, m_encoded, 0);

    WriteCompactSize(stream, m_N);

    if (elements.empty()) {
        return;
    }

    BitStreamWriter<CVectorWriter> bitwriter(stream);

    uint64_t last_value = 0;
    for (uint64_t value : BuildHashedSet(elements)) {
        uint64_t delta = value - last_value;
        GolombRiceEncode(bitwriter, m_P, delta);
        last_value = value;
    }

    bitwriter.Flush();
}

bool GCSFilter::Match(const GCSFilter::Element& element) const
{
    uint64_t query = HashToRange(element);

    CVectorReader stream(GCS_SER_TYPE, GCS_SER_VERSION, m_encoded, 0);

    // Seek forward by size of N
    uint64_t N = ReadCompactSize(stream);
    assert(N == m_N);

    BitStreamReader<CVectorReader> bitreader(stream);

    uint64_t value = 0;
    for (uint64_t i = 0; i < m_N; i++) {
        uint64_t delta = GolombRiceDecode(bitreader, m_P);
        value += delta;

        if (query == value) {
            return true;
        } else if (query < value) {
            break;
        }
    }

    return false;
}

bool GCSFilter::MatchAny(const std::set<Element>& elements) const
{
    const std::vector<uint64_t>&& queries = BuildHashedSet(elements);

    CVectorReader stream(GCS_SER_TYPE, GCS_SER_VERSION, m_encoded, 0);

    // Seek forward by size of N
    uint64_t N = ReadCompactSize(stream);
    assert(N == m_N);

    BitStreamReader<CVectorReader> bitreader(stream);

    uint64_t value = 0;
    auto query_it = queries.begin();
    for (uint64_t i = 0; i < m_N; i++) {
        uint64_t delta = GolombRiceDecode(bitreader, m_P);
        value += delta;

        while (true) {
            if (query_it == queries.end()) {
                return false;
            } else if (*query_it == value) {
                return true;
            } else if (*query_it > value) {
                break;
            }

            query_it++;
        }
    }

    return false;
}

static std::set<GCSFilter::Element> BasicFilterElements(const CBlock& block)
{
    std::set<GCSFilter::Element> elements;
    for (const CTransactionRef& tx : block.vtx) {
        // Include txid of each transaction.
        const uint256& txid = tx->GetHash();
        elements.emplace(txid.begin(), txid.end());

        // Include previous outpoint of each input, except for coinbase.
        if (!tx->IsCoinBase()) {
            for (const CTxIn& txin : tx->vin) {
                std::vector<unsigned char> ser_outpoint;
                CVectorWriter(GCS_SER_TYPE, GCS_SER_VERSION, ser_outpoint, 0, txin.prevout);
                elements.insert(std::move(ser_outpoint));
            }
        }

        // Include all data pushes in output scripts.
        for (const CTxOut& txout : tx->vout) {
            // Skip unparseable scripts.
            if (!txout.scriptPubKey.HasValidOps()) {
                continue;
            }

            CScript::const_iterator pc = txout.scriptPubKey.begin();
            opcodetype opcode_dummy;
            std::vector<unsigned char> data;
            while (txout.scriptPubKey.GetOp(pc, opcode_dummy, data)) {
                if (!data.empty()) {
                    elements.insert(std::move(data));
                }
            }
        }
    }

    return elements;
}

static std::set<GCSFilter::Element> ExtendedFilterElements(const CBlock& block)
{
    std::set<GCSFilter::Element> elements;
    for (const CTransactionRef& tx : block.vtx) {
        if (!tx->IsCoinBase()) {
            for (const CTxIn& txin : tx->vin) {
                // Include all data pushes in input scripts.
                CScript::const_iterator pc = txin.scriptSig.begin();
                opcodetype opcode_dummy;
                std::vector<unsigned char> data;
                while (txin.scriptSig.GetOp(pc, opcode_dummy, data)) {
                    if (!data.empty()) {
                        elements.insert(std::move(data));
                    }
                }

                // Include all script witnesses.
                for (const auto& data : txin.scriptWitness.stack) {
                    elements.insert(data);
                }
            }
        }
    }

    return elements;
}

BlockFilter::BlockFilter(BlockFilterType filter_type, const CBlock& block)
    : m_filter_type(filter_type), m_block_hash(block.GetHash())
{
    switch (m_filter_type) {
    case BlockFilterType::BASIC:
        m_filter = GCSFilter(m_block_hash.GetUint64(0), m_block_hash.GetUint64(1),
                             BASIC_FILTER_FP_RATE, BasicFilterElements(block));
        break;

    case BlockFilterType::EXTENDED:
        m_filter = GCSFilter(m_block_hash.GetUint64(0), m_block_hash.GetUint64(1),
                             EXTENDED_FILTER_FP_RATE, ExtendedFilterElements(block));
        break;

    default:
        throw std::invalid_argument("unknown filter_type");
    }
}

uint256 BlockFilter::GetHash() const
{
    const auto& data = m_filter.GetEncoded();

    uint256 result;
    CHash256().Write(data.data(), data.size()).Finalize(result.begin());
    return result;
}

uint256 BlockFilter::ComputeHeader(const uint256& prev_header) const
{
    const uint256& filter_hash = GetHash();

    uint256 result;
    CHash256()
        .Write(filter_hash.begin(), filter_hash.size())
        .Write(prev_header.begin(), prev_header.size())
        .Finalize(result.begin());
    return result;
}
