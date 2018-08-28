// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_BLOCKFILTER_H
#define BITCOIN_INDEX_BLOCKFILTER_H

#include <blockfilter.h>
#include <chain.h>
#include <index/base.h>

/**
 * BlockFilterIndex is used to store and retrieve block filters, hashes, and headers for a range of
 * blocks by height. An index is constructed for each supported filter type with its own database
 * (ie. filter data for different types are stored in differente databases).
 *
 * This index is used to serve BIP 157 net requests.
 */
class BlockFilterIndex final : public BaseIndex
{
private:
    BlockFilterType m_filter_type;
    std::string m_name;
    std::unique_ptr<BaseIndex::DB> m_db;

protected:
    bool WriteBlock(const CBlock& block, const CBlockIndex* pindex) override;

    bool Rewind(const CBlockIndex* current_tip, const CBlockIndex* new_tip) override;

    BaseIndex::DB& GetDB() const override { return *m_db; }

    const char* GetName() const override { return m_name.c_str(); }

public:
    /** Constructs the index, which becomes available to be queried. */
    explicit BlockFilterIndex(BlockFilterType filter_type,
                              size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    BlockFilterType GetFilterType() const { return m_filter_type; }

    /** Get a single filter by block. */
    bool LookupFilter(const CBlockIndex* block_index, BlockFilter& filter_out) const;

    /** Get a single filter header by block. */
    bool LookupFilterHeader(const CBlockIndex* block_index, uint256& header_out) const;

    /** Get a range of filters between two heights on a chain. */
    bool LookupFilterRange(int start_height, const CBlockIndex* stop_index,
                           std::vector<BlockFilter>& filters_out) const;

    /** Get a range of filter hashes between two heights on a chain. */
    bool LookupFilterHashRange(int start_height, const CBlockIndex* stop_index,
                               std::vector<uint256>& hashes_out) const;
};

#endif // BITCOIN_INDEX_BLOCKFILTER_H
