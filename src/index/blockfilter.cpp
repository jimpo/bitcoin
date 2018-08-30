// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <map>

#include <dbwrapper.h>
#include <index/blockfilter.h>
#include <util.h>
#include <validation.h>

/* The index database stores three items for each block: the encoded filter, its D256 hash, and the
 * header. Those belonging to blocks on the active chain are indexed by height, and those belonging
 * to blocks that have been reorganized out of the active chain are indexed by block hash. This
 * ensures that filter data for any block that becomes part of the active chain can always be
 * retrieved, alleviating timing concerns.
 *
 * Keys for the height index have the type pair<char, pair<DB_BLOCK_HEIGHT, int>>.
 * Keys for the hash index have the type pair<char, pair<DB_BLOCK_HASH, int>>.
 */
constexpr char DB_FILTER = 'f';
constexpr char DB_FILTER_HASH = 'h';
constexpr char DB_FILTER_HEADER = 'r';

constexpr char DB_BLOCK_HASH = 's';
constexpr char DB_BLOCK_HEIGHT = 't';

static std::map<BlockFilterType, BlockFilterIndex> g_filter_indexes;

BlockFilterIndex::BlockFilterIndex(BlockFilterType filter_type,
                                   size_t n_cache_size, bool f_memory, bool f_wipe)
    : m_filter_type(filter_type)
{
    const std::string& filter_name = BlockFilterTypeName(filter_type);
    if (filter_name == "") throw std::invalid_argument("unknown filter_type");

    m_name = filter_name + " block filter index";
    m_db = MakeUnique<BaseIndex::DB>(GetDataDir() / "indexes" / "blockfilter" / filter_name,
                                     n_cache_size, f_memory, f_wipe);
}

bool BlockFilterIndex::WriteBlock(const CBlock& block, const CBlockIndex* pindex)
{
    CBlockUndo block_undo;
    uint256 prev_header;

    if (pindex->nHeight > 0) {
        if (!UndoReadFromDisk(block_undo, pindex)) {
            return false;
        }

        std::pair<uint256, uint256> read_out;
        std::pair<char, int> prev_height_key(DB_BLOCK_HEIGHT, pindex->nHeight - 1);
        if (!m_db->Read(std::make_pair(DB_FILTER_HEADER, prev_height_key), read_out)) {
            return false;
        }

        uint256 expected_block_hash = pindex->pprev->GetBlockHash();
        if (read_out.first != expected_block_hash) {
            return error("%s: previous block header belongs to unexpected block %s; expected %s",
                         __func__, read_out.first.ToString(), expected_block_hash.ToString());
        }

        prev_header = read_out.second;
    }

    BlockFilter filter(m_filter_type, block, block_undo);
    std::pair<char, int> height_key(DB_BLOCK_HEIGHT, pindex->nHeight);

    CDBBatch batch(*m_db);
    batch.Write(std::make_pair(DB_FILTER, height_key),
                std::make_pair(pindex->GetBlockHash(), filter.GetEncodedFilter()));
    batch.Write(std::make_pair(DB_FILTER_HASH, height_key),
                std::make_pair(pindex->GetBlockHash(), filter.GetHash()));
    batch.Write(std::make_pair(DB_FILTER_HEADER, height_key),
                std::make_pair(pindex->GetBlockHash(), filter.ComputeHeader(prev_header)));
    return m_db->WriteBatch(batch);
}

template <typename T>
static bool CopyHeightIndexToHashIndex(CDBIterator& db_it, CDBBatch& batch,
                                       const std::string& index_name, char key_prefix,
                                       int start_height, const CBlockIndex* stop_index)
{
    db_it.Seek(std::make_pair(key_prefix, std::make_pair(DB_BLOCK_HEIGHT, start_height)));

    for (int height = start_height; height <= stop_index->nHeight; ++height) {
        std::pair<char, std::pair<char, int>> key, expected_key;
        expected_key = std::make_pair(key_prefix, std::make_pair(DB_BLOCK_HEIGHT, height));

        if (!db_it.GetKey(key) || key != expected_key) {
            return error("%s: unexpected key in %s: expected (%c, (%c, %d))",
                         __func__, index_name, key_prefix, DB_BLOCK_HEIGHT, height);
        }

        std::pair<uint256, T> value;
        if (!db_it.GetValue(value)) {
            return error("%s: unable to read value in %s at key (%c, (%c, %d))",
                         __func__, index_name, key_prefix, DB_BLOCK_HEIGHT, height);
        }

        auto hash_key = std::make_pair(key_prefix, std::make_pair(DB_BLOCK_HASH, value.first));
        batch.Write(hash_key, std::move(value.second));

        db_it.Next();
    }
    return true;
}

bool BlockFilterIndex::Rewind(const CBlockIndex* current_tip, const CBlockIndex* new_tip)
{
    assert(current_tip->GetAncestor(new_tip->nHeight) == new_tip);

    CDBBatch batch(*m_db);
    std::unique_ptr<CDBIterator> db_it(m_db->NewIterator());

    if (!CopyHeightIndexToHashIndex<std::vector<unsigned char>>(*db_it, batch, m_name, DB_FILTER,
                                                                new_tip->nHeight, current_tip)) {
        return false;
    }
    if (!CopyHeightIndexToHashIndex<uint256>(*db_it, batch, m_name, DB_FILTER_HASH,
                                             new_tip->nHeight, current_tip)) {
        return false;
    }
    if (!CopyHeightIndexToHashIndex<uint256>(*db_it, batch, m_name, DB_FILTER_HEADER,
                                             new_tip->nHeight, current_tip)) {
        return false;
    }

    if (!m_db->WriteBatch(batch)) return false;

    return BaseIndex::Rewind(current_tip, new_tip);
}

template <typename T>
static bool LookupOne(const CDBWrapper& db, char key_prefix,
                      const CBlockIndex* block_index, T& result)
{
    // First check if the result is stored under the height index and the value there matches the
    // block hash. This should be the case if the block is on the active chain.
    std::pair<char, int> height_key(DB_BLOCK_HEIGHT, block_index->nHeight);
    std::pair<uint256, T> read_out;
    if (!db.Read(std::make_pair(key_prefix, height_key), read_out)) {
        return false;
    }
    if (read_out.first == block_index->GetBlockHash()) {
        result = std::move(read_out.second);
        return true;
    }

    // If value at the height index corresponds to an different block, the result will be stored in
    // the hash index.
    std::pair<char, uint256> hash_key(DB_BLOCK_HASH, block_index->GetBlockHash());
    return db.Read(std::make_pair(key_prefix, hash_key), result);
}

template <typename T>
static bool LookupRange(CDBWrapper& db, const std::string& index_name,
                        char key_prefix, int start_height, const CBlockIndex* stop_index,
                        std::vector<T>& results)
{
    if (start_height < 0) {
        return error("%s: start height (%d) is negative", __func__, start_height);
    }
    if (start_height > stop_index->nHeight) {
        return error("%s: start height (%d) is greater than stop height (%d)",
                     __func__, start_height, stop_index->nHeight);
    }

    std::vector<std::pair<uint256, T>> values(stop_index->nHeight - start_height + 1);

    std::unique_ptr<CDBIterator> db_it(db.NewIterator());
    db_it->Seek(std::make_pair(key_prefix, std::make_pair(DB_BLOCK_HEIGHT, start_height)));
    for (int height = start_height; height <= stop_index->nHeight; ++height) {
        std::pair<char, std::pair<char, int>> key, expected_key;
        expected_key = std::make_pair(key_prefix, std::make_pair(DB_BLOCK_HEIGHT, height));

        if (!db_it->Valid() || !db_it->GetKey(key) || key != expected_key) {
            return false;
        }

        size_t i = height - start_height;
        if (!db_it->GetValue(values[i])) {
            return error("%s: unable to read value in %s at key (%c, (%c, %d))",
                         __func__, index_name, key_prefix, DB_BLOCK_HEIGHT, height);
        }

        db_it->Next();
    }

    results.resize(stop_index->nHeight - start_height + 1);
    for (const CBlockIndex* block_index = stop_index;
         block_index && block_index->nHeight >= start_height;
         block_index = block_index->pprev) {
        uint256 block_hash = block_index->GetBlockHash();

        size_t i = block_index->nHeight - start_height;
        if (block_hash == values[i].first) {
            results[i] = std::move(values[i].second);
            continue;
        }

        std::pair<char, uint256> hash_key(DB_BLOCK_HASH, block_hash);
        if (!db.Read(std::make_pair(key_prefix, hash_key), results[i])) {
            return error("%s: unable to read value in %s at key (%c, (%c, %s))",
                         __func__, index_name, key_prefix, DB_BLOCK_HASH, block_hash.ToString());
        }
    }

    return true;
}

bool BlockFilterIndex::LookupFilter(const CBlockIndex* block_index, BlockFilter& filter_out) const
{
    std::vector<unsigned char> encoded_filter;
    if (!LookupOne(*m_db, DB_FILTER, block_index, encoded_filter)) {
        return false;
    }

    filter_out = BlockFilter(m_filter_type, block_index->GetBlockHash(), std::move(encoded_filter));
    return true;
}

bool BlockFilterIndex::LookupFilterHeader(const CBlockIndex* block_index, uint256& header_out) const
{
    return LookupOne(*m_db, DB_FILTER_HEADER, block_index, header_out);
}

bool BlockFilterIndex::LookupFilterRange(int start_height, const CBlockIndex* stop_index,
                                         std::vector<BlockFilter>& filters_out) const
{
    std::vector<std::vector<unsigned char>> encoded_filters;
    if (!LookupRange(*m_db, m_name, DB_FILTER, start_height, stop_index, encoded_filters)) {
        return false;
    }

    filters_out.resize(stop_index->nHeight - start_height + 1);

    auto it = filters_out.rbegin();
    auto encoded_filter_it = encoded_filters.rbegin();
    const CBlockIndex* pindex = stop_index;

    while (it != filters_out.rend()) {
        *it = BlockFilter(m_filter_type, pindex->GetBlockHash(), std::move(*encoded_filter_it));

        ++it;
        ++encoded_filter_it;
        pindex = pindex->pprev;
    }

    return true;
}

bool BlockFilterIndex::LookupFilterHashRange(int start_height, const CBlockIndex* stop_index,
                                             std::vector<uint256>& hashes_out) const
{
    return LookupRange(*m_db, m_name, DB_FILTER_HASH, start_height, stop_index, hashes_out);
}

BlockFilterIndex* GetBlockFilterIndex(BlockFilterType filter_type)
{
    auto it = g_filter_indexes.find(filter_type);
    return it != g_filter_indexes.end() ? &it->second : nullptr;
}

void ForEachBlockFilterIndex(std::function<void (BlockFilterIndex&)> fn)
{
    for (auto& entry : g_filter_indexes) fn(entry.second);
}

bool InitBlockFilterIndex(BlockFilterType filter_type,
                          size_t n_cache_size, bool f_memory, bool f_wipe)
{
    auto result = g_filter_indexes.emplace(std::piecewise_construct,
                                           std::forward_as_tuple(filter_type),
                                           std::forward_as_tuple(filter_type,
                                                                 n_cache_size, f_memory, f_wipe));
    return result.second;
}

bool DestroyBlockFilterIndex(BlockFilterType filter_type)
{
    return g_filter_indexes.erase(filter_type);
}

void DestroyAllBlockFilterIndexes()
{
    g_filter_indexes.clear();
}
