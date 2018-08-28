// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <map>

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
