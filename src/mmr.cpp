// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>
#include <bitset>
#include <iostream>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <mmr.h>
#include <primitives/block.h>
#include <utilmath.h>
#include <validation.h>

static const char DB_NEXT_INDEX = 'I';
static const char DB_ENTRIES = 'e';
static const char DB_BEST_BLOCK = 'B';

std::unique_ptr<MMR> g_mmr;

// Assuming there is a peak at index i-1, the number of peaks at indices less
// than i is given by the number of bits set in the binary representation of i.
static int NumOfPeaksBeforeIndex(uint64_t idx)
{
    return std::bitset<64>(idx).count();
}

// Returns the height of the peak containing insertion index idx in an MMR with
// the given total inserted entries.
static uint PeakHeight(uint64_t idx, uint64_t total)
{
    return Log2Floor(static_cast<uint32_t>(idx ^ total));
}

static uint EntryListSize(uint64_t idx)
{
    return PeakHeight(idx, idx + 1) + 1;
}

void MMRDB::Entry::Clear()
{
    m_count = 0;
    m_hash.SetNull();
}

MMRDB::EntryList::EntryList(size_t capacity)
{
    m_entries.reserve(capacity);
}

bool MMRDB::EntryList::Empty() const
{
    for (const Entry& entry : m_entries) {
        if (entry.m_count > 0) {
            return false;
        }
    }
    return true;
}

void MMRDB::EntryList::Clear(size_t size)
{
    for (size_t i = 0; i < std::min(size, m_entries.size()); ++i) {
        m_entries[i].Clear();
    }
    m_entries.resize(size);
}

MMRDB::MMRDB(size_t cache_size, bool f_memory, bool f_wipe) :
    CDBWrapper(GetDataDir() / "utxommr", cache_size, f_memory, f_wipe)
{}

bool MMRDB::ReadNextIndex(uint64_t& index) const
{
    if (Read(DB_NEXT_INDEX, index)) {
        return true;
    }
    if (!Exists(DB_NEXT_INDEX)) {
        index = 0;
        return true;
    }
    return false;
}

void MMRDB::WriteNextIndex(CDBBatch& batch, const uint64_t index)
{
    batch.Write(DB_NEXT_INDEX, index);
}

bool MMRDB::ReadBestBlock(uint256& block_hash) const
{
    return Read(DB_BEST_BLOCK, block_hash);
}

void MMRDB::WriteBestBlock(const uint256& block_hash)
{
    Write(DB_BEST_BLOCK, block_hash);
}

bool MMRDB::ReadEntries(uint64_t index, MMRDB::EntryList& entry_list) const
{
    auto key = std::make_pair(DB_ENTRIES, index);
    if (Read(key, entry_list)) {
        if (entry_list.m_entries.size() != EntryListSize(index)) {
            return error("MMR entry list read has unexpected size");
        }
        return true;
    }
    if (!Exists(key)) {
        entry_list.Clear(EntryListSize(index));
        return true;
    }
    return false;
}

void MMRDB::WriteEntries(CDBBatch& batch, uint64_t index, const MMRDB::EntryList& entry_list)
{
    auto key = std::make_pair(DB_ENTRIES, index);
    if (entry_list.Empty()) {
        batch.Erase(key);
    } else {
        batch.Write(key, entry_list);
    }
}

void MMRDB::CompactEntries(uint64_t start_index, uint64_t end_index)
{
    int64_t start_time = GetTimeMicros();
    CompactRange(std::make_pair(DB_ENTRIES, start_index),
                 std::make_pair(DB_ENTRIES, end_index));
    int64_t end_time = GetTimeMicros();
    LogPrintf("MMR compaction time %s us\n", end_time - start_time);
}

MMR::MMR(std::unique_ptr<MMRDB> db) : m_db(std::move(db))
{
    assert(m_db->ReadNextIndex(m_next_index));
    assert(RefreshPeakCache());
}

uint256 MMR::RootHash() const
{
    MMRDB::Entry root;
    root.m_count = 0;

    // First hash in chain is a commitment to the MMR size.
    root.m_hash = (BaseHashWriter<CSHA256>(SER_GETHASH, 0) << m_next_index).GetHash();

    for (auto it = m_peak_cache.rbegin(); it != m_peak_cache.rend(); ++it) {
        // Entry hash is a commitment to child counts and hashes.
        BaseHashWriter<CSHA256> hash_writer(SER_GETHASH, 0);
        hash_writer << *it << root;

        root.m_count += it->m_count;
        root.m_hash = hash_writer.GetHash();
    }

    return (BaseHashWriter<CSHA256>(SER_GETHASH, 0) << root).GetHash();
}

uint32_t MMR::LeafCount() const
{
    uint32_t count = 0;
    for (const auto& entry : m_peak_cache) {
        count += entry.m_count;
    }
    return count;
}

uint256 MMR::BestBlock() const
{
    uint256 block_hash;
    m_db->ReadBestBlock(block_hash);
    return block_hash;
}

void MMR::Append(CDBBatch& batch, const MMRDB::Entry& entry)
{
    uint64_t index = m_next_index++;
    int peak_height = PeakHeight(index, m_next_index);

    // Entries are all of the intermediate hashes at each index representing
    // roots of the merkle subtrees at height i.
    MMRDB::EntryList entry_list(peak_height + 1);

    auto& entries = entry_list.m_entries;
    entries.resize(peak_height + 1);
    entries[0] = entry;

    for (int height = 1; height <= peak_height; ++height) {
        MMRDB::Entry& left_peak = m_peak_cache.back();
        MMRDB::Entry& right_peak = entries[height - 1];

        // Entry count is the sum of child counts.
        entries[height].m_count = left_peak.m_count + right_peak.m_count;

        // Entry hash is a commitment to child counts and hashes.
        BaseHashWriter<CSHA256> hash_writer(SER_GETHASH, 0);
        hash_writer << left_peak << right_peak;
        entries[height].m_hash = hash_writer.GetHash();

        m_peak_cache.pop_back();
    }

    m_db->WriteEntries(batch, index, entry_list);
    m_db->WriteNextIndex(batch, m_next_index);

    // The last entry at the last index is a new peak.
    m_peak_cache.push_back(entries.back());
}

void MMR::Rewind(size_t hashes_count)
{
    CDBBatch batch(*m_db);

    uint64_t new_next_index = m_next_index - hashes_count;
    m_db->WriteNextIndex(batch, new_next_index);

    MMRDB::EntryList empty_entry_list(0);
    for (uint64_t index = new_next_index; index < m_next_index; ++index) {
        m_db->WriteEntries(batch, index, empty_entry_list);
    }

    assert(m_db->WriteBatch(batch));
    m_next_index = new_next_index;

    assert(RefreshPeakCache());
}

uint64_t MMR::UpdateParents(CDBBatch& batch, MMRDB::EntryList& right_entry_list, uint64_t index, uint64_t next_index, uint peak_height, uint& update_count)
{
    MMRDB::EntryList left_entry_list(/*capacity=*/peak_height + 1);

    for (uint height = 1; height <= peak_height; ++height) {
        uint64_t last_index = index;
        index |= (1ULL << (height - 1));

        if (index == last_index) {
            // The right entry list stays the same, so no need to flush it
            // yet. Just load the next left_entry_list.
            uint64_t left_index = index & ~(1ULL << (height - 1));
            assert(m_db->ReadEntries(left_index, left_entry_list));

        } else {
            // The index has moved right, so move what is currently the
            // right side to the left side for this iteration.
            uint64_t left_index = last_index;
            std::swap(left_entry_list.m_entries, right_entry_list.m_entries);
            m_db->WriteEntries(batch, left_index, left_entry_list);
            update_count++;

            // If the next_index to be modified is lower, then it is guaranteed to share this entry.
            // In this case, we can skip forward one iteration and let the next loop update the
            // parent entries.
            if (next_index < index) {
                return index;
            }

            assert(m_db->ReadEntries(index, right_entry_list));
        }

        MMRDB::Entry& left_entry = left_entry_list.m_entries[height - 1];
        MMRDB::Entry& right_entry = right_entry_list.m_entries[height - 1];
        MMRDB::Entry& parent_entry = right_entry_list.m_entries[height];

        if (left_entry.m_count == 0 && right_entry.m_count == 0) {
            parent_entry.Clear();
        } else if (left_entry.m_count == 0 && right_entry.m_count == 1) {
            parent_entry = right_entry;
        } else if (left_entry.m_count == 1 && right_entry.m_count == 0) {
            parent_entry = left_entry;
        } else {
            parent_entry.m_count = left_entry.m_count + right_entry.m_count;
            BaseHashWriter<CSHA256> hash_writer(SER_GETHASH, 0);
            hash_writer << left_entry << right_entry;
            parent_entry.m_hash = hash_writer.GetHash();
        }
    }

    m_db->WriteEntries(batch, index, right_entry_list);
    update_count++;

    int peak_cache_idx = NumOfPeaksBeforeIndex(index + 1) - 1;
    m_peak_cache[peak_cache_idx] = right_entry_list.m_entries.back();

    return index;
}

uint MMR::Remove(std::vector<uint64_t> indices)
{
    if (indices.empty()) return 0;

    CDBBatch batch(*m_db);

    std::sort(indices.begin(), indices.end());

    uint update_count = 0;

    uint64_t min_index = indices.front();
    uint64_t max_index = min_index; // This is a placeholder value that gets overwritten in the loop below;

    for (uint i = 0; i < indices.size(); ++i) {
        uint64_t index = indices[i];

        if (index >= m_next_index) {
            continue;
        }

        uint peak_height = PeakHeight(index, m_next_index);
        MMRDB::EntryList entry_list(/*capacity=*/peak_height + 1);

        assert(m_db->ReadEntries(index, entry_list));

        MMRDB::Entry& leaf_entry = entry_list.m_entries[0];
        switch (leaf_entry.m_count) {
        case 0:
            // Nothing to remove
            continue;

        case 1:
            leaf_entry.Clear();
            break;

        default:
            // Only leaves could possibly be at height 0.
            assert(false);
        }

        const uint64_t next_index = i + 1 < indices.size() ? indices[i + 1] : m_next_index;
        max_index = UpdateParents(batch, entry_list, index, next_index, peak_height, update_count);
    }

    assert(m_db->WriteBatch(batch));
    // m_db->CompactEntries(min_index, max_index);

    return update_count;
}

uint MMR::Insert(std::vector<std::pair<uint64_t, uint256>> leaves)
{
    if (leaves.empty()) return 0;

    CDBBatch batch(*m_db);

    std::sort(leaves.begin(), leaves.end());

    uint update_count = 0;

    uint64_t min_index = leaves.front().first;
    uint64_t max_index = min_index; // This is a placeholder value that gets overwritten in the loop below;

    for (uint i = 0; i < leaves.size(); ++i) {
        uint64_t index = leaves[i].first;
        const uint256& hash = leaves[i].second;

        // Extend the MMR to insert the entry.
        if (index >= m_next_index) {
            MMRDB::Entry entry;

            entry.m_count = 0;
            while (m_next_index < index) {
                Append(batch, entry);
                update_count++;
            }

            entry.m_count = 1;
            entry.m_hash = hash;
            Append(batch, entry);
            update_count++;

            max_index = index;
            continue;
        }

        uint peak_height = PeakHeight(index, m_next_index);

        MMRDB::EntryList entry_list(/*capacity=*/peak_height + 1);
        assert(m_db->ReadEntries(index, entry_list));

        MMRDB::Entry& leaf_entry = entry_list.m_entries[0];
        switch (leaf_entry.m_count) {
        case 0:
            leaf_entry.m_count = 1;
            leaf_entry.m_hash = hash;
            break;

        case 1:
            if (leaf_entry.m_hash == hash) {
                continue;
            }
            leaf_entry.m_hash = hash;
            break;

        default:
            // Only leaves could possibly be at height 0.
            assert(false);
        }

        const uint64_t next_index = i + 1 < leaves.size() ? leaves[i + 1].first : m_next_index;
        max_index = UpdateParents(batch, entry_list, index, next_index, peak_height, update_count);
    }

    assert(m_db->WriteBatch(batch));
    // m_db->CompactEntries(min_index, max_index);

    return update_count;
}

bool MMR::RefreshPeakCache()
{
    uint n_peaks = NumOfPeaksBeforeIndex(m_next_index);
    m_peak_cache.resize(n_peaks);

    uint64_t peak_next_index = m_next_index;
    for (uint i = 0; i < n_peaks; ++i) {
        uint64_t peak_index = peak_next_index - 1;

        MMRDB::EntryList peak_entry_list(EntryListSize(peak_index));
        if (!m_db->ReadEntries(peak_index, peak_entry_list)) {
            return false;
        }
        m_peak_cache[n_peaks - i - 1] = peak_entry_list.m_entries.back();

        peak_next_index &= peak_next_index - 1; // Clear the least-significant bit
    }

    return true;
}

void MMR::GetAppendHashes(const CBlock& block, const CCoinsView& coins_view, std::vector<std::pair<uint64_t, uint256>>& hashes) const
{
    Coin coin;
    for (const CTransactionRef& tx : block.vtx) {
        uint256 tx_hash = tx->GetHash();
        for (size_t i = 0; i < tx->vout.size(); i++) {
            //if (coins_view.GetCoin(COutPoint(tx_hash, i), coin)) {
                BaseHashWriter<CSHA256> hash_writer(SER_GETHASH, 0);
                hash_writer << coin;
                hashes.emplace_back(coin.m_index, hash_writer.GetHash());
                //}
        }
    }
}

void MMR::GetRemoveIndices(const CBlockUndo& block_undo, std::vector<uint64_t>& indices) const
{
    indices.clear();

    for (const CTxUndo& tx_undo : block_undo.vtxundo) {
        for (const Coin& coin : tx_undo.vprevout) {
            indices.push_back(coin.m_index);
        }
    }
}

void MMR::BlockConnected(const CBlock& block, const CBlockUndo& block_undo, const CCoinsView& coins_view, const CBlockIndex* block_index)
{
    uint256 best_block = BestBlock();
    assert(best_block == block.hashPrevBlock);

    // Get a total count of inputs and outputs.
    size_t txin_count = 0;
    size_t txout_count = 0;
    for (const CTransactionRef& tx : block.vtx) {
        txin_count += tx->vin.size();
        txout_count += tx->vout.size();
    }

    int64_t start_time = GetTimeMicros();

     // Append created coins to the UTXO set.
    std::vector<std::pair<uint64_t, uint256>> append_hashes;
    append_hashes.reserve(txout_count);
    GetAppendHashes(block, coins_view, append_hashes);
    uint db_insert = Insert(std::move(append_hashes));

    int64_t part1_time = GetTimeMicros();

   // Remove spent coins from the UTXO set.
    std::vector<uint64_t> remove_indices;
    remove_indices.reserve(txin_count);
    GetRemoveIndices(block_undo, remove_indices);
    uint db_remove = Remove(std::move(remove_indices));

    m_db->WriteBestBlock(block.GetHash());

    int64_t end_time = GetTimeMicros();
    LogPrintf("MMR::BlockConnected: height %d, count %d, insert %dus, remove %dus, txin count %d, txout count %d, db remove %d, db insert %d\n",
              block_index->nHeight, LeafCount(),
              part1_time - start_time, end_time - part1_time,
              txin_count, txout_count,
              db_remove, db_insert);
}

void MMR::BlockDisconnected(const CBlock& block, const CBlockUndo& block_undo)
{
    uint256 best_block = BestBlock();
    assert(best_block == block.GetHash());

    // Get a total count of inputs and outputs.
    size_t txin_count = 0;
    size_t txout_count = 0;
    for (const CTransactionRef& tx : block.vtx) {
        txin_count += tx->vin.size();
        txout_count += tx->vout.size();
    }

    std::vector<std::pair<uint64_t, uint256>> append_hashes;
    append_hashes.reserve(txin_count);
    for (const CTxUndo& tx_undo : block_undo.vtxundo) {
        for (const Coin& coin : tx_undo.vprevout) {
            BaseHashWriter<CSHA256> hash_writer(SER_GETHASH, 0);
            hash_writer << coin;
            append_hashes.emplace_back(coin.m_index, hash_writer.GetHash());
        }
    }
    Insert(std::move(append_hashes));

    // Rewind the appended UTXOs.
    Rewind(txout_count);

    m_db->WriteBestBlock(block.hashPrevBlock);
}

void MMR::CatchUp()
{
    LOCK(cs_main);
    CBlockIndex* block_index = LookupBlockIndex(BestBlock());
    while (block_index && !chainActive.Contains(block_index)) {
        block_index = block_index->pprev;
    }

    CBlockUndo block_undo;

    if (block_index) {
        block_index = chainActive.Next(block_index);
    } else {
        block_index = chainActive.Genesis();
    }

    while (block_index != nullptr) {
        LogPrintf("CatchUp(): %d\n", block_index->nHeight);

        CBlock block;
        assert(ReadBlockFromDisk(block, block_index, Params().GetConsensus()));
        assert(UndoReadFromDisk(block_undo, block_index));
        BlockConnected(block, block_undo, *pcoinsTip, block_index);

        block_index = chainActive.Next(block_index);
    }
}
