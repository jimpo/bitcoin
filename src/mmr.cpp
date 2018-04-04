// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>
#include <bitset>
#include <iostream>

#include <chain.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <mmr.h>
#include <primitives/block.h>
#include <utilmath.h>

static const char DB_NEXT_INDEX = 'I';
static const char DB_ENTRIES = 'e';
static const char DB_TX_INDEX = 'i';

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

void MMMRDB::Entry::Clear()
{
    m_count = 0;
    m_hash.SetNull();
}

MMMRDB::EntryList::EntryList(size_t capacity)
{
    m_entries.reserve(capacity);
}

bool MMMRDB::EntryList::Empty() const
{
    for (const Entry& entry : m_entries) {
        if (entry.m_count > 0) {
            return false;
        }
    }
    return true;
}

void MMMRDB::EntryList::Clear(size_t size)
{
    for (size_t i = 0; i < std::min(size, m_entries.size()); ++i) {
        m_entries[i].Clear();
    }
    m_entries.resize(size);
}

MMMRDB::MMMRDB(size_t cache_size, bool f_memory, bool f_wipe) :
    CDBWrapper(GetDataDir() / "mmrdb", cache_size, f_memory, f_wipe)
{}

bool MMMRDB::ReadNextIndex(uint64_t& index) const
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

bool MMMRDB::WriteNextIndex(const uint64_t index)
{
    return Write(DB_NEXT_INDEX, index);
}

bool MMMRDB::ReadTxIndex(const uint256& tx_hash, uint64_t& index) const
{
    auto key = std::make_pair(DB_TX_INDEX, tx_hash);
    if (Read(key, index)) {
        return true;
    }
    if (!Exists(key)) {
        index = 0;
        return true;
    }
    return false;
}

bool MMMRDB::WriteTxIndex(const uint256& tx_hash, const uint64_t index)
{
    return Write(std::make_pair(DB_TX_INDEX, tx_hash), index);
}

bool MMMRDB::ReadEntries(uint64_t index, MMMRDB::EntryList& entry_list) const
{
    auto key = std::make_pair(DB_ENTRIES, index);
    if (Read(key, entry_list)) {
        if (entry_list.m_entries.size() != EntryListSize(index)) {
            return error("MMMR entry list read has unexpected size");
        }
        return true;
    }
    if (!Exists(key)) {
        entry_list.Clear(EntryListSize(index));
        return true;
    }
    return false;
}

bool MMMRDB::WriteEntries(uint64_t index, const MMMRDB::EntryList& entry_list)
{
    auto key = std::make_pair(DB_ENTRIES, index);
    if (entry_list.Empty()) {
        return Erase(key);
    }
    return Write(key, entry_list);
}

MMMR::MMMR(std::unique_ptr<MMMRDB> db) : m_db(std::move(db))
{
    assert(m_db->ReadNextIndex(m_next_index));
}

uint256 MMMR::RootHash() const
{
    MMMRDB::Entry root;
    root.m_count = 0;

    // First hash in chain is a commitment to the MMMR size.
    root.m_hash = (BaseHashWriter<CSHA256>(SER_GETHASH, 0) << m_next_index).GetHash();

    for (auto it = m_peak_cache.rbegin(); it != m_peak_cache.rend(); ++it) {
        // Entry hash is a commitment to child counts and hashes.
        BaseHashWriter<CSHA256> hash_writer(SER_GETHASH, 0);
        hash_writer << *it << root;

        root.m_count += it->m_count;
        root.m_hash = hash_writer.GetHash();
    }
    return root.m_hash;
}

void MMMR::Append(std::vector<uint256> hashes)
{
    for (const uint256& hash : hashes) {
        uint64_t index = m_next_index++;
        int peak_height = PeakHeight(index, m_next_index);

        // Entries are all of the intermediate hashes at each index representing
        // roots of the merkle subtrees at height i.
        MMMRDB::EntryList entry_list(peak_height + 1);

        auto& entries = entry_list.m_entries;
        entries.resize(peak_height + 1);
        entries[0].m_count = 1;
        entries[0].m_hash = hash;

        for (int height = 1; height <= peak_height; ++height) {
            MMMRDB::Entry& left_peak = m_peak_cache.back();
            MMMRDB::Entry& right_peak = entries[height - 1];

            // Entry count is the sum of child counts.
            entries[height].m_count = left_peak.m_count + right_peak.m_count;

            // Entry hash is a commitment to child counts and hashes.
            BaseHashWriter<CSHA256> hash_writer(SER_GETHASH, 0);
            hash_writer << left_peak << right_peak;
            entries[height].m_hash = hash_writer.GetHash();

            m_peak_cache.pop_back();
        }

        assert(m_db->WriteEntries(index, entry_list));

        // The last entry at the last index is a new peak.
        m_peak_cache.push_back(entries.back());
    }

    assert(m_db->WriteNextIndex(m_next_index));
}

void MMMR::Rewind(size_t hashes_count)
{
    uint64_t new_next_index = m_next_index - hashes_count;
    assert(m_db->WriteNextIndex(new_next_index));

    MMMRDB::EntryList empty_entry_list(0);
    for (uint64_t index = new_next_index; index < m_next_index; ++index) {
        assert(m_db->WriteEntries(index, empty_entry_list));
    }

    m_next_index = new_next_index;

    uint n_peaks = NumOfPeaksBeforeIndex(m_next_index);
    m_peak_cache.resize(n_peaks);

    uint64_t peak_next_index = new_next_index;
    for (uint i = 0; i < n_peaks; ++i) {
        uint64_t peak_index = peak_next_index - 1;

        MMMRDB::EntryList peak_entry_list(EntryListSize(peak_index));
        assert(m_db->ReadEntries(peak_index, peak_entry_list));
        m_peak_cache[n_peaks - i - 1] = peak_entry_list.m_entries.back();

        peak_next_index &= peak_next_index - 1; // Clear the least-significant bit
    }
}

void MMMR::Remove(std::vector<uint64_t> indices)
{
    std::sort(indices.begin(), indices.end());
    for (uint i = 0; i < indices.size(); ++i) {
        uint64_t leaf_index = indices[i];

        uint peak_height = PeakHeight(leaf_index, m_next_index);

        uint64_t index = leaf_index;
        MMMRDB::EntryList left_entry_list(/*capacity=*/peak_height + 1);
        MMMRDB::EntryList right_entry_list(/*capacity=*/peak_height + 1);

        assert(m_db->ReadEntries(index, right_entry_list));

        MMMRDB::Entry& leaf_entry = right_entry_list.m_entries[0];
        switch (leaf_entry.m_count) {
        case 0:
            // Already removed
            break;

        case 1:
            leaf_entry.Clear();
            break;

        default:
            // Only leaves could possibly be at height 0.
            assert(false);
        }

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
                assert(m_db->WriteEntries(left_index, left_entry_list));
                assert(m_db->ReadEntries(index, right_entry_list));
            }

            MMMRDB::Entry& left_entry = left_entry_list.m_entries[height - 1];
            MMMRDB::Entry& right_entry = right_entry_list.m_entries[height - 1];
            MMMRDB::Entry& parent_entry = right_entry_list.m_entries[height];

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

        assert(m_db->WriteEntries(index, right_entry_list));
        int peak_cache_idx = NumOfPeaksBeforeIndex(index + 1) - 1;
        m_peak_cache[peak_cache_idx] = right_entry_list.m_entries.back();
    }
}

void MMMR::Insert(std::vector<std::pair<uint64_t, uint256>> leaves)
{
    std::sort(leaves.begin(), leaves.end());
    for (uint i = 0; i < leaves.size(); ++i) {
        uint64_t leaf_index = leaves[i].first;
        const uint256& hash = leaves[i].second;

        uint peak_height = PeakHeight(leaf_index, m_next_index);

        uint64_t index = leaf_index;
        MMMRDB::EntryList left_entry_list(/*capacity=*/peak_height + 1);
        MMMRDB::EntryList right_entry_list(/*capacity=*/peak_height + 1);

        assert(m_db->ReadEntries(index, right_entry_list));

        MMMRDB::Entry& leaf_entry = right_entry_list.m_entries[0];
        switch (leaf_entry.m_count) {
        case 0:
            // Re-add the hash
            leaf_entry.m_count = 1;
            leaf_entry.m_hash = hash;
            break;

        case 1:
            if (leaf_entry.m_hash == hash) {
                // Already re-added
            } else {
                // Log that the hash was incorrect or delay an error or something
            }
            break;

        default:
            // Only leaves could possibly be at height 0.
            assert(false);
        }

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
                assert(m_db->WriteEntries(left_index, left_entry_list));
                assert(m_db->ReadEntries(index, right_entry_list));
            }

            MMMRDB::Entry& left_entry = left_entry_list.m_entries[height - 1];
            MMMRDB::Entry& right_entry = right_entry_list.m_entries[height - 1];
            MMMRDB::Entry& parent_entry = right_entry_list.m_entries[height];

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

        assert(m_db->WriteEntries(index, right_entry_list));
        int peak_cache_idx = NumOfPeaksBeforeIndex(index + 1) - 1;
        m_peak_cache[peak_cache_idx] = right_entry_list.m_entries.back();
    }
}

bool MMMR::GetAppendHashes(const CBlock& block, std::vector<uint256>& hashes) const
{
    uint64_t index = NextIndex();
    for (const CTransactionRef& tx : block.vtx) {
        for (size_t i = 0; i < tx->vout.size(); i++) {
            BaseHashWriter<CSHA256> hash_writer(SER_GETHASH, 0);
            hash_writer
                << index
                << COutPoint(tx->GetHash(), i)
                << tx->vout[i];
            hashes.push_back(hash_writer.GetHash());
            ++index;
        }
    }
    return true;
}

bool MMMR::GetRemoveIndices(const CBlock& block, std::vector<uint64_t>& indices) const
{
    indices.clear();

    std::map<uint256, uint64_t> tx_index_cache;

    auto tx_it = block.vtx.begin();
    tx_it++;  // Skip the coinbase tx
    for (; tx_it != block.vtx.end(); ++tx_it) {
        const CTransactionRef& tx = *tx_it;
        for (size_t i = 0; i < tx->vin.size(); i++) {
            const CTxIn& txin = tx->vin[i];

            uint64_t tx_index;
            auto it = tx_index_cache.find(txin.prevout.hash);
            if (it != tx_index_cache.end()) {
                tx_index = it->second;
            } else {
                assert(m_db->ReadTxIndex(txin.prevout.hash, tx_index));
                tx_index_cache.emplace(txin.prevout.hash, tx_index);
            }

            indices.push_back(tx_index + i);
        }
    }

    return true;
}

void MMMR::BlockConnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* block_index,
                          const std::vector<CTransactionRef>& txn_conflicted)
{
    int64_t start_time = GetTimeMicros();

    // Get a total count of inputs and outputs.
    size_t txin_count = 0;
    size_t txout_count = 0;
    for (const CTransactionRef& tx : block->vtx) {
        txin_count += tx->vin.size();
        txout_count += tx->vout.size();
    }

    // Write start indexes of coins by tx hash.
    uint64_t index = NextIndex();
    for (const CTransactionRef& tx : block->vtx) {
        assert(m_db->WriteTxIndex(tx->GetHash(), index));
        index += tx->vout.size();
    }

    int64_t part1_time = GetTimeMicros();

    // Remove spent coins from the UTXO set.
    std::vector<uint64_t> remove_indices;
    remove_indices.reserve(txin_count);
    assert(GetRemoveIndices(*block, remove_indices));
    Remove(std::move(remove_indices));

    int64_t part2_time = GetTimeMicros();

    // Append created coins to the UTXO set.
    std::vector<uint256> append_hashes;
    append_hashes.reserve(txout_count);
    assert(GetAppendHashes(*block, append_hashes));
    Append(std::move(append_hashes));

    int64_t end_time = GetTimeMicros();
    LogPrintf("MMMR::BlockConnected: height %d, time %dus, txindex %dus, remove %dus, append %dus\n",
              block_index->nHeight, end_time - start_time, part1_time - start_time, part2_time - part1_time, end_time - part2_time);
}

void MMMR::BlockDisconnected(const std::shared_ptr<const CBlock>& block)
{
    // Get a total count of inputs and outputs.
    size_t txin_count = 0;
    size_t txout_count = 0;
    for (const CTransactionRef& tx : block->vtx) {
        txin_count += tx->vin.size();
        txout_count += tx->vout.size();
    }

    // Rewind the appended UTXOs.
    Rewind(txout_count);
}
