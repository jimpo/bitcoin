// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>
#include <bitset>
#include <iostream>

#include <crypto/sha256.h>
#include <hash.h>
#include <mmr.h>
#include <utilmath.h>

static const char DB_NEXT_INDEX = 'I';
static const char DB_ENTRIES = 'e';

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

MMMR::Leaf MMMR::Insert(const CDataStream& data)
{
    uint64_t index = m_next_index++;

    // Leaf hash commits to both data and insertion index.
    uint256 hash = (BaseHashWriter<CSHA256>(SER_GETHASH, 0) << index << data).GetHash();

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
    assert(m_db->WriteNextIndex(m_next_index));

    // The last entry at the last index is a new peak.
    m_peak_cache.push_back(entries.back());

    return std::make_pair(index, hash);
}

void MMMR::RewindInsert(uint64_t next_index)
{
    MMMRDB::EntryList empty_entry_list(0);
    assert(m_db->WriteNextIndex(next_index));

    for (uint64_t index = next_index; index < m_next_index; ++index) {
        assert(m_db->WriteEntries(index, empty_entry_list));
    }

    m_next_index = next_index;

    uint n_peaks = NumOfPeaksBeforeIndex(m_next_index);
    m_peak_cache.resize(n_peaks);

    uint64_t peak_next_index = next_index;
    for (uint i = 0; i < n_peaks; ++i) {
        uint64_t peak_index = peak_next_index - 1;

        MMMRDB::EntryList peak_entry_list(EntryListSize(peak_index));
        assert(m_db->ReadEntries(peak_index, peak_entry_list));
        m_peak_cache[n_peaks - i - 1] = peak_entry_list.m_entries.back();

        peak_next_index &= peak_next_index - 1; // Clear the least-significant bit
    }
}

void MMMR::Remove(std::vector<MMMR::Leaf> leaves)
{
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
            // Already removed
            break;

        case 1:
            if (leaf_entry.m_hash == hash) {
                leaf_entry.Clear();
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

void MMMR::UndoRemove(std::vector<MMMR::Leaf> leaves)
{
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
