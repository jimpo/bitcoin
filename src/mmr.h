// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MMR_H
#define BITCOIN_MMR_H

#include <dbwrapper.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>

class MMMRDB : public CDBWrapper
{
public:
    struct Entry {
        uint32_t m_count;
        uint256 m_hash;

        Entry() : m_count(0) {}

        void Clear();

        ADD_SERIALIZE_METHODS;

        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            READWRITE(m_count);
            READWRITE(m_hash);
        }
    };

    struct EntryList {
        std::vector<Entry> m_entries;

        EntryList(size_t capacity);
        EntryList(EntryList&& other) = default;

        bool Empty() const;
        void Clear(size_t size);

        template <typename Stream>
        void Serialize(Stream& s) const
        {
            uint8_t max_height = m_entries.size();

            uint8_t height = 0;
            while (height < max_height && m_entries[height].m_count == 0) {
                ++height;
            }
            uint8_t terminal_height = height;

            while (height < max_height && m_entries[height].m_count == 1) {
                ++height;
            }
            uint8_t middle_height = height;

            s << terminal_height << middle_height << max_height;

            if (terminal_height < middle_height) {
                const uint256& terminal_hash = m_entries[terminal_height].m_hash;
                s << terminal_hash;
            }

            for (; height < max_height; ++height) {
                s << m_entries[height];
            }
        }

        template <typename Stream>
        void Unserialize(Stream& s)
        {
            uint8_t terminal_height, middle_height, max_height;
            s >> terminal_height >> middle_height >> max_height;

            m_entries.resize(max_height);

            uint8_t height = 0;
            for (; height < terminal_height; ++height) {
                m_entries[height].Clear();
            }

            if (terminal_height < middle_height) {
                uint256 terminal_hash;
                s >> terminal_hash;

                for (; height < middle_height; ++height) {
                    m_entries[height].m_count = 1;
                    m_entries[height].m_hash = terminal_hash;
                }
            }

            for (; height < max_height; ++height) {
                s >> m_entries[height];
            }
        }
    };

    explicit MMMRDB(size_t cache_size, bool f_memory = false, bool f_wipe = false);

    bool ReadEntries(uint64_t index, EntryList& entry_list) const;
    bool WriteEntries(uint64_t index, const EntryList& entry_list);
    bool ReadNextIndex(uint64_t& index) const;
    bool WriteNextIndex(const uint64_t index);
};

class MMMR
{
private:
    std::unique_ptr<MMMRDB> m_db;
    std::vector<MMMRDB::Entry> m_peak_cache;
    uint64_t m_next_index;

public:
    typedef std::pair<uint64_t, uint256> Leaf;

    MMMR(std::unique_ptr<MMMRDB> db);

    uint64_t NextIndex() const { return m_next_index; }

    uint256 RootHash() const;
    Leaf Insert(const CDataStream& data);
    void RewindInsert(uint64_t next_index);
    void Remove(std::vector<Leaf> leaves);
    void UndoRemove(std::vector<Leaf> leaves);
};

#endif // BITCOIN_MMR_H
