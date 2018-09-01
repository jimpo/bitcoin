// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_FLATFILE_H
#define BITCOIN_FLATFILE_H

#include <string>

#include <fs.h>
#include <logging.h>
#include <serialize.h>

struct CDiskBlockPos
{
    int nFile;
    unsigned int nPos;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(nFile, VarIntMode::NONNEGATIVE_SIGNED));
        READWRITE(VARINT(nPos));
    }

    CDiskBlockPos() {
        SetNull();
    }

    CDiskBlockPos(int nFileIn, unsigned int nPosIn) {
        nFile = nFileIn;
        nPos = nPosIn;
    }

    friend bool operator==(const CDiskBlockPos &a, const CDiskBlockPos &b) {
        return (a.nFile == b.nFile && a.nPos == b.nPos);
    }

    friend bool operator!=(const CDiskBlockPos &a, const CDiskBlockPos &b) {
        return !(a == b);
    }

    void SetNull() { nFile = -1; nPos = 0; }
    bool IsNull() const { return (nFile == -1); }

    std::string ToString() const
    {
        return strprintf("CDiskBlockPos(nFile=%i, nPos=%i)", nFile, nPos);
    }

};

class FlatFileSeq
{
private:
    fs::path m_dir;
    const char* m_prefix;
    size_t m_chunk_size;

public:
    FlatFileSeq(fs::path dir, const char* prefix, size_t chunk_size);

    fs::path FileName(const CDiskBlockPos& pos) const;

    FILE* Open(const CDiskBlockPos& pos, bool read_only = false);
    size_t Allocate(const CDiskBlockPos& pos, size_t add_size, bool& out_of_space);
};

#endif // BITCOIN_FLATFILE_H
