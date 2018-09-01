// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <flatfile.h>
#include <util.cpp>

FlatFileSeq::FlatFileSeq(fs::path dir, const char* prefix, size_t chunk_size)
    : m_dir(std::move(dir)), m_prefix(prefix), m_chunk_size(chunk_size)
{}

fs::path FlatFileSeq::FileName(const CDiskBlockPos& pos) const
{
    return m_dir / strprintf("%s%05u.dat", m_prefix, pos.nFile);
}

FILE* FlatFileSeq::Open(const CDiskBlockPos& pos, bool fReadOnly)
{
    if (pos.IsNull())
        return nullptr;
    fs::path path = FileName(pos);
    fs::create_directories(path.parent_path());
    FILE* file = fsbridge::fopen(path, fReadOnly ? "rb": "rb+");
    if (!file && !fReadOnly)
        file = fsbridge::fopen(path, "wb+");
    if (!file) {
        LogPrintf("Unable to open file %s\n", path.string());
        return nullptr;
    }
    if (pos.nPos) {
        if (fseek(file, pos.nPos, SEEK_SET)) {
            LogPrintf("Unable to seek to position %u of %s\n", pos.nPos, path.string());
            fclose(file);
            return nullptr;
        }
    }
    return file;
}

size_t FlatFileSeq::Allocate(const CDiskBlockPos& pos, size_t add_size, bool& out_of_space)
{
    out_of_space = false;

    unsigned int nOldChunks = (pos.nPos + m_chunk_size - 1) / m_chunk_size;
    unsigned int nNewChunks = (pos.nPos + add_size + m_chunk_size - 1) / m_chunk_size;
    if (nNewChunks > nOldChunks) {
        size_t old_size = pos.nPos;
        size_t new_size = nNewChunks * m_chunk_size;
        size_t inc_size = new_size - old_size;

        if (CheckDiskSpace(m_dir, inc_size)) {
            FILE *file = Open(pos);
            if (file) {
                LogPrintf("Pre-allocating up to position 0x%x in %s%05u.dat\n", new_size, m_prefix, pos.nFile);
                AllocateFileRange(file, pos.nPos, inc_size);
                fclose(file);
                return inc_size;
            }
        }
        else {
            out_of_space = true;
        }
    }
    return 0;
}
