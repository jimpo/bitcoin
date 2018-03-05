// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MERKLESET_H
#define BITCOIN_MERKLESET_H

#include <deque>
#include <memory>
#include <vector>

#include <uint256.h>

class MerkleSet
{
    enum UpdateOp {
        INSERT,
        REMOVE
    };

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;

public:
    MerkleSet(size_t chunk_size);

    std::vector<bool> Update(std::vector<std::pair<uint256, UpdateOp>> hashes);

    bool Has(uint256 hash, std::vector<uint256>* proof) const;

    uint256 RootHash() const;
};

#endif // BITCOIN_MERKLESET_H
