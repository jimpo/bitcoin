// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_TXINDEX_H
#define BITCOIN_INDEX_TXINDEX_H

#include <txdb.h>
#include <uint256.h>
#include <validationinterface.h>

class CBlockIndex;

/**
 * TxIndex is used to look up transactions included in the blockchain by hash.
 * The index is written to a keyspace in the block index database and records
 * the filesystem location of each transaction by transaction hash.
 */
class TxIndex final : public CValidationInterface
{
private:
    const std::shared_ptr<CBlockTreeDB> m_db;
    std::atomic<bool> m_synced;
    std::atomic<const CBlockIndex*> m_best_block_index;

    /// Initialize internal state from the database and block index.
    bool Init();

    /// Write update index entries for a newly connected block.
    bool WriteBlock(const CBlock& block, const CBlockIndex* pindex);

protected:
    void BlockConnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex,
                        const std::vector<CTransactionRef>& txn_conflicted) override;

public:
    explicit TxIndex(const std::shared_ptr<CBlockTreeDB>& db);

    /// Look up the on-disk location of a transaction by hash.
    bool FindTx(const uint256& txid, CDiskTxPos& pos) const;

    void Start();
    void Stop();
};

#endif // BITCOIN_INDEX_TXINDEX_H
