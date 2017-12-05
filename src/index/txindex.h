// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_TXINDEX_H
#define BITCOIN_INDEX_TXINDEX_H

#include <threadinterrupt.h>
#include <txdb.h>
#include <uint256.h>
#include <validationinterface.h>

#include <boost/variant.hpp>
#include <future>

class CBlockIndex;

struct TxIndexUpdate {
    std::shared_ptr<const CBlock> m_block;
    const CBlockIndex* m_pindex;

    TxIndexUpdate() = default;
    TxIndexUpdate(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex) :
        m_block(block), m_pindex(pindex) {}

    TxIndexUpdate(TxIndexUpdate&& other) = default;

    TxIndexUpdate& operator=(TxIndexUpdate&& other) = default;
};

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

    std::thread m_thread_sync;
    CThreadInterrupt m_interrupt;

    std::deque<boost::variant<TxIndexUpdate, std::promise<void> > > m_queue;
    std::mutex m_queue_mtx;
    std::condition_variable m_queue_signal;

    /// Initialize internal state from the database and block index.
    bool Init();

    /// Sync the tx index with the block index starting from the current best
    /// block. Intended to be run in its own thread, m_thread_sync, and can be
    /// interrupted with m_interrupt.
    void ThreadSync();

    /// Write update index entries for a newly connected block.
    bool WriteBlock(const CBlock& block, const CBlockIndex* pindex);

protected:
    void BlockConnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex,
                        const std::vector<CTransactionRef>& txn_conflicted) override;

public:
    explicit TxIndex(const std::shared_ptr<CBlockTreeDB>& db);

    /// Destructor interrupts sync thread if running and blocks until it exits.
    ~TxIndex();

    /// Blocks the current thread until the tx index is caught up to the current
    /// state of the block chain.
    bool BlockUntilSyncedToCurrentChain();

    /// Look up the on-disk location of a transaction by hash.
    bool FindTx(const uint256& txid, CDiskTxPos& pos) const;

    void Interrupt();
    void Start();
    void Stop();
};

/// The global transaction index, used in GetTransaction. May be null.
extern std::unique_ptr<TxIndex> g_txindex;

#endif // BITCOIN_INDEX_TXINDEX_H
