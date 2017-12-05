// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <future>

#include <chainparams.h>
#include <index/txindex.h>
#include <init.h>
#include <tinyformat.h>
#include <ui_interface.h>
#include <util.h>
#include <validation.h>
#include <warnings.h>

std::unique_ptr<TxIndex> g_txindex;

template<typename... Args>
static void FatalError(const char* fmt, const Args&... args)
{
    std::string strMessage = tfm::format(fmt, args...);
    SetMiscWarning(strMessage);
    LogPrintf("*** %s\n", strMessage);
    uiInterface.ThreadSafeMessageBox(
        "Error: A fatal internal error occurred, see debug.log for details",
        "", CClientUIInterface::MSG_ERROR);
    StartShutdown();
}

TxIndex::TxIndex(const std::shared_ptr<CBlockTreeDB>& db) :
    m_db(db), m_synced(false), m_best_block_index(nullptr)
{}

TxIndex::~TxIndex()
{
    Interrupt();
    Stop();
}

bool TxIndex::Init()
{
    LOCK(cs_main);

    uint256 best_block_hash;
    if (!m_db->ReadTxIndexBestBlockHash(best_block_hash)) {
        FatalError("%s: Failed to read from tx index database", __func__);
        return false;
    }

    if (!best_block_hash.IsNull()) {
        auto it = mapBlockIndex.find(best_block_hash);
        if (it == mapBlockIndex.end()) {
            FatalError("%s: Last block synced by txindex is unknown", __func__);
            return false;
        }

        const auto pindex = it->second;
        m_best_block_index = pindex;

        auto chain_tip = chainActive.Tip();
        if (pindex->GetAncestor(chain_tip->nHeight) == chain_tip) {
            m_synced = true;
        }

        return true;
    }

    auto chain_tip = chainActive.Tip();
    if (!chain_tip) {
        m_synced = true;
        return true;
    }

    // The prior implementation of txindex was always in sync with block index
    // and presence was indicated with a boolean DB flag.
    bool f_migrate_index;
    m_db->ReadFlag("txindex", f_migrate_index);
    if (f_migrate_index) {
        m_best_block_index = chain_tip;
        m_synced = true;
    }

    return true;
}

static const CBlockIndex* NextSyncBlock(const CBlockIndex* pindex_prev)
{
    AssertLockHeld(cs_main);

    if (!pindex_prev) {
        return chainActive.Genesis();
    }

    auto pindex = chainActive.Next(pindex_prev);
    if (pindex) {
        return pindex;
    }

    return chainActive.Next(chainActive.FindFork(pindex_prev));
}

void TxIndex::ThreadSync()
{
    auto pindex = m_best_block_index.load();
    if (!m_synced) {
        auto& consensus_params = Params().GetConsensus();

        LogPrintf("Syncing txindex with block chain from height %d\n",
                  pindex ? pindex->nHeight + 1 : 0);

        while (true) {
            if (m_interrupt) {
                return;
            }

            {
                LOCK(cs_main);
                auto pindex_next = NextSyncBlock(pindex);
                if (!pindex_next) {
                    m_best_block_index = pindex;
                    m_synced = true;
                    break;
                }
                pindex = pindex_next;
            }

            CBlock block;
            if (!ReadBlockFromDisk(block, pindex, consensus_params)) {
                FatalError("%s: Failed to read block %s from disk",
                           __func__, pindex->GetBlockHash().ToString());
                return;
            }
            if (!WriteBlock(block, pindex)) {
                FatalError("%s: Failed to write block %s to tx index database",
                           __func__, pindex->GetBlockHash().ToString());
                return;
            }
        }
    }

    LogPrintf("txindex is enabled at height %d\n", pindex->nHeight);

    while (!m_interrupt) {
        m_queue_signal.sleep_for(std::chrono::seconds(3600));

        // Process queue until empty or interrupted.
        while (true) {
            if (m_interrupt) {
                return;
            }

            TxIndexUpdate update;
            {
                LOCK(m_cs_queue);
                if (m_queue.empty()) {
                    m_queue_signal.reset();
                    break;
                }

                auto entry = std::move(m_queue.front());
                m_queue.pop_front();

                // Queue entry may just be a marker inserted by BlockUntilSyncedToCurrentChain.
                if (auto promise = boost::get<std::promise<void> >(&entry)) {
                    promise->set_value();
                    continue;
                }

                update = std::move(boost::get<TxIndexUpdate>(entry));
            }

            auto pindex = update.m_pindex;

            // Ensure block connects to an ancestor of the current best block.
            {
                LOCK(cs_main);
                auto best_block_index = m_best_block_index.load();
                if (best_block_index->GetAncestor(pindex->nHeight - 1) != pindex->pprev) {
                    FatalError("%s: Block %s does not connect to an ancestor of known best chain (tip=%s)",
                               __func__, pindex->GetBlockHash().ToString(),
                               best_block_index->GetBlockHash().ToString());
                    return;
                }
            }

            if (WriteBlock(*update.m_block, pindex)) {
                m_best_block_index = pindex;
            } else {
                FatalError("%s: Failed to write block %s to txindex",
                           __func__, pindex->GetBlockHash().ToString());
                return;
            }
        }
    }
}

bool TxIndex::WriteBlock(const CBlock& block, const CBlockIndex* pindex)
{
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(block.vtx.size());
    for (auto tx : block.vtx) {
        vPos.push_back(std::make_pair(tx->GetHash(), pos));
        pos.nTxOffset += ::GetSerializeSize(*tx, SER_DISK, CLIENT_VERSION);
    }
    return m_db->WriteTxIndex(vPos, pindex->GetBlockHash());
}

void TxIndex::BlockConnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex,
                    const std::vector<CTransactionRef>& txn_conflicted)
{
    if (!m_synced) {
        return;
    }

    LOCK(m_cs_queue);
    m_queue.push_back(TxIndexUpdate(block, pindex));
    m_queue_signal();
}

bool TxIndex::BlockUntilSyncedToCurrentChain()
{
    AssertLockNotHeld(cs_main);

    if (!m_synced) {
        return false;
    }

    {
        // Skip the queue-draining stuff if we know we're caught up with
        // chainActive.Tip()...

        LOCK(cs_main);
        auto chain_tip = chainActive.Tip();
        auto best_block_index = m_best_block_index.load();
        if (best_block_index->GetAncestor(chain_tip->nHeight) == chain_tip) {
            return true;
        }
    }

    // ...otherwise put a callback in the validation interface queue and wait
    // for the queue to drain enough to execute it (indicating we are caught up
    // at least with the time we entered this function).

    std::promise<void> promise1;
    CallFunctionInValidationInterfaceQueue([&promise1] {
        promise1.set_value();
    });
    promise1.get_future().wait();

    std::future<void> future2;
    {
        LOCK(m_cs_queue);
        m_queue.push_back(std::promise<void>());
        m_queue_signal();

        auto& promise = boost::get<std::promise<void>>(m_queue.back());
        future2 = std::move(promise.get_future());
    }
    future2.wait();

    return true;
}

bool TxIndex::FindTx(const uint256& txid, CDiskTxPos& pos) const
{
    return m_db->ReadTxIndex(txid, pos);
}

void TxIndex::Interrupt()
{
    m_interrupt();
    m_queue_signal();
}

void TxIndex::Start()
{
    RegisterValidationInterface(this);
    if (!Init()) {
        return;
    }

    m_thread_sync = std::thread(&TraceThread<std::function<void()> >, "txindex",
                                std::function<void()>(std::bind(&TxIndex::ThreadSync, this)));
}

void TxIndex::Stop()
{
    UnregisterValidationInterface(this);

    if (m_thread_sync.joinable()) {
        m_thread_sync.join();
    }
}
