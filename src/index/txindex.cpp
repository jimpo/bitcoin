// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <index/txindex.h>
#include <init.h>
#include <tinyformat.h>
#include <ui_interface.h>
#include <util.h>
#include <validation.h>
#include <warnings.h>

constexpr int64_t SYNC_LOG_INTERVAL = 30; // seconds

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

TxIndex::TxIndex(std::unique_ptr<TxIndexDB> db) :
    m_db(std::move(db)), m_synced(false), m_best_block_index(nullptr)
{}

bool TxIndex::Init()
{
    LOCK(cs_main);

    const CBlockIndex* chain_tip = chainActive.Tip();
    uint256 tip_hash;
    if (chain_tip) {
        tip_hash = chain_tip->GetBlockHash();
    }

    // Attempt to migrate txindex from the old database to the new one. Even if
    // chain_tip is null, the node could be reindexing and we still want to
    // delete txindex records in the old database.
    if (!m_db->MigrateData(*pblocktree, tip_hash)) {
        return false;
    }

    if (!chain_tip) {
        m_synced = true;
        return true;
    }

    uint256 best_block_hash;
    if (!m_db->ReadBestBlockHash(best_block_hash)) {
        FatalError("%s: Failed to read from tx index database", __func__);
        return false;
    }

    if (best_block_hash.IsNull()) {
        return true;
    }

    const CBlockIndex* pindex = LookupBlockIndex(best_block_hash);
    if (!pindex) {
        FatalError("%s: Last block synced by txindex is unknown", __func__);
        return false;
    }

    m_best_block_index = pindex;
    if (pindex->GetAncestor(chain_tip->nHeight) == chain_tip) {
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

    const CBlockIndex* pindex = chainActive.Next(pindex_prev);
    if (pindex) {
        return pindex;
    }

    return chainActive.Next(chainActive.FindFork(pindex_prev));
}

void TxIndex::ThreadSync()
{
    const CBlockIndex* pindex = m_best_block_index.load();
    if (!m_synced) {
        auto& consensus_params = Params().GetConsensus();

        int64_t last_log_time = 0;
        while (true) {
            {
                LOCK(cs_main);
                const CBlockIndex* pindex_next = NextSyncBlock(pindex);
                if (!pindex_next) {
                    m_best_block_index = pindex;
                    m_synced = true;
                    break;
                }
                pindex = pindex_next;
            }

            int64_t current_time = GetTime();
            if (last_log_time + SYNC_LOG_INTERVAL < current_time) {
                LogPrintf("Syncing txindex with block chain from height %d\n", pindex->nHeight);
                last_log_time = current_time;
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

    if (pindex) {
        LogPrintf("txindex is enabled at height %d\n", pindex->nHeight);
    } else {
        LogPrintf("txindex is enabled\n");
    }
}

bool TxIndex::WriteBlock(const CBlock& block, const CBlockIndex* pindex)
{
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos>> vPos;
    vPos.reserve(block.vtx.size());
    for (const auto& tx : block.vtx) {
        vPos.emplace_back(tx->GetHash(), pos);
        pos.nTxOffset += ::GetSerializeSize(*tx, SER_DISK, CLIENT_VERSION);
    }
    return m_db->WriteTxs(vPos, pindex->GetBlockHash());
}

void TxIndex::BlockConnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex,
                    const std::vector<CTransactionRef>& txn_conflicted)
{
    if (!m_synced) {
        return;
    }

    // Ensure block connects to an ancestor of the current best block. This should always be the
    // case assuming BlockConnected is called on the ValidationInterfaces in the proper order.
    const CBlockIndex* best_block_index = m_best_block_index.load();
    if (!best_block_index) {
        if (pindex->nHeight != 0) {
            FatalError("%s: First block connected is not the genesis block (height=%d)",
                       __func__, pindex->nHeight);
            return;
        }
    } else {
        if (best_block_index->GetAncestor(pindex->nHeight - 1) != pindex->pprev) {
            FatalError("%s: Block %s does not connect to an ancestor of known best chain (tip=%s)",
                       __func__, pindex->GetBlockHash().ToString(),
                       best_block_index->GetBlockHash().ToString());
            return;
        }
    }

    if (WriteBlock(*block, pindex)) {
        m_best_block_index = pindex;
    } else {
        FatalError("%s: Failed to write block %s to txindex",
                   __func__, pindex->GetBlockHash().ToString());
        return;
    }
}

bool TxIndex::FindTx(const uint256& txid, CDiskTxPos& pos) const
{
    return m_db->ReadTxPos(txid, pos);
}

void TxIndex::Start()
{
    // Need to register this ValidationInterface before running Init(), so that
    // callbacks are not missed if Init sets m_synced to true.
    RegisterValidationInterface(this);
    if (!Init()) {
        return;
    }

    m_thread_sync = std::thread(&TraceThread<std::function<void()>>, "txindex",
                                std::bind(&TxIndex::ThreadSync, this));
}

void TxIndex::Stop()
{
    UnregisterValidationInterface(this);

    if (m_thread_sync.joinable()) {
        m_thread_sync.join();
    }
}
