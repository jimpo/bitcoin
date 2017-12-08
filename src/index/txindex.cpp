// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/txindex.h>
#include <init.h>
#include <tinyformat.h>
#include <ui_interface.h>
#include <util.h>
#include <validation.h>
#include <warnings.h>

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

    auto chain_tip = chainActive.Tip();
    uint256 tip_hash;
    if (chain_tip) {
        tip_hash = chain_tip->GetBlockHash();
    }

    if (!m_db->MigrateData(*pblocktree, tip_hash)) {
        return false;
    }

    uint256 best_block_hash;
    if (!m_db->ReadBestBlockHash(best_block_hash)) {
        FatalError("%s: Failed to read from tx index database", __func__);
        return false;
    }

    if (best_block_hash.IsNull()) {
        return true;
    }

    auto it = mapBlockIndex.find(best_block_hash);
    if (it == mapBlockIndex.end()) {
        FatalError("%s: Last block synced by txindex is unknown", __func__);
        return false;
    }

    const auto pindex = it->second;
    m_best_block_index = pindex;
    if (!chain_tip || pindex->GetAncestor(chain_tip->nHeight) == chain_tip) {
        m_synced = true;
    }

    return true;
}

bool TxIndex::WriteBlock(const CBlock& block, const CBlockIndex* pindex)
{
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos>> vPos;
    vPos.reserve(block.vtx.size());
    for (auto tx : block.vtx) {
        vPos.push_back(std::make_pair(tx->GetHash(), pos));
        pos.nTxOffset += ::GetSerializeSize(*tx, SER_DISK, CLIENT_VERSION);
    }
    return m_db->WriteTxns(vPos) && m_db->WriteBestBlockHash(pindex->GetBlockHash());
}

void TxIndex::BlockConnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* pindex,
                    const std::vector<CTransactionRef>& txn_conflicted)
{
    if (!m_synced) {
        return;
    }

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
    RegisterValidationInterface(this);
    if (!Init()) {
        return;
    }
}

void TxIndex::Stop()
{
    UnregisterValidationInterface(this);
}
