// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitset>

#include <chain.h>
#include <crypto/sha256.h>
#include <utilmath.h>

/**
 * CChain implementation
 */
uint256 CChain::ComputeMMRPeak(int header_height, int root_height,
                               std::vector<uint256>* intermediate_entries,
                               std::vector<uint256>* proof_branch) const
{
    if (header_height > root_height) {
        throw std::invalid_argument("header_height must be <= root_height");
    }

    int peak_height = Log2Floor(static_cast<uint32_t>(header_height ^ (root_height + 1)));

    if (intermediate_entries) {
        intermediate_entries->reserve(peak_height);
    }
    if (proof_branch) {
        proof_branch->reserve(peak_height);
    }

    CSHA256 hasher;
    uint256 peak = vChain[header_height]->GetBlockHash();
    int idx = header_height;

    for (int bit = 0; bit < peak_height; ++bit) {
        int mask = 1 << bit;
        const uint256& peak_other = GetMMREntry(idx ^ mask, bit);

        hasher.Reset();
        if (idx & mask) {
            hasher.Write(peak_other.begin(), peak_other.size());
            hasher.Write(peak.begin(), peak.size());
        } else {
            hasher.Write(peak.begin(), peak.size());
            hasher.Write(peak_other.begin(), peak_other.size());
        }
        hasher.Finalize(peak.begin());

        if (intermediate_entries) {
            intermediate_entries->push_back(peak);
        }
        if (proof_branch) {
            proof_branch->push_back(peak_other);
        }

        idx |= mask;
    }

    return peak;
}

std::vector<uint256> CChain::GetMMRPeaks(int root_height) const
{
    int idx = root_height + 1;
    int n_peaks = std::bitset<32>(idx).count();

    std::vector<uint256> peaks;
    peaks.reserve(n_peaks);

    for (int bit = 0; idx != 0; ++bit) {
        int mask = 1 << bit;
        if (idx & mask) {
            peaks.push_back(GetMMREntry(idx - 1, bit));
            idx ^= mask;
        }
    }

    return peaks;
}

void CChain::SetTip(CBlockIndex *pindex) {
    if (pindex == nullptr) {
        vChain.clear();
        return;
    }
    vChain.resize(pindex->nHeight + 1);
    m_mmr_entries.resize(pindex->nHeight + 1);

    CBlockIndex* pindex_walk = pindex;
    while (pindex_walk && vChain[pindex_walk->nHeight] != pindex_walk) {
        vChain[pindex_walk->nHeight] = pindex_walk;
        pindex_walk = pindex_walk->pprev;
    }

    int height = pindex_walk ? pindex_walk->nHeight + 1 : 0;
    for (; height <= pindex->nHeight; ++height) {
        ComputeMMRPeak(height, height, &m_mmr_entries[height], nullptr);
    }
}

CBlockLocator CChain::GetLocator(const CBlockIndex *pindex) const {
    int nStep = 1;
    std::vector<uint256> vHave;
    vHave.reserve(32);

    if (!pindex)
        pindex = Tip();
    while (pindex) {
        vHave.push_back(pindex->GetBlockHash());
        // Stop when we have added the genesis block.
        if (pindex->nHeight == 0)
            break;
        // Exponentially larger steps back, plus the genesis block.
        int nHeight = std::max(pindex->nHeight - nStep, 0);
        if (Contains(pindex)) {
            // Use O(1) CChain index if possible.
            pindex = (*this)[nHeight];
        } else {
            // Otherwise, use O(log n) skiplist.
            pindex = pindex->GetAncestor(nHeight);
        }
        if (vHave.size() > 10)
            nStep *= 2;
    }

    return CBlockLocator(vHave);
}

const CBlockIndex *CChain::FindFork(const CBlockIndex *pindex) const {
    if (pindex == nullptr) {
        return nullptr;
    }
    if (pindex->nHeight > Height())
        pindex = pindex->GetAncestor(Height());
    while (pindex && !Contains(pindex))
        pindex = pindex->pprev;
    return pindex;
}

CBlockIndex* CChain::FindEarliestAtLeast(int64_t nTime) const
{
    std::vector<CBlockIndex*>::const_iterator lower = std::lower_bound(vChain.begin(), vChain.end(), nTime,
        [](CBlockIndex* pBlock, const int64_t& time) -> bool { return pBlock->GetBlockTimeMax() < time; });
    return (lower == vChain.end() ? nullptr : *lower);
}

uint256 CChain::GenerateMMRCommitment(int root_height) const
{
    if (root_height > Height()) {
        throw std::invalid_argument("root_height must be <= chain height");
    }

    CSHA256 hasher;
    uint256 commitment;
    for (const uint256& peak : GetMMRPeaks(root_height)) {
        hasher.Reset()
            .Write(commitment.begin(), commitment.size())
            .Write(peak.begin(), peak.size())
            .Finalize(commitment.begin());
    }
    return commitment;
}

std::vector<uint256> CChain::GenerateMMRProof(int header_height, int root_height,
                                              uint256* root_commitment) const
{
    if (header_height > root_height) {
        throw std::invalid_argument("header_height must be <= root_height");
    }

    int idx = root_height + 1;

    // This is the height of the MMR peak containing the header at requested height.
    int peak_height = Log2Floor(static_cast<uint32_t>(header_height ^ idx));

    // Calculate the number of peaks above and below the the one containing the requested header.
    int mask = (1 << peak_height) - 1;
    int n_lower_peaks = std::bitset<32>(idx & mask).count();
    int n_higher_peaks = std::bitset<32>(idx & ~mask).count() - 1;

    std::vector<uint256> proof;
    proof.reserve(peak_height + 1 + n_higher_peaks);

    // Populate first peak_height branch entries with the branch into the peak.
    const uint256& proof_peak = ComputeMMRPeak(header_height, root_height, nullptr, &proof);

    const std::vector<uint256>& peaks = GetMMRPeaks(root_height);

    CSHA256 hasher;
    uint256 commitment;
    for (int i = 0; i < n_lower_peaks; i++) {
        hasher.Reset()
            .Write(commitment.begin(), commitment.size())
            .Write(peaks[i].begin(), peaks[i].size())
            .Finalize(commitment.begin());
    }

    // Add aggregated hash of all lower peaks to proof.
    proof.push_back(commitment);
    hasher.Reset()
        .Write(commitment.begin(), commitment.size())
        .Write(proof_peak.begin(), proof_peak.size())
        .Finalize(commitment.begin());

    for (unsigned int i = n_lower_peaks + 1; i < peaks.size(); ++i) {
        // Add all higher peaks to proof
        proof.push_back(peaks[i]);
        hasher.Reset()
            .Write(commitment.begin(), commitment.size())
            .Write(peaks[i].begin(), peaks[i].size())
            .Finalize(commitment.begin());
    }

    if (root_commitment) {
        *root_commitment = commitment;
    }

    return proof;
}

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
int static inline InvertLowestOne(int n) { return n & (n - 1); }

/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
int static inline GetSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable,
    // but the following expression seems to perform well in simulations (max 110 steps to go back
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

const CBlockIndex* CBlockIndex::GetAncestor(int height) const
{
    if (height > nHeight || height < 0) {
        return nullptr;
    }

    const CBlockIndex* pindexWalk = this;
    int heightWalk = nHeight;
    while (heightWalk > height) {
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = GetSkipHeight(heightWalk - 1);
        if (pindexWalk->pskip != nullptr &&
            (heightSkip == height ||
             (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                       heightSkipPrev >= height)))) {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pindexWalk = pindexWalk->pskip;
            heightWalk = heightSkip;
        } else {
            assert(pindexWalk->pprev);
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }
    return pindexWalk;
}

CBlockIndex* CBlockIndex::GetAncestor(int height)
{
    return const_cast<CBlockIndex*>(static_cast<const CBlockIndex*>(this)->GetAncestor(height));
}

void CBlockIndex::BuildSkip()
{
    if (pprev)
        pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
}

arith_uint256 GetBlockProof(const CBlockIndex& block)
{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for an arith_uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (bnTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}

int64_t GetBlockProofEquivalentTime(const CBlockIndex& to, const CBlockIndex& from, const CBlockIndex& tip, const Consensus::Params& params)
{
    arith_uint256 r;
    int sign = 1;
    if (to.nChainWork > from.nChainWork) {
        r = to.nChainWork - from.nChainWork;
    } else {
        r = from.nChainWork - to.nChainWork;
        sign = -1;
    }
    r = r * arith_uint256(params.nPowTargetSpacing) / GetBlockProof(tip);
    if (r.bits() > 63) {
        return sign * std::numeric_limits<int64_t>::max();
    }
    return sign * r.GetLow64();
}

/** Find the last common ancestor two blocks have.
 *  Both pa and pb must be non-nullptr. */
const CBlockIndex* LastCommonAncestor(const CBlockIndex* pa, const CBlockIndex* pb) {
    if (pa->nHeight > pb->nHeight) {
        pa = pa->GetAncestor(pb->nHeight);
    } else if (pb->nHeight > pa->nHeight) {
        pb = pb->GetAncestor(pa->nHeight);
    }

    while (pa != pb && pa && pb) {
        pa = pa->pprev;
        pb = pb->pprev;
    }

    // Eventually all chain branches meet at the genesis block.
    assert(pa == pb);
    return pa;
}

bool VerifyChainMMRProof(int header_height, int root_height, const uint256& block_hash,
                         const uint256& root_commitment, const std::vector<uint256>& proof)
{
    if (header_height > root_height) {
        throw std::invalid_argument("header_height must be <= root_height");
    }

    // This is the height of the MMR peak containing the header at requested height.
    int peak_height = Log2Floor(static_cast<uint32_t>(header_height ^ (root_height + 1)));

    CSHA256 hasher;
    uint256 commitment = block_hash;

    int i;
    for (i = 0; i < peak_height; ++i) {
        hasher.Reset();
        if (header_height & (1 << i)) {
            hasher.Write(proof[i].begin(), CSHA256::OUTPUT_SIZE);
            hasher.Write(commitment.begin(), CSHA256::OUTPUT_SIZE);
        } else {
            hasher.Write(commitment.begin(), CSHA256::OUTPUT_SIZE);
            hasher.Write(proof[i].begin(), CSHA256::OUTPUT_SIZE);
        }
        hasher.Finalize(commitment.begin());
    }

    hasher.Reset()
        .Write(proof[i].begin(), proof[i].size())
        .Write(commitment.begin(), commitment.size())
        .Finalize(commitment.begin());
    ++i;

    for (; i < static_cast<int>(proof.size()); ++i) {
        hasher.Reset()
            .Write(commitment.begin(), commitment.size())
            .Write(proof[i].begin(), proof[i].size())
            .Finalize(commitment.begin());
    }

    return commitment == root_commitment;
}
