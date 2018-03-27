// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>
#include <iostream>

#include <crypto/sha256.h>
#include <merkleset.h>
#include <util.h>
#include <utilstrencodings.h>

namespace {

    constexpr size_t POINTER_SIZE = sizeof(unsigned char*);

    constexpr size_t HASH_SIZE = 32;

    constexpr size_t SLOT_SIZE = sizeof(uint32_t) + HASH_SIZE;

    typedef unsigned char* hash_ref;

    struct Node {
        // Second hardest problem in computer science strikes again.
        struct Slot {
            uint32_t* m_count;
            hash_ref m_hash;

            Slot();
            Slot(uint32_t* count, hash_ref hash);

            uint32_t Count();
            void Set(uint32_t count, hash_ref hash);
            void Clear();
        };

        Slot m_parent;
        bool m_bit;
        unsigned char** m_chunk_ref;
        unsigned char* m_data;
        size_t m_size;

        Node();
        Node(Slot parent, bool bit, unsigned char** chunk_ref, unsigned char* data, size_t size);

        size_t ChildSize() const;

        Slot LeftSlot();
        Slot RightSlot();

        Node LeftChild();
        Node RightChild();

        void UpdateParent();

        bool IsTerminal();
    };

    void SetHash(hash_ref dst, const hash_ref src)
    {
        memcpy(dst, src, HASH_SIZE);
    }

    bool HashBit(const hash_ref hash, int index)
    {
        return hash[index / 8] & (1 << (7 - (index % 8)));
    }

    int HashCompare(const hash_ref hash_a, const hash_ref hash_b)
    {
        return memcmp(hash_a, hash_b, HASH_SIZE);
    }

    bool HashEqual(const hash_ref hash_a, const hash_ref hash_b)
    {
        return HashCompare(hash_a, hash_b) == 0;
    }

    std::string HashToHex(const hash_ref hash)
    {
        return HexStr(hash, hash + 4);
    }

    bool UpdateCompare(const std::pair<uint256, MerkleSet::UpdateOp>& a,
                       const std::pair<uint256, MerkleSet::UpdateOp>& b)
    {
        return a.first < b.first;
    }

} // namespace

class MerkleSet::Impl
{
private:
    uint32_t m_count;
    unsigned char m_root_hash[HASH_SIZE];
    unsigned char* m_root_chunk;
    size_t m_chunk_size;

    unsigned char* AllocateChunk() const;
    bool DeallocateChunk(unsigned char* chunk) const;

    bool AddHashSingle(std::deque<Node>& node_stack, const hash_ref insert_hash);
    void AddHashPair(std::deque<Node>& node_stack, const hash_ref hash1, const hash_ref hash2);
    void AddHashTriple(std::deque<Node>& node_stack, const hash_ref hash1, const hash_ref hash2, const hash_ref hash3);
    void PushNode(std::deque<Node>& node_stack, Node& node);

    void AdvancePosition(std::deque<Node>& node_stack, const hash_ref next_position);
    bool RemoveHash(std::deque<Node>& node_stack, const hash_ref remove_hash);
    void RollUpTerminalNode(std::deque<Node>& node_stack);
    void ClearNode(std::deque<Node>& node_stack);

public:
    Impl(size_t chunk_size);
    ~Impl();

    std::vector<bool> Update(std::vector<std::pair<uint256, UpdateOp>> hashes);
    bool Has(uint256 hash, std::vector<uint256>* proof) const;
    uint256 RootHash() const;
    uint32_t Count() const;
};

MerkleSet::MerkleSet(size_t chunk_size)
    : m_impl(MakeUnique<MerkleSet::Impl>(chunk_size))
{}

MerkleSet::~MerkleSet() = default;

std::vector<bool> MerkleSet::Update(std::vector<std::pair<uint256, UpdateOp>> hashes)
{
    return m_impl->Update(std::move(hashes));
}

bool MerkleSet::Has(uint256 hash, std::vector<uint256>* proof) const
{
    return m_impl->Has(hash, proof);
}

uint256 MerkleSet::RootHash() const
{
    return m_impl->RootHash();
}

uint32_t MerkleSet::Count() const
{
    return m_impl->Count();
}

Node::Slot::Slot() : Slot(nullptr, nullptr) {}

Node::Slot::Slot(uint32_t* count, hash_ref hash)
    : m_count(count), m_hash(hash)
{}

inline uint32_t Node::Slot::Count()
{
    return *m_count;
}

inline void Node::Slot::Set(uint32_t count, hash_ref hash)
{
    *m_count = count;
    SetHash(m_hash, hash);
}

inline void Node::Slot::Clear()
{
    *m_count = 0;
    memset(m_hash, 0, HASH_SIZE);
}

Node::Node() : Node(Slot(), 0, nullptr, nullptr, 0) {}

Node::Node(Slot parent, bool bit, unsigned char** chunk_ref, unsigned char* data, size_t size)
    : m_parent(parent), m_bit(bit), m_chunk_ref(chunk_ref), m_data(data), m_size(size)
{}

inline size_t Node::ChildSize() const
{
    return (m_size - 2 * SLOT_SIZE) / 2;
}

inline Node::Slot Node::LeftSlot()
{
    uint32_t* count = reinterpret_cast<uint32_t*>(m_data);
    hash_ref hash = m_data + sizeof(uint32_t);
    return Slot(count, hash);
}

inline Node::Slot Node::RightSlot()
{
    uint32_t* count = reinterpret_cast<uint32_t*>(m_data + SLOT_SIZE);
    hash_ref hash = m_data + SLOT_SIZE + sizeof(uint32_t);
    return Slot(count, hash);
}

inline Node Node::LeftChild()
{
    unsigned char* child_data = m_data + 2 * SLOT_SIZE;
    return Node(LeftSlot(), 0, nullptr, child_data, ChildSize());
}

inline Node Node::RightChild()
{
    unsigned char* child_data = m_data + 2 * SLOT_SIZE + ChildSize();
    return Node(RightSlot(), 1, nullptr, child_data, ChildSize());
}

void Node::UpdateParent()
{
    *m_parent.m_count = LeftSlot().Count() + RightSlot().Count();
    CSHA256().
        Write(m_data, 2 * (sizeof(uint32_t) + HASH_SIZE)).
        Finalize(m_parent.m_hash);
}

bool Node::IsTerminal()
{
    return LeftSlot().Count() == 1 && RightSlot().Count() == 1;
}

MerkleSet::Impl::Impl(size_t chunk_size)
    : m_count(0), m_root_chunk(nullptr), m_chunk_size(0)
{
    memset(m_root_hash, 0, sizeof(m_root_hash));

    size_t next_chunk_size = POINTER_SIZE;
    while (next_chunk_size <= chunk_size) {
        m_chunk_size = next_chunk_size;
        next_chunk_size = (SLOT_SIZE + m_chunk_size) * 2;
    }
    if (m_chunk_size <= POINTER_SIZE) {
        throw std::invalid_argument("chunk_size");
    }
}

MerkleSet::Impl::~Impl()
{
    // Massive memory leak
}

std::vector<bool> MerkleSet::Impl::Update(std::vector<std::pair<uint256, MerkleSet::UpdateOp>> hashes)
{
    std::deque<Node> node_stack;
    Node::Slot root_slot(&m_count, m_root_hash);

    // Collect update results for each hash into a vector.
    std::vector<bool> result;
    result.reserve(hashes.size());

    // Stable sort will reorder hashes, but not update operations grouped by hash.
    std::stable_sort(hashes.begin(), hashes.end(), UpdateCompare);

    for (auto& update : hashes) {
        // Cannot add empty hashes, as they would be confused with terminals.
        if (update.first.IsNull()) {
            result.push_back(false);
            continue;
        }

        hash_ref hash = update.first.begin();
        bool modified;

        switch (update.second) {
        case MerkleSet::UpdateOp::INSERT:
            if (!node_stack.empty()) {
                AdvancePosition(node_stack, hash);
                modified = AddHashSingle(node_stack, hash);

            } else {
                switch (root_slot.Count()) {
                case 0:
                    root_slot.Set(1, hash);
                    modified = true;
                    break;

                case 1:
                    if (HashEqual(root_slot.m_hash, hash)) {
                        modified = false;
                        break;
                    }

                    assert(m_root_chunk == nullptr);
                    m_root_chunk = AllocateChunk();
                    node_stack.emplace_back(root_slot, 0, &m_root_chunk, m_root_chunk, m_chunk_size);

                    {
                        hash_ref hash1 = hash, hash2 = root_slot.m_hash;
                        if (HashCompare(hash1, hash2) > 0) {
                            std::swap(hash1, hash2);
                        }

                        AddHashPair(node_stack, hash1, hash2);
                    }

                    modified = true;
                    break;

                default:
                    assert(m_root_chunk != nullptr);
                    node_stack.emplace_back(root_slot, 0, &m_root_chunk, m_root_chunk, m_chunk_size);

                    AdvancePosition(node_stack, hash);
                    modified = AddHashSingle(node_stack, hash);
                    break;

                }
            }
            break;

        case MerkleSet::UpdateOp::REMOVE:
            if (!node_stack.empty()) {
                AdvancePosition(node_stack, hash);
                modified = RemoveHash(node_stack, hash);

            } else {
                switch (root_slot.Count()) {
                case 0:
                    modified = false;
                    break;

                case 1:
                    if (HashEqual(root_slot.m_hash, hash)) {
                        modified = true;
                        root_slot.Clear();
                    } else {
                        modified = false;
                    }
                    break;

                default:
                    assert(m_root_chunk != nullptr);
                    node_stack.emplace_back(root_slot, 0, &m_root_chunk, m_root_chunk, m_chunk_size);

                    AdvancePosition(node_stack, hash);
                    modified = RemoveHash(node_stack, hash);
                    break;

                }
            }
            break;

        default:
            throw std::logic_error("Unhandled MerkleSet::UpdateOp");

        }

        result.push_back(modified);
    }

    // Unwind the node stack, computing middle node hashes.
    while (!node_stack.empty()) {
        node_stack.back().UpdateParent();
        node_stack.pop_back();
    }

    return result;
}

bool MerkleSet::Impl::RemoveHash(std::deque<Node>& node_stack, const hash_ref remove_hash)
{
    Node& node = node_stack.back();
    int index = node_stack.size() - 1;

    Node::Slot slot, other_slot;
    Node child_node, other_child_node;
    if (!HashBit(remove_hash, index)) {
        slot = node.LeftSlot(), other_slot = node.RightSlot();
        child_node = node.LeftChild(), other_child_node = node.RightChild();
    } else {
        slot = node.RightSlot(), other_slot = node.LeftSlot();
        child_node = node.RightChild(), other_child_node = node.LeftChild();
    }

    switch (slot.Count()) {
    case 0:
        return false;

    case 1:
        switch (other_slot.Count()) {
        case 0:
            throw std::logic_error("INTERNAL ERROR: node has one empty child and one terminal");

        case 1:
            if (HashEqual(remove_hash, slot.m_hash)) {
                node.m_parent.Set(1, other_slot.m_hash);
            } else if (HashEqual(remove_hash, other_slot.m_hash)) {
                node.m_parent.Set(1, slot.m_hash);
            } else {
                return false;
            }

            ClearNode(node_stack);
            if (!node_stack.empty() && node_stack.back().IsTerminal()) {
                RollUpTerminalNode(node_stack);
            }
            return true;

        default:
            if (!HashEqual(remove_hash, slot.m_hash)) {
                return false;
            }

            slot.Clear();

            // Push for the sake of doing the dereference thing.
            PushNode(node_stack, other_child_node);
            if (node_stack.back().IsTerminal()) {
                RollUpTerminalNode(node_stack);
            } else {
                node_stack.pop_back();
            }
            return true;

        }

    default:
        PushNode(node_stack, child_node);
        return RemoveHash(node_stack, remove_hash); // tail-recursion

    }
}

void MerkleSet::Impl::AdvancePosition(std::deque<Node>& node_stack, const hash_ref next_position)
{
    // Determine bit index where position and insert_hash diverge.
    int prefix_index = 0;
    auto stack_it = ++node_stack.begin();
    while (stack_it != node_stack.end() &&
           stack_it->m_bit == HashBit(next_position, prefix_index)) {
        ++prefix_index;
        ++stack_it;
    }

    // Rewind stack back to the divergence point.
    int index = node_stack.size() - 1;
    while (prefix_index < index) {
        node_stack.back().UpdateParent();
        node_stack.pop_back();
        --index;
    }
}

bool MerkleSet::Impl::AddHashSingle(std::deque<Node>& node_stack, const hash_ref insert_hash)
{
    Node& node = node_stack.back();
    int index = node_stack.size() - 1;

    Node::Slot slot, other_slot;
    Node child_node;
    if (!HashBit(insert_hash, index)) {
        slot = node.LeftSlot();
        other_slot = node.RightSlot();
        child_node = node.LeftChild();
    } else {
        slot = node.RightSlot();
        other_slot = node.LeftSlot();
        child_node = node.RightChild();
    }

    switch (slot.Count()) {
    case 0:
        switch (other_slot.Count()) {
        case 0:
            throw std::logic_error("INTERNAL ERROR: node has two empy children");

        case 1:
            throw std::logic_error("INTERNAL ERROR: node has one empty child and one terminal");

        default:
            slot.Set(1, insert_hash);
            return true;

        }

    case 1:
        if (HashEqual(insert_hash, slot.m_hash)) {
            return false;
        }

        switch (other_slot.Count()) {
        case 0:
            throw std::logic_error("INTERNAL ERROR: node has one empty child and one terminal");

        case 1:
            if (HashEqual(insert_hash, other_slot.m_hash)) {
                return false;
            }

            {
                Node::Slot left_slot = node.LeftSlot();
                Node::Slot right_slot = node.RightSlot();

                // Make copies of left_hash and right_hash, then set the original locations to empty.
                unsigned char left_hash_copy[HASH_SIZE], right_hash_copy[HASH_SIZE];
                SetHash(left_hash_copy, left_slot.m_hash);
                SetHash(right_hash_copy, right_slot.m_hash);

                left_slot.Clear();
                right_slot.Clear();

                hash_ref hash1 = left_hash_copy, hash2 = insert_hash, hash3 = right_hash_copy;
                if (HashCompare(hash1, hash2) > 0) {
                    std::swap(hash1, hash2);
                }
                if (HashCompare(hash3, hash2) < 0) {
                    std::swap(hash2, hash3);
                }

                AddHashTriple(node_stack, hash1, hash2, hash3);
            }
            return true;

        default:
            PushNode(node_stack, child_node);
            {
                hash_ref hash1 = slot.m_hash, hash2 = insert_hash;
                if (HashCompare(hash1, hash2) > 0) {
                    std::swap(hash1, hash2);
                }

                AddHashPair(node_stack, hash1, hash2);
            }
            return true;

        }

    default:
        PushNode(node_stack, child_node);
        return AddHashSingle(node_stack, insert_hash); // tail recursion

    }
}

void MerkleSet::Impl::RollUpTerminalNode(std::deque<Node>& node_stack)
{
    bool any_changes = false;
    unsigned char left_hash[HASH_SIZE], right_hash[HASH_SIZE];

    while (node_stack.size() >= 2) {
        Node& node = node_stack.back();
        Node& parent_node = *(++node_stack.rbegin());

        Node::Slot parent_other_slot;
        if (node.m_bit) {
            parent_other_slot = parent_node.LeftSlot();
        } else {
            parent_other_slot = parent_node.RightSlot();
        }

        if (parent_other_slot.Count() != 0) {
            break;
        }

        if (!any_changes) {
            SetHash(left_hash, node.LeftSlot().m_hash);
            SetHash(right_hash, node.RightSlot().m_hash);
            any_changes = true;
        }

        ClearNode(node_stack);
    }

    if (!any_changes) {
        return;
    }

    Node& node = node_stack.back();
    node.LeftSlot().Set(1, left_hash);
    node.RightSlot().Set(1, right_hash);
}

void MerkleSet::Impl::AddHashPair(std::deque<Node>& node_stack, const hash_ref hash1, const hash_ref hash2)
{
    Node& node = node_stack.back();
    Node::Slot left_slot = node.LeftSlot();
    Node::Slot right_slot = node.RightSlot();

    assert(left_slot.Count() == 0);
    assert(right_slot.Count() == 0);

    left_slot.Set(1, hash1);
    right_slot.Set(1, hash2);
}

void MerkleSet::Impl::AddHashTriple(std::deque<Node>& node_stack, const hash_ref hash1, const hash_ref hash2, const hash_ref hash3)
{
    Node& node = node_stack.back();
    int index = node_stack.size() - 1;

    Node::Slot left_slot = node.LeftSlot();
    Node::Slot right_slot = node.RightSlot();
    assert(left_slot.Count() == 0);
    assert(right_slot.Count() == 0);

    uint8_t bit1 = HashBit(hash1, index);
    uint8_t bit2 = HashBit(hash2, index);
    uint8_t bit3 = HashBit(hash3, index);

    if (bit1 == 0 && bit2 == 0 && bit3 == 0) {
        Node child_node = node.LeftChild();
        PushNode(node_stack, child_node);
        AddHashTriple(node_stack, hash1, hash2, hash3);

    } else if (bit1 == 1 && bit2 == 1 && bit3 == 1) {
        Node child_node = node.RightChild();
        PushNode(node_stack, child_node);
        AddHashTriple(node_stack, hash1, hash2, hash3);

    } else if (bit1 == 0 && bit2 == 0 && bit3 == 1) {
        Node child_node = node.LeftChild();
        PushNode(node_stack, child_node);
        AddHashPair(node_stack, hash1, hash2);
        right_slot.Set(1, hash3);

    } else if (bit1 == 0 && bit2 == 1 && bit3 == 1) {
        Node child_node = node.RightChild();
        PushNode(node_stack, child_node);
        AddHashPair(node_stack, hash2, hash3);
        left_slot.Set(1, hash1);

    } else {
        throw std::logic_error("INTERNAL ERROR: insert triple called with unsorted hashes");

    }
}

void MerkleSet::Impl::PushNode(std::deque<Node>& node_stack, Node& node)
{
    if (node.m_size == POINTER_SIZE) {
        unsigned char** chunk_ref = reinterpret_cast<unsigned char**>(node.m_data);
        if (*chunk_ref == nullptr) {
            *chunk_ref = AllocateChunk();
        }
        node_stack.emplace_back(node.m_parent, node.m_bit, chunk_ref, *chunk_ref, m_chunk_size);
    } else {
        node_stack.push_back(node);
    }
}

void MerkleSet::Impl::ClearNode(std::deque<Node>& node_stack)
{
    Node& node = node_stack.back();
    if (node.m_chunk_ref) {
        DeallocateChunk(*node.m_chunk_ref);
        *node.m_chunk_ref = nullptr;
    } else {
        node.LeftSlot().Clear();
        node.RightSlot().Clear();
    }
    node_stack.pop_back();
}

unsigned char* MerkleSet::Impl::AllocateChunk() const
{
    unsigned char* chunk = new unsigned char[m_chunk_size];
    memset(chunk, 0, m_chunk_size);
    return chunk;
}

bool MerkleSet::Impl::DeallocateChunk(unsigned char* chunk) const
{
    delete chunk;
    return true;
}

bool MerkleSet::Impl::Has(uint256 hash, std::vector<uint256>* proof) const
{
    return true;
}

uint256 MerkleSet::Impl::RootHash() const
{
    uint256 result;
    memcpy(result.begin(), m_root_hash, HASH_SIZE);
    return result;
}

uint32_t MerkleSet::Impl::Count() const
{
    return m_count;
}
