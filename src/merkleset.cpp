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

    typedef unsigned char* hash_ref;

    struct Node {
        hash_ref m_parent_hash;
        unsigned char** m_chunk_ref;
        unsigned char* m_data;
        size_t m_size;

        Node();
        Node(hash_ref parent_hash, unsigned char** chunk_ref, unsigned char* data, size_t size);

        size_t ChildSize() const { return (m_size - HASH_SIZE * 2) / 2; }
        hash_ref LeftHash() { return m_data; }
        hash_ref RightHash() { return m_data + HASH_SIZE; }

        Node LeftChild()
        {
            unsigned char* child_data = m_data + HASH_SIZE * 2;
            return Node(LeftHash(), nullptr, child_data, ChildSize());
        }

        Node RightChild()
        {
            unsigned char* child_data = m_data + HASH_SIZE * 2 + ChildSize();
            return Node(RightHash(), nullptr, child_data, ChildSize());
        }

        void UpdateParentHash();

        bool IsTerminal();
    };

    enum HashType {
        EMPTY,
        TERMINAL,
        MIDDLE
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

    HashType GetType(const hash_ref hash)
    {
        static unsigned char empty_hash[32] = {0};

        if (HashBit(hash, 0)) {
            return HashType::MIDDLE;
        } else if (HashEqual(hash, empty_hash)) {
            return HashType::EMPTY;
        } else {
            return HashType::TERMINAL;
        }
    }

    void SetType(hash_ref hash, HashType type)
    {
        switch (type) {
        case HashType::EMPTY:
            memset(hash, 0, HASH_SIZE);
            break;
        case HashType::TERMINAL:
            hash[0] &= 0x7F;
            break;
        case HashType::MIDDLE:
            hash[0] |= 0x80;
            break;
        }
    }

} // namespace

class MerkleSet::Impl
{
private:
    unsigned char m_root_hash[HASH_SIZE];
    unsigned char* m_root_chunk;
    size_t m_chunk_size;

    unsigned char* AllocateChunk() const;
    bool DeallocateChunk(unsigned char* chunk) const;

    bool AddHashSingle(std::deque<Node>& node_stack, const hash_ref insert_hash);
    void AddHashPair(std::deque<Node>& node_stack, const hash_ref hash1, const hash_ref hash2);
    void AddHashTriple(std::deque<Node>& node_stack, const hash_ref hash1, const hash_ref hash2, const hash_ref hash3);
    void PushNode(std::deque<Node>& node_stack, Node& node);

    void AdvancePosition(std::deque<Node>& node_stack, hash_ref& position, const hash_ref next_position);
    bool RemoveHash(std::deque<Node>& node_stack, const hash_ref remove_hash);
    void RollUpTerminalNode(std::deque<Node>& node_stack, const hash_ref position);
    void ClearNode(std::deque<Node>& node_stack);

public:
    Impl(size_t chunk_size);
    ~Impl();

    std::vector<bool> Update(std::vector<std::pair<uint256, UpdateOp>> hashes);
    bool Has(uint256 hash, std::vector<uint256>* proof) const;
    uint256 RootHash() const;
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

Node::Node() : Node(nullptr, nullptr, nullptr, 0) {}

Node::Node(hash_ref parent_hash, unsigned char** chunk_ref, unsigned char* data, size_t size)
    : m_parent_hash(parent_hash), m_chunk_ref(chunk_ref), m_data(data), m_size(size)
{}

void Node::UpdateParentHash()
{
    CSHA256().Write(m_data, HASH_SIZE * 2).Finalize(m_parent_hash);
    SetType(m_parent_hash, HashType::MIDDLE);
}

bool Node::IsTerminal()
{
    return
        GetType(LeftHash()) == HashType::TERMINAL &&
        GetType(RightHash()) == HashType::TERMINAL;
}

MerkleSet::Impl::Impl(size_t chunk_size)
    : m_root_chunk(nullptr), m_chunk_size(chunk_size)
{
    memset(m_root_hash, 0, sizeof(m_root_hash));
}

MerkleSet::Impl::~Impl()
{
    // Massive memory leak
}

std::vector<bool> MerkleSet::Impl::Update(std::vector<std::pair<uint256, MerkleSet::UpdateOp>> hashes)
{
    static unsigned char start_position[32] = {0};

    std::deque<Node> node_stack;
    hash_ref position = start_position;

    for (auto& update : hashes) {
        hash_ref hash = update.first.begin();
        SetType(hash, HashType::TERMINAL);
    }
    std::sort(hashes.begin(), hashes.end());

    // Collect update results for each hash into a vector.
    std::vector<bool> result;
    result.reserve(hashes.size());

    for (auto& update : hashes) {
        // Cannot add empty hashes, as they would be confused with terminals.
        if (update.first.IsNull()) {
            result.push_back(false);
            continue;
        }

        hash_ref hash = update.first.begin();
        bool modified;

        std::cout << "Adding: " << HexStr(hash, hash + 32) << std::endl;
        std::cout << "Position: " << HexStr(position, position + 32) << std::endl;

        switch (update.second) {
        case MerkleSet::UpdateOp::INSERT:
            if (!node_stack.empty()) {
                AdvancePosition(node_stack, position, hash);
                position = hash;
                modified = AddHashSingle(node_stack, hash);

            } else {
                switch (GetType(m_root_hash)) {
                case HashType::EMPTY:
                    SetHash(m_root_hash, hash);
                    modified = true;
                    break;

                case HashType::TERMINAL:
                    if (HashEqual(m_root_hash, hash)) {
                        modified = false;
                        break;
                    }

                    assert(m_root_chunk == nullptr);
                    m_root_chunk = AllocateChunk();
                    node_stack.emplace_back(m_root_hash, &m_root_chunk, m_root_chunk, m_chunk_size);

                    {
                        hash_ref hash1 = hash, hash2 = m_root_hash;
                        if (HashCompare(hash1, hash2) > 0) {
                            std::swap(hash1, hash2);
                        }

                        AddHashPair(node_stack, hash1, hash2);
                    }

                    modified = true;
                    break;

                case HashType::MIDDLE:
                    assert(m_root_chunk != nullptr);
                    node_stack.emplace_back(m_root_hash, &m_root_chunk, m_root_chunk, m_chunk_size);

                    AdvancePosition(node_stack, position, hash);
                    position = hash;
                    modified = AddHashSingle(node_stack, hash);
                    break;

                default:
                    throw std::logic_error("Unhandled HashType");

                }
            }
            break;

        case MerkleSet::UpdateOp::REMOVE:
            if (!node_stack.empty()) {
                AdvancePosition(node_stack, position, hash);
                modified = AddHashSingle(node_stack, hash);

            } else {
                switch (GetType(m_root_hash)) {
                case HashType::EMPTY:
                    modified = false;
                    break;

                case HashType::TERMINAL:
                    if (HashEqual(m_root_hash, hash)) {
                        modified = true;
                        SetType(m_root_hash, HashType::EMPTY);
                    } else {
                        modified = false;
                    }
                    break;

                case HashType::MIDDLE:
                    assert(m_root_chunk != nullptr);
                    node_stack.emplace_back(m_root_hash, &m_root_chunk, m_root_chunk, m_chunk_size);

                    AdvancePosition(node_stack, position, hash);
                    modified = RemoveHash(node_stack, hash);
                    break;

                default:
                    throw std::logic_error("Unhandled HashType");

                }
            }
            break;

        default:
            throw std::logic_error("Unhandled MerkleSet::UpdateOp");

        }

        std::cout << "Modified: " << modified << std::endl;
        result.push_back(modified);
    }

    // Unwind the node stack, computing middle node hashes.
    while (!node_stack.empty()) {
        node_stack.back().UpdateParentHash();
        node_stack.pop_back();
    }

    return result;
}

bool MerkleSet::Impl::RemoveHash(std::deque<Node>& node_stack, const hash_ref remove_hash)
{
    Node& node = node_stack.back();
    int index = node_stack.size();

    hash_ref node_hash = node.LeftHash(), other_node_hash = node.RightHash();
    Node child_node = node.LeftChild(), other_child_node = node.RightChild();
    if (HashBit(remove_hash, index)) {
        std::swap(node_hash, other_node_hash);
        std::swap(child_node, other_child_node);
    }

    switch (GetType(node_hash)) {
    case HashType::EMPTY:
        return false;

    case HashType::TERMINAL:
        switch (GetType(other_node_hash)) {
        case HashType::EMPTY:
            throw std::logic_error("INTERNAL ERROR: node has one empty child and one terminal");

        case HashType::TERMINAL:
            if (HashEqual(remove_hash, node_hash)) {
                SetHash(node.m_parent_hash, other_node_hash);
            } else if (HashEqual(remove_hash, other_node_hash)) {
                SetHash(node.m_parent_hash, node_hash);
            } else {
                return false;
            }

            ClearNode(node_stack);
            RollUpTerminalNode(node_stack, remove_hash);
            return true;

        case HashType::MIDDLE:
            if (!HashEqual(remove_hash, node_hash)) {
                return false;
            }

            SetType(node_hash, HashType::EMPTY);

            // Push for the sake of doing the dereference thing.
            PushNode(node_stack, other_child_node);
            if (node_stack.back().IsTerminal()) {
                RollUpTerminalNode(node_stack, remove_hash);
            } else {
                node_stack.pop_back();
            }
            return true;

        }

    case HashType::MIDDLE:
        PushNode(node_stack, child_node);
        return RemoveHash(node_stack, remove_hash); // tail-recursion

    default:
        throw std::logic_error("Unhandled HashType");

    }
}

void MerkleSet::Impl::AdvancePosition(std::deque<Node>& node_stack, hash_ref& position, const hash_ref next_position)
{
    int index = node_stack.size();

    // Determine bit index where position and insert_hash diverge.
    int prefix_index = 1;
    while (prefix_index < index &&
           HashBit(position, prefix_index) == HashBit(next_position, prefix_index)) {
        ++prefix_index;
    }

    while (prefix_index < index) {
        node_stack.back().UpdateParentHash();
        node_stack.pop_back();
        --index;
    }

    position = next_position;
}

bool MerkleSet::Impl::AddHashSingle(std::deque<Node>& node_stack, const hash_ref insert_hash)
{
    Node& node = node_stack.back();
    int index = node_stack.size();

    std::cout << "Single: " << index << std::endl;

    hash_ref node_hash, other_node_hash;
    Node child_node;
    if (!HashBit(insert_hash, index)) {
        node_hash = node.LeftHash();
        other_node_hash = node.RightHash();
        child_node = node.LeftChild();
    } else {
        node_hash = node.RightHash();
        other_node_hash = node.LeftHash();
        child_node = node.RightChild();
    }

    switch (GetType(node_hash)) {
    case HashType::EMPTY:
        switch (GetType(other_node_hash)) {
        case HashType::EMPTY:
            throw std::logic_error("INTERNAL ERROR: node has two empy children");

        case HashType::TERMINAL:
            throw std::logic_error("INTERNAL ERROR: node has one empty child and one terminal");

        case HashType::MIDDLE:
            SetHash(node_hash, insert_hash);
            return true;

        }

    case HashType::TERMINAL:
        if (HashEqual(insert_hash, node_hash)) {
            return false;
        }

        switch (GetType(other_node_hash)) {
        case HashType::EMPTY:
            throw std::logic_error("INTERNAL ERROR: node has one empty child and one terminal");

        case HashType::TERMINAL:
            if (HashEqual(insert_hash, other_node_hash)) {
                return false;
            }

            // Make copies of left_hash and right_hash, then set the original locations to empty.
            unsigned char left_hash_copy[HASH_SIZE], right_hash_copy[HASH_SIZE];
            SetHash(left_hash_copy, node.LeftHash());
            SetHash(right_hash_copy, node.RightHash());
            SetType(node.LeftHash(), HashType::EMPTY);
            SetType(node.RightHash(), HashType::EMPTY);

            {
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

        case HashType::MIDDLE:
            PushNode(node_stack, child_node);
            {
                hash_ref hash1 = node_hash, hash2 = insert_hash;
                if (HashCompare(hash1, hash2) > 0) {
                    std::swap(hash1, hash2);
                }

                AddHashPair(node_stack, hash1, hash2);
            }
            return true;

        }

    case HashType::MIDDLE:
        PushNode(node_stack, child_node);
        return AddHashSingle(node_stack, insert_hash); // tail recursion

    default:
        throw std::logic_error("Unhandled HashType");

    }
}

void MerkleSet::Impl::RollUpTerminalNode(std::deque<Node>& node_stack, const hash_ref position)
{
    unsigned char left_hash[HASH_SIZE], right_hash[HASH_SIZE];
    SetHash(left_hash, node_stack.back().LeftHash());
    SetHash(right_hash, node_stack.back().RightHash());

    bool any_changes = false;
    while (node_stack.size() >= 2) {
        int index = node_stack.size() - 1;
        Node& parent_node = *(++node_stack.rbegin());

        hash_ref parent_other_hash;
        if (HashBit(position, index)) {
            parent_other_hash = parent_node.LeftHash();
        } else {
            parent_other_hash = parent_node.RightHash();
        }

        if (GetType(parent_other_hash) != HashType::EMPTY) {
            break;
        }

        any_changes = true;
        ClearNode(node_stack);
    }

    if (!any_changes) {
        return;
    }

    Node& node = node_stack.back();
    SetHash(node.LeftHash(), left_hash);
    SetHash(node.RightHash(), right_hash);
}

void MerkleSet::Impl::AddHashPair(std::deque<Node>& node_stack, const hash_ref hash1, const hash_ref hash2)
{
    Node& node = node_stack.back();
    hash_ref left_hash = node.LeftHash();
    hash_ref right_hash = node.RightHash();

    std::cout << "Pair: " << node_stack.size() << std::endl;

    assert(GetType(left_hash) == HashType::EMPTY);
    assert(GetType(right_hash) == HashType::EMPTY);
    assert(GetType(hash1) == HashType::TERMINAL);
    assert(GetType(hash2) == HashType::TERMINAL);

    SetHash(left_hash, hash1);
    SetHash(right_hash, hash2);
}

void MerkleSet::Impl::AddHashTriple(std::deque<Node>& node_stack, const hash_ref hash1, const hash_ref hash2, const hash_ref hash3)
{
    Node& node = node_stack.back();
    int index = node_stack.size();

    std::cout << "Triple: " << node_stack.size() << std::endl;

    assert(GetType(node.LeftHash()) == HashType::EMPTY);
    assert(GetType(node.RightHash()) == HashType::EMPTY);
    assert(GetType(hash1) == HashType::TERMINAL);
    assert(GetType(hash2) == HashType::TERMINAL);
    assert(GetType(hash3) == HashType::TERMINAL);

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
        SetHash(node.RightHash(), hash3);

    } else if (bit1 == 0 && bit2 == 1 && bit3 == 1) {
        Node child_node = node.RightChild();
        PushNode(node_stack, child_node);
        AddHashPair(node_stack, hash2, hash3);
        SetHash(node.LeftHash(), hash1);

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
        node_stack.emplace_back(node.m_parent_hash, chunk_ref, *chunk_ref, m_chunk_size);
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
        SetType(node.LeftHash(), HashType::EMPTY);
        SetType(node.RightHash(), HashType::EMPTY);
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
