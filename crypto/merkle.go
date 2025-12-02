package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// MerkleNode represents a node in the Merkle tree
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Hash  []byte
}

// MerkleTree provides tamper-evident storage for votes
type MerkleTree struct {
	Root   *MerkleNode
	Leaves []*MerkleNode
}

// MerkleProof proves that a leaf is part of the tree
type MerkleProof struct {
	Hashes    [][]byte
	Positions []bool // true = right, false = left
}

// NewMerkleTree creates a new Merkle tree from vote data
func NewMerkleTree(data [][]byte) *MerkleTree {
	if len(data) == 0 {
		return &MerkleTree{}
	}

	// Create leaf nodes
	leaves := make([]*MerkleNode, len(data))
	for i, d := range data {
		hash := sha256.Sum256(d)
		leaves[i] = &MerkleNode{Hash: hash[:]}
	}

	// Build tree bottom-up
	root := buildTree(leaves)

	return &MerkleTree{
		Root:   root,
		Leaves: leaves,
	}
}

// buildTree recursively builds the Merkle tree
func buildTree(nodes []*MerkleNode) *MerkleNode {
	if len(nodes) == 0 {
		return nil
	}
	if len(nodes) == 1 {
		return nodes[0]
	}

	// If odd number of nodes, duplicate the last one
	if len(nodes)%2 != 0 {
		nodes = append(nodes, nodes[len(nodes)-1])
	}

	// Build parent level
	var parents []*MerkleNode
	for i := 0; i < len(nodes); i += 2 {
		left := nodes[i]
		right := nodes[i+1]

		// Combine hashes
		combined := append(left.Hash, right.Hash...)
		hash := sha256.Sum256(combined)

		parent := &MerkleNode{
			Left:  left,
			Right: right,
			Hash:  hash[:],
		}
		parents = append(parents, parent)
	}

	return buildTree(parents)
}

// GetRootHash returns the root hash of the tree
func (mt *MerkleTree) GetRootHash() string {
	if mt.Root == nil {
		return ""
	}
	return hex.EncodeToString(mt.Root.Hash)
}

// GenerateProof generates a Merkle proof for a specific leaf index
func (mt *MerkleTree) GenerateProof(leafIndex int) (*MerkleProof, error) {
	if leafIndex < 0 || leafIndex >= len(mt.Leaves) {
		return nil, fmt.Errorf("invalid leaf index")
	}

	proof := &MerkleProof{
		Hashes:    [][]byte{},
		Positions: []bool{},
	}

	// Build proof path from leaf to root
	currentIndex := leafIndex
	levelSize := len(mt.Leaves)

	// Handle odd number of leaves
	nodes := make([]*MerkleNode, len(mt.Leaves))
	copy(nodes, mt.Leaves)
	if len(nodes)%2 != 0 {
		nodes = append(nodes, nodes[len(nodes)-1])
	}

	for levelSize > 1 {
		// Find sibling
		var siblingIndex int
		if currentIndex%2 == 0 {
			// Current is left, sibling is right
			siblingIndex = currentIndex + 1
			proof.Positions = append(proof.Positions, true) // sibling is on right
		} else {
			// Current is right, sibling is left
			siblingIndex = currentIndex - 1
			proof.Positions = append(proof.Positions, false) // sibling is on left
		}

		proof.Hashes = append(proof.Hashes, nodes[siblingIndex].Hash)

		// Move to parent level
		currentIndex = currentIndex / 2

		// Build parent level
		var parents []*MerkleNode
		for i := 0; i < len(nodes); i += 2 {
			combined := append(nodes[i].Hash, nodes[i+1].Hash...)
			hash := sha256.Sum256(combined)
			parents = append(parents, &MerkleNode{Hash: hash[:]})
		}

		nodes = parents
		levelSize = len(nodes)

		if len(nodes)%2 != 0 && len(nodes) > 1 {
			nodes = append(nodes, nodes[len(nodes)-1])
		}
	}

	return proof, nil
}

// VerifyProof verifies a Merkle proof
func VerifyProof(leafData []byte, proof *MerkleProof, rootHash string) bool {
	// Hash the leaf
	hash := sha256.Sum256(leafData)
	currentHash := hash[:]

	// Apply proof path
	for i := 0; i < len(proof.Hashes); i++ {
		var combined []byte
		if proof.Positions[i] {
			// Sibling is on right
			combined = append(currentHash, proof.Hashes[i]...)
		} else {
			// Sibling is on left
			combined = append(proof.Hashes[i], currentHash...)
		}

		hash := sha256.Sum256(combined)
		currentHash = hash[:]
	}

	// Compare with root hash
	computedRoot := hex.EncodeToString(currentHash)
	return computedRoot == rootHash
}

// AddLeaf adds a new leaf to the tree and rebuilds it
func (mt *MerkleTree) AddLeaf(data []byte) {
	hash := sha256.Sum256(data)
	newLeaf := &MerkleNode{Hash: hash[:]}
	mt.Leaves = append(mt.Leaves, newLeaf)

	// Rebuild tree
	mt.Root = buildTree(mt.Leaves)
}

// GetLeafCount returns the number of leaves in the tree
func (mt *MerkleTree) GetLeafCount() int {
	return len(mt.Leaves)
}
