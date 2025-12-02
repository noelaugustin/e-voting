package crypto

import (
	"testing"
)

func TestNewMerkleTree(t *testing.T) {
	data := [][]byte{
		[]byte("vote1"),
		[]byte("vote2"),
		[]byte("vote3"),
		[]byte("vote4"),
	}

	tree := NewMerkleTree(data)

	if tree == nil {
		t.Fatal("Tree is nil")
	}

	if tree.Root == nil {
		t.Error("Root is nil")
	}

	if len(tree.Leaves) != len(data) {
		t.Errorf("Expected %d leaves, got %d", len(data), len(tree.Leaves))
	}
}

func TestGetRootHash(t *testing.T) {
	data := [][]byte{
		[]byte("vote1"),
		[]byte("vote2"),
		[]byte("vote3"),
	}

	tree := NewMerkleTree(data)
	rootHash := tree.GetRootHash()

	if rootHash == "" {
		t.Error("Root hash is empty")
	}

	// Test that same data produces same root hash
	tree2 := NewMerkleTree(data)
	rootHash2 := tree2.GetRootHash()

	if rootHash != rootHash2 {
		t.Error("Same data should produce same root hash")
	}
}

func TestGenerateAndVerifyProof(t *testing.T) {
	data := [][]byte{
		[]byte("vote1"),
		[]byte("vote2"),
		[]byte("vote3"),
		[]byte("vote4"),
	}

	tree := NewMerkleTree(data)
	rootHash := tree.GetRootHash()

	// Test proof for each leaf
	for i := 0; i < len(data); i++ {
		proof, err := tree.GenerateProof(i)
		if err != nil {
			t.Fatalf("Failed to generate proof for leaf %d: %v", i, err)
		}

		// Verify proof
		valid := VerifyProof(data[i], proof, rootHash)
		if !valid {
			t.Errorf("Proof verification failed for leaf %d", i)
		}
	}
}

func TestVerifyProofWithWrongData(t *testing.T) {
	data := [][]byte{
		[]byte("vote1"),
		[]byte("vote2"),
		[]byte("vote3"),
	}

	tree := NewMerkleTree(data)
	rootHash := tree.GetRootHash()

	proof, err := tree.GenerateProof(0)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	// Verify with wrong data
	wrongData := []byte("wrong vote")
	valid := VerifyProof(wrongData, proof, rootHash)
	if valid {
		t.Error("Proof should not verify with wrong data")
	}
}

func TestAddLeaf(t *testing.T) {
	data := [][]byte{
		[]byte("vote1"),
		[]byte("vote2"),
	}

	tree := NewMerkleTree(data)
	initialRoot := tree.GetRootHash()
	initialCount := tree.GetLeafCount()

	// Add new leaf
	tree.AddLeaf([]byte("vote3"))

	newRoot := tree.GetRootHash()
	newCount := tree.GetLeafCount()

	if newRoot == initialRoot {
		t.Error("Root hash should change after adding leaf")
	}

	if newCount != initialCount+1 {
		t.Errorf("Expected %d leaves, got %d", initialCount+1, newCount)
	}
}

func TestEmptyTree(t *testing.T) {
	tree := NewMerkleTree([][]byte{})

	if tree.Root != nil {
		t.Error("Empty tree should have nil root")
	}

	if tree.GetRootHash() != "" {
		t.Error("Empty tree should have empty root hash")
	}
}

func TestSingleLeafTree(t *testing.T) {
	data := [][]byte{[]byte("single vote")}
	tree := NewMerkleTree(data)

	if tree.Root == nil {
		t.Error("Single leaf tree should have a root")
	}

	rootHash := tree.GetRootHash()
	if rootHash == "" {
		t.Error("Single leaf tree should have a root hash")
	}

	// Generate and verify proof
	proof, err := tree.GenerateProof(0)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	valid := VerifyProof(data[0], proof, rootHash)
	if !valid {
		t.Error("Proof verification failed for single leaf")
	}
}

func TestOddNumberOfLeaves(t *testing.T) {
	data := [][]byte{
		[]byte("vote1"),
		[]byte("vote2"),
		[]byte("vote3"),
		[]byte("vote4"),
		[]byte("vote5"),
	}

	tree := NewMerkleTree(data)
	rootHash := tree.GetRootHash()

	// Verify all proofs work with odd number of leaves
	for i := 0; i < len(data); i++ {
		proof, err := tree.GenerateProof(i)
		if err != nil {
			t.Fatalf("Failed to generate proof for leaf %d: %v", i, err)
		}

		valid := VerifyProof(data[i], proof, rootHash)
		if !valid {
			t.Errorf("Proof verification failed for leaf %d with odd number of leaves", i)
		}
	}
}
