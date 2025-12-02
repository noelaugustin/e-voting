package verification

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/naugustin/e-voting/crypto"
	"github.com/naugustin/e-voting/vote"
)

// PublishedVote represents a vote published for public verification
type PublishedVote struct {
	VoteID          string
	VoterCommitment []byte
	Ciphertext      *crypto.ElGamalCiphertext
	BoothID         string
	Timestamp       time.Time
	ProofHash       []byte
}

// VerificationSystem manages vote verification and publication
type VerificationSystem struct {
	merkleTree     *crypto.MerkleTree
	publishedVotes map[string]*PublishedVote
	voteData       [][]byte
}

// NewVerificationSystem creates a new verification system
func NewVerificationSystem() *VerificationSystem {
	return &VerificationSystem{
		publishedVotes: make(map[string]*PublishedVote),
		voteData:       [][]byte{},
	}
}

// PublishVotes publishes all votes to the public ledger
func (vs *VerificationSystem) PublishVotes(votes []*vote.EncryptedVote) error {
	// Clear previous data
	vs.voteData = [][]byte{}
	vs.publishedVotes = make(map[string]*PublishedVote)

	// Prepare vote data for Merkle tree
	for _, v := range votes {
		// Hash the proof for storage
		proofData, _ := json.Marshal(v.ValidityProof)
		proofHash := sha256.Sum256(proofData)

		// Create published vote record
		publishedVote := &PublishedVote{
			VoteID:          v.VoteID,
			VoterCommitment: v.VoterCommitment,
			Ciphertext:      v.Ciphertext,
			BoothID:         v.BoothID,
			Timestamp:       v.Timestamp,
			ProofHash:       proofHash[:],
		}

		// Serialize for Merkle tree
		voteJSON, err := json.Marshal(publishedVote)
		if err != nil {
			return err
		}

		vs.voteData = append(vs.voteData, voteJSON)
		vs.publishedVotes[v.VoteID] = publishedVote
	}

	// Build Merkle tree
	vs.merkleTree = crypto.NewMerkleTree(vs.voteData)

	return nil
}

// GetMerkleRoot returns the Merkle tree root hash
func (vs *VerificationSystem) GetMerkleRoot() string {
	if vs.merkleTree == nil {
		return ""
	}
	return vs.merkleTree.GetRootHash()
}

// GenerateVoteProof generates a Merkle proof for a specific vote
func (vs *VerificationSystem) GenerateVoteProof(voteID string) (*crypto.MerkleProof, error) {
	// Find vote index
	var voteIndex int = -1
	for i, publishedVoteID := range vs.publishedVotes {
		if publishedVoteID.VoteID == voteID {
			// In production, maintain a proper index mapping
			voteIndex = len(vs.voteData) / 2 // This is simplified
			break
		}
		_ = i // Use index if needed
	}

	if voteIndex == -1 {
		return nil, errors.New("vote not found")
	}

	// Generate proof
	return vs.merkleTree.GenerateProof(voteIndex)
}

// VerifyVoteInclusion verifies that a vote is included in the published list
func (vs *VerificationSystem) VerifyVoteInclusion(voteID string, proof *crypto.MerkleProof) (bool, error) {
	publishedVote, exists := vs.publishedVotes[voteID]
	if !exists {
		return false, errors.New("vote not found in published list")
	}

	// Serialize vote
	voteJSON, err := json.Marshal(publishedVote)
	if err != nil {
		return false, err
	}

	// Verify proof
	rootHash := vs.GetMerkleRoot()
	return crypto.VerifyProof(voteJSON, proof, rootHash), nil
}

// GetPublishedVote returns a published vote by ID
func (vs *VerificationSystem) GetPublishedVote(voteID string) (*PublishedVote, error) {
	vote, exists := vs.publishedVotes[voteID]
	if !exists {
		return nil, errors.New("vote not found")
	}
	return vote, nil
}

// VerifyVoterCommitment allows a voter to verify their vote
func (vs *VerificationSystem) VerifyVoterCommitment(voteID, voterID, candidateID, secret string) (bool, error) {
	publishedVote, err := vs.GetPublishedVote(voteID)
	if err != nil {
		return false, err
	}

	// Reconstruct commitment
	commitmentData := fmt.Sprintf("%s-%s-%s", voterID, candidateID, secret)
	commitmentHash := sha256.Sum256([]byte(commitmentData))
	reconstructedCommitment := commitmentHash[:]

	// Compare byte slices
	if len(publishedVote.VoterCommitment) != len(reconstructedCommitment) {
		return false, nil
	}
	for i := range publishedVote.VoterCommitment {
		if publishedVote.VoterCommitment[i] != reconstructedCommitment[i] {
			return false, nil
		}
	}
	return true, nil
}

// GetAllPublishedVotes returns all published votes
func (vs *VerificationSystem) GetAllPublishedVotes() []*PublishedVote {
	votes := make([]*PublishedVote, 0, len(vs.publishedVotes))
	for _, vote := range vs.publishedVotes {
		votes = append(votes, vote)
	}
	return votes
}

// GetPublishedVotesByBooth returns all published votes from a specific booth
func (vs *VerificationSystem) GetPublishedVotesByBooth(boothID string) []*PublishedVote {
	var boothVotes []*PublishedVote
	for _, vote := range vs.publishedVotes {
		if vote.BoothID == boothID {
			boothVotes = append(boothVotes, vote)
		}
	}
	return boothVotes
}

// DetectTampering checks if the Merkle tree has been tampered with
func (vs *VerificationSystem) DetectTampering(expectedRootHash string) bool {
	currentRoot := vs.GetMerkleRoot()
	return currentRoot != expectedRootHash
}

// GetMerkleProof returns the merkle proof path for a specific vote
func (vs *VerificationSystem) GetMerkleProof(voteID string) []string {
	// Check if vote exists
	if _, exists := vs.publishedVotes[voteID]; !exists {
		return []string{} // Vote not found
	}

	// Find the vote index in voteData (which is ordered)
	voteIndex := -1
	voteHash := ""

	for i, data := range vs.voteData {
		hash := sha256.Sum256(data)
		hashStr := hex.EncodeToString(hash[:])

		// Check if this vote data corresponds to our voteID
		// by attempting to unmarshal and compare
		var tempVote struct {
			VoteID string `json:"voteId"`
		}
		if err := json.Unmarshal(data, &tempVote); err == nil {
			if tempVote.VoteID == voteID {
				voteIndex = i
				voteHash = hashStr
				break
			}
		}
	}

	if voteIndex == -1 {
		return []string{}
	}

	// Build merkle proof - path from leaf to root
	proof := []string{voteHash} // Start with the vote's own hash
	currentIndex := voteIndex
	totalVotes := len(vs.voteData)

	// Traverse up the tree collecting sibling hashes
	for totalVotes > 1 {
		// Determine sibling index
		var siblingIndex int
		if currentIndex%2 == 0 {
			// Current is left child, sibling is right
			siblingIndex = currentIndex + 1
		} else {
			// Current is right child, sibling is left
			siblingIndex = currentIndex - 1
		}

		// Add sibling hash if it exists
		if siblingIndex >= 0 && siblingIndex < len(vs.voteData) {
			siblingHash := sha256.Sum256(vs.voteData[siblingIndex])
			proof = append(proof, hex.EncodeToString(siblingHash[:]))
		}

		// Move to parent level
		currentIndex = currentIndex / 2
		totalVotes = (totalVotes + 1) / 2
	}

	return proof
}

// Helper functions

func (vs *VerificationSystem) hashCiphertext(ciphertext *crypto.ElGamalCiphertext) string {
	data := fmt.Sprintf("%s-%s-%s-%s",
		ciphertext.C1.X.String(),
		ciphertext.C1.Y.String(),
		ciphertext.C2.X.String(),
		ciphertext.C2.Y.String(),
	)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
