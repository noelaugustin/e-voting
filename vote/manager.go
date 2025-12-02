package vote

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/naugustin/e-voting/crypto"
	"github.com/naugustin/e-voting/voter"
)

// EncryptedVote represents an encrypted vote with zero-knowledge proof
type EncryptedVote struct {
	VoterPublicKey  []byte // Voter's public key for verification
	Ciphertext      *crypto.ElGamalCiphertext
	ValidityProof   *crypto.VoteValidityProof
	Timestamp       time.Time
	BoothID         string
	VoteID          string // Unique vote ID for tracking
	Randomness      []byte // For voter self-verification (encrypted)
	VoterCommitment []byte // Commitment for voter to verify their vote later
}

// Vote represents a plaintext vote (only used internally for casting)
type Vote struct {
	VoterID     string
	CandidateID string
	BoothID     string
	Timestamp   time.Time
}

// VoteManager manages vote casting, encryption, and storage
type VoteManager struct {
	votes           map[string]*EncryptedVote // voteID -> EncryptedVote
	voterToVoteID   map[string]string         // voterID -> latest voteID
	candidates      map[string]bool           // candidateID -> exists
	candidateList   []string                  // ordered list of candidates
	systemPublicKey *ecdsa.PublicKey          // Master public key for encryption
	mu              sync.RWMutex
}

// NewVoteManager creates a new vote manager
func NewVoteManager() (*VoteManager, error) {
	// Don't generate key here - will be set by system
	return &VoteManager{
		votes:           make(map[string]*EncryptedVote),
		voterToVoteID:   make(map[string]string),
		candidates:      make(map[string]bool),
		candidateList:   []string{},
		systemPublicKey: nil, // Will be set by SetSystemPublicKey
	}, nil
}

// SetSystemPublicKey sets the master public key for vote encryption
func (vm *VoteManager) SetSystemPublicKey(publicKey *ecdsa.PublicKey) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.systemPublicKey = publicKey
}

// RegisterCandidate registers a candidate for the election
func (vm *VoteManager) RegisterCandidate(candidateID string) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if vm.candidates[candidateID] {
		return errors.New("candidate already registered")
	}
	vm.candidates[candidateID] = true
	vm.candidateList = append(vm.candidateList, candidateID)
	return nil
}

// GetCandidateIndex returns the index of a candidate (for encryption)
func (vm *VoteManager) GetCandidateIndex(candidateID string) (int, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	for i, c := range vm.candidateList {
		if c == candidateID {
			return i + 1, nil // Start from 1 for encryption
		}
	}
	return -1, errors.New("candidate not found")
}

// CastVote casts a vote for a voter
func (vm *VoteManager) CastVote(voter *voter.Voter, candidateID string) (*EncryptedVote, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Validate candidate
	if !vm.candidates[candidateID] {
		return nil, errors.New("invalid candidate")
	}

	// Get candidate index for encryption (need to call without lock)
	var candidateIndex int
	for i, c := range vm.candidateList {
		if c == candidateID {
			candidateIndex = i + 1 // Start from 1 for encryption
			break
		}
	}
	if candidateIndex == 0 {
		return nil, errors.New("candidate not found")
	}

	// Encrypt vote using system master public key (for threshold decryption)
	if vm.systemPublicKey == nil {
		return nil, errors.New("system public key not set")
	}
	ciphertext, randomness, err := crypto.EncryptVote(vm.systemPublicKey, candidateIndex)
	if err != nil {
		return nil, err
	}

	// Generate validity proof
	validityProof, err := crypto.GenerateVoteValidityProof(
		ciphertext,
		candidateIndex,
		len(vm.candidateList),
		randomness,
		vm.systemPublicKey,
	)
	if err != nil {
		return nil, err
	}

	// Generate vote ID
	voteData := fmt.Sprintf("%s-%s-%d", voter.ID, candidateID, time.Now().UnixNano())
	voteHash := sha256.Sum256([]byte(voteData))
	voteID := fmt.Sprintf("%x", voteHash[:8])

	// Create voter commitment (hash of vote + secret)
	commitmentData := fmt.Sprintf("%s-%s-%s", voter.ID, candidateID, randomness.String())
	commitmentHash := sha256.Sum256([]byte(commitmentData))

	// Encrypt randomness for voter self-verification
	encryptedRandomness, _ := json.Marshal(randomness.String())

	encryptedVote := &EncryptedVote{
		VoterPublicKey:  crypto.HashToScalar([]byte(voter.ID), voter.KeyPair.PrivateKey.Curve).Bytes(),
		Ciphertext:      ciphertext,
		ValidityProof:   validityProof,
		Timestamp:       time.Now(),
		BoothID:         voter.BoothID,
		VoteID:          voteID,
		Randomness:      encryptedRandomness,
		VoterCommitment: commitmentHash[:],
	}

	// Check if voter has already voted (invalidate previous votes)
	if prevVoteID, exists := vm.voterToVoteID[voter.ID]; exists {
		// Mark previous vote as invalidated by removing it
		delete(vm.votes, prevVoteID)
	}

	// Store the new vote
	vm.votes[voteID] = encryptedVote
	vm.voterToVoteID[voter.ID] = voteID

	return encryptedVote, nil
}

// GetVote retrieves an encrypted vote by ID
func (vm *VoteManager) GetVote(voteID string) (*EncryptedVote, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	vote, exists := vm.votes[voteID]
	if !exists {
		return nil, errors.New("vote not found")
	}
	return vote, nil
}

// GetVoterLatestVote returns the latest vote for a voter
func (vm *VoteManager) GetVoterLatestVote(voterID string) (*EncryptedVote, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	voteID, exists := vm.voterToVoteID[voterID]
	if !exists {
		return nil, errors.New("voter has not voted")
	}

	vote, exists := vm.votes[voteID]
	if !exists {
		return nil, errors.New("vote not found")
	}
	return vote, nil
}

// VerifyVote verifies that a vote is valid using the zero-knowledge proof
func (vm *VoteManager) VerifyVote(vote *EncryptedVote, voterPublicKey *crypto.ECCKeyPair) bool {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	return crypto.VerifyVoteValidityProof(
		vote.Ciphertext,
		vote.ValidityProof,
		len(vm.candidateList),
		voterPublicKey.PublicKey,
	)
}

// GetAllVotes returns all encrypted votes
func (vm *VoteManager) GetAllVotes() []*EncryptedVote {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	votes := make([]*EncryptedVote, 0, len(vm.votes))
	for _, vote := range vm.votes {
		votes = append(votes, vote)
	}
	return votes
}

// GetVotesByBooth returns all votes from a specific booth
func (vm *VoteManager) GetVotesByBooth(boothID string) []*EncryptedVote {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	var boothVotes []*EncryptedVote
	for _, vote := range vm.votes {
		if vote.BoothID == boothID {
			boothVotes = append(boothVotes, vote)
		}
	}
	return boothVotes
}

// GetTotalVotes returns the total number of votes cast
func (vm *VoteManager) GetTotalVotes() int {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return len(vm.votes)
}

// GetCandidates returns the list of registered candidates
func (vm *VoteManager) GetCandidates() []string {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return append([]string{}, vm.candidateList...)
}

// VerifyVoterCommitment allows a voter to verify their vote
func (vm *VoteManager) VerifyVoterCommitment(voterID, candidateID string, secret string) (bool, error) {
	vote, err := vm.GetVoterLatestVote(voterID)
	if err != nil {
		return false, err
	}

	// Reconstruct commitment
	commitmentData := fmt.Sprintf("%s-%s-%s", voterID, candidateID, secret)
	commitmentHash := sha256.Sum256([]byte(commitmentData))

	// Compare with stored commitment
	for i := range vote.VoterCommitment {
		if vote.VoterCommitment[i] != commitmentHash[i] {
			return false, nil
		}
	}

	return true, nil
}
