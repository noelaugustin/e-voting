package evoting

import (
	"errors"

	"github.com/naugustin/e-voting/analytics"
	"github.com/naugustin/e-voting/authority"
	"github.com/naugustin/e-voting/crypto"
	"github.com/naugustin/e-voting/verification"
	"github.com/naugustin/e-voting/vote"
	"github.com/naugustin/e-voting/voter"
)

// VotingSystem represents the complete e-voting system
type VotingSystem struct {
	voterRegistry      *voter.VoterRegistry
	voteManager        *vote.VoteManager
	verificationSystem *verification.VerificationSystem
	analyticsEngine    *analytics.AnalyticsEngine
	authorityRegistry  *authority.AuthorityRegistry // Threshold decryption authorities
	isPublished        bool
}

// NewVotingSystem creates a new voting system
func NewVotingSystem() (*VotingSystem, error) {
	voterRegistry, err := voter.NewVoterRegistry()
	if err != nil {
		return nil, err
	}

	voteManager, err := vote.NewVoteManager()
	if err != nil {
		return nil, err
	}

	// Create default 5-of-9 authority registry
	authorityRegistry, err := authority.NewAuthorityRegistry(5, 9)
	if err != nil {
		return nil, err
	}

	// Set master public key in vote manager for encryption
	voteManager.SetSystemPublicKey(authorityRegistry.GetPublicInfo().MasterPublicKey)

	return &VotingSystem{
		voterRegistry:      voterRegistry,
		voteManager:        voteManager,
		verificationSystem: verification.NewVerificationSystem(),
		analyticsEngine:    analytics.NewAnalyticsEngine(),
		authorityRegistry:  authorityRegistry,
		isPublished:        false,
	}, nil
}

// RegisterVoter registers a new voter
func (vs *VotingSystem) RegisterVoter(voterID, boothID string) (*voter.Voter, error) {
	return vs.voterRegistry.RegisterVoter(voterID, boothID)
}

// RegisterCandidate registers a candidate for the election
func (vs *VotingSystem) RegisterCandidate(candidateID string) error {
	return vs.voteManager.RegisterCandidate(candidateID)
}

// CastVote casts a vote for a voter
func (vs *VotingSystem) CastVote(voter *voter.Voter, candidateID string) (*vote.EncryptedVote, error) {
	if vs.isPublished {
		return nil, errors.New("votes have been published; no more votes can be cast")
	}

	return vs.voteManager.CastVote(voter, candidateID)
}

// PublishVotes publishes all votes for verification (before counting)
func (vs *VotingSystem) PublishVotes() error {
	if vs.isPublished {
		return errors.New("votes already published")
	}

	votes := vs.voteManager.GetAllVotes()
	err := vs.verificationSystem.PublishVotes(votes)
	if err != nil {
		return err
	}

	vs.isPublished = true
	return nil
}

// GetMerkleRoot returns the Merkle tree root hash for tamper detection
func (vs *VotingSystem) GetMerkleRoot() string {
	return vs.verificationSystem.GetMerkleRoot()
}

// VerifyVoterVote allows a voter to verify their vote
func (vs *VotingSystem) VerifyVoterVote(voterID, candidateID, secret string) (bool, error) {
	if !vs.isPublished {
		return false, errors.New("votes not yet published")
	}

	// Get voter's latest vote
	encryptedVote, err := vs.voteManager.GetVoterLatestVote(voterID)
	if err != nil {
		return false, err
	}

	// Verify using the verification system
	return vs.verificationSystem.VerifyVoterCommitment(
		encryptedVote.VoteID,
		voterID,
		candidateID,
		secret,
	)
}

// CountVotes counts all votes and returns results
func (vs *VotingSystem) CountVotes() (map[string]int, error) {
	if !vs.isPublished {
		return nil, errors.New("votes must be published before counting")
	}

	votes := vs.voteManager.GetAllVotes()
	candidateList := vs.voteManager.GetCandidates()

	// Use threshold decryption with authorities
	decryptionFunc := func(ciphertext *crypto.ElGamalCiphertext) (int, error) {
		// Decrypt using k-of-n threshold authorities
		maxCandidates := len(candidateList)
		return vs.authorityRegistry.DecryptWithAnyAuthorities(ciphertext, maxCandidates)
	}

	return vs.analyticsEngine.CountVotesByCandidate(votes, decryptionFunc, candidateList)
}

// GetBoothAnalytics returns vote count for a specific booth
func (vs *VotingSystem) GetBoothAnalytics(boothID string) int {
	votes := vs.voteManager.GetVotesByBooth(boothID)
	return len(votes)
}

// GetBoothCandidateAnalytics returns candidate vote counts for a booth
func (vs *VotingSystem) GetBoothCandidateAnalytics(boothID string) (map[string]int, error) {
	if !vs.isPublished {
		return nil, errors.New("votes must be published before analytics")
	}

	votes := vs.voteManager.GetVotesByBooth(boothID)
	candidateList := vs.voteManager.GetCandidates()

	// Use threshold decryption with authorities
	decryptionFunc := func(ciphertext *crypto.ElGamalCiphertext) (int, error) {
		maxCandidates := len(candidateList)
		return vs.authorityRegistry.DecryptWithAnyAuthorities(ciphertext, maxCandidates)
	}

	return vs.analyticsEngine.CountVotesByCandidate(votes, decryptionFunc, candidateList)
}

// GetTotalVotes returns the total number of votes cast
func (vs *VotingSystem) GetTotalVotes() int {
	return vs.voteManager.GetTotalVotes()
}

// GetAllBooths returns a list of all booths with votes
func (vs *VotingSystem) GetAllBooths() []string {
	boothMap := make(map[string]bool)
	votes := vs.voteManager.GetAllVotes()

	for _, v := range votes {
		boothMap[v.BoothID] = true
	}

	booths := make([]string, 0, len(boothMap))
	for booth := range boothMap {
		booths = append(booths, booth)
	}

	return booths
}

// DetectTampering checks if the vote list has been tampered with
func (vs *VotingSystem) DetectTampering(expectedRootHash string) bool {
	return vs.verificationSystem.DetectTampering(expectedRootHash)
}

// GetCandidates returns the list of registered candidates
func (vs *VotingSystem) GetCandidates() []string {
	return vs.voteManager.GetCandidates()
}

// GetVoter retrieves a voter by ID
func (vs *VotingSystem) GetVoter(voterID string) (*voter.Voter, error) {
	return vs.voterRegistry.GetVoter(voterID)
}

// GetAuthorityRegistry returns the authority registry for threshold decryption
func (vs *VotingSystem) GetAuthorityRegistry() *authority.AuthorityRegistry {
	return vs.authorityRegistry
}

// SetupThresholdAuthorities initializes k-of-n threshold authorities
// This replaces the default 5-of-9 setup
func (vs *VotingSystem) SetupThresholdAuthorities(k, n int) error {
	authorityRegistry, err := authority.NewAuthorityRegistry(k, n)
	if err != nil {
		return err
	}
	vs.authorityRegistry = authorityRegistry

	// Update vote manager to use new master public key
	vs.voteManager.SetSystemPublicKey(authorityRegistry.GetPublicInfo().MasterPublicKey)

	return nil
}

// GetCandidateIndex returns the index of a candidate
func (vs *VotingSystem) GetCandidateIndex(candidateID string) (int, error) {
	return vs.voteManager.GetCandidateIndex(candidateID)
}

// GetTotalVoters returns the total number of registered voters
func (vs *VotingSystem) GetTotalVoters() int {
	return vs.voterRegistry.GetTotalVoters()
}

// GetAllPublishedVotes returns all published votes for audit
func (vs *VotingSystem) GetAllPublishedVotes() []*verification.PublishedVote {
	return vs.verificationSystem.GetAllPublishedVotes()
}

// GetMerkleProof returns the merkle proof for a specific vote
func (vs *VotingSystem) GetMerkleProof(voteID string) []string {
	return vs.verificationSystem.GetMerkleProof(voteID)
}
