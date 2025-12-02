package voter

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/naugustin/e-voting/crypto"
)

// Voter represents a registered voter
type Voter struct {
	ID               string
	KeyPair          *crypto.ECCKeyPair
	BoothID          string
	BlindToken       []byte // Blind signature token for anonymity
	RegistrationTime time.Time
	VotingToken      string // One-time token for voting
}

// VoterRegistry manages voter registration and authentication
type VoterRegistry struct {
	voters           map[string]*Voter
	authorityKeyPair *crypto.ECCKeyPair
	mu               sync.RWMutex
}

// NewVoterRegistry creates a new voter registry
func NewVoterRegistry() (*VoterRegistry, error) {
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	return &VoterRegistry{
		voters:           make(map[string]*Voter),
		authorityKeyPair: keyPair,
	}, nil
}

// RegisterVoter registers a new voter with a unique ID and booth assignment
func (vr *VoterRegistry) RegisterVoter(voterID, boothID string) (*Voter, error) {
	vr.mu.Lock()
	defer vr.mu.Unlock()

	if _, exists := vr.voters[voterID]; exists {
		return nil, errors.New("voter already registered")
	}

	// Generate key pair for voter
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// Generate blind token for anonymity
	blindToken := []byte(voterID + boothID)
	r, s, err := crypto.BlindSignature(vr.authorityKeyPair.PrivateKey, blindToken)
	if err != nil {
		return nil, err
	}

	// Serialize signature
	tokenData := map[string]interface{}{
		"r": r.String(),
		"s": s.String(),
	}
	tokenBytes, _ := json.Marshal(tokenData)

	// Generate one-time voting token
	votingToken := crypto.HashToScalar([]byte(voterID+time.Now().String()), keyPair.PrivateKey.Curve).String()

	voter := &Voter{
		ID:               voterID,
		KeyPair:          keyPair,
		BoothID:          boothID,
		BlindToken:       tokenBytes,
		RegistrationTime: time.Now(),
		VotingToken:      votingToken,
	}

	vr.voters[voterID] = voter
	return voter, nil
}

// GetVoter retrieves a voter by ID
func (vr *VoterRegistry) GetVoter(voterID string) (*Voter, error) {
	vr.mu.RLock()
	defer vr.mu.RUnlock()

	voter, exists := vr.voters[voterID]
	if !exists {
		return nil, errors.New("voter not found")
	}
	return voter, nil
}

// AuthenticateVoter authenticates a voter using their voting token
func (vr *VoterRegistry) AuthenticateVoter(voterID, votingToken string) (*Voter, error) {
	voter, err := vr.GetVoter(voterID)
	if err != nil {
		return nil, err
	}

	if voter.VotingToken != votingToken {
		return nil, errors.New("invalid voting token")
	}

	return voter, nil
}

// GetVotersByBooth returns all voters registered at a specific booth
func (vr *VoterRegistry) GetVotersByBooth(boothID string) []*Voter {
	vr.mu.RLock()
	defer vr.mu.RUnlock()

	var boothVoters []*Voter
	for _, voter := range vr.voters {
		if voter.BoothID == boothID {
			boothVoters = append(boothVoters, voter)
		}
	}
	return boothVoters
}

// RevokeVoter revokes a voter's registration (for testing/admin purposes)
func (vr *VoterRegistry) RevokeVoter(voterID string) error {
	vr.mu.Lock()
	defer vr.mu.Unlock()

	if _, exists := vr.voters[voterID]; !exists {
		return errors.New("voter not found")
	}
	delete(vr.voters, voterID)
	return nil
}

// GetTotalVoters returns the total number of registered voters
func (vr *VoterRegistry) GetTotalVoters() int {
	vr.mu.RLock()
	defer vr.mu.RUnlock()
	return len(vr.voters)
}

// GetAuthorityPublicKey returns the authority's public key for verification
func (vr *VoterRegistry) GetAuthorityPublicKey() *ecdsa.PublicKey {
	return vr.authorityKeyPair.PublicKey
}
