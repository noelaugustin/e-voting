package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/naugustin/e-voting/crypto"
)

var DataDir = "data"

func init() {
	if envDir := os.Getenv("EVOTING_DATA_DIR"); envDir != "" {
		DataDir = envDir
	}
}

const (
	ElectionFile      = "election.json"
	AuthoritiesFile   = "authorities.json"
	VotersFile        = "voters.json"
	VotesFile         = "votes.json"
	ResultsFile       = "results.json"
	BoothsFile        = "booths.json"
	AuthorityKeysFile = "keys.json" // Private keys, strictly for demo
)

type StateManager struct {
	mu sync.RWMutex
}

func NewStateManager() *StateManager {
	return &StateManager{}
}

func (sm *StateManager) EnsureDataDir() error {
	if _, err := os.Stat(DataDir); os.IsNotExist(err) {
		return os.Mkdir(DataDir, 0755)
	}
	return nil
}

func (sm *StateManager) Reset() error {
	return os.RemoveAll(DataDir)
}

// Generic Save/Load helpers

func saveJSON(filename string, data interface{}) error {
	path := filepath.Join(DataDir, filename)
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func loadJSON(filename string, target interface{}) error {
	path := filepath.Join(DataDir, filename)
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewDecoder(file).Decode(target)
}

// Data Structures for Persistence

type ElectionData struct {
	Name            string   `json:"name"`
	K               int      `json:"k"`
	N               int      `json:"n"`
	MasterPublicKey string   `json:"masterPublicKey"`
	Candidates      []string `json:"candidates"`
	IsPublished     bool     `json:"isPublished"`
}

type AuthorityData struct {
	ID        int    `json:"id"`
	PublicKey string `json:"publicKey"`
	// Verification points would go here
}

type AuthorityKeyData struct {
	ID         int    `json:"id"`
	PrivateKey string `json:"privateKey"`
}

type VoterData struct {
	ID          string `json:"id"`
	BoothID     string `json:"boothId"`
	PublicKey   string `json:"publicKey"`
	PrivateKey  string `json:"privateKey"` // Demo only
	VotingToken string `json:"votingToken"`
}

type VoteData struct {
	VoteID     string                    `json:"voteId"`
	VoterID    string                    `json:"voterId"`
	Ciphertext *crypto.ElGamalCiphertext `json:"ciphertext"`
	Proof      *crypto.VoteValidityProof `json:"proof"`
	Timestamp  string                    `json:"timestamp"`
}
