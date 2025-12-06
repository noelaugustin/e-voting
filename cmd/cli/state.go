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
	AuthorityKeysFile = "keys.json"            // Private keys, strictly for demo
	MachineKeysFile   = "machine_keys.json"    // Machine private keys (demo: local secure storage)
	BoothKeysFile     = "booth_keys.json"      // Booth private keys (demo: physical booth storage)
	AdminKeysFile     = "admin_keys_demo.json" // Election admin private key (demo: offline root)
	MachinesFile      = "machines.json"        // Public machine registry
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
	MasterPublicKey string   `json:"masterPublicKey"` // Threshold Encryption Key
	AdminPublicKey  string   `json:"adminPublicKey"`  // Admin Signing Key (Root of Trust)
	Candidates      []string `json:"candidates"`
	IsPublished     bool     `json:"isPublished"`
}

type AuthorityData struct {
	ID                 int    `json:"id"`
	PublicKey          string `json:"publicKey"`
	VerificationPointX string `json:"verificationPointX"`
	VerificationPointY string `json:"verificationPointY"`
}

type AuthorityKeyData struct {
	ID         int    `json:"id"`
	PrivateKey string `json:"privateKey"`
}

type AdminKeyData struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

type VoterData struct {
	ID          string `json:"id"`
	BoothID     string `json:"boothId"`
	PublicKey   string `json:"publicKey"`
	PrivateKey  string `json:"privateKey"` // Demo only
	VotingToken string `json:"votingToken"`
}

type VoteData struct {
	VoteID           string                      `json:"voteId"`
	VoterID          string                      `json:"voterId"`
	MachineID        string                      `json:"machineId"`
	Ciphertexts      []*crypto.ElGamalCiphertext `json:"ciphertexts"` // per-candidate vector
	Proof            *crypto.OneHotValidityProof `json:"proof"`
	Timestamp        string                      `json:"timestamp"`
	PreviousHash     string                      `json:"previousHash"`     // Tamper evidence
	Hash             string                      `json:"hash"`             // Current hash
	MachineSignature string                      `json:"machineSignature"` // Machine authentication
}

type MachineKeyData struct {
	ID         string `json:"id"`
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

type GlobalConfig struct {
	ElectionID  string `json:"electionId"`
	AdminPublic string `json:"adminPublic"` // Hex encoded
}

type BoothData struct {
	ID             string   `json:"id"`
	Location       string   `json:"location"`
	PublicKey      string   `json:"publicKey"`      // New: Booth Identity
	AdminSignature string   `json:"adminSignature"` // New: Verified by Election
	Machines       []string `json:"machines"`       // List of Machine IDs
}

type BoothKeyData struct {
	ID         string `json:"id"`
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

type MachineData struct {
	ID             string `json:"id"`
	BoothID        string `json:"boothId"`
	IsActive       bool   `json:"isActive"`
	PublicKey      string `json:"publicKey"`      // New: Machine Identity
	BoothSignature string `json:"boothSignature"` // New: Verified by Booth
}
