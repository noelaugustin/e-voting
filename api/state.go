package api

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// ServerState manages the in-memory state of the voting system
type ServerState struct {
	Election     *ElectionInfo
	System       interface{}             // *evoting.VotingSystem (avoiding import cycle)
	VotingTokens map[string]string       // voterId -> token
	VoteReceipts map[string]*VoteReceipt // voteId -> receipt
	CountSession *CountingSession
	RateLimits   map[string]*RateLimit // voterId -> rate limit
	mu           sync.RWMutex
}

// ElectionInfo stores election metadata
type ElectionInfo struct {
	ElectionID          string    `json:"electionId"`
	Name                string    `json:"name"`
	Status              string    `json:"status"` // SETUP, VOTING, COUNTING, COMPLETED
	Threshold           int       `json:"threshold"`
	TotalAuthorities    int       `json:"totalAuthorities"`
	MasterPublicKeyHash string    `json:"masterPublicKeyHash"`
	CreatedAt           time.Time `json:"createdAt"`
}

// VoteReceipt stores vote receipt for voter verification
type VoteReceipt struct {
	VoteID      string    `json:"voteId"`
	VoterID     string    `json:"voterId"`
	CandidateID string    `json:"candidateId"`
	Commitment  string    `json:"commitment"`
	Timestamp   time.Time `json:"timestamp"`
	Secret      string    `json:"secret"` // Randomness for verification
}

// CountingSession manages the vote counting process
type CountingSession struct {
	RequestID           string         `json:"requestId"`
	Status              string         `json:"status"` // INITIATED, IN_PROGRESS, COMPLETED
	AwaitingAuthorities []int          `json:"awaitingAuthorities"`
	ReceivedPartials    map[int]bool   `json:"receivedPartials"`
	RejectedAuthorities []int          `json:"rejectedAuthorities"`
	Results             map[string]int `json:"results,omitempty"`
	StartedAt           time.Time      `json:"startedAt"`
	CompletedAt         *time.Time     `json:"completedAt,omitempty"`
}

// RateLimit tracks rate limiting per voter
type RateLimit struct {
	LastVoteTime time.Time
	VoteCount    int
}

// NewServerState creates a new server state
func NewServerState() *ServerState {
	return &ServerState{
		VotingTokens: make(map[string]string),
		VoteReceipts: make(map[string]*VoteReceipt),
		RateLimits:   make(map[string]*RateLimit),
	}
}

// CheckRateLimit checks if a voter can submit a vote
func (s *ServerState) CheckRateLimit(voterID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	limit, exists := s.RateLimits[voterID]
	if !exists {
		s.RateLimits[voterID] = &RateLimit{
			LastVoteTime: time.Now(),
			VoteCount:    1,
		}
		return true
	}

	// Rate limit: max 1 vote per 10 seconds
	if time.Since(limit.LastVoteTime) < 10*time.Second {
		return false
	}

	limit.LastVoteTime = time.Now()
	limit.VoteCount++
	return true
}

// Response helpers
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}
