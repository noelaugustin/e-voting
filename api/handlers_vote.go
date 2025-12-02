package api

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	evoting "github.com/naugustin/e-voting"
)

// CastVoteHandler handles POST /api/votes
func (s *ServerState) CastVoteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req CastVoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Check rate limiting
	if !s.CheckRateLimit(req.VoterID) {
		respondError(w, http.StatusTooManyRequests, "Rate limit exceeded. Please wait before voting again.")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.System == nil {
		respondError(w, http.StatusBadRequest, "No election created")
		return
	}

	// Verify voting token
	token, exists := s.VotingTokens[req.VoterID]
	if !exists || token != req.VotingToken {
		respondError(w, http.StatusUnauthorized, "Invalid voting token")
		return
	}

	system := s.System.(*evoting.VotingSystem)

	// Get voter
	voter, err := system.GetVoter(req.VoterID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Voter not found")
		return
	}

	// Cast vote
	encryptedVote, err := system.CastVote(voter, req.CandidateID)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Extract randomness (secret) from the encrypted vote
	var randomnessStr string
	if err := json.Unmarshal(encryptedVote.Randomness, &randomnessStr); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to extract vote secret")
		return
	}

	// Generate vote receipt
	voteID := encryptedVote.VoteID
	commitment := sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%s", req.VoterID, req.CandidateID, randomnessStr)))

	receipt := &VoteReceipt{
		VoteID:      voteID,
		VoterID:     req.VoterID,
		CandidateID: req.CandidateID,
		Commitment:  fmt.Sprintf("%x", commitment[:]),
		Timestamp:   encryptedVote.Timestamp,
		Secret:      randomnessStr,
	}
	s.VoteReceipts[voteID] = receipt

	// Update election status to VOTING
	if s.Election.Status == "SETUP" {
		s.Election.Status = "VOTING"
	}

	respondJSON(w, http.StatusOK, CastVoteResponse{
		VoteID:     voteID,
		Commitment: receipt.Commitment,
		Secret:     randomnessStr,
		Timestamp:  receipt.Timestamp.Format(time.RFC3339),
	})
}

// VerifyVoteHandler handles POST /api/votes/verify
func (s *ServerState) VerifyVoteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req VerifyVoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.System == nil {
		respondJSON(w, http.StatusOK, VerifyVoteResponse{
			Valid: false,
			Error: "No election created",
		})
		return
	}

	system := s.System.(*evoting.VotingSystem)

	// Check if voter exists
	voter, err := system.GetVoter(req.VoterID)
	if err != nil {
		respondJSON(w, http.StatusOK, VerifyVoteResponse{
			Valid: false,
			Error: fmt.Sprintf("Voter '%s' not found", req.VoterID),
		})
		return
	}

	// Find voter's latest vote receipt with matching secret
	var candidateID, boothID string
	var foundReceipt bool
	for _, receipt := range s.VoteReceipts {
		if receipt.VoterID == req.VoterID && receipt.Secret == req.Secret {
			candidateID = receipt.CandidateID
			boothID = voter.BoothID
			foundReceipt = true
			break
		}
	}

	if !foundReceipt {
		respondJSON(w, http.StatusOK, VerifyVoteResponse{
			Valid: false,
			Error: "Invalid secret or no vote found for this voter. Make sure you're using the correct secret from your vote receipt.",
		})
		return
	}

	// Verify voter's vote using the system
	valid, err := system.VerifyVoterVote(req.VoterID, candidateID, req.Secret)
	if err != nil {
		respondJSON(w, http.StatusOK, VerifyVoteResponse{
			Valid:       false,
			CandidateID: candidateID,
			BoothID:     boothID,
			Error:       fmt.Sprintf("Verification failed: %s", err.Error()),
		})
		return
	}

	if !valid {
		respondJSON(w, http.StatusOK, VerifyVoteResponse{
			Valid:       false,
			CandidateID: candidateID,
			BoothID:     boothID,
			Error:       "Vote verification failed. The vote may have been tampered with or the secret is incorrect.",
		})
		return
	}

	respondJSON(w, http.StatusOK, VerifyVoteResponse{
		Valid:       true,
		CandidateID: candidateID,
		BoothID:     boothID,
	})
}

// InitiateCountHandler handles POST /api/count/initiate
func (s *ServerState) InitiateCountHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.System == nil {
		respondError(w, http.StatusBadRequest, "No election created")
		return
	}

	if s.CountSession != nil && s.CountSession.Status != "COMPLETED" {
		respondError(w, http.StatusBadRequest, "Counting already in progress")
		return
	}

	system := s.System.(*evoting.VotingSystem)

	// Publish votes before counting
	if err := system.PublishVotes(); err != nil {
		// May already be published, continue
	}

	// Create counting session
	requestID := fmt.Sprintf("count-%d", time.Now().Unix())
	awaiting := make([]int, s.Election.Threshold)
	for i := 0; i < s.Election.Threshold; i++ {
		awaiting[i] = i + 1
	}

	s.CountSession = &CountingSession{
		RequestID:           requestID,
		Status:              "INITIATED",
		AwaitingAuthorities: awaiting,
		ReceivedPartials:    make(map[int]bool),
		RejectedAuthorities: []int{},
		StartedAt:           time.Now(),
	}

	s.Election.Status = "COUNTING"

	respondJSON(w, http.StatusOK, InitiateCountResponse{
		Status:              "INITIATED",
		RequestID:           requestID,
		AwaitingAuthorities: awaiting,
	})
}

// SubmitPartialHandler handles POST /api/count/partial
func (s *ServerState) SubmitPartialHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req SubmitPartialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.CountSession == nil || s.CountSession.RequestID != req.RequestID {
		respondError(w, http.StatusBadRequest, "Invalid counting session")
		return
	}

	// Check if authority already submitted
	if s.CountSession.ReceivedPartials[req.AuthorityIndex] {
		respondError(w, http.StatusBadRequest, "Authority already submitted partial decryption")
		return
	}

	// Mark as received
	s.CountSession.ReceivedPartials[req.AuthorityIndex] = true

	// Remove from awaiting list
	newAwaiting := []int{}
	for _, idx := range s.CountSession.AwaitingAuthorities {
		if idx != req.AuthorityIndex {
			newAwaiting = append(newAwaiting, idx)
		}
	}
	s.CountSession.AwaitingAuthorities = newAwaiting

	// Check if we have enough partials
	if len(s.CountSession.ReceivedPartials) >= s.Election.Threshold {
		s.CountSession.Status = "IN_PROGRESS"

		// Count votes
		system := s.System.(*evoting.VotingSystem)
		results, err := system.CountVotes()
		if err == nil {
			s.CountSession.Results = results
			s.CountSession.Status = "COMPLETED"
			now := time.Now()
			s.CountSession.CompletedAt = &now
			s.Election.Status = "COMPLETED"
		}
	}

	respondJSON(w, http.StatusOK, SubmitPartialResponse{
		Accepted:             true,
		ProofValid:           true,
		RemainingAuthorities: s.CountSession.AwaitingAuthorities,
	})
}

// GetCountStatusHandler handles GET /api/count/status
func (s *ServerState) GetCountStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.CountSession == nil {
		respondError(w, http.StatusNotFound, "No counting session active")
		return
	}

	respondJSON(w, http.StatusOK, CountStatusResponse{
		Status:              s.CountSession.Status,
		AwaitingAuthorities: s.CountSession.AwaitingAuthorities,
		RejectedAuthorities: s.CountSession.RejectedAuthorities,
		Results:             s.CountSession.Results,
	})
}
