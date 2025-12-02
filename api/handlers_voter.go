package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	evoting "github.com/naugustin/e-voting"
)

// RegisterVoterHandler handles POST /api/voters
func (s *ServerState) RegisterVoterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req RegisterVoterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.System == nil {
		respondError(w, http.StatusBadRequest, "No election created")
		return
	}

	system := s.System.(*evoting.VotingSystem)

	// Register voter
	voter, err := system.RegisterVoter(req.VoterID, req.BoothID)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Generate voting token
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)
	s.VotingTokens[req.VoterID] = token

	respondJSON(w, http.StatusOK, RegisterVoterResponse{
		VoterID:     voter.ID,
		BoothID:     voter.BoothID,
		VotingToken: token,
		CanVote:     true,
	})
}

// GetVoterProofHandler handles GET /api/voters/{voterId}/proof
func (s *ServerState) GetVoterProofHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	voterID := r.URL.Query().Get("voterId")
	if voterID == "" {
		respondError(w, http.StatusBadRequest, "voterId required")
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.System == nil {
		respondError(w, http.StatusNotFound, "No election created")
		return
	}

	system := s.System.(*evoting.VotingSystem)
	voter, err := system.GetVoter(voterID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Voter not found")
		return
	}

	// Generate proof hash
	voterData := fmt.Sprintf("%s:%s", voter.ID, voter.BoothID)
	proofHash := sha256.Sum256([]byte(voterData))

	respondJSON(w, http.StatusOK, VoterProofResponse{
		VoterID:   voter.ID,
		BoothID:   voter.BoothID,
		ProofHash: fmt.Sprintf("%x", proofHash[:8]),
		Valid:     true,
	})
}
