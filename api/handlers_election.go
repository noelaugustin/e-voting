package api

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	evoting "github.com/naugustin/e-voting"
)

// CreateElectionHandler handles POST /api/election
func (s *ServerState) CreateElectionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req CreateElectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate parameters
	if req.K < 1 || req.N < 1 || req.K > req.N {
		respondError(w, http.StatusBadRequest, "Invalid k or n parameters")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Create voting system
	system, err := evoting.NewVotingSystem()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create voting system")
		return
	}

	// Setup threshold authorities
	if err := system.SetupThresholdAuthorities(req.K, req.N); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to setup authorities")
		return
	}

	// Get public info
	registry := system.GetAuthorityRegistry()
	publicInfo := registry.GetPublicInfo()

	// Compute public key hash
	pkHash := sha256.Sum256(append(publicInfo.MasterPublicKey.X.Bytes(), publicInfo.MasterPublicKey.Y.Bytes()...))

	// Generate election ID
	electionID := fmt.Sprintf("election-%d", time.Now().Unix())

	// Create election info
	s.Election = &ElectionInfo{
		ElectionID:          electionID,
		Name:                req.Name,
		Status:              "SETUP",
		Threshold:           req.K,
		TotalAuthorities:    req.N,
		MasterPublicKeyHash: fmt.Sprintf("%x", pkHash[:]),
		CreatedAt:           time.Now(),
	}
	s.System = system

	// Prepare response
	authorities := make([]AuthorityInfo, req.N)
	for i := 0; i < req.N; i++ {
		authID := fmt.Sprintf("authority-%d", i+1)
		auth, _ := registry.GetAuthority(authID)

		// Hash verification point
		vpHash := sha256.Sum256(append(publicInfo.VerificationPoints[i].X.Bytes(), publicInfo.VerificationPoints[i].Y.Bytes()...))

		authorities[i] = AuthorityInfo{
			Index:                 i + 1,
			Name:                  auth.Name,
			VerificationPointHash: fmt.Sprintf("%x", vpHash[:8]),
		}
	}

	respondJSON(w, http.StatusOK, CreateElectionResponse{
		ElectionID:          s.Election.ElectionID,
		Threshold:           req.K,
		TotalAuthorities:    req.N,
		MasterPublicKeyHash: s.Election.MasterPublicKeyHash,
		Authorities:         authorities,
	})
}

// GetElectionHandler handles GET /api/election
func (s *ServerState) GetElectionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.Election == nil || s.System == nil {
		respondError(w, http.StatusNotFound, "No election created")
		return
	}

	system := s.System.(*evoting.VotingSystem)
	candidates := system.GetCandidates()
	totalVoters := system.GetTotalVoters()
	votesCast := system.GetTotalVotes()

	respondJSON(w, http.StatusOK, ElectionInfoResponse{
		Name:                s.Election.Name,
		Status:              s.Election.Status,
		Threshold:           s.Election.Threshold,
		TotalAuthorities:    s.Election.TotalAuthorities,
		MasterPublicKeyHash: s.Election.MasterPublicKeyHash,
		Candidates:          candidates,
		TotalVoters:         totalVoters,
		VotesCast:           votesCast,
	})
}

// RegisterCandidateHandler handles POST /api/candidates
func (s *ServerState) RegisterCandidateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req RegisterCandidateRequest
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

	if err := system.RegisterCandidate(req.CandidateID); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Get candidate index
	index, _ := system.GetCandidateIndex(req.CandidateID)

	respondJSON(w, http.StatusOK, CandidateInfo{
		CandidateID: req.CandidateID,
		Index:       index,
	})
}

// GetCandidatesHandler handles GET /api/candidates
func (s *ServerState) GetCandidatesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.System == nil {
		respondError(w, http.StatusNotFound, "No election created")
		return
	}

	system := s.System.(*evoting.VotingSystem)
	candidates := system.GetCandidates()
	result := make([]CandidateInfo, len(candidates))

	for i, cid := range candidates {
		idx, _ := system.GetCandidateIndex(cid)
		result[i] = CandidateInfo{
			CandidateID: cid,
			Index:       idx,
		}
	}

	respondJSON(w, http.StatusOK, result)
}
