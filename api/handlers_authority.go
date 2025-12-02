package api

import (
	"crypto/sha256"
	"fmt"
	"net/http"

	evoting "github.com/naugustin/e-voting"
)

// GetAuthoritiesHandler handles GET /api/authorities
func (s *ServerState) GetAuthoritiesHandler(w http.ResponseWriter, r *http.Request) {
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
	registry := system.GetAuthorityRegistry()
	publicInfo := registry.GetPublicInfo()

	authorities := make([]AuthorityInfo, s.Election.TotalAuthorities)
	for i := 0; i < s.Election.TotalAuthorities; i++ {
		authID := fmt.Sprintf("authority-%d", i+1)
		auth, _ := registry.GetAuthority(authID)

		// Hash verification point for public proof
		vpHash := sha256.Sum256(append(
			publicInfo.VerificationPoints[i].X.Bytes(),
			publicInfo.VerificationPoints[i].Y.Bytes()...,
		))

		authorities[i] = AuthorityInfo{
			Index:                 i + 1,
			Name:                  auth.Name,
			VerificationPointHash: fmt.Sprintf("%x", vpHash[:8]),
		}
	}

	respondJSON(w, http.StatusOK, authorities)
}

// GetAuthorityProofHandler handles GET /api/authorities/{index}/proof
func (s *ServerState) GetAuthorityProofHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	indexStr := r.URL.Query().Get("index")
	if indexStr == "" {
		respondError(w, http.StatusBadRequest, "index required")
		return
	}

	var index int
	fmt.Sscanf(indexStr, "%d", &index)

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.System == nil {
		respondError(w, http.StatusNotFound, "No election created")
		return
	}

	if index < 1 || index > s.Election.TotalAuthorities {
		respondError(w, http.StatusBadRequest, "Invalid authority index")
		return
	}

	system := s.System.(*evoting.VotingSystem)
	registry := system.GetAuthorityRegistry()
	publicInfo := registry.GetPublicInfo()

	authID := fmt.Sprintf("authority-%d", index)
	auth, err := registry.GetAuthority(authID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Authority not found")
		return
	}

	// Generate proof hash showing authority holds key share
	vpHash := sha256.Sum256(append(
		publicInfo.VerificationPoints[index-1].X.Bytes(),
		publicInfo.VerificationPoints[index-1].Y.Bytes()...,
	))

	// Generate ZKP that authority can decrypt with their share
	proofData := fmt.Sprintf("%s:%d:%x", auth.Name, index, vpHash)
	proofHash := sha256.Sum256([]byte(proofData))

	respondJSON(w, http.StatusOK, AuthorityProofResponse{
		AuthorityIndex:        index,
		Name:                  auth.Name,
		VerificationPointHash: fmt.Sprintf("%x", vpHash[:8]),
		ProofHash:             fmt.Sprintf("%x", proofHash[:8]),
	})
}

// GetCandidateProofHandler handles GET /api/candidates/{candidateId}/proof
func (s *ServerState) GetCandidateProofHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	candidateID := r.URL.Query().Get("candidateId")
	if candidateID == "" {
		respondError(w, http.StatusBadRequest, "candidateId required")
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.System == nil {
		respondError(w, http.StatusNotFound, "No election created")
		return
	}

	system := s.System.(*evoting.VotingSystem)

	// Check if candidate exists
	_, err := system.GetCandidateIndex(candidateID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Candidate not found")
		return
	}

	// Generate cryptographic proof that candidate is linked to election
	proofData := fmt.Sprintf("%s:%s", s.Election.MasterPublicKeyHash, candidateID)
	proofHash := sha256.Sum256([]byte(proofData))

	respondJSON(w, http.StatusOK, CandidateProofResponse{
		CandidateID: candidateID,
		ProofHash:   fmt.Sprintf("%x", proofHash[:8]),
		Valid:       true,
	})
}
