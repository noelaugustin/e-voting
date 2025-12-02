package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	evoting "github.com/naugustin/e-voting"
)

// GetAuditPackageHandler handles GET /api/audit/package
// Returns complete audit package with merkle tree and all published votes
func (s *ServerState) GetAuditPackageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.System == nil {
		respondError(w, http.StatusBadRequest, "No election created")
		return
	}

	if s.Election == nil {
		respondError(w, http.StatusBadRequest, "No election information")
		return
	}

	system := s.System.(*evoting.VotingSystem)

	// Get merkle root
	merkleRoot := system.GetMerkleRoot()
	if merkleRoot == "" {
		respondError(w, http.StatusBadRequest, "Votes not yet published")
		return
	}

	// Get all published votes
	publishedVotes := system.GetAllPublishedVotes()
	voteInfos := make([]PublishedVoteInfo, 0, len(publishedVotes))

	for _, pv := range publishedVotes {
		// Hash the ciphertext for verification
		ciphertextData := fmt.Sprintf("%v", pv.Ciphertext)
		ciphertextHash := sha256.Sum256([]byte(ciphertextData))

		// Get merkle proof for this vote
		merkleProof := system.GetMerkleProof(pv.VoteID)

		voteInfo := PublishedVoteInfo{
			VoteID:          pv.VoteID,
			BoothID:         pv.BoothID,
			Timestamp:       pv.Timestamp.Format(time.RFC3339),
			CiphertextHash:  hex.EncodeToString(ciphertextHash[:]),
			VoterCommitment: hex.EncodeToString(pv.VoterCommitment),
			ProofHash:       hex.EncodeToString(pv.ProofHash),
			MerkleProof:     merkleProof,
		}
		voteInfos = append(voteInfos, voteInfo)
	}

	// Get candidates
	candidateList := system.GetCandidates()
	candidates := make([]CandidateInfo, 0, len(candidateList))
	for i, cid := range candidateList {
		candidates = append(candidates, CandidateInfo{
			CandidateID: cid,
			Index:       i + 1,
			ProofHash:   "", // Can be obtained from separate endpoint
		})
	}

	// Get results if counting is complete
	var results map[string]int
	if s.CountSession != nil && s.CountSession.Status == "COMPLETED" {
		results = s.CountSession.Results
	}

	auditPackage := AuditPackageResponse{
		ElectionID:          s.Election.ElectionID,
		ElectionName:        s.Election.Name,
		Status:              s.Election.Status,
		Threshold:           s.Election.Threshold,
		TotalAuthorities:    s.Election.TotalAuthorities,
		MasterPublicKeyHash: s.Election.MasterPublicKeyHash,
		MerkleRoot:          merkleRoot,
		Candidates:          candidates,
		PublishedVotes:      voteInfos,
		Results:             results,
		TotalVotes:          len(voteInfos),
		GeneratedAt:         time.Now().Format(time.RFC3339),
	}

	respondJSON(w, http.StatusOK, auditPackage)
}

// VerifyMyVoteHandler handles POST /api/audit/verify-my-vote
// Allows voter to verify their vote is included in the merkle tree
func (s *ServerState) VerifyMyVoteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req VerifyMyVoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.System == nil {
		respondJSON(w, http.StatusOK, VerifyMyVoteResponse{
			Found: false,
			Valid: false,
			Error: "No election created",
		})
		return
	}

	system := s.System.(*evoting.VotingSystem)

	// Check if votes are published
	merkleRoot := system.GetMerkleRoot()
	if merkleRoot == "" {
		respondJSON(w, http.StatusOK, VerifyMyVoteResponse{
			Found: false,
			Valid: false,
			Error: "Votes not yet published",
		})
		return
	}

	// Find voter's vote receipt
	var candidateID, voteID string
	var foundReceipt bool
	for _, receipt := range s.VoteReceipts {
		if receipt.VoterID == req.VoterID && receipt.Secret == req.Secret {
			candidateID = receipt.CandidateID
			voteID = receipt.VoteID
			foundReceipt = true
			break
		}
	}

	if !foundReceipt {
		respondJSON(w, http.StatusOK, VerifyMyVoteResponse{
			Found: false,
			Valid: false,
			Error: "Vote not found with provided secret",
		})
		return
	}

	// Verify vote commitment
	valid, err := system.VerifyVoterVote(req.VoterID, candidateID, req.Secret)
	if err != nil {
		respondJSON(w, http.StatusOK, VerifyMyVoteResponse{
			Found:       true,
			Valid:       false,
			CandidateID: candidateID,
			VoteID:      voteID,
			Error:       fmt.Sprintf("Verification failed: %s", err.Error()),
		})
		return
	}

	// Get merkle proof
	merkleProof := system.GetMerkleProof(voteID)
	merkleIncluded := len(merkleProof) > 0

	respondJSON(w, http.StatusOK, VerifyMyVoteResponse{
		Found:          true,
		Valid:          valid,
		CandidateID:    candidateID,
		VoteID:         voteID,
		MerkleIncluded: merkleIncluded,
		MerkleProof:    merkleProof,
	})
}

// GetMerkleRootHandler handles GET /api/audit/merkle-root
// Returns just the merkle root hash
func (s *ServerState) GetMerkleRootHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.System == nil {
		respondError(w, http.StatusBadRequest, "No election created")
		return
	}

	system := s.System.(*evoting.VotingSystem)
	merkleRoot := system.GetMerkleRoot()

	if merkleRoot == "" {
		respondError(w, http.StatusBadRequest, "Votes not yet published")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"merkleRoot": merkleRoot,
		"timestamp":  time.Now().Format(time.RFC3339),
	})
}
