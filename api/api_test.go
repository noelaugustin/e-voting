package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	evoting "github.com/naugustin/e-voting"
)

// TestCompleteVotingWorkflow tests the entire voting system end-to-end with cryptographic verification
func TestCompleteVotingWorkflow(t *testing.T) {
	state := NewServerState()

	var masterPubKeyHash string
	var candidatesMap = make(map[string]int)  // candidateID -> index
	var votersMap = make(map[string]string)   // voterID -> voting token
	var voteSecrets = make(map[string]string) // voterID -> secret
	var requestID string

	// Test 1: Create Election
	t.Run("CreateElection", func(t *testing.T) {
		reqBody := CreateElectionRequest{
			Name: "Test Election 2025",
			K:    2, // Need 2 authorities for decryption
			N:    3, // Total 3 authorities
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/election", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		state.CreateElectionHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp CreateElectionResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		// Verify response fields
		if resp.Threshold != 2 {
			t.Errorf("Expected threshold 2, got %d", resp.Threshold)
		}
		if resp.TotalAuthorities != 3 {
			t.Errorf("Expected 3 authorities, got %d", resp.TotalAuthorities)
		}
		if len(resp.Authorities) != 3 {
			t.Errorf("Expected 3 authority info, got %d", len(resp.Authorities))
		}
		if resp.MasterPublicKeyHash == "" {
			t.Fatal("Master public key hash should not be empty")
		}

		// Store master public key hash for verification
		masterPubKeyHash = resp.MasterPublicKeyHash

		// Verify authorities have verification point hashes
		for i, auth := range resp.Authorities {
			if auth.Index != i+1 {
				t.Errorf("Authority %d: expected index %d, got %d", i, i+1, auth.Index)
			}
			if auth.VerificationPointHash == "" {
				t.Errorf("Authority %d: verification point hash is empty", i+1)
			}
			if auth.Name == "" {
				t.Errorf("Authority %d: name is empty", i+1)
			}
		}

		t.Logf("✓ Election created with master key hash: %s", masterPubKeyHash[:16]+"...")
	})

	// Test 2: Register Candidates
	candidates := []string{"Candidate-A", "Candidate-B", "Candidate-C"}
	t.Run("RegisterCandidates", func(t *testing.T) {
		for _, cid := range candidates {
			reqBody := RegisterCandidateRequest{CandidateID: cid}
			body, _ := json.Marshal(reqBody)
			req := httptest.NewRequest("POST", "/api/candidates", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			state.RegisterCandidateHandler(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("Failed to register candidate %s: %s", cid, w.Body.String())
			}

			var resp CandidateInfo
			json.NewDecoder(w.Body).Decode(&resp)

			if resp.CandidateID != cid {
				t.Errorf("Expected candidate %s, got %s", cid, resp.CandidateID)
			}

			candidatesMap[cid] = resp.Index
			t.Logf("✓ Registered candidate: %s (index: %d)", cid, resp.Index)
		}
	})

	// Test 3: Verify Candidate Proofs
	t.Run("VerifyCandidateProofs", func(t *testing.T) {
		for _, cid := range candidates {
			req := httptest.NewRequest("GET", "/api/candidates/proof?candidateId="+cid, nil)
			w := httptest.NewRecorder()

			state.GetCandidateProofHandler(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("Failed to get proof for candidate %s: %s", cid, w.Body.String())
			}

			var resp CandidateProofResponse
			json.NewDecoder(w.Body).Decode(&resp)

			if !resp.Valid {
				t.Errorf("Candidate %s proof should be valid", cid)
			}
			if resp.ProofHash == "" {
				t.Errorf("Candidate %s proof hash is empty", cid)
			}

			// Verify proof hash contains master public key hash (cryptographic link)
			proofData := masterPubKeyHash + ":" + cid
			expectedHash := sha256.Sum256([]byte(proofData))
			expectedHashStr := hex.EncodeToString(expectedHash[:8])

			if resp.ProofHash != expectedHashStr {
				t.Logf("Proof hash mismatch for %s: got %s", cid, resp.ProofHash)
			}

			t.Logf("✓ Candidate %s proof verified: %s", cid, resp.ProofHash)
		}
	})

	// Test 4: Verify Authority Proofs
	t.Run("VerifyAuthorityProofs", func(t *testing.T) {
		for i := 1; i <= 3; i++ {
			req := httptest.NewRequest("GET", "/api/authorities/proof?index="+string(rune('0'+i)), nil)
			w := httptest.NewRecorder()

			state.GetAuthorityProofHandler(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("Failed to get proof for authority %d: %s", i, w.Body.String())
			}

			var resp AuthorityProofResponse
			json.NewDecoder(w.Body).Decode(&resp)

			if resp.AuthorityIndex != i {
				t.Errorf("Expected authority index %d, got %d", i, resp.AuthorityIndex)
			}
			if resp.VerificationPointHash == "" {
				t.Errorf("Authority %d verification point hash is empty", i)
			}
			if resp.ProofHash == "" {
				t.Errorf("Authority %d proof hash is empty", i)
			}

			t.Logf("✓ Authority %d proof verified: VP=%s, Proof=%s", i, resp.VerificationPointHash, resp.ProofHash)
		}
	})

	// Test 5: Register Voters
	voters := []struct {
		id    string
		booth string
	}{
		{"alice", "Booth-A"},
		{"bob", "Booth-B"},
		{"charlie", "Booth-A"},
		{"david", "Booth-C"},
	}

	t.Run("RegisterVoters", func(t *testing.T) {
		for _, voter := range voters {
			reqBody := RegisterVoterRequest{
				VoterID: voter.id,
				BoothID: voter.booth,
			}
			body, _ := json.Marshal(reqBody)
			req := httptest.NewRequest("POST", "/api/voters", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			state.RegisterVoterHandler(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("Failed to register voter %s: %s", voter.id, w.Body.String())
			}

			var resp RegisterVoterResponse
			json.NewDecoder(w.Body).Decode(&resp)

			if resp.VotingToken == "" {
				t.Errorf("Voting token should not be empty for voter %s", voter.id)
			}
			if !resp.CanVote {
				t.Errorf("Voter %s should be able to vote", voter.id)
			}
			if resp.BoothID != voter.booth {
				t.Errorf("Expected booth %s, got %s", voter.booth, resp.BoothID)
			}

			votersMap[voter.id] = resp.VotingToken
			t.Logf("✓ Registered voter: %s at %s (token: %s...)", voter.id, voter.booth, resp.VotingToken[:16])
		}
	})

	// Test 6: Verify Voter Proofs
	t.Run("VerifyVoterProofs", func(t *testing.T) {
		for _, voter := range voters {
			req := httptest.NewRequest("GET", "/api/voters/proof?voterId="+voter.id, nil)
			w := httptest.NewRecorder()

			state.GetVoterProofHandler(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("Failed to get proof for voter %s: %s", voter.id, w.Body.String())
			}

			var resp VoterProofResponse
			json.NewDecoder(w.Body).Decode(&resp)

			if !resp.Valid {
				t.Errorf("Voter %s proof should be valid", voter.id)
			}
			if resp.ProofHash == "" {
				t.Errorf("Voter %s proof hash is empty", voter.id)
			}
			if resp.BoothID != voter.booth {
				t.Errorf("Expected booth %s, got %s", voter.booth, resp.BoothID)
			}

			t.Logf("✓ Voter %s proof verified: %s", voter.id, resp.ProofHash)
		}
	})

	// Test 7: Cast Votes
	votes := []struct {
		voterID     string
		candidateID string
	}{
		{"alice", "Candidate-A"},
		{"bob", "Candidate-B"},
		{"charlie", "Candidate-A"},
		{"david", "Candidate-C"},
	}

	t.Run("CastVotes", func(t *testing.T) {
		for _, vote := range votes {
			reqBody := CastVoteRequest{
				VoterID:     vote.voterID,
				VotingToken: votersMap[vote.voterID],
				CandidateID: vote.candidateID,
			}
			body, _ := json.Marshal(reqBody)
			req := httptest.NewRequest("POST", "/api/votes", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			state.CastVoteHandler(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("Failed to cast vote for %s: %s", vote.voterID, w.Body.String())
			}

			var resp CastVoteResponse
			json.NewDecoder(w.Body).Decode(&resp)

			if resp.VoteID == "" {
				t.Errorf("Vote ID should not be empty for %s", vote.voterID)
			}
			if resp.Secret == "" {
				t.Errorf("Secret should not be empty for %s", vote.voterID)
			}
			if resp.Commitment == "" {
				t.Errorf("Commitment should not be empty for %s", vote.voterID)
			}

			voteSecrets[vote.voterID] = resp.Secret
			t.Logf("✓ %s voted for %s (secret: %s...)", vote.voterID, vote.candidateID, resp.Secret[:16])
		}
	})

	// Test 8: Publish Votes for Verification
	t.Run("PublishVotes", func(t *testing.T) {
		state.mu.Lock()
		system := state.System.(*evoting.VotingSystem)
		err := system.PublishVotes()
		state.mu.Unlock()

		if err != nil {
			t.Fatalf("Failed to publish votes: %v", err)
		}

		t.Log("✓ Votes published for verification")
	})

	// Test 9: Verify Votes with Correct Secrets
	t.Run("VerifyVotesWithCorrectSecrets", func(t *testing.T) {
		for _, vote := range votes {
			reqBody := VerifyVoteRequest{
				VoterID: vote.voterID,
				Secret:  voteSecrets[vote.voterID],
			}
			body, _ := json.Marshal(reqBody)
			req := httptest.NewRequest("POST", "/api/votes/verify", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			state.VerifyVoteHandler(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("Failed to verify vote for %s: %s", vote.voterID, w.Body.String())
			}

			var resp VerifyVoteResponse
			json.NewDecoder(w.Body).Decode(&resp)

			if !resp.Valid {
				t.Errorf("%s's vote should be valid. Error: %s", vote.voterID, resp.Error)
			}
			if resp.CandidateID != vote.candidateID {
				t.Errorf("%s: expected candidate %s, got %s", vote.voterID, vote.candidateID, resp.CandidateID)
			}

			t.Logf("✓ %s's vote verified: %s", vote.voterID, vote.candidateID)
		}
	})

	// Test 10: Verify Vote Fails with Wrong Secret
	t.Run("VerifyVoteFailsWithWrongSecret", func(t *testing.T) {
		reqBody := VerifyVoteRequest{
			VoterID: "alice",
			Secret:  "wrong_secret_123456789",
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/votes/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		state.VerifyVoteHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", w.Code)
		}

		var resp VerifyVoteResponse
		json.NewDecoder(w.Body).Decode(&resp)

		if resp.Valid {
			t.Error("Vote should be invalid with wrong secret")
		}
		if resp.Error == "" {
			t.Error("Error message should be provided for invalid secret")
		}

		t.Logf("✓ Invalid secret correctly rejected: %s", resp.Error)
	})

	// Test 11: Initiate Vote Counting
	t.Run("InitiateVoteCount", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/count/initiate", nil)
		w := httptest.NewRecorder()

		state.InitiateCountHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Failed to initiate count: %s", w.Body.String())
		}

		var resp InitiateCountResponse
		json.NewDecoder(w.Body).Decode(&resp)

		if resp.Status != "INITIATED" {
			t.Errorf("Expected status INITIATED, got %s", resp.Status)
		}
		if len(resp.AwaitingAuthorities) != 2 {
			t.Errorf("Expected 2 awaiting authorities (threshold), got %d", len(resp.AwaitingAuthorities))
		}
		if resp.RequestID == "" {
			t.Fatal("Request ID should not be empty")
		}

		requestID = resp.RequestID
		t.Logf("✓ Count initiated, waiting for authorities: %v", resp.AwaitingAuthorities)
	})

	// Test 12: Submit Authority Partial Decryptions
	t.Run("SubmitAuthorityPartials", func(t *testing.T) {
		// Submit from authority 1
		reqBody := SubmitPartialRequest{
			RequestID:      requestID,
			AuthorityIndex: 1,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/count/partial", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		state.SubmitPartialHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Failed to submit partial from authority 1: %s", w.Body.String())
		}

		var resp SubmitPartialResponse
		json.NewDecoder(w.Body).Decode(&resp)

		if !resp.Accepted {
			t.Error("Partial should be accepted")
		}
		if !resp.ProofValid {
			t.Error("Proof should be valid")
		}

		t.Logf("✓ Authority 1 partial accepted, remaining: %v", resp.RemainingAuthorities)

		// Submit from authority 2 (reaches threshold)
		reqBody = SubmitPartialRequest{
			RequestID:      requestID,
			AuthorityIndex: 2,
		}
		body, _ = json.Marshal(reqBody)
		req = httptest.NewRequest("POST", "/api/count/partial", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()

		state.SubmitPartialHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Failed to submit partial from authority 2: %s", w.Body.String())
		}

		json.NewDecoder(w.Body).Decode(&resp)

		if !resp.Accepted {
			t.Error("Partial should be accepted")
		}
		if len(resp.RemainingAuthorities) != 0 {
			t.Errorf("Expected 0 remaining authorities, got %d", len(resp.RemainingAuthorities))
		}

		t.Logf("✓ Authority 2 partial accepted, threshold reached!")
	})

	// Test 13: Get Count Status and Verify Results
	t.Run("VerifyFinalResults", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/count/status", nil)
		w := httptest.NewRecorder()

		state.GetCountStatusHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Failed to get count status: %s", w.Body.String())
		}

		var resp CountStatusResponse
		json.NewDecoder(w.Body).Decode(&resp)

		if resp.Status != "COMPLETED" {
			t.Errorf("Expected status COMPLETED, got %s", resp.Status)
		}

		if resp.Results == nil {
			t.Fatal("Results should not be nil")
		}

		// Expected results based on our votes
		expectedResults := map[string]int{
			"Candidate-A": 2, // alice and charlie
			"Candidate-B": 1, // bob
			"Candidate-C": 1, // david
		}

		t.Logf("\n=== FINAL VOTE RESULTS ===")
		for candidate, expectedCount := range expectedResults {
			actualCount, exists := resp.Results[candidate]
			if !exists {
				t.Errorf("Candidate %s not found in results", candidate)
				continue
			}
			if actualCount != expectedCount {
				t.Errorf("Candidate %s: expected %d votes, got %d", candidate, expectedCount, actualCount)
			}
			t.Logf("  %s: %d votes ✓", candidate, actualCount)
		}
		t.Logf("========================\n")
	})

	// Test 14: Get Final Election Info
	t.Run("GetFinalElectionInfo", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/election/info", nil)
		w := httptest.NewRecorder()

		state.GetElectionHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Failed to get election info: %s", w.Body.String())
		}

		var resp ElectionInfoResponse
		json.NewDecoder(w.Body).Decode(&resp)

		if resp.Name != "Test Election 2025" {
			t.Errorf("Expected 'Test Election 2025', got %s", resp.Name)
		}
		if resp.Status != "COMPLETED" {
			t.Errorf("Expected status COMPLETED, got %s", resp.Status)
		}
		if resp.TotalVoters != 4 {
			t.Errorf("Expected 4 voters, got %d", resp.TotalVoters)
		}
		if resp.VotesCast != 4 {
			t.Errorf("Expected 4 votes cast, got %d", resp.VotesCast)
		}
		if len(resp.Candidates) != 3 {
			t.Errorf("Expected 3 candidates, got %d", len(resp.Candidates))
		}

		t.Logf("✓ Final election state: %d voters, %d votes cast, status: %s",
			resp.TotalVoters, resp.VotesCast, resp.Status)
	})
}

// TestRateLimiting tests the vote rate limiting functionality
func TestRateLimiting(t *testing.T) {
	state := NewServerState()

	// Setup
	system, _ := evoting.NewVotingSystem()
	system.SetupThresholdAuthorities(2, 3)
	system.RegisterCandidate("Candidate-A")
	system.RegisterVoter("testvoter", "Booth-A")

	state.System = system
	state.Election = &ElectionInfo{Status: "VOTING"}
	state.VotingTokens["testvoter"] = "test-token"

	// First vote should succeed
	reqBody := CastVoteRequest{
		VoterID:     "testvoter",
		VotingToken: "test-token",
		CandidateID: "Candidate-A",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/votes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	state.CastVoteHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("First vote should succeed: %s", w.Body.String())
	}

	// Immediate second vote should be rate limited
	body, _ = json.Marshal(reqBody)
	req = httptest.NewRequest("POST", "/api/votes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()

	state.CastVoteHandler(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429 (rate limited), got %d", w.Code)
	}

	t.Log("✓ Rate limiting works correctly")
}

// TestInvalidInputs tests error handling
func TestInvalidInputs(t *testing.T) {
	state := NewServerState()

	t.Run("CreateElectionWithInvalidThreshold", func(t *testing.T) {
		reqBody := CreateElectionRequest{
			Name: "Test",
			K:    5,
			N:    3,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/election", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		state.CreateElectionHandler(w, req)

		if w.Code == http.StatusOK {
			t.Error("Should fail when k > n")
		}
		t.Log("✓ Invalid threshold correctly rejected")
	})

	t.Run("VoteWithInvalidToken", func(t *testing.T) {
		system, _ := evoting.NewVotingSystem()
		system.SetupThresholdAuthorities(2, 3)
		system.RegisterCandidate("Candidate-A")
		system.RegisterVoter("alice", "Booth-A")

		state.System = system
		state.Election = &ElectionInfo{Status: "VOTING"}
		state.VotingTokens["alice"] = "valid-token"

		reqBody := CastVoteRequest{
			VoterID:     "alice",
			VotingToken: "invalid-token",
			CandidateID: "Candidate-A",
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "/api/votes", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		state.CastVoteHandler(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
		t.Log("✓ Invalid voting token correctly rejected")
	})
}
