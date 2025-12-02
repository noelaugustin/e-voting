package evoting

import (
	"testing"

	"github.com/naugustin/e-voting/voter"
)

func TestNewVotingSystem(t *testing.T) {
	system, err := NewVotingSystem()
	if err != nil {
		t.Fatalf("Failed to create voting system: %v", err)
	}

	if system == nil {
		t.Fatal("System is nil")
	}

	if system.voterRegistry == nil {
		t.Error("Voter registry is nil")
	}

	if system.voteManager == nil {
		t.Error("Vote manager is nil")
	}

	if system.verificationSystem == nil {
		t.Error("Verification system is nil")
	}

	if system.analyticsEngine == nil {
		t.Error("Analytics engine is nil")
	}
}

func TestRegisterVoter(t *testing.T) {
	system, err := NewVotingSystem()
	if err != nil {
		t.Fatalf("Failed to create voting system: %v", err)
	}

	voter, err := system.RegisterVoter("voter1", "Booth-A")
	if err != nil {
		t.Fatalf("Failed to register voter: %v", err)
	}

	if voter.ID != "voter1" {
		t.Errorf("Expected voter ID 'voter1', got '%s'", voter.ID)
	}

	if voter.BoothID != "Booth-A" {
		t.Errorf("Expected booth ID 'Booth-A', got '%s'", voter.BoothID)
	}
}

func TestRegisterCandidate(t *testing.T) {
	system, err := NewVotingSystem()
	if err != nil {
		t.Fatalf("Failed to create voting system: %v", err)
	}

	err = system.RegisterCandidate("Candidate-A")
	if err != nil {
		t.Fatalf("Failed to register candidate: %v", err)
	}

	err = system.RegisterCandidate("Candidate-B")
	if err != nil {
		t.Fatalf("Failed to register candidate: %v", err)
	}

	candidates := system.GetCandidates()
	if len(candidates) != 2 {
		t.Errorf("Expected 2 candidates, got %d", len(candidates))
	}
}

func TestCastVote(t *testing.T) {
	system, err := NewVotingSystem()
	if err != nil {
		t.Fatalf("Failed to create voting system: %v", err)
	}

	// Register candidate and voter
	system.RegisterCandidate("Candidate-A")
	voter, _ := system.RegisterVoter("voter1", "Booth-A")

	// Cast vote
	_, err = system.CastVote(voter, "Candidate-A")
	if err != nil {
		t.Fatalf("Failed to cast vote: %v", err)
	}

	// Verify vote was recorded
	totalVotes := system.GetTotalVotes()
	if totalVotes != 1 {
		t.Errorf("Expected 1 vote, got %d", totalVotes)
	}
}

func TestMultipleVotes(t *testing.T) {
	system, err := NewVotingSystem()
	if err != nil {
		t.Fatalf("Failed to create voting system: %v", err)
	}

	// Register candidates
	system.RegisterCandidate("Candidate-A")
	system.RegisterCandidate("Candidate-B")

	// Register voters
	voter1, _ := system.RegisterVoter("voter1", "Booth-A")
	voter2, _ := system.RegisterVoter("voter2", "Booth-A")
	voter3, _ := system.RegisterVoter("voter3", "Booth-B")

	// Cast votes
	system.CastVote(voter1, "Candidate-A")
	system.CastVote(voter2, "Candidate-B")
	system.CastVote(voter3, "Candidate-A")

	totalVotes := system.GetTotalVotes()
	if totalVotes != 3 {
		t.Errorf("Expected 3 votes, got %d", totalVotes)
	}
}

func TestRevote(t *testing.T) {
	system, err := NewVotingSystem()
	if err != nil {
		t.Fatalf("Failed to create voting system: %v", err)
	}

	// Register candidates
	system.RegisterCandidate("Candidate-A")
	system.RegisterCandidate("Candidate-B")

	// Register voter
	voter, _ := system.RegisterVoter("voter1", "Booth-A")

	// First vote
	system.CastVote(voter, "Candidate-A")
	totalVotes := system.GetTotalVotes()
	if totalVotes != 1 {
		t.Errorf("Expected 1 vote after first cast, got %d", totalVotes)
	}

	// Second vote (should invalidate first)
	system.CastVote(voter, "Candidate-B")
	totalVotes = system.GetTotalVotes()
	if totalVotes != 1 {
		t.Errorf("Expected 1 vote after revote (previous invalidated), got %d", totalVotes)
	}
}

func TestPublishVotes(t *testing.T) {
	system, err := NewVotingSystem()
	if err != nil {
		t.Fatalf("Failed to create voting system: %v", err)
	}

	// Register and vote
	system.RegisterCandidate("Candidate-A")
	voter, _ := system.RegisterVoter("voter1", "Booth-A")
	system.CastVote(voter, "Candidate-A")

	// Publish votes
	err = system.PublishVotes()
	if err != nil {
		t.Fatalf("Failed to publish votes: %v", err)
	}

	// Get Merkle root
	rootHash := system.GetMerkleRoot()
	if rootHash == "" {
		t.Error("Merkle root is empty")
	}

	// Try to vote after publication (should fail)
	_, err = system.CastVote(voter, "Candidate-A")
	if err == nil {
		t.Error("Should not be able to cast vote after publication")
	}
}

func TestBoothAnalytics(t *testing.T) {
	system, err := NewVotingSystem()
	if err != nil {
		t.Fatalf("Failed to create voting system: %v", err)
	}

	// Register candidates
	system.RegisterCandidate("Candidate-A")
	system.RegisterCandidate("Candidate-B")

	// Register voters in different booths
	voter1, _ := system.RegisterVoter("voter1", "Booth-A")
	voter2, _ := system.RegisterVoter("voter2", "Booth-A")
	voter3, _ := system.RegisterVoter("voter3", "Booth-B")

	// Cast votes
	system.CastVote(voter1, "Candidate-A")
	system.CastVote(voter2, "Candidate-B")
	system.CastVote(voter3, "Candidate-A")

	// Check booth analytics
	boothACount := system.GetBoothAnalytics("Booth-A")
	if boothACount != 2 {
		t.Errorf("Expected 2 votes in Booth-A, got %d", boothACount)
	}

	boothBCount := system.GetBoothAnalytics("Booth-B")
	if boothBCount != 1 {
		t.Errorf("Expected 1 vote in Booth-B, got %d", boothBCount)
	}
}

func TestGetAllBooths(t *testing.T) {
	system, err := NewVotingSystem()
	if err != nil {
		t.Fatalf("Failed to create voting system: %v", err)
	}

	// Register candidates
	system.RegisterCandidate("Candidate-A")

	// Register voters in different booths
	voter1, _ := system.RegisterVoter("voter1", "Booth-A")
	voter2, _ := system.RegisterVoter("voter2", "Booth-B")
	voter3, _ := system.RegisterVoter("voter3", "Booth-C")

	// Cast votes
	system.CastVote(voter1, "Candidate-A")
	system.CastVote(voter2, "Candidate-A")
	system.CastVote(voter3, "Candidate-A")

	// Get all booths
	booths := system.GetAllBooths()
	if len(booths) != 3 {
		t.Errorf("Expected 3 booths, got %d", len(booths))
	}
}

func TestDetectTampering(t *testing.T) {
	system, err := NewVotingSystem()
	if err != nil {
		t.Fatalf("Failed to create voting system: %v", err)
	}

	// Register and vote
	system.RegisterCandidate("Candidate-A")
	voter, _ := system.RegisterVoter("voter1", "Booth-A")
	system.CastVote(voter, "Candidate-A")

	// Publish votes
	system.PublishVotes()
	rootHash := system.GetMerkleRoot()

	// Check tampering with correct hash
	tampered := system.DetectTampering(rootHash)
	if tampered {
		t.Error("Should not detect tampering with correct root hash")
	}

	// Check tampering with wrong hash
	tampered = system.DetectTampering("wrong_hash")
	if !tampered {
		t.Error("Should detect tampering with wrong root hash")
	}
}

func TestCompleteVotingFlow(t *testing.T) {
	system, err := NewVotingSystem()
	if err != nil {
		t.Fatalf("Failed to create voting system: %v", err)
	}

	// 1. Register candidates
	system.RegisterCandidate("Candidate-A")
	system.RegisterCandidate("Candidate-B")
	system.RegisterCandidate("Candidate-C")

	// 2. Register voters
	voters := make([]*voter.Voter, 10)
	for i := 0; i < 10; i++ {
		boothID := "Booth-A"
		if i >= 5 {
			boothID = "Booth-B"
		}
		voters[i], _ = system.RegisterVoter(string(rune('0'+i)), boothID)
	}

	// 3. Cast votes
	system.CastVote(voters[0], "Candidate-A")
	system.CastVote(voters[1], "Candidate-A")
	system.CastVote(voters[2], "Candidate-B")
	system.CastVote(voters[3], "Candidate-C")
	system.CastVote(voters[4], "Candidate-A")
	system.CastVote(voters[5], "Candidate-B")
	system.CastVote(voters[6], "Candidate-B")
	system.CastVote(voters[7], "Candidate-C")
	system.CastVote(voters[8], "Candidate-A")
	system.CastVote(voters[9], "Candidate-C")

	// 4. Test revote
	system.CastVote(voters[0], "Candidate-B") // Change vote

	totalVotes := system.GetTotalVotes()
	if totalVotes != 10 {
		t.Errorf("Expected 10 votes (including revote), got %d", totalVotes)
	}

	// 5. Publish votes
	err = system.PublishVotes()
	if err != nil {
		t.Fatalf("Failed to publish votes: %v", err)
	}

	// 6. Verify Merkle root exists
	rootHash := system.GetMerkleRoot()
	if rootHash == "" {
		t.Error("Merkle root should not be empty")
	}

	// 7. Check booth analytics
	boothAVotes := system.GetBoothAnalytics("Booth-A")
	boothBVotes := system.GetBoothAnalytics("Booth-B")

	if boothAVotes != 5 {
		t.Errorf("Expected 5 votes in Booth-A, got %d", boothAVotes)
	}

	if boothBVotes != 5 {
		t.Errorf("Expected 5 votes in Booth-B, got %d", boothBVotes)
	}

	// 8. Verify no tampering
	tampered := system.DetectTampering(rootHash)
	if tampered {
		t.Error("Should not detect tampering with correct root hash")
	}
}
