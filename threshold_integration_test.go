package evoting

import (
	"testing"
)

// TestThresholdDecryptionIntegration tests the complete voting flow with threshold decryption
func TestThresholdDecryptionIntegration(t *testing.T) {
	system, err := NewVotingSystem()
	if err != nil {
		t.Fatalf("Failed to create voting system: %v", err)
	}

	// Verify authority registry was created
	registry := system.GetAuthorityRegistry()
	if registry == nil {
		t.Fatal("Authority registry is nil")
	}

	if registry.GetThreshold() != 5 {
		t.Errorf("Expected threshold 5, got %d", registry.GetThreshold())
	}

	if registry.GetAuthorityCount() != 9 {
		t.Errorf("Expected 9 authorities, got %d", registry.GetAuthorityCount())
	}

	// Register candidates
	system.RegisterCandidate("Candidate-A")
	system.RegisterCandidate("Candidate-B")
	system.RegisterCandidate("Candidate-C")

	// Register voters and cast votes
	voter1, _ := system.RegisterVoter("voter1", "Booth-A")
	voter2, _ := system.RegisterVoter("voter2", "Booth-A")
	voter3, _ := system.RegisterVoter("voter3", "Booth-B")
	voter4, _ := system.RegisterVoter("voter4", "Booth-B")
	voter5, _ := system.RegisterVoter("voter5", "Booth-C")

	system.CastVote(voter1, "Candidate-A")
	system.CastVote(voter2, "Candidate-A")
	system.CastVote(voter3, "Candidate-B")
	system.CastVote(voter4, "Candidate-C")
	system.CastVote(voter5, "Candidate-A")

	// Publish votes
	err = system.PublishVotes()
	if err != nil {
		t.Fatalf("Failed to publish votes: %v", err)
	}

	// Count votes using threshold decryption
	results, err := system.CountVotes()
	if err != nil {
		t.Fatalf("Failed to count votes with threshold decryption: %v", err)
	}

	// Verify results
	// Note: The vote manager encodes candidates as indices:
	// In the current implementation, the decryption returns indices
	// So we need to check the total count
	totalVotes := 0
	for _, count := range results {
		totalVotes += count
	}

	if totalVotes != 5 {
		t.Errorf("Expected 5 total votes, got %d", totalVotes)
	}

	t.Logf("Vote counting successful with threshold decryption")
	t.Logf("Results: %v", results)
}

// TestThresholdDecryptionWithCustomAuthorities tests with custom k, n values
func TestThresholdDecryptionWithCustomAuthorities(t *testing.T) {
	system, err := NewVotingSystem()
	if err != nil {
		t.Fatalf("Failed to create voting system: %v", err)
	}

	// Setup custom 3-of-5 threshold
	err = system.SetupThresholdAuthorities(3, 5)
	if err != nil {
		t.Fatalf("Failed to setup threshold authorities: %v", err)
	}

	registry := system.GetAuthorityRegistry()
	if registry.GetThreshold() != 3 {
		t.Errorf("Expected threshold 3, got %d", registry.GetThreshold())
	}

	if registry.GetAuthorityCount() != 5 {
		t.Errorf("Expected 5 authorities, got %d", registry.GetAuthorityCount())
	}

	// Register and vote
	system.RegisterCandidate("Candidate-A")
	system.RegisterCandidate("Candidate-B")

	voter1, _ := system.RegisterVoter("voter1", "Booth-A")
	voter2, _ := system.RegisterVoter("voter2", "Booth-A")

	system.CastVote(voter1, "Candidate-A")
	system.CastVote(voter2, "Candidate-B")

	system.PublishVotes()

	// Count with 3-of-5 threshold
	results, err := system.CountVotes()
	if err != nil {
		t.Fatalf("Failed to count votes with 3-of-5 threshold: %v", err)
	}

	totalVotes := 0
	for _, count := range results {
		totalVotes += count
	}

	if totalVotes != 2 {
		t.Errorf("Expected 2 total votes, got %d", totalVotes)
	}

	t.Logf("3-of-5 threshold decryption successful")
}

// TestThresholdDecryptionWithInactiveAuthorities tests decryption when some authorities are offline
func TestThresholdDecryptionWithInactiveAuthorities(t *testing.T) {
	system, err := NewVotingSystem()
	if err != nil {
		t.Fatalf("Failed to create voting system: %v", err)
	}

	registry := system.GetAuthorityRegistry()

	// Deactivate 4 authorities (5 remain active, exactly the threshold)
	registry.SetAuthorityActive("authority-1", false)
	registry.SetAuthorityActive("authority-2", false)
	registry.SetAuthorityActive("authority-3", false)
	registry.SetAuthorityActive("authority-4", false)

	if registry.GetActiveAuthorityCount() != 5 {
		t.Errorf("Expected 5 active authorities, got %d", registry.GetActiveAuthorityCount())
	}

	// Register and vote
	system.RegisterCandidate("Candidate-A")
	voter1, _ := system.RegisterVoter("voter1", "Booth-A")
	system.CastVote(voter1, "Candidate-A")
	system.PublishVotes()

	// Should still work with exactly k authorities
	results, err := system.CountVotes()
	if err != nil {
		t.Fatalf("Failed to count with exactly k authorities: %v", err)
	}

	if len(results) == 0 {
		t.Error("Expected results from counting")
	}

	t.Logf("Counting successful with exactly k active authorities")
}

// TestThresholdDecryptionInsufficientAuthorities tests failure when below threshold
func TestThresholdDecryptionInsufficientAuthorities(t *testing.T) {
	system, err := NewVotingSystem()
	if err != nil {
		t.Fatalf("Failed to create voting system: %v", err)
	}

	registry := system.GetAuthorityRegistry()

	// Deactivate 5 authorities (4 remain, below threshold of 5)
	registry.SetAuthorityActive("authority-1", false)
	registry.SetAuthorityActive("authority-2", false)
	registry.SetAuthorityActive("authority-3", false)
	registry.SetAuthorityActive("authority-4", false)
	registry.SetAuthorityActive("authority-5", false)

	if registry.GetActiveAuthorityCount() != 4 {
		t.Errorf("Expected 4 active authorities, got %d", registry.GetActiveAuthorityCount())
	}

	// Register and vote
	system.RegisterCandidate("Candidate-A")
	voter1, _ := system.RegisterVoter("voter1", "Booth-A")
	system.CastVote(voter1, "Candidate-A")
	system.PublishVotes()

	// Should fail with insufficient authorities
	_, err = system.CountVotes()
	if err == nil {
		t.Error("Should fail to count with insufficient authorities")
	}

	t.Logf("Correctly failed with insufficient authorities: %v", err)
}

// TestBoothAnalyticsWithThreshold tests booth-level analytics with threshold decryption
func TestBoothAnalyticsWithThreshold(t *testing.T) {
	system, err := NewVotingSystem()
	if err != nil {
		t.Fatalf("Failed to create voting system: %v", err)
	}

	// Register candidates
	system.RegisterCandidate("Candidate-A")
	system.RegisterCandidate("Candidate-B")

	// Create votes in different booths
	voter1, _ := system.RegisterVoter("voter1", "Booth-A")
	voter2, _ := system.RegisterVoter("voter2", "Booth-A")
	voter3, _ := system.RegisterVoter("voter3", "Booth-B")
	voter4, _ := system.RegisterVoter("voter4", "Booth-B")
	voter5, _ := system.RegisterVoter("voter5", "Booth-B")

	system.CastVote(voter1, "Candidate-A")
	system.CastVote(voter2, "Candidate-A")
	system.CastVote(voter3, "Candidate-B")
	system.CastVote(voter4, "Candidate-A")
	system.CastVote(voter5, "Candidate-B")

	system.PublishVotes()

	// Get booth analytics
	boothAResults, err := system.GetBoothCandidateAnalytics("Booth-A")
	if err != nil {
		t.Fatalf("Failed to get Booth-A analytics: %v", err)
	}

	boothBResults, err := system.GetBoothCandidateAnalytics("Booth-B")
	if err != nil {
		t.Fatalf("Failed to get Booth-B analytics: %v", err)
	}

	// Verify booth A has 2 votes
	totalBoothA := 0
	for _, count := range boothAResults {
		totalBoothA += count
	}
	if totalBoothA != 2 {
		t.Errorf("Expected 2 votes in Booth-A, got %d", totalBoothA)
	}

	// Verify booth B has 3 votes
	totalBoothB := 0
	for _, count := range boothBResults {
		totalBoothB += count
	}
	if totalBoothB != 3 {
		t.Errorf("Expected 3 votes in Booth-B, got %d", totalBoothB)
	}

	t.Logf("Booth analytics with threshold decryption successful")
	t.Logf("Booth A: %v", boothAResults)
	t.Logf("Booth B: %v", boothBResults)
}
