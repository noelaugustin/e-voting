package evoting

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestScalability_Small tests with 10 candidates and 100 voters in parallel
func TestScalability_Small(t *testing.T) {
	t.Log("=== Small Scale Parallel Test ===")
	t.Log("Candidates: 10")
	t.Log("Voters: 100")
	t.Log("Testing concurrent registration and voting")
	t.Log("")

	// Initialize system
	system, err := NewVotingSystem()
	if err != nil {
		t.Fatalf("Failed to create voting system: %v", err)
	}

	// Phase 1: Register 10 candidates
	t.Log("Phase 1: Registering 10 candidates...")
	for i := 1; i <= 10; i++ {
		candidateID := fmt.Sprintf("Candidate-%d", i)
		if err := system.RegisterCandidate(candidateID); err != nil {
			t.Fatalf("Failed to register candidate %s: %v", candidateID, err)
		}
	}
	t.Log("✓ Registered 10 candidates")

	// Phase 2: Register 100 voters in parallel
	t.Log("\nPhase 2: Registering 100 voters in parallel...")
	startReg := time.Now()

	var wg sync.WaitGroup
	for i := 1; i <= 100; i++ {
		wg.Add(1)
		go func(voterNum int) {
			defer wg.Done()
			voterID := fmt.Sprintf("Voter-%d", voterNum)
			boothID := fmt.Sprintf("Booth-%d", (voterNum%10)+1)
			_, err := system.RegisterVoter(voterID, boothID)
			if err != nil {
				t.Errorf("Failed to register voter %s: %v", voterID, err)
			}
		}(i)
	}
	wg.Wait()
	regDuration := time.Since(startReg)

	t.Logf("✓ Registered 100 voters in %v (%.0f voters/sec)",
		regDuration, 100.0/regDuration.Seconds())

	// Phase 3: Cast votes in parallel
	t.Log("\nPhase 3: Casting 100 votes in parallel...")
	startVote := time.Now()

	for i := 1; i <= 100; i++ {
		wg.Add(1)
		go func(voterNum int) {
			defer wg.Done()
			voterID := fmt.Sprintf("Voter-%d", voterNum)
			candidateID := fmt.Sprintf("Candidate-%d", (voterNum%10)+1)

			// Get voter to cast vote
			v, err := system.voterRegistry.GetVoter(voterID)
			if err != nil {
				t.Errorf("Failed to get voter %s: %v", voterID, err)
				return
			}

			_, err = system.CastVote(v, candidateID)
			if err != nil {
				t.Errorf("Failed to cast vote for %s: %v", voterID, err)
			}
		}(i)
	}
	wg.Wait()
	voteDuration := time.Since(startVote)

	t.Logf("✓ Cast 100 votes in %v (%.0f votes/sec)",
		voteDuration, 100.0/voteDuration.Seconds())

	// Phase 4: Verify results
	t.Log("\nPhase 4: Verifying results...")

	totalVoters := system.voterRegistry.GetTotalVoters()
	totalVotes := system.voteManager.GetTotalVotes()
	totalCandidates := len(system.voteManager.GetCandidates())

	t.Logf("Total Voters: %d", totalVoters)
	t.Logf("Total Votes: %d", totalVotes)
	t.Logf("Total Candidates: %d", totalCandidates)

	if totalVoters != 100 {
		t.Errorf("Expected 100 voters, got %d", totalVoters)
	}
	if totalVotes != 100 {
		t.Errorf("Expected 100 votes, got %d", totalVotes)
	}
	if totalCandidates != 10 {
		t.Errorf("Expected 10 candidates, got %d", totalCandidates)
	}

	t.Log("\n✅ Small scale concurrent test passed!")
}
