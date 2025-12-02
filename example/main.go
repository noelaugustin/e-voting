package main

import (
	"fmt"
	"log"

	evoting "github.com/naugustin/e-voting"
	"github.com/naugustin/e-voting/voter"
)

func main() {
	fmt.Println("=== E-Voting System Demo ===")
	fmt.Println()

	// Initialize the voting system
	system, err := evoting.NewVotingSystem()
	if err != nil {
		log.Fatalf("Failed to create voting system: %v", err)
	}
	fmt.Println("✓ Voting system initialized")

	// Register candidates
	candidates := []string{"Candidate-A", "Candidate-B", "Candidate-C"}
	for _, candidate := range candidates {
		err := system.RegisterCandidate(candidate)
		if err != nil {
			log.Fatalf("Failed to register candidate %s: %v", candidate, err)
		}
	}
	fmt.Printf("✓ Registered %d candidates: %v\n", len(candidates), candidates)

	// Register voters
	voterData := []struct {
		ID      string
		BoothID string
	}{
		{"Alice", "Booth-North"},
		{"Bob", "Booth-North"},
		{"Charlie", "Booth-South"},
		{"Diana", "Booth-South"},
		{"Eve", "Booth-East"},
		{"Frank", "Booth-East"},
		{"Grace", "Booth-West"},
		{"Henry", "Booth-West"},
	}

	voters := make(map[string]*voter.Voter)
	for _, vd := range voterData {
		v, err := system.RegisterVoter(vd.ID, vd.BoothID)
		if err != nil {
			log.Fatalf("Failed to register voter %s: %v", vd.ID, err)
		}
		voters[vd.ID] = v
	}
	fmt.Printf("✓ Registered %d voters\n\n", len(voters))

	// Cast votes
	fmt.Println("=== Casting Votes ===")
	voteChoices := map[string]string{
		"Alice":   "Candidate-A",
		"Bob":     "Candidate-B",
		"Charlie": "Candidate-A",
		"Diana":   "Candidate-C",
		"Eve":     "Candidate-A",
		"Frank":   "Candidate-B",
		"Grace":   "Candidate-C",
		"Henry":   "Candidate-A",
	}

	for voterID, candidateID := range voteChoices {
		_, err := system.CastVote(voters[voterID], candidateID)
		if err != nil {
			log.Fatalf("Failed to cast vote for %s: %v", voterID, err)
		}
		fmt.Printf("✓ %s voted for %s (encrypted)\n", voterID, candidateID)
	}

	// Demonstrate revote (vote invalidation)
	fmt.Println("\n=== Testing Revote (Previous Vote Invalidation) ===")
	fmt.Println("Alice decides to change her vote...")
	_, err = system.CastVote(voters["Alice"], "Candidate-C")
	if err != nil {
		log.Fatalf("Failed to revote: %v", err)
	}
	fmt.Println("✓ Alice changed vote to Candidate-C (previous vote invalidated)")

	fmt.Printf("\nTotal votes cast: %d\n", system.GetTotalVotes())

	// Publish votes
	fmt.Println("\n=== Publishing Votes for Verification ===")
	err = system.PublishVotes()
	if err != nil {
		log.Fatalf("Failed to publish votes: %v", err)
	}
	fmt.Println("✓ Votes published to public ledger")

	// Get Merkle root for tamper detection
	merkleRoot := system.GetMerkleRoot()
	fmt.Printf("✓ Merkle Tree Root Hash: %s\n", merkleRoot[:16]+"...")

	// Try to vote after publication (should fail)
	fmt.Println("\n=== Testing Post-Publication Vote Attempt ===")
	_, err = system.CastVote(voters["Bob"], "Candidate-A")
	if err != nil {
		fmt.Printf("✓ Expected error: %v\n", err)
	} else {
		fmt.Println("✗ Should not allow voting after publication")
	}

	// Booth-level analytics
	fmt.Println("\n=== Booth-Level Analytics ===")
	booths := system.GetAllBooths()
	fmt.Printf("Number of booths: %d\n", len(booths))
	for _, booth := range booths {
		count := system.GetBoothAnalytics(booth)
		fmt.Printf("  %s: %d votes\n", booth, count)
	}

	// Tamper detection
	fmt.Println("\n=== Tamper Detection ===")
	tamperedRoot := "tampered_hash_12345"
	isTampered := system.DetectTampering(tamperedRoot)
	if isTampered {
		fmt.Println("✓ Tampering detected with incorrect root hash")
	}

	isTampered = system.DetectTampering(merkleRoot)
	if !isTampered {
		fmt.Println("✓ No tampering detected with correct root hash")
	}

	// Summary
	fmt.Println("\n=== Summary ===")
	fmt.Printf("Total candidates: %d\n", len(system.GetCandidates()))
	fmt.Printf("Total votes: %d\n", system.GetTotalVotes())
	fmt.Printf("Total booths: %d\n", len(booths))
	fmt.Println("\n✓ E-Voting system demonstration complete!")
	fmt.Println("\nNote: In a production system:")
	fmt.Println("  - Vote counting would use threshold cryptography")
	fmt.Println("  - Multiple authorities would cooperate for decryption")
	fmt.Println("  - Voters would receive receipts for self-verification")
	fmt.Println("  - System would be distributed across multiple servers")
	fmt.Println("  - Hardware security modules would protect private keys")
}
