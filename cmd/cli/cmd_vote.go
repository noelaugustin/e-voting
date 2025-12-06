package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/naugustin/e-voting/crypto"
)

func handleVoteCommand(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: evoting-cli vote <subcommand> [args]")
		fmt.Println("Subcommands: cast, publish, verify")
		os.Exit(1)
	}

	switch args[0] {
	case "cast":
		castVote(args[1:])
	case "publish":
		publishVotes()
	case "verify":
		verifyVote(args[1:])
	default:
		fmt.Printf("Unknown vote subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func castVote(args []string) {
	castCmd := flag.NewFlagSet("cast", flag.ExitOnError)
	voterID := castCmd.String("voter", "", "Voter ID")
	candidate := castCmd.String("candidate", "", "Candidate ID")
	// privateKey := castCmd.String("private-key", "", "Voter Private Key")
	castCmd.Parse(args)

	// Load election to get candidates and master public key
	var election ElectionData
	if err := loadJSON(ElectionFile, &election); err != nil {
		fmt.Printf("Error loading election: %v\n", err)
		os.Exit(1)
	}

	// Verify candidate
	candidateFound := false
	for _, c := range election.Candidates {
		if c == *candidate {
			candidateFound = true
			break
		}
	}
	if !candidateFound {
		fmt.Printf("Error: Candidate '%s' not found in election\n", *candidate)
		os.Exit(1)
	}

	// Reconstruct Master Public Key
	// We stored it as hex string in election.MasterPublicKey
	if election.MasterPublicKey == "" {
		fmt.Println("Error: Master Public Key not found in election data")
		os.Exit(1)
	}

	// Parse Master Public Key
	// It was serialized as %x%x (X and Y concatenated)
	// Since P-256 coordinates are 32 bytes (64 hex chars), we can split it.
	if len(election.MasterPublicKey) != 128 {
		fmt.Printf("Error: Invalid Master Public Key length: %d\n", len(election.MasterPublicKey))
		os.Exit(1)
	}

	xStr := election.MasterPublicKey[:64]
	yStr := election.MasterPublicKey[64:]

	x := new(big.Int)
	x.SetString(xStr, 16)
	y := new(big.Int)
	y.SetString(yStr, 16)

	masterKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// Encrypt Vote
	// Map candidate string to index
	candidateIndex := -1
	for i, c := range election.Candidates {
		if c == *candidate {
			candidateIndex = i
			break
		}
	}

	ciphertext, randomness, err := crypto.EncryptVote(masterKey, candidateIndex)
	if err != nil {
		fmt.Printf("Error encrypting vote: %v\n", err)
		os.Exit(1)
	}

	// Generate Validity Proof
	proof, err := crypto.GenerateVoteValidityProof(ciphertext, candidateIndex, len(election.Candidates), randomness, masterKey)
	if err != nil {
		fmt.Printf("Error generating proof: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Vote cast for %s by %s (Encrypted & Saved).\n", *candidate, *voterID)

	// Save to votes.json
	var votes []VoteData
	loadJSON(VotesFile, &votes) // Ignore error

	// Remove existing vote from this voter (Last Vote Counts)
	newVotes := make([]VoteData, 0)
	for _, v := range votes {
		if v.VoterID != *voterID {
			newVotes = append(newVotes, v)
		}
	}

	// Create new vote
	vote := VoteData{
		VoteID:     fmt.Sprintf("vote-%s-%d", *voterID, len(votes)+1),
		VoterID:    *voterID,
		Ciphertext: ciphertext,
		Proof:      proof,
		Timestamp:  "2024-12-06T12:00:00Z", // Dummy timestamp
	}

	newVotes = append(newVotes, vote)

	if err := saveJSON(VotesFile, newVotes); err != nil {
		fmt.Printf("Error saving vote: %v\n", err)
		os.Exit(1)
	}
}

func publishVotes() {
	fmt.Println("Publishing votes... (Simulation)")
}

func verifyVote(args []string) {
	fmt.Println("Verifying vote... (Simulation)")
}
