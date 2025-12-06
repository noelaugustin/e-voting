package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/naugustin/e-voting/crypto"
)

// consolidateVotes filters votes to ensure only the last vote per voter counts
func consolidateVotes(votes []VoteData) []VoteData {
	latestVotes := make(map[string]VoteData)

	for _, v := range votes {
		existing, ok := latestVotes[v.VoterID]
		if !ok {
			latestVotes[v.VoterID] = v
			continue
		}

		// Compar timestamps
		// Fallback to naive string comparison if parsing fails (for demo simplicity/legacy support)
		tNew, err1 := time.Parse(time.RFC3339, v.Timestamp)
		tOld, err2 := time.Parse(time.RFC3339, existing.Timestamp)

		if err1 == nil && err2 == nil {
			if !tNew.Before(tOld) {
				latestVotes[v.VoterID] = v
			}
		} else {
			// Fallback: assume order in file implies order? Or just string compare
			// If we appended, the later one is likely newer.
			// But let's trust the one later in the list if timestamps are broken
			latestVotes[v.VoterID] = v
		}
	}

	// Convert map back to slice
	var consolidated []VoteData
	for _, v := range latestVotes {
		consolidated = append(consolidated, v)
	}
	return consolidated
}

func handleKeysCommand(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: evoting-cli keys <subcommand> [args]")
		fmt.Println("Subcommands: release")
		os.Exit(1)
	}

	switch args[0] {
	case "release":
		releaseKeys()
	default:
		fmt.Printf("Unknown keys subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func releaseKeys() {
	// In a real system, authorities would independently release their partial decryptions
	// Here, we simulate this by using the stored private keys to generate partial decryptions for all votes

	fmt.Println("Releasing authority keys and generating partial decryptions...")

	// 1. Load Election
	var election ElectionData
	if err := loadJSON(ElectionFile, &election); err != nil {
		fmt.Printf("Error loading election: %v\n", err)
		os.Exit(1)
	}

	// 2. Load Votes
	var rawVotes []VoteData
	if err := loadJSON(VotesFile, &rawVotes); err != nil {
		fmt.Printf("Error loading votes: %v\n", err)
		os.Exit(1)
	}

	votes := consolidateVotes(rawVotes)
	if len(rawVotes) != len(votes) {
		fmt.Printf("Consolidated votes: %d -> %d (removed superseded votes)\n", len(rawVotes), len(votes))
	}

	if len(votes) == 0 {
		fmt.Println("No votes to decrypt.")
		return
	}

	// 3. Load Authority Keys
	var authKeys []AuthorityKeyData
	if err := loadJSON(AuthorityKeysFile, &authKeys); err != nil {
		fmt.Printf("Error loading authority keys: %v\n", err)
		os.Exit(1)
	}

	// 4. Load Authorities (for verification points)
	var auths []AuthorityData
	if err := loadJSON(AuthoritiesFile, &auths); err != nil {
		fmt.Printf("Error loading authorities: %v\n", err)
		os.Exit(1)
	}

	// We need to reconstruct the AuthorityRegistry to perform operations
	// But we can just use the crypto functions directly if we have the shares.
	// Let's reconstruct the shares.

	// Aggregate homomorphic tallies per candidate by summing ciphertexts.
	// Then generate partial decryptions for each aggregated candidate ciphertext.

	// Prepare aggregated ciphertexts per candidate
	numCandidates := len(votes[0].Ciphertexts)
	aggregated := make([]*crypto.ElGamalCiphertext, numCandidates)

	// We need k authorities.
	k := election.K
	if len(authKeys) < k {
		fmt.Printf("Error: Not enough authority keys available (%d < %d)\n", len(authKeys), k)
		os.Exit(1)
	}

	curve := elliptic.P256()

	// Parse Master Public Key
	xStr := election.MasterPublicKey[:64]
	yStr := election.MasterPublicKey[64:]
	x := new(big.Int)
	x.SetString(xStr, 16)
	y := new(big.Int)
	y.SetString(yStr, 16)

	// Reconstruct Master Public Key (ecdsa.PublicKey)
	masterECDSA := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Aggregate ciphertexts across all votes
	for _, vote := range votes {
		for i := 0; i < numCandidates; i++ {
			if aggregated[i] == nil {
				// initialize first sum as this ciphertext
				aggregated[i] = vote.Ciphertexts[i]
			} else {
				aggregated[i] = crypto.AddCiphertexts(aggregated[i], vote.Ciphertexts[i], curve)
			}
		}
	}

	// Prepare public threshold info for verification
	// Parse verification points from loaded authorities
	verificationPoints := make([]crypto.Point, election.N)
	for _, auth := range auths {
		if auth.ID < 1 || auth.ID > election.N {
			continue
		}
		vx := new(big.Int)
		vx.SetString(auth.VerificationPointX, 16)
		vy := new(big.Int)
		vy.SetString(auth.VerificationPointY, 16)
		verificationPoints[auth.ID-1] = crypto.Point{X: vx, Y: vy}
	}

	publicInfo := &crypto.ThresholdPublicInfo{
		Threshold:          election.K,
		TotalShares:        election.N,
		MasterPublicKey:    masterECDSA,
		VerificationPoints: verificationPoints,
	}

	// Generate partial decryptions for each aggregated candidate ciphertext
	perCandidatePartials := make(map[int][]*crypto.PartialDecryptionShare)
	for i := 0; i < numCandidates; i++ {
		var candidatePartials []*crypto.PartialDecryptionShare
		for a := 0; a < k; a++ {
			keyData := authKeys[a]
			shareVal := new(big.Int)
			shareVal.SetString(keyData.PrivateKey, 10)
			share := &crypto.ThresholdKeyShare{
				Index:      keyData.ID,
				ShareValue: shareVal,
				PublicKey:  masterECDSA,
			}
			partial, err := crypto.PartialDecrypt(share, aggregated[i])
			if err != nil {
				fmt.Printf("Error generating partial for authority %d on candidate %d: %v\n", keyData.ID, i, err)
				os.Exit(1)
			}
			// Verify partial using public info and verification point
			if !crypto.VerifyPartialDecryption(partial, aggregated[i], publicInfo) {
				fmt.Printf("Warning: partial from authority %d failed verification; skipping\n", keyData.ID)
				continue
			}
			candidatePartials = append(candidatePartials, partial)
		}
		perCandidatePartials[i] = candidatePartials
	}

	if err := saveJSON("partials.json", perCandidatePartials); err != nil {
		fmt.Printf("Error saving partial decryptions: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated partial decryptions for %d aggregated candidate ciphertexts.\n", numCandidates)
	fmt.Println("Saved to data/partials.json")
}

func handleResultsCommand(args []string) {
	fmt.Println("Calculating results...")

	// 1. Load Election
	var election ElectionData
	if err := loadJSON(ElectionFile, &election); err != nil {
		fmt.Printf("Error loading election: %v\n", err)
		os.Exit(1)
	}

	// Load number of candidates from election
	numCandidates := len(election.Candidates)

	// 4. Reconstruct Master Public Key (needed for curve info)
	xStr := election.MasterPublicKey[:64]
	yStr := election.MasterPublicKey[64:]
	x := new(big.Int)
	x.SetString(xStr, 16)
	y := new(big.Int)
	y.SetString(yStr, 16)
	curve := elliptic.P256()

	masterECDSA := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Prepare public threshold info for verification
	// We need VerificationPoints from loaded authorities
	var auths []AuthorityData
	loadJSON(AuthoritiesFile, &auths) // ignore error if missing (but needed for verification)

	verificationPoints := make([]crypto.Point, election.N)
	for _, auth := range auths {
		if auth.ID < 1 || auth.ID > election.N {
			continue
		}
		vx := new(big.Int)
		vx.SetString(auth.VerificationPointX, 16)
		vy := new(big.Int)
		vy.SetString(auth.VerificationPointY, 16)
		verificationPoints[auth.ID-1] = crypto.Point{X: vx, Y: vy}
	}

	publicInfo := &crypto.ThresholdPublicInfo{
		Threshold:          election.K,
		TotalShares:        election.N,
		MasterPublicKey:    masterECDSA,
		VerificationPoints: verificationPoints,
	}

	// Combine Partials to get the result
	fmt.Println("Decrypting aggregated tallies...")

	results := make(map[string]int)
	for _, c := range election.Candidates {
		results[c] = 0
	}

	// Structure of partials.json: map[candidateIndex][]PartialDecryptionShare
	var perCandidatePartials map[int][]*crypto.PartialDecryptionShare
	if err := loadJSON("partials.json", &perCandidatePartials); err != nil {
		fmt.Printf("Error loading partials: %v. Did you run 'keys release'?\n", err)
		os.Exit(1)
	}

	// We also need the aggregated ciphertexts to combine; recompute aggregation to get ciphertexts
	var rawVotes []VoteData
	_ = loadJSON(VotesFile, &rawVotes)
	votes := consolidateVotes(rawVotes)

	curve = elliptic.P256()
	aggregated := make([]*crypto.ElGamalCiphertext, numCandidates)
	for _, vote := range votes {
		for i := 0; i < numCandidates; i++ {
			if aggregated[i] == nil {
				aggregated[i] = vote.Ciphertexts[i]
			} else {
				aggregated[i] = crypto.AddCiphertexts(aggregated[i], vote.Ciphertexts[i], curve)
			}
		}
	}

	for i := 0; i < numCandidates; i++ {
		parts := perCandidatePartials[i]
		count, err := crypto.CombinePartialDecryptions(parts, aggregated[i], publicInfo, len(votes))
		if err != nil {
			fmt.Printf("Failed to decrypt tally for candidate %d: %v\n", i, err)
			continue
		}
		if i >= 0 && i < len(election.Candidates) {
			results[election.Candidates[i]] = count
		}
	}

	fmt.Println("\nElection Results:")
	fmt.Println("-----------------")
	for name, count := range results {
		fmt.Printf("%s: %d\n", name, count)
	}
}

func handleExportCommand(args []string) {
	fmt.Println("Export not implemented yet.")
}
