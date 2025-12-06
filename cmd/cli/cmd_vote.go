package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

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
	machineID := castCmd.String("machine", "", "Machine ID (optional)")
	// privateKey := castCmd.String("private-key", "", "Voter Private Key")
	castCmd.Parse(args)

	if *voterID == "" || *candidate == "" {
		fmt.Println("Error: --voter and --candidate are required")
		castCmd.Usage()
		os.Exit(1)
	}

	// Validate Machine if provided
	var machinePrivKey *ecdsa.PrivateKey
	if *machineID != "" {
		var booths []BoothData
		if err := loadJSON(BoothsFile, &booths); err == nil {
			found := false
			for _, b := range booths {
				for _, m := range b.Machines {
					if m == *machineID {
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if !found {
				fmt.Printf("Warning: Machine ID '%s' not found in any registered booth.\n", *machineID)
			}
		}

		// Load machine keys
		var machineKeys []MachineKeyData
		loadJSON(MachineKeysFile, &machineKeys)
		for _, mk := range machineKeys {
			if mk.ID == *machineID {
				pk := new(big.Int)
				pk.SetString(mk.PrivateKey, 10)
				machinePrivKey = &ecdsa.PrivateKey{
					PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()},
					D:         pk,
				}
				machinePrivKey.PublicKey.X, machinePrivKey.PublicKey.Y = elliptic.P256().ScalarBaseMult(pk.Bytes())
				break
			}
		}
		if machinePrivKey == nil {
			fmt.Printf("Warning: No private keys found for machine '%s'. Cannot sign vote.\n", *machineID)
		}
	}

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

	// Encrypt vector: per-candidate ciphertexts (1 for chosen, 0 otherwise)
	var ciphertexts []*crypto.ElGamalCiphertext
	var randomness *big.Int // use randomness of chosen for proof linkage
	for i := 0; i < len(election.Candidates); i++ {
		ct, r, err := crypto.EncryptVote(masterKey, func() int {
			if i == candidateIndex {
				return 1
			} else {
				return 0
			}
		}())
		if err != nil {
			fmt.Printf("Error encrypting component %d: %v\n", i, err)
			os.Exit(1)
		}
		ciphertexts = append(ciphertexts, ct)
		if i == candidateIndex {
			randomness = r
		}
	}

	// Generate composite one-hot proof over the vector (demo placeholder)
	proof, err := crypto.GenerateOneHotProof(ciphertexts, candidateIndex, randomness, masterKey)
	if err != nil {
		fmt.Printf("Error generating proof: %v\n", err)
		os.Exit(1)
	}

	// Load existing votes/log
	var votes []VoteData
	loadJSON(VotesFile, &votes) // Ignore error on first run

	// Create new vote
	vote := VoteData{
		VoteID:       fmt.Sprintf("vote-%s-%d", *voterID, len(votes)+1),
		VoterID:      *voterID,
		MachineID:    *machineID,
		Ciphertexts:  ciphertexts,
		Proof:        proof,
		Timestamp:    time.Now().Format(time.RFC3339Nano),
		PreviousHash: "GENESIS",
	}

	// Get Previous Hash
	if len(votes) > 0 {
		vote.PreviousHash = votes[len(votes)-1].Hash
	}

	// Sign with Machine Key
	if machinePrivKey != nil {
		// Sign (VoteID + VoterID + Timestamp + PrevHash)
		msg := vote.VoteID + vote.VoterID + vote.Timestamp + vote.PreviousHash
		r, s, err := crypto.SignData(machinePrivKey, []byte(msg))
		if err == nil {
			vote.MachineSignature = fmt.Sprintf("%x,%x", r, s)
		} else {
			fmt.Printf("Warning: Failed to sign vote: %v\n", err)
		}
	}

	// Compute Current Hash
	// Hash(PreviousHash + VoteID + VoterID + EncryptedData)
	h := sha256.New()
	h.Write([]byte(vote.PreviousHash))
	h.Write([]byte(vote.VoteID))
	h.Write([]byte(vote.VoterID))
	// Add encrypted data to hash
	cipherBytes, _ := json.Marshal(vote.Ciphertexts)
	h.Write(cipherBytes)
	h.Write([]byte(vote.MachineSignature))
	vote.Hash = hex.EncodeToString(h.Sum(nil))

	// Append to log (do not replace previous votes yet, consolidation happens at counting)
	votes = append(votes, vote)

	if err := saveJSON(VotesFile, votes); err != nil {
		fmt.Printf("Error saving vote: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Vote cast for %s by %s (Encrypted & Saved).\n", *candidate, *voterID)
	if *machineID != "" {
		fmt.Printf("Recorded via Machine: %s\n", *machineID)
		if vote.MachineSignature != "" {
			fmt.Println("Vote cryptographically signed by machine.")
		}
	}
	fmt.Printf("Vote Hash: %s\n", vote.Hash)
}

func publishVotes() {
	fmt.Println("Publishing votes... (Simulation)")
}

func verifyVote(args []string) {
	verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)
	checkTamper := verifyCmd.Bool("tamper", true, "Check hash chain integrity")
	verifyCmd.Parse(args)

	// Verify one-hot proofs for all votes
	var election ElectionData
	if err := loadJSON(ElectionFile, &election); err != nil {
		fmt.Printf("Error loading election: %v\n", err)
		os.Exit(1)
	}
	var votes []VoteData
	if err := loadJSON(VotesFile, &votes); err != nil {
		fmt.Printf("Error loading votes: %v\n", err)
		os.Exit(1)
	}
	// Reconstruct Master Public Key
	xStr := election.MasterPublicKey[:64]
	yStr := election.MasterPublicKey[64:]
	x := new(big.Int)
	x.SetString(xStr, 16)
	y := new(big.Int)
	y.SetString(yStr, 16)
	// ...
	masterKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	// Prepare Chain Verification
	// Need Admin Key (Election), Booth Keys (from Booths file), Machine Keys (from Machines file)
	var machines []MachineData
	loadJSON(MachinesFile, &machines)
	var booths []BoothData
	loadJSON(BoothsFile, &booths)

	// Helper to reconstruct public key from hex
	parsePubKey := func(hexStr string) *ecdsa.PublicKey {
		if len(hexStr) != 128 {
			return nil
		}
		x, y := new(big.Int), new(big.Int)
		x.SetString(hexStr[:64], 16)
		y.SetString(hexStr[64:], 16)
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	}

	// Helper to parse signature
	parseSig := func(sigStr string) (*big.Int, *big.Int) {
		parts := strings.Split(sigStr, ",")
		if len(parts) != 2 {
			return nil, nil
		}
		r, s := new(big.Int), new(big.Int)
		r.SetString(parts[0], 16)
		s.SetString(parts[1], 16)
		return r, s
	}

	adminPubKey := parsePubKey(election.AdminPublicKey)
	if adminPubKey == nil && *checkTamper {
		fmt.Println("Warning: Election has no Admin Public Key. Chain verification disabled.")
	}

	validCount := 0
	integrityValid := true

	for i, v := range votes {
		// 1. ZKP Verification
		if v.Proof != nil && crypto.VerifyOneHotProof(v.Ciphertexts, v.Proof, masterKey) {
			validCount++
		}

		// 2. Tamper Evidence / Hash Chain
		if *checkTamper {
			// A. Chain Integrity
			expectedPrev := "GENESIS"
			if i > 0 {
				expectedPrev = votes[i-1].Hash
			}
			if v.PreviousHash != expectedPrev {
				fmt.Printf("FAIL: Hash chain broken at vote %s (Index %d). PrevHash mismatch.\n", v.VoteID, i)
				integrityValid = false
			}

			// B. Recompute current hash
			h := sha256.New()
			h.Write([]byte(v.PreviousHash))
			h.Write([]byte(v.VoteID))
			h.Write([]byte(v.VoterID))
			cipherBytes, _ := json.Marshal(v.Ciphertexts)
			h.Write(cipherBytes)
			h.Write([]byte(v.MachineSignature))
			computedHash := hex.EncodeToString(h.Sum(nil))

			if computedHash != v.Hash {
				fmt.Printf("FAIL: Hash mismatch at vote %s (Index %d).\n", v.VoteID, i)
				integrityValid = false
			}

			// C. Certificate Chain Validation (Machine Authentication)
			if v.MachineID != "" && adminPubKey != nil {
				// 1. Find Machine
				var machine *MachineData
				for _, m := range machines {
					if m.ID == v.MachineID {
						machine = &m
						break
					}
				}
				if machine == nil {
					fmt.Printf("FAIL: Unregistered Machine ID %s for vote %s\n", v.MachineID, v.VoteID)
					integrityValid = false
					continue
				}

				// 2. Find Booth
				var booth *BoothData
				for _, b := range booths {
					if b.ID == machine.BoothID {
						booth = &b
						break
					}
				}
				if booth == nil {
					fmt.Printf("FAIL: Unregistered Booth ID %s for machine %s\n", machine.BoothID, machine.ID)
					integrityValid = false
					continue
				}

				// 3. Verify Chain: Election -> Booth -> Machine -> Vote

				// Verify Booth Signature (Signed by Admin)
				boothPubKey := parsePubKey(booth.PublicKey)
				r, s := parseSig(booth.AdminSignature)
				if boothPubKey == nil || r == nil || !crypto.VerifySignature(adminPubKey, []byte(booth.PublicKey), r, s) {
					fmt.Printf("FAIL: Booth %s has invalid signature from Election Admin\n", booth.ID)
					integrityValid = false
				}

				// Verify Machine Signature (Signed by Booth)
				machinePubKey := parsePubKey(machine.PublicKey)
				r, s = parseSig(machine.BoothSignature)
				if machinePubKey == nil || r == nil || !crypto.VerifySignature(boothPubKey, []byte(machine.PublicKey), r, s) {
					fmt.Printf("FAIL: Machine %s has invalid signature from Booth %s\n", machine.ID, booth.ID)
					integrityValid = false
				}

				// Verify Vote Signature (Signed by Machine)
				r, s = parseSig(v.MachineSignature)
				msg := v.VoteID + v.VoterID + v.Timestamp + v.PreviousHash
				if r == nil || !crypto.VerifySignature(machinePubKey, []byte(msg), r, s) {
					fmt.Printf("FAIL: Vote %s has invalid signature from Machine %s\n", v.VoteID, machine.ID)
					integrityValid = false
				}
			}
		}
	}
	// ... existing verify logic ...
	fmt.Printf("Verified %d/%d vote proofs (one-hot).\n", validCount, len(votes))
	if *checkTamper {
		if integrityValid {
			fmt.Println("Hash chain integrity: OK")
		} else {
			fmt.Println("Hash chain integrity: FAILED")
			os.Exit(1)
		}
	}

	// 3. Merkle Tree Inclusion / Hierarchical Audit
	// Group votes by machine
	votesByMachine := make(map[string][]string) // MachineID -> []VoteHash
	for _, v := range votes {
		// Use the vote's Hash as the leaf data
		mid := "Unknown"
		if v.MachineID != "" {
			mid = v.MachineID
		}
		votesByMachine[mid] = append(votesByMachine[mid], v.Hash)
	}

	// Compute Machine Roots
	machineRoots := make(map[string]string)
	fmt.Println("\n--- Merkle Tree Audit ---")

	// We need to map MachineID to BoothID
	machineToBooth := make(map[string]string)
	for _, m := range machines {
		machineToBooth[m.ID] = m.BoothID
	}

	boothMachineRoots := make(map[string][]string) // BoothID -> []MachineRootHash

	for mid, hashes := range votesByMachine {
		// Convert hex strings to bytes
		var data [][]byte
		for _, h := range hashes {
			b, _ := hex.DecodeString(h)
			data = append(data, b)
		}
		tree := crypto.NewMerkleTree(data)
		root := tree.GetRootHash()
		machineRoots[mid] = root

		fmt.Printf("Machine %s Root: %s (Votes: %d)\n", mid, root, len(hashes))

		bid := machineToBooth[mid]
		if bid == "" {
			bid = "Unknown"
		}
		boothMachineRoots[bid] = append(boothMachineRoots[bid], root)
	}

	// Compute Booth Roots
	var boothRoots []string
	for bid, roots := range boothMachineRoots {
		var data [][]byte
		for _, r := range roots {
			b, _ := hex.DecodeString(r)
			data = append(data, b)
		}
		tree := crypto.NewMerkleTree(data)
		root := tree.GetRootHash()
		fmt.Printf("Booth %s Root:   %s (Machines: %d)\n", bid, root, len(roots))
		boothRoots = append(boothRoots, root)
	}

	// Compute Election Root
	var electionRoot string
	if len(boothRoots) > 0 {
		var data [][]byte
		for _, r := range boothRoots {
			b, _ := hex.DecodeString(r)
			data = append(data, b)
		}
		tree := crypto.NewMerkleTree(data)
		electionRoot = tree.GetRootHash()
	}

	fmt.Printf("\nGLOBAL ELECTION MERKLE ROOT: %s\n", electionRoot)
}
