package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/naugustin/e-voting/authority"
)

func handleElectionCommand(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: evoting-cli election <subcommand> [args]")
		fmt.Println("Subcommands: create, reset")
		os.Exit(1)
	}

	switch args[0] {
	case "create":
		createElection(args[1:])
	case "reset":
		resetElectionCLI()
	default:
		fmt.Printf("Unknown election subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func createElection(args []string) {
	createCmd := flag.NewFlagSet("create", flag.ExitOnError)
	name := createCmd.String("name", "Demo Election", "Name of the election")
	candidates := createCmd.String("candidates", "Alice,Bob,Charlie", "Comma-separated list of candidates")
	n := createCmd.Int("n", 0, "Total number of authorities (required)")
	k := createCmd.Int("k", 0, "Threshold number of authorities (required)")
	createCmd.Parse(args)

	if *n == 0 || *k == 0 {
		fmt.Println("Error: --n and --k are required")
		createCmd.Usage()
		os.Exit(1)
	}

	if *k > *n {
		fmt.Printf("Error: Threshold k=%d cannot be greater than total authorities n=%d\n", *k, *n)
		os.Exit(1)
	}

	// Ensure data directory exists
	sm := NewStateManager()
	if err := sm.EnsureDataDir(); err != nil {
		fmt.Printf("Error creating data dir: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generating threshold keys (k=%d, n=%d)...\n", *k, *n)

	// Generate keys using authority package
	registry, err := authority.NewAuthorityRegistry(*k, *n)
	if err != nil {
		fmt.Printf("Error generating keys: %v\n", err)
		os.Exit(1)
	}

	// Update authorities with new keys and save private keys
	activeAuths := registry.GetActiveAuthorities()
	var updatedAuths []AuthorityData
	var keyData []AuthorityKeyData

	// We need to capture the Master Public Key
	var masterPubKey string

	for i, auth := range activeAuths {
		pubKeyStr := fmt.Sprintf("%064x%064x", auth.KeyShare.PublicKey.X, auth.KeyShare.PublicKey.Y)
		if i == 0 {
			masterPubKey = pubKeyStr
		}

		updatedAuths = append(updatedAuths, AuthorityData{
			ID:        auth.KeyShare.Index,
			PublicKey: pubKeyStr,
		})

		// Serialize private key share
		keyData = append(keyData, AuthorityKeyData{
			ID:         auth.KeyShare.Index,
			PrivateKey: auth.KeyShare.ShareValue.String(),
		})
	}

	// Save updated authorities
	if err := saveJSON(AuthoritiesFile, updatedAuths); err != nil {
		fmt.Printf("Error updating authorities: %v\n", err)
		os.Exit(1)
	}

	// Save private keys (for demo/decryption)
	if err := saveJSON(AuthorityKeysFile, keyData); err != nil {
		fmt.Printf("Error saving authority keys: %v\n", err)
		os.Exit(1)
	}

	election := ElectionData{
		Name:            *name,
		K:               *k,
		N:               *n,
		Candidates:      strings.Split(*candidates, ","),
		IsPublished:     false,
		MasterPublicKey: masterPubKey,
	}

	if err := saveJSON(ElectionFile, election); err != nil {
		fmt.Printf("Error saving election: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Election '%s' created with %d candidates and %d authorities.\n", election.Name, len(election.Candidates), election.N)
	fmt.Printf("Master Public Key: %s...\n", masterPubKey[:20])
}

func resetElectionCLI() {
	fmt.Print("Are you sure you want to reset ALL election data? (y/N): ")
	var response string
	fmt.Scanln(&response)

	if strings.ToLower(response) != "y" {
		fmt.Println("Reset cancelled.")
		return
	}

	sm := NewStateManager()
	if err := sm.Reset(); err != nil {
		fmt.Printf("Error resetting data: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Election data reset successfully.")
}
