package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/naugustin/e-voting/crypto"
)

func handleVoterCommand(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: evoting-cli voter <subcommand> [args]")
		fmt.Println("Subcommands: add, freeze")
		os.Exit(1)
	}

	switch args[0] {
	case "add":
		addVoter(args[1:])
	case "freeze":
		freezeVoters()
	default:
		fmt.Printf("Unknown voter subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func addVoter(args []string) {
	addCmd := flag.NewFlagSet("add", flag.ExitOnError)
	id := addCmd.String("id", "", "Voter ID")
	booth := addCmd.String("booth", "", "Booth ID")
	addCmd.Parse(args)

	if *id == "" || *booth == "" {
		fmt.Println("Error: --id and --booth are required")
		addCmd.Usage()
		os.Exit(1)
	}

	// Load existing voters
	var voters []VoterData
	loadJSON(VotersFile, &voters) // Ignore error if file doesn't exist

	// Check for duplicates
	for _, v := range voters {
		if v.ID == *id {
			fmt.Printf("Error: Voter %s already exists\n", *id)
			os.Exit(1)
		}
	}

	// Generate voter keys
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error generating voter keys: %v\n", err)
		os.Exit(1)
	}

	voter := VoterData{
		ID:          *id,
		BoothID:     *booth,
		PublicKey:   fmt.Sprintf("%x%x", keyPair.PublicKey.X, keyPair.PublicKey.Y),
		PrivateKey:  keyPair.PrivateKey.D.String(), // Save private key for demo
		VotingToken: "demo-token-" + *id,           // Simplified token
	}

	voters = append(voters, voter)

	if err := saveJSON(VotersFile, voters); err != nil {
		fmt.Printf("Error saving voter: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Voter %s added to booth %s.\n", *id, *booth)
}

func freezeVoters() {
	fmt.Println("Freezing voter list... (Not implemented in demo)")
}
