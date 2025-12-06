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

func handleBoothCommand(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: evoting-cli booth <subcommand> [args]")
		fmt.Println("Subcommands: create, add-machine, list")
		os.Exit(1)
	}

	switch args[0] {
	case "create":
		createBooth(args[1:])
	case "add-machine":
		addMachine(args[1:])
	case "list":
		listBooths()
	default:
		fmt.Printf("Unknown booth subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func createBooth(args []string) {
	cmd := flag.NewFlagSet("create", flag.ExitOnError)
	id := cmd.String("id", "", "Booth ID")
	location := cmd.String("location", "Default Location", "Physical location of the booth")
	cmd.Parse(args)

	if *id == "" {
		fmt.Println("Error: --id is required")
		cmd.Usage()
		os.Exit(1)
	}

	// Load existing booths
	var booths []BoothData
	loadJSON(BoothsFile, &booths) // error ignored (file might not exist)

	// Check for duplicate
	for _, b := range booths {
		if b.ID == *id {
			fmt.Printf("Error: Booth '%s' already exists\n", *id)
			os.Exit(1)
		}
	}

	// 1. Generate Booth Keys
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error generating booth keys: %v\n", err)
		os.Exit(1)
	}

	privStr := keyPair.PrivateKey.D.String()
	pubStr := fmt.Sprintf("%064x%064x", keyPair.PublicKey.X, keyPair.PublicKey.Y)

	// 2. Load Admin Key to sign Booth Identity
	var adminKey AdminKeyData
	if err := loadJSON(AdminKeysFile, &adminKey); err != nil {
		fmt.Println("Error: Could not load Admin Keys. Is the election created?")
		os.Exit(1)
	}

	adminPrivInt := new(big.Int)
	adminPrivInt.SetString(adminKey.PrivateKey, 10)
	adminPrivKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()},
		D:         adminPrivInt,
	}
	// Reconstruct Admin Public Key point for completeness (not strictly needed for signing)
	adminPrivKey.PublicKey.X, adminPrivKey.PublicKey.Y = elliptic.P256().ScalarBaseMult(adminPrivInt.Bytes())

	// Sign Booth Public Key with Admin Private Key
	r, s, err := crypto.SignData(adminPrivKey, []byte(pubStr))
	if err != nil {
		fmt.Printf("Error signing Booth Identity: %v\n", err)
		os.Exit(1)
	}
	adminSig := fmt.Sprintf("%x,%x", r, s)

	// 3. Save Private Key
	var boothKeys []BoothKeyData
	loadJSON(BoothKeysFile, &boothKeys) // ignore error
	boothKeys = append(boothKeys, BoothKeyData{
		ID:         *id,
		PrivateKey: privStr,
		PublicKey:  pubStr,
	})
	if err := saveJSON(BoothKeysFile, boothKeys); err != nil {
		fmt.Printf("Error saving booth keys: %v\n", err)
		os.Exit(1)
	}

	newBooth := BoothData{
		ID:             *id,
		Location:       *location,
		PublicKey:      pubStr,
		AdminSignature: adminSig,
		Machines:       []string{},
	}

	booths = append(booths, newBooth)
	if err := saveJSON(BoothsFile, booths); err != nil {
		fmt.Printf("Error saving booth: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Booth '%s' created at '%s' (Identity Signed by Election).\n", *id, *location)
}

func addMachine(args []string) {
	cmd := flag.NewFlagSet("add-machine", flag.ExitOnError)
	boothID := cmd.String("booth", "", "Booth ID to add machine to")
	machineID := cmd.String("id", "", "Machine ID")
	cmd.Parse(args)

	if *boothID == "" || *machineID == "" {
		fmt.Println("Error: --booth and --id (machine) are required")
		cmd.Usage()
		os.Exit(1)
	}

	// Load booths
	var booths []BoothData
	if err := loadJSON(BoothsFile, &booths); err != nil {
		fmt.Printf("Error loading booths: %v\n", err)
		os.Exit(1)
	}

	// Find booth
	var targetBooth *BoothData
	for i := range booths {
		if booths[i].ID == *boothID {
			targetBooth = &booths[i]
			break
		}
	}

	if targetBooth == nil {
		fmt.Printf("Error: Booth '%s' not found\n", *boothID)
		os.Exit(1)
	}

	// Check if machine ID exists globally (optional, but good practice)
	for _, m := range targetBooth.Machines {
		if m == *machineID {
			fmt.Printf("Error: Machine '%s' already exists in booth '%s'\n", *machineID, *boothID)
			os.Exit(1)
		}
	}

	// Generate Machine Key Pair
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error generating machine keys: %v\n", err)
		os.Exit(1)
	}

	privStr := keyPair.PrivateKey.D.String()
	pubStr := fmt.Sprintf("%064x%064x", keyPair.PublicKey.X, keyPair.PublicKey.Y)

	// Sign Machine Identity with Booth Key
	// Load Booth Private Key
	var boothKeys []BoothKeyData
	if err := loadJSON(BoothKeysFile, &boothKeys); err != nil {
		fmt.Println("Error: Booth Private Keys not found.")
		os.Exit(1)
	}
	var boothPrivKey *ecdsa.PrivateKey
	for _, bk := range boothKeys {
		if bk.ID == *boothID {
			d := new(big.Int)
			d.SetString(bk.PrivateKey, 10)
			boothPrivKey = &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()},
				D:         d,
			}
			boothPrivKey.PublicKey.X, boothPrivKey.PublicKey.Y = elliptic.P256().ScalarBaseMult(d.Bytes())
			break
		}
	}

	if boothPrivKey == nil {
		fmt.Printf("Error: Private key for Booth '%s' not found.\n", *boothID)
		os.Exit(1)
	}

	r, s, err := crypto.SignData(boothPrivKey, []byte(pubStr))
	if err != nil {
		fmt.Printf("Error signing Machine Identity: %v\n", err)
		os.Exit(1)
	}
	boothSig := fmt.Sprintf("%x,%x", r, s)

	// Save Public Machine Data (Registry)
	var machines []MachineData
	loadJSON(MachinesFile, &machines) // ignore error
	machines = append(machines, MachineData{
		ID:             *machineID,
		BoothID:        *boothID,
		IsActive:       true,
		PublicKey:      pubStr,
		BoothSignature: boothSig,
	})
	if err := saveJSON(MachinesFile, machines); err != nil {
		fmt.Printf("Error saving machine public registry: %v\n", err)
		os.Exit(1)
	}

	// Save Machine Keys (Simulated "Secure Enclave" or local storage)
	var machineKeys []MachineKeyData
	loadJSON(MachineKeysFile, &machineKeys) // ignore error
	machineKeys = append(machineKeys, MachineKeyData{
		ID:         *machineID,
		PrivateKey: privStr,
		PublicKey:  pubStr,
	})
	if err := saveJSON(MachineKeysFile, machineKeys); err != nil {
		fmt.Printf("Error saving machine keys: %v\n", err)
		os.Exit(1)
	}

	// Update booth list
	targetBooth.Machines = append(targetBooth.Machines, *machineID)

	if err := saveJSON(BoothsFile, booths); err != nil {
		fmt.Printf("Error saving booths: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Machine '%s' added to booth '%s' with cryptographic binding.\n", *machineID, *boothID)
}

func listBooths() {
	var booths []BoothData
	if err := loadJSON(BoothsFile, &booths); err != nil {
		fmt.Println("No booths found.")
		return
	}

	fmt.Println("Booths:")
	fmt.Println("-------")
	for _, b := range booths {
		fmt.Printf("ID: %s | Location: %s | Machines: %v\n", b.ID, b.Location, b.Machines)
	}
}
