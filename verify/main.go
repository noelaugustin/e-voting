package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/naugustin/e-voting/api"
)

const DefaultServerURL = "http://localhost:8080"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	command := os.Args[1]
	serverURL := getEnv("EVOTING_SERVER", DefaultServerURL)
	switch command {
	case "download":
		downloadAuditPackage(serverURL)
	case "verify":
		if len(os.Args) < 4 {
			fmt.Println("Usage: evoting-verify verify <voterId> <secret>")
			os.Exit(1)
		}
		verifyMyVote(os.Args[2], os.Args[3], serverURL)
	case "info":
		if len(os.Args) < 3 {
			fmt.Println("Usage: evoting-verify info <file>")
			os.Exit(1)
		}
		showInfo(os.Args[2])
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("E-Voting Verification Tool")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  download              - Download audit package")
	fmt.Println("  verify <id> <secret>  - Verify vote online")
	fmt.Println("  info <file>           - Show package info")
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func downloadAuditPackage(serverURL string) {
	fmt.Println("📦 Downloading audit package...")
	resp, err := http.Get(serverURL + "/api/audit/package")
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("❌ Server error: %d\n", resp.StatusCode)
		os.Exit(1)
	}
	body, _ := io.ReadAll(resp.Body)
	filename := "audit-package.json"
	os.WriteFile(filename, body, 0644)
	var pkg api.AuditPackageResponse
	json.Unmarshal(body, &pkg)
	fmt.Printf("✅ Downloaded: %s\n", filename)
	fmt.Printf("   Election: %s\n", pkg.ElectionName)
	fmt.Printf("   Total Votes: %d\n", pkg.TotalVotes)
}

func verifyMyVote(voterID, secret, serverURL string) {
	fmt.Printf("🔍 Verifying vote for '%s'...\n", voterID)
	reqBody := api.VerifyMyVoteRequest{VoterID: voterID, Secret: secret}
	jsonData, _ := json.Marshal(reqBody)
	resp, err := http.Post(serverURL+"/api/audit/verify-my-vote", "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result api.VerifyMyVoteResponse
	json.Unmarshal(body, &result)
	if !result.Found {
		fmt.Printf("❌ Not found: %s\n", result.Error)
		os.Exit(1)
	}
	if !result.Valid {
		fmt.Printf("❌ Invalid: %s\n", result.Error)
		os.Exit(1)
	}
	fmt.Println("✅ Vote verified!")
	fmt.Printf("   Candidate: %s\n", result.CandidateID)
	fmt.Printf("   Merkle Proof: %d hashes\n", len(result.MerkleProof))
}

func showInfo(filename string) {
	data, _ := os.ReadFile(filename)
	var pkg api.AuditPackageResponse
	json.Unmarshal(data, &pkg)
	fmt.Println("📦 AUDIT PACKAGE")
	fmt.Printf("Election: %s\n", pkg.ElectionName)
	fmt.Printf("Status: %s\n", pkg.Status)
	fmt.Printf("Total Votes: %d\n", pkg.TotalVotes)
	if len(pkg.Results) > 0 {
		fmt.Println("\nResults:")
		for candidate, votes := range pkg.Results {
			fmt.Printf("  %s: %d votes\n", candidate, votes)
		}
	}
}
