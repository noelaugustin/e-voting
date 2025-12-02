package main

import (
	"log"
	"net/http"

	"github.com/naugustin/e-voting/api"
)

func main() {
	state := api.NewServerState()

	// Election endpoints
	http.HandleFunc("/api/election", state.CreateElectionHandler)
	http.HandleFunc("/api/election/info", state.GetElectionHandler)

	// Candidate endpoints
	http.HandleFunc("/api/candidates", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			state.RegisterCandidateHandler(w, r)
		} else if r.Method == http.MethodGet {
			state.GetCandidatesHandler(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	http.HandleFunc("/api/candidates/proof", state.GetCandidateProofHandler)

	// Voter endpoints
	http.HandleFunc("/api/voters", state.RegisterVoterHandler)
	http.HandleFunc("/api/voters/proof", state.GetVoterProofHandler)

	// Authority endpoints
	http.HandleFunc("/api/authorities", state.GetAuthoritiesHandler)
	http.HandleFunc("/api/authorities/proof", state.GetAuthorityProofHandler)

	// Vote endpoints
	http.HandleFunc("/api/votes", state.CastVoteHandler)
	http.HandleFunc("/api/votes/verify", state.VerifyVoteHandler)

	// Counting endpoints
	http.HandleFunc("/api/count/initiate", state.InitiateCountHandler)
	http.HandleFunc("/api/count/partial", state.SubmitPartialHandler)
	http.HandleFunc("/api/count/status", state.GetCountStatusHandler)

	// Audit and verification endpoints
	http.HandleFunc("/api/audit/package", state.GetAuditPackageHandler)
	http.HandleFunc("/api/audit/verify-my-vote", state.VerifyMyVoteHandler)
	http.HandleFunc("/api/audit/merkle-root", state.GetMerkleRootHandler)

	// Serve static web files
	fs := http.FileServer(http.Dir("./web"))
	http.Handle("/", fs)

	log.Println("🗳️  E-Voting Server starting on http://localhost:8080")
	log.Println("📊 Web interface: http://localhost:8080")
	log.Println("🔌 API endpoint: http://localhost:8080/api")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
