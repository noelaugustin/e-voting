package api

// Request types

type CreateElectionRequest struct {
	Name string `json:"name"`
	K    int    `json:"k"` // Threshold
	N    int    `json:"n"` // Total authorities
}

type RegisterCandidateRequest struct {
	CandidateID string `json:"candidateId"`
}

type RegisterVoterRequest struct {
	VoterID string `json:"voterId"`
	BoothID string `json:"boothId"`
}

type CastVoteRequest struct {
	VoterID     string `json:"voterId"`
	VotingToken string `json:"votingToken"`
	CandidateID string `json:"candidateId"`
}

type VerifyVoteRequest struct {
	VoterID string `json:"voterId"`
	Secret  string `json:"secret"`
}

type SubmitPartialRequest struct {
	RequestID      string `json:"requestId"`
	AuthorityIndex int    `json:"authorityIndex"`
}

// Response types

type CreateElectionResponse struct {
	ElectionID          string          `json:"electionId"`
	Threshold           int             `json:"threshold"`
	TotalAuthorities    int             `json:"totalAuthorities"`
	MasterPublicKeyHash string          `json:"masterPublicKeyHash"`
	Authorities         []AuthorityInfo `json:"authorities"`
}

type AuthorityInfo struct {
	Index                 int    `json:"index"`
	Name                  string `json:"name"`
	VerificationPointHash string `json:"verificationPointHash"`
}

type RegisterVoterResponse struct {
	VoterID     string `json:"voterId"`
	BoothID     string `json:"boothId"`
	VotingToken string `json:"votingToken"`
	CanVote     bool   `json:"canVote"`
}

type CastVoteResponse struct {
	VoteID     string `json:"voteId"`
	Commitment string `json:"commitment"`
	Secret     string `json:"secret"`
	Timestamp  string `json:"timestamp"`
}

type VerifyVoteResponse struct {
	Valid       bool   `json:"valid"`
	CandidateID string `json:"candidateId,omitempty"`
	BoothID     string `json:"boothId,omitempty"`
	Error       string `json:"error,omitempty"` // Reason for verification failure
}

type InitiateCountResponse struct {
	Status              string `json:"status"`
	RequestID           string `json:"requestId"`
	AwaitingAuthorities []int  `json:"awaitingAuthorities"`
}

type SubmitPartialResponse struct {
	Accepted             bool  `json:"accepted"`
	ProofValid           bool  `json:"proofValid"`
	RemainingAuthorities []int `json:"remainingAuthorities"`
}

type CountStatusResponse struct {
	Status              string         `json:"status"`
	AwaitingAuthorities []int          `json:"awaitingAuthorities"`
	RejectedAuthorities []int          `json:"rejectedAuthorities"`
	Results             map[string]int `json:"results,omitempty"`
}

type ElectionInfoResponse struct {
	Name                string   `json:"name"`
	Status              string   `json:"status"`
	Threshold           int      `json:"threshold"`
	TotalAuthorities    int      `json:"totalAuthorities"`
	MasterPublicKeyHash string   `json:"masterPublicKeyHash"`
	Candidates          []string `json:"candidates"`
	TotalVoters         int      `json:"totalVoters"`
	VotesCast           int      `json:"votesCast"`
}

type CandidateInfo struct {
	CandidateID string `json:"candidateId"`
	Index       int    `json:"index"`
	ProofHash   string `json:"proofHash"` // Proof of valid candidate
}

type AuthorityProofResponse struct {
	AuthorityIndex        int    `json:"authorityIndex"`
	Name                  string `json:"name"`
	VerificationPointHash string `json:"verificationPointHash"`
	ProofHash             string `json:"proofHash"` // ZKP that authority holds key share
}

type CandidateProofResponse struct {
	CandidateID string `json:"candidateId"`
	ProofHash   string `json:"proofHash"`
	Valid       bool   `json:"valid"`
}

type VoterProofResponse struct {
	VoterID   string `json:"voterId"`
	BoothID   string `json:"boothId"`
	ProofHash string `json:"proofHash"`
	Valid     bool   `json:"valid"`
}

// Audit and verification types

type MerkleTreeNode struct {
	Hash  string `json:"hash"`
	Left  string `json:"left,omitempty"`
	Right string `json:"right,omitempty"`
}

type PublishedVoteInfo struct {
	VoteID          string   `json:"voteId"`
	BoothID         string   `json:"boothId"`
	Timestamp       string   `json:"timestamp"`
	CiphertextHash  string   `json:"ciphertextHash"`
	VoterCommitment string   `json:"voterCommitment"`
	ProofHash       string   `json:"proofHash"`
	MerkleProof     []string `json:"merkleProof"` // Hashes to prove inclusion
}

type AuditPackageResponse struct {
	ElectionID          string              `json:"electionId"`
	ElectionName        string              `json:"electionName"`
	Status              string              `json:"status"`
	Threshold           int                 `json:"threshold"`
	TotalAuthorities    int                 `json:"totalAuthorities"`
	MasterPublicKeyHash string              `json:"masterPublicKeyHash"`
	MerkleRoot          string              `json:"merkleRoot"`
	Candidates          []CandidateInfo     `json:"candidates"`
	PublishedVotes      []PublishedVoteInfo `json:"publishedVotes"`
	Results             map[string]int      `json:"results,omitempty"`
	TotalVotes          int                 `json:"totalVotes"`
	GeneratedAt         string              `json:"generatedAt"`
}

type VerifyMyVoteRequest struct {
	VoterID string `json:"voterId"`
	Secret  string `json:"secret"`
}

type VerifyMyVoteResponse struct {
	Found          bool     `json:"found"`
	Valid          bool     `json:"valid"`
	CandidateID    string   `json:"candidateId,omitempty"`
	VoteID         string   `json:"voteId,omitempty"`
	MerkleIncluded bool     `json:"merkleIncluded"`
	MerkleProof    []string `json:"merkleProof,omitempty"`
	Error          string   `json:"error,omitempty"`
}
