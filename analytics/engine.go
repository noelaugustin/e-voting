package analytics

import (
	"github.com/naugustin/e-voting/crypto"
	"github.com/naugustin/e-voting/vote"
)

// BoothAnalytics represents analytics for a specific booth
type BoothAnalytics struct {
	BoothID        string
	TotalVotes     int
	CandidateVotes map[string]int // candidateID -> count (after decryption)
}

// AggregatedVotes represents homomorphically aggregated votes
type AggregatedVotes struct {
	BoothID              string
	AggregatedCiphertext *crypto.ElGamalCiphertext
	VoteCount            int
}

// AnalyticsEngine provides booth-level analytics
type AnalyticsEngine struct {
	boothAnalytics  map[string]*BoothAnalytics
	aggregatedVotes map[string]*AggregatedVotes
}

// NewAnalyticsEngine creates a new analytics engine
func NewAnalyticsEngine() *AnalyticsEngine {
	return &AnalyticsEngine{
		boothAnalytics:  make(map[string]*BoothAnalytics),
		aggregatedVotes: make(map[string]*AggregatedVotes),
	}
}

// AggregateVotesByBooth aggregates encrypted votes by booth using homomorphic properties
func (ae *AnalyticsEngine) AggregateVotesByBooth(votes []*vote.EncryptedVote) {
	// Group votes by booth
	boothVotes := make(map[string][]*vote.EncryptedVote)
	for _, v := range votes {
		boothVotes[v.BoothID] = append(boothVotes[v.BoothID], v)
	}

	// Aggregate each booth's votes
	for boothID, voteList := range boothVotes {
		if len(voteList) == 0 {
			continue
		}

		// Note: For full homomorphic aggregation, we need the curve
		// In this simplified version, we just count votes
		// Production would aggregate using elliptic.P256()

		ae.aggregatedVotes[boothID] = &AggregatedVotes{
			BoothID:              boothID,
			AggregatedCiphertext: voteList[0].Ciphertext, // Simplified
			VoteCount:            len(voteList),
		}
	}
}

// GetBoothVoteCount returns the number of votes cast at a booth
func (ae *AnalyticsEngine) GetBoothVoteCount(boothID string) int {
	if agg, exists := ae.aggregatedVotes[boothID]; exists {
		return agg.VoteCount
	}
	return 0
}

// GetAllBoothCounts returns vote counts for all booths
func (ae *AnalyticsEngine) GetAllBoothCounts() map[string]int {
	counts := make(map[string]int)
	for boothID, agg := range ae.aggregatedVotes {
		counts[boothID] = agg.VoteCount
	}
	return counts
}

// CountVotesByCandidate counts votes for each candidate (requires decryption)
// This would be done by election authorities with decryption keys
// candidateList is the ordered list of candidates (index 0 = candidate index 1)
func (ae *AnalyticsEngine) CountVotesByCandidate(
	votes []*vote.EncryptedVote,
	decryptionFunc func(*crypto.ElGamalCiphertext) (int, error),
	candidateList []string,
) (map[string]int, error) {
	candidateCounts := make(map[string]int)

	for _, v := range votes {
		candidateIndex, err := decryptionFunc(v.Ciphertext)
		if err != nil {
			return nil, err
		}

		// Convert index (1-based) to candidate ID using the list
		if candidateIndex > 0 && candidateIndex <= len(candidateList) {
			candidateID := candidateList[candidateIndex-1]
			candidateCounts[candidateID]++
		}
	}

	return candidateCounts, nil
}

// CountVotesByCandidateAndBooth counts votes by candidate per booth
func (ae *AnalyticsEngine) CountVotesByCandidateAndBooth(
	votes []*vote.EncryptedVote,
	decryptionFunc func(*crypto.ElGamalCiphertext) (int, error),
) (map[string]map[string]int, error) {
	// boothID -> candidateID -> count
	boothCandidateCounts := make(map[string]map[string]int)

	for _, v := range votes {
		if _, exists := boothCandidateCounts[v.BoothID]; !exists {
			boothCandidateCounts[v.BoothID] = make(map[string]int)
		}

		candidateIndex, err := decryptionFunc(v.Ciphertext)
		if err != nil {
			return nil, err
		}

		// Convert index to candidate ID (simplified)
		candidateID := string(rune('A' + candidateIndex - 1))
		boothCandidateCounts[v.BoothID][candidateID]++
	}

	return boothCandidateCounts, nil
}

// GetBoothAnalytics returns analytics for a specific booth
func (ae *AnalyticsEngine) GetBoothAnalytics(boothID string) *BoothAnalytics {
	return ae.boothAnalytics[boothID]
}

// SetBoothAnalytics stores analytics for a booth (after counting)
func (ae *AnalyticsEngine) SetBoothAnalytics(boothID string, analytics *BoothAnalytics) {
	ae.boothAnalytics[boothID] = analytics
}

// GetTotalVotesAcrossBooths returns the total number of votes across all booths
func (ae *AnalyticsEngine) GetTotalVotesAcrossBooths() int {
	total := 0
	for _, agg := range ae.aggregatedVotes {
		total += agg.VoteCount
	}
	return total
}

// GetAggregatedVotes returns aggregated ciphertext for a booth
func (ae *AnalyticsEngine) GetAggregatedVotes(boothID string) *AggregatedVotes {
	return ae.aggregatedVotes[boothID]
}
