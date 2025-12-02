package crypto

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestGenerateThresholdKeys(t *testing.T) {
	k, n := 3, 5
	shares, publicInfo, err := GenerateThresholdKeys(k, n)

	if err != nil {
		t.Fatalf("Failed to generate threshold keys: %v", err)
	}

	if len(shares) != n {
		t.Errorf("Expected %d shares, got %d", n, len(shares))
	}

	if publicInfo.Threshold != k {
		t.Errorf("Expected threshold %d, got %d", k, publicInfo.Threshold)
	}

	if publicInfo.TotalShares != n {
		t.Errorf("Expected total shares %d, got %d", n, publicInfo.TotalShares)
	}

	// Verify all shares have correct indices
	for i, share := range shares {
		if share.Index != i+1 {
			t.Errorf("Share %d has incorrect index %d", i, share.Index)
		}

		if share.ShareValue == nil {
			t.Errorf("Share %d has nil value", i)
		}

		if share.PublicKey == nil {
			t.Errorf("Share %d has nil public key", i)
		}
	}

	// Verify verification points
	if len(publicInfo.VerificationPoints) != n {
		t.Errorf("Expected %d verification points, got %d", n, len(publicInfo.VerificationPoints))
	}
}

func TestThresholdKeysInvalidParameters(t *testing.T) {
	tests := []struct {
		k, n int
		desc string
	}{
		{5, 3, "k > n"},
		{0, 5, "k = 0"},
		{5, 0, "n = 0"},
		{-1, 5, "negative k"},
	}

	for _, tt := range tests {
		_, _, err := GenerateThresholdKeys(tt.k, tt.n)
		if err == nil {
			t.Errorf("Expected error for %s, got nil", tt.desc)
		}
	}
}

func TestPartialDecrypt(t *testing.T) {
	k, n := 3, 5
	shares, publicInfo, err := GenerateThresholdKeys(k, n)
	if err != nil {
		t.Fatalf("Failed to generate threshold keys: %v", err)
	}

	// Encrypt a vote
	voteChoice := 2
	ciphertext, _, err := EncryptVote(publicInfo.MasterPublicKey, voteChoice)
	if err != nil {
		t.Fatalf("Failed to encrypt vote: %v", err)
	}

	// Each authority performs partial decryption
	partials := make([]*PartialDecryptionShare, n)
	for i, share := range shares {
		partial, err := PartialDecrypt(share, ciphertext)
		if err != nil {
			t.Fatalf("Failed partial decryption for authority %d: %v", i, err)
		}

		if partial.AuthorityIndex != share.Index {
			t.Errorf("Partial has wrong index: expected %d, got %d", share.Index, partial.AuthorityIndex)
		}

		partials[i] = partial
	}

	// Verify all partials are well-formed
	curve := publicInfo.MasterPublicKey.Curve
	for i, partial := range partials {
		if !curve.IsOnCurve(partial.PartialPoint.X, partial.PartialPoint.Y) {
			t.Errorf("Partial %d point not on curve", i)
		}
	}
}

func TestCombinePartialDecryptions(t *testing.T) {
	k, n := 3, 5
	shares, publicInfo, err := GenerateThresholdKeys(k, n)
	if err != nil {
		t.Fatalf("Failed to generate threshold keys: %v", err)
	}

	tests := []struct {
		voteChoice int
		desc       string
	}{
		{0, "Candidate A (index 0)"},
		{1, "Candidate B (index 1)"},
		{2, "Candidate C (index 2)"},
	}

	for _, tt := range tests {
		// Encrypt vote
		ciphertext, _, err := EncryptVote(publicInfo.MasterPublicKey, tt.voteChoice)
		if err != nil {
			t.Fatalf("Failed to encrypt vote for %s: %v", tt.desc, err)
		}

		// Get partial decryptions from all authorities
		partials := make([]*PartialDecryptionShare, n)
		for i, share := range shares {
			partial, err := PartialDecrypt(share, ciphertext)
			if err != nil {
				t.Fatalf("Failed partial decryption for %s, authority %d: %v", tt.desc, i, err)
			}
			partials[i] = partial
		}

		// Combine using first k shares
		decrypted, err := CombinePartialDecryptions(partials[:k], ciphertext, publicInfo, 10)
		if err != nil {
			t.Fatalf("Failed to combine partials for %s: %v", tt.desc, err)
		}

		if decrypted != tt.voteChoice {
			t.Errorf("Decryption mismatch for %s: expected %d, got %d", tt.desc, tt.voteChoice, decrypted)
		}
	}
}

func TestThresholdRequirement(t *testing.T) {
	k, n := 5, 9
	shares, publicInfo, err := GenerateThresholdKeys(k, n)
	if err != nil {
		t.Fatalf("Failed to generate threshold keys: %v", err)
	}

	voteChoice := 1
	ciphertext, _, err := EncryptVote(publicInfo.MasterPublicKey, voteChoice)
	if err != nil {
		t.Fatalf("Failed to encrypt vote: %v", err)
	}

	// Get all partial decryptions
	allPartials := make([]*PartialDecryptionShare, n)
	for i, share := range shares {
		partial, err := PartialDecrypt(share, ciphertext)
		if err != nil {
			t.Fatalf("Failed partial decryption: %v", err)
		}
		allPartials[i] = partial
	}

	// Test with insufficient shares (k-1)
	_, err = CombinePartialDecryptions(allPartials[:k-1], ciphertext, publicInfo, 10)
	if err == nil {
		t.Error("Should fail with insufficient shares (k-1)")
	}

	// Test with exactly k shares (should succeed)
	decrypted, err := CombinePartialDecryptions(allPartials[:k], ciphertext, publicInfo, 10)
	if err != nil {
		t.Errorf("Failed with exactly k shares: %v", err)
	}
	if decrypted != voteChoice {
		t.Errorf("Expected %d, got %d with k shares", voteChoice, decrypted)
	}

	// Test with k+1 shares (should succeed)
	decrypted, err = CombinePartialDecryptions(allPartials[:k+1], ciphertext, publicInfo, 10)
	if err != nil {
		t.Errorf("Failed with k+1 shares: %v", err)
	}
	if decrypted != voteChoice {
		t.Errorf("Expected %d, got %d with k+1 shares", voteChoice, decrypted)
	}

	// Test with all n shares (should succeed)
	decrypted, err = CombinePartialDecryptions(allPartials, ciphertext, publicInfo, 10)
	if err != nil {
		t.Errorf("Failed with all shares: %v", err)
	}
	if decrypted != voteChoice {
		t.Errorf("Expected %d, got %d with all shares", voteChoice, decrypted)
	}
}

func TestDifferentShareCombinations(t *testing.T) {
	k, n := 3, 5
	shares, publicInfo, err := GenerateThresholdKeys(k, n)
	if err != nil {
		t.Fatalf("Failed to generate threshold keys: %v", err)
	}

	voteChoice := 2
	ciphertext, _, err := EncryptVote(publicInfo.MasterPublicKey, voteChoice)
	if err != nil {
		t.Fatalf("Failed to encrypt vote: %v", err)
	}

	// Get all partial decryptions
	allPartials := make([]*PartialDecryptionShare, n)
	for i, share := range shares {
		partial, err := PartialDecrypt(share, ciphertext)
		if err != nil {
			t.Fatalf("Failed partial decryption: %v", err)
		}
		allPartials[i] = partial
	}

	// Test different combinations of k shares
	// Combination 1: shares 0,1,2
	decrypted, err := CombinePartialDecryptions(allPartials[0:3], ciphertext, publicInfo, 10)
	if err != nil || decrypted != voteChoice {
		t.Errorf("Failed with shares 0,1,2: %v, decrypted=%d", err, decrypted)
	}

	// Combination 2: shares 1,2,3
	decrypted, err = CombinePartialDecryptions(allPartials[1:4], ciphertext, publicInfo, 10)
	if err != nil || decrypted != voteChoice {
		t.Errorf("Failed with shares 1,2,3: %v, decrypted=%d", err, decrypted)
	}

	// Combination 3: shares 0,2,4
	partialsCombination := []*PartialDecryptionShare{allPartials[0], allPartials[2], allPartials[4]}
	decrypted, err = CombinePartialDecryptions(partialsCombination, ciphertext, publicInfo, 10)
	if err != nil || decrypted != voteChoice {
		t.Errorf("Failed with shares 0,2,4: %v, decrypted=%d", err, decrypted)
	}
}

func TestVerifyPartialDecryption(t *testing.T) {
	k, n := 3, 5
	shares, publicInfo, err := GenerateThresholdKeys(k, n)
	if err != nil {
		t.Fatalf("Failed to generate threshold keys: %v", err)
	}

	voteChoice := 1
	ciphertext, _, err := EncryptVote(publicInfo.MasterPublicKey, voteChoice)
	if err != nil {
		t.Fatalf("Failed to encrypt vote: %v", err)
	}

	// Generate valid partial decryption
	partial, err := PartialDecrypt(shares[0], ciphertext)
	if err != nil {
		t.Fatalf("Failed partial decryption: %v", err)
	}

	// Verify it
	valid := VerifyPartialDecryption(partial, ciphertext, publicInfo)
	if !valid {
		t.Error("Valid partial decryption failed verification")
	}

	// Test with invalid authority index
	invalidPartial := &PartialDecryptionShare{
		AuthorityIndex: 0, // Invalid (should be 1 to n)
		PartialPoint:   partial.PartialPoint,
	}
	valid = VerifyPartialDecryption(invalidPartial, ciphertext, publicInfo)
	if valid {
		t.Error("Should reject partial with invalid authority index")
	}

	// Test with out-of-range index
	invalidPartial2 := &PartialDecryptionShare{
		AuthorityIndex: n + 1, // Out of range
		PartialPoint:   partial.PartialPoint,
	}
	valid = VerifyPartialDecryption(invalidPartial2, ciphertext, publicInfo)
	if valid {
		t.Error("Should reject partial with out-of-range index")
	}

	// Test with point not on curve
	invalidPartial3 := &PartialDecryptionShare{
		AuthorityIndex: 1,
		PartialPoint:   Point{X: big.NewInt(123), Y: big.NewInt(456)}, // Not on curve
	}
	valid = VerifyPartialDecryption(invalidPartial3, ciphertext, publicInfo)
	if valid {
		t.Error("Should reject partial with point not on curve")
	}
}

func TestEvaluatePolynomial(t *testing.T) {
	curve := elliptic.P256()
	N := curve.Params().N

	// f(x) = 5 + 3x + 2x^2
	coeffs := []*big.Int{
		big.NewInt(5),
		big.NewInt(3),
		big.NewInt(2),
	}

	// f(0) = 5
	result := evaluatePolynomial(coeffs, big.NewInt(0), N)
	expected := big.NewInt(5)
	if result.Cmp(expected) != 0 {
		t.Errorf("f(0): expected %s, got %s", expected, result)
	}

	// f(1) = 5 + 3 + 2 = 10
	result = evaluatePolynomial(coeffs, big.NewInt(1), N)
	expected = big.NewInt(10)
	if result.Cmp(expected) != 0 {
		t.Errorf("f(1): expected %s, got %s", expected, result)
	}

	// f(2) = 5 + 6 + 8 = 19
	result = evaluatePolynomial(coeffs, big.NewInt(2), N)
	expected = big.NewInt(19)
	if result.Cmp(expected) != 0 {
		t.Errorf("f(2): expected %s, got %s", expected, result)
	}
}

func TestLagrangeCoefficient(t *testing.T) {
	curve := elliptic.P256()
	N := curve.Params().N

	// Indices: 1, 2, 3
	indices := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}

	// Calculate all Lagrange coefficients at x=0
	// λ_0(0) = (0-2)(0-3) / (1-2)(1-3) = 6 / 2 = 3
	// λ_1(0) = (0-1)(0-3) / (2-1)(2-3) = 3 / -1 = -3
	// λ_2(0) = (0-1)(0-2) / (3-1)(3-2) = 2 / 2 = 1

	lambda0 := lagrangeCoefficient(0, indices, N)
	lambda1 := lagrangeCoefficient(1, indices, N)
	lambda2 := lagrangeCoefficient(2, indices, N)

	// Verify they sum to 1 (mod N)
	// 3 + (-3) + 1 = 1
	sum := new(big.Int).Add(lambda0, lambda1)
	sum.Add(sum, lambda2)
	sum.Mod(sum, N)

	if sum.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("Lagrange coefficients should sum to 1, got %s", sum)
	}
}

// Benchmark threshold key generation
func BenchmarkGenerateThresholdKeys(b *testing.B) {
	k, n := 5, 9
	for i := 0; i < b.N; i++ {
		_, _, _ = GenerateThresholdKeys(k, n)
	}
}

// Benchmark partial decryption
func BenchmarkPartialDecrypt(b *testing.B) {
	k, n := 5, 9
	shares, publicInfo, _ := GenerateThresholdKeys(k, n)
	ciphertext, _, _ := EncryptVote(publicInfo.MasterPublicKey, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = PartialDecrypt(shares[0], ciphertext)
	}
}

// Benchmark combining partial decryptions
func BenchmarkCombinePartialDecryptions(b *testing.B) {
	k, n := 5, 9
	shares, publicInfo, _ := GenerateThresholdKeys(k, n)
	ciphertext, _, _ := EncryptVote(publicInfo.MasterPublicKey, 1)

	partials := make([]*PartialDecryptionShare, k)
	for i := 0; i < k; i++ {
		partials[i], _ = PartialDecrypt(shares[i], ciphertext)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CombinePartialDecryptions(partials, ciphertext, publicInfo, 10)
	}
}
