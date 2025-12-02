package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// ThresholdKeyShare represents one authority's share of the threshold key
type ThresholdKeyShare struct {
	Index      int              // Share index (1 to n)
	ShareValue *big.Int         // The secret share value
	PublicKey  *ecdsa.PublicKey // Master public key (same for all shares)
}

// DiscreteLogEqualityProof proves that log_G(VerificationPoint) == log_C1(Partial)
// Uses Chaum-Pedersen protocol for non-interactive zero-knowledge proof
type DiscreteLogEqualityProof struct {
	Commitment1 Point    // t1 = r * G
	Commitment2 Point    // t2 = r * C1
	Challenge   *big.Int // c = Hash(G, C1, VerificationPoint, Partial, t1, t2)
	Response    *big.Int // s = r - c * share_i
}

// PartialDecryptionShare represents a partial decryption by one authority
type PartialDecryptionShare struct {
	AuthorityIndex int                       // Which authority provided this
	PartialPoint   Point                     // The partial decryption: shareValue * C1
	Proof          *DiscreteLogEqualityProof // Proof of correctness
}

// ThresholdPublicInfo contains public information about the threshold scheme
type ThresholdPublicInfo struct {
	Threshold          int              // k: minimum shares needed
	TotalShares        int              // n: total shares created
	MasterPublicKey    *ecdsa.PublicKey // Master public key
	VerificationPoints []Point          // Public verification points for each share
}

// GenerateThresholdKeys splits a master private key into n shares
// requiring k shares to decrypt. Uses Shamir's Secret Sharing.
//
// Returns:
// - shares: n key shares to distribute to authorities
// - publicInfo: public parameters for verification
func GenerateThresholdKeys(k, n int) ([]*ThresholdKeyShare, *ThresholdPublicInfo, error) {
	if k > n {
		return nil, nil, errors.New("threshold k must be <= total shares n")
	}
	if k < 1 || n < 1 {
		return nil, nil, errors.New("k and n must be positive")
	}

	curve := elliptic.P256()

	// Generate master private key (this is a_0 in the polynomial)
	masterPrivateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Generate polynomial coefficients: f(x) = a_0 + a_1*x + ... + a_{k-1}*x^{k-1}
	// a_0 is the master private key, others are random
	coefficients := make([]*big.Int, k)
	coefficients[0] = masterPrivateKey.D // Secret is the constant term

	for i := 1; i < k; i++ {
		coeff, err := rand.Int(rand.Reader, curve.Params().N)
		if err != nil {
			return nil, nil, err
		}
		coefficients[i] = coeff
	}

	// Generate n shares by evaluating polynomial at points 1, 2, ..., n
	shares := make([]*ThresholdKeyShare, n)
	verificationPoints := make([]Point, n)

	for i := 1; i <= n; i++ {
		// Evaluate f(i) mod N
		x := big.NewInt(int64(i))
		shareValue := evaluatePolynomial(coefficients, x, curve.Params().N)

		shares[i-1] = &ThresholdKeyShare{
			Index:      i,
			ShareValue: shareValue,
			PublicKey:  &masterPrivateKey.PublicKey,
		}

		// Create verification point: shareValue * G
		// This allows public verification that partial decryptions are correct
		vx, vy := curve.ScalarBaseMult(shareValue.Bytes())
		verificationPoints[i-1] = Point{X: vx, Y: vy}
	}

	publicInfo := &ThresholdPublicInfo{
		Threshold:          k,
		TotalShares:        n,
		MasterPublicKey:    &masterPrivateKey.PublicKey,
		VerificationPoints: verificationPoints,
	}

	return shares, publicInfo, nil
}

// PartialDecrypt performs partial decryption using one authority's share
// Returns: shareValue * C1 with zero-knowledge proof of correctness
func PartialDecrypt(share *ThresholdKeyShare, ciphertext *ElGamalCiphertext) (*PartialDecryptionShare, error) {
	if share == nil || ciphertext == nil {
		return nil, errors.New("share and ciphertext must not be nil")
	}

	curve := share.PublicKey.Curve

	// Compute partial decryption: shareValue * C1
	partialX, partialY := curve.ScalarMult(ciphertext.C1.X, ciphertext.C1.Y, share.ShareValue.Bytes())
	partial := Point{X: partialX, Y: partialY}

	// Generate verification point for this share: share * G
	verificationX, verificationY := curve.ScalarBaseMult(share.ShareValue.Bytes())
	verificationPoint := Point{X: verificationX, Y: verificationY}

	// Generate zero-knowledge proof that log_G(verificationPoint) == log_C1(partial)
	proof, err := generateDiscreteLogEqualityProof(share.ShareValue, ciphertext.C1, verificationPoint, partial, curve)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %w", err)
	}

	return &PartialDecryptionShare{
		AuthorityIndex: share.Index,
		PartialPoint:   partial,
		Proof:          proof,
	}, nil
}

// CombinePartialDecryptions combines k partial decryptions to recover the plaintext
// Using Lagrange interpolation to reconstruct shareValue_1*C1 + ... + shareValue_k*C1
// which equals (secret * C1) due to polynomial reconstruction
func CombinePartialDecryptions(
	partials []*PartialDecryptionShare,
	ciphertext *ElGamalCiphertext,
	publicInfo *ThresholdPublicInfo,
	maxChoice int,
) (int, error) {
	if len(partials) < publicInfo.Threshold {
		return -1, fmt.Errorf("need at least %d shares, got %d", publicInfo.Threshold, len(partials))
	}

	// Use only first k shares
	k := publicInfo.Threshold
	partials = partials[:k]

	curve := publicInfo.MasterPublicKey.Curve
	N := curve.Params().N

	// Extract indices for Lagrange interpolation
	indices := make([]*big.Int, k)
	for i, partial := range partials {
		indices[i] = big.NewInt(int64(partial.AuthorityIndex))
	}

	// Compute combined point using Lagrange interpolation
	// Result = Σ(λ_i * partial_i) where λ_i is the Lagrange coefficient
	var combinedX, combinedY *big.Int

	for i, partial := range partials {
		// Calculate Lagrange coefficient λ_i at x=0
		lambda := lagrangeCoefficient(i, indices, N)

		// Multiply partial point by lambda: lambda * partial_i
		partialX, partialY := curve.ScalarMult(partial.PartialPoint.X, partial.PartialPoint.Y, lambda.Bytes())

		if i == 0 {
			combinedX, combinedY = partialX, partialY
		} else {
			// Add to running sum
			combinedX, combinedY = curve.Add(combinedX, combinedY, partialX, partialY)
		}
	}

	// Now we have reconstructed: secret * C1
	// Complete ElGamal decryption: M = C2 - (secret * C1)

	// Negate the combined point (negate Y coordinate)
	negY := new(big.Int).Sub(curve.Params().P, combinedY)

	// M = C2 + (-combined)
	msgX, msgY := curve.Add(ciphertext.C2.X, ciphertext.C2.Y, combinedX, negY)

	// Brute force discrete log to recover vote choice
	for i := 0; i <= maxChoice; i++ {
		testX, testY := curve.ScalarBaseMult(big.NewInt(int64(i)).Bytes())
		if testX.Cmp(msgX) == 0 && testY.Cmp(msgY) == 0 {
			return i, nil
		}
	}

	return -1, errors.New("failed to decrypt vote: discrete log not found")
}

// VerifyPartialDecryption verifies that an authority computed their partial decryption correctly
// Uses zero-knowledge proof to verify: log_G(verificationPoint) == log_C1(partial)
func VerifyPartialDecryption(
	partial *PartialDecryptionShare,
	ciphertext *ElGamalCiphertext,
	publicInfo *ThresholdPublicInfo,
) bool {
	if partial.AuthorityIndex < 1 || partial.AuthorityIndex > publicInfo.TotalShares {
		return false
	}

	if partial.Proof == nil {
		return false // Proof required
	}

	curve := publicInfo.MasterPublicKey.Curve

	// Basic sanity check: point is on curve
	if !curve.IsOnCurve(partial.PartialPoint.X, partial.PartialPoint.Y) {
		return false
	}

	verificationPoint := publicInfo.VerificationPoints[partial.AuthorityIndex-1]
	proof := partial.Proof

	// Verify Chaum-Pedersen proof
	// Check 1: s*G + c*VerificationPoint == t1
	sG_x, sG_y := curve.ScalarBaseMult(proof.Response.Bytes())
	cVP_x, cVP_y := curve.ScalarMult(verificationPoint.X, verificationPoint.Y, proof.Challenge.Bytes())
	check1X, check1Y := curve.Add(sG_x, sG_y, cVP_x, cVP_y)

	if check1X.Cmp(proof.Commitment1.X) != 0 || check1Y.Cmp(proof.Commitment1.Y) != 0 {
		return false // First verification equation failed
	}

	// Check 2: s*C1 + c*Partial == t2
	sC1_x, sC1_y := curve.ScalarMult(ciphertext.C1.X, ciphertext.C1.Y, proof.Response.Bytes())
	cP_x, cP_y := curve.ScalarMult(partial.PartialPoint.X, partial.PartialPoint.Y, proof.Challenge.Bytes())
	check2X, check2Y := curve.Add(sC1_x, sC1_y, cP_x, cP_y)

	if check2X.Cmp(proof.Commitment2.X) != 0 || check2Y.Cmp(proof.Commitment2.Y) != 0 {
		return false // Second verification equation failed
	}

	// Verify challenge was computed correctly (Fiat-Shamir)
	expectedChallenge := computeDLEQChallenge(curve, ciphertext.C1, verificationPoint, partial.PartialPoint, proof.Commitment1, proof.Commitment2)
	if proof.Challenge.Cmp(expectedChallenge) != 0 {
		return false // Challenge doesn't match (proof may be replayed or forged)
	}

	// All checks passed - authority used correct share
	return true
}

// Helper: Evaluate polynomial at point x modulo N
// f(x) = a_0 + a_1*x + a_2*x^2 + ... using Horner's method
func evaluatePolynomial(coefficients []*big.Int, x, N *big.Int) *big.Int {
	if len(coefficients) == 0 {
		return big.NewInt(0)
	}

	// Horner's method: f(x) = a_0 + x(a_1 + x(a_2 + x(a_3 + ...)))
	result := new(big.Int).Set(coefficients[len(coefficients)-1])

	for i := len(coefficients) - 2; i >= 0; i-- {
		result.Mul(result, x)
		result.Add(result, coefficients[i])
		result.Mod(result, N)
	}

	return result
}

// Helper: Calculate Lagrange coefficient λ_i at x=0
// λ_i = Π_{j≠i} (0 - x_j) / (x_i - x_j) mod N
func lagrangeCoefficient(i int, indices []*big.Int, N *big.Int) *big.Int {
	xi := indices[i]
	numerator := big.NewInt(1)
	denominator := big.NewInt(1)

	for j, xj := range indices {
		if j == i {
			continue
		}

		// Numerator: (0 - x_j) = -x_j
		negXj := new(big.Int).Neg(xj)
		negXj.Mod(negXj, N)
		numerator.Mul(numerator, negXj)
		numerator.Mod(numerator, N)

		// Denominator: (x_i - x_j)
		diff := new(big.Int).Sub(xi, xj)
		diff.Mod(diff, N)
		denominator.Mul(denominator, diff)
		denominator.Mod(denominator, N)
	}

	// Compute numerator / denominator mod N
	// This is numerator * denominator^(-1) mod N
	denomInv := new(big.Int).ModInverse(denominator, N)
	if denomInv == nil {
		// Should not happen with valid indices
		return big.NewInt(0)
	}

	result := new(big.Int).Mul(numerator, denomInv)
	result.Mod(result, N)

	return result
}
