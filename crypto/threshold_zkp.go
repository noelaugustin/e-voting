package crypto

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// generateDiscreteLogEqualityProof generates a Chaum-Pedersen proof
// that log_G(verificationPoint) == log_C1(partial)
func generateDiscreteLogEqualityProof(
	shareValue *big.Int,
	C1 Point,
	verificationPoint Point,
	partial Point,
	curve elliptic.Curve,
) (*DiscreteLogEqualityProof, error) {
	N := curve.Params().N

	// Pick random r
	r, err := rand.Int(rand.Reader, N)
	if err != nil {
		return nil, err
	}

	// Compute commitments
	// t1 = r * G
	t1X, t1Y := curve.ScalarBaseMult(r.Bytes())
	commitment1 := Point{X: t1X, Y: t1Y}

	// t2 = r * C1
	t2X, t2Y := curve.ScalarMult(C1.X, C1.Y, r.Bytes())
	commitment2 := Point{X: t2X, Y: t2Y}

	// Compute challenge using Fiat-Shamir heuristic
	challenge := computeDLEQChallenge(curve, C1, verificationPoint, partial, commitment1, commitment2)

	// Compute response: s = r - c * shareValue (mod N)
	response := new(big.Int).Mul(challenge, shareValue)
	response.Sub(r, response)
	response.Mod(response, N)

	return &DiscreteLogEqualityProof{
		Commitment1: commitment1,
		Commitment2: commitment2,
		Challenge:   challenge,
		Response:    response,
	}, nil
}

// computeDLEQChallenge computes the Fiat-Shamir challenge for discrete log equality
// c = Hash(G, C1, VerificationPoint, Partial, t1, t2) mod N
func computeDLEQChallenge(
	curve elliptic.Curve,
	C1 Point,
	verificationPoint Point,
	partial Point,
	commitment1 Point,
	commitment2 Point,
) *big.Int {
	// Concatenate all public parameters and commitments
	var data []byte

	// G (generator)
	data = append(data, curve.Params().Gx.Bytes()...)
	data = append(data, curve.Params().Gy.Bytes()...)

	// C1
	data = append(data, C1.X.Bytes()...)
	data = append(data, C1.Y.Bytes()...)

	// VerificationPoint
	data = append(data, verificationPoint.X.Bytes()...)
	data = append(data, verificationPoint.Y.Bytes()...)

	// Partial
	data = append(data, partial.X.Bytes()...)
	data = append(data, partial.Y.Bytes()...)

	// Commitment1 (t1)
	data = append(data, commitment1.X.Bytes()...)
	data = append(data, commitment1.Y.Bytes()...)

	// Commitment2 (t2)
	data = append(data, commitment2.X.Bytes()...)
	data = append(data, commitment2.Y.Bytes()...)

	// Hash and convert to challenge
	hash := sha256.Sum256(data)
	challenge := new(big.Int).SetBytes(hash[:])
	challenge.Mod(challenge, curve.Params().N)

	return challenge
}
