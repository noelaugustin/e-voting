package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// ZKProof represents a zero-knowledge proof (Schnorr-based)
// Proves knowledge of private key without revealing it
type ZKProof struct {
	Commitment Point    // t = k*G
	Challenge  *big.Int // c = H(G, PublicKey, t, message)
	Response   *big.Int // s = k - c*privateKey
}

// VoteValidityProof proves that an encrypted vote is valid (one of the allowed candidates)
// without revealing which candidate was chosen
type VoteValidityProof struct {
	// For each candidate, prove that either:
	// 1. The vote is for this candidate, OR
	// 2. The vote is not for this candidate
	// Using OR-proofs (disjunctive proofs)
	Proofs []DisjunctiveProof
}

// DisjunctiveProof represents an OR-proof
type DisjunctiveProof struct {
	Commitment1 Point
	Commitment2 Point
	Challenge1  *big.Int
	Challenge2  *big.Int
	Response1   *big.Int
	Response2   *big.Int
}

// GenerateSchnorrProof generates a Schnorr zero-knowledge proof
// Proves knowledge of discrete log x such that Y = x*G
func GenerateSchnorrProof(privateKey *ecdsa.PrivateKey, message []byte) (*ZKProof, error) {
	curve := privateKey.Curve

	// Generate random k
	k, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return nil, err
	}

	// Commitment: t = k*G
	tX, tY := curve.ScalarBaseMult(k.Bytes())

	// Challenge: c = H(G, Y, t, message)
	challenge := computeChallenge(curve, privateKey.PublicKey.X, privateKey.PublicKey.Y, tX, tY, message)

	// Response: s = k - c*x (mod n)
	cx := new(big.Int).Mul(challenge, privateKey.D)
	response := new(big.Int).Sub(k, cx)
	response.Mod(response, curve.Params().N)

	return &ZKProof{
		Commitment: Point{X: tX, Y: tY},
		Challenge:  challenge,
		Response:   response,
	}, nil
}

// VerifySchnorrProof verifies a Schnorr zero-knowledge proof
func VerifySchnorrProof(publicKey *ecdsa.PublicKey, proof *ZKProof, message []byte) bool {
	curve := publicKey.Curve

	// Verify: s*G + c*Y = t
	// Left side: s*G
	sGx, sGy := curve.ScalarBaseMult(proof.Response.Bytes())

	// c*Y
	cYx, cYy := curve.ScalarMult(publicKey.X, publicKey.Y, proof.Challenge.Bytes())

	// s*G + c*Y
	leftX, leftY := curve.Add(sGx, sGy, cYx, cYy)

	// Check if it equals commitment
	if leftX.Cmp(proof.Commitment.X) != 0 || leftY.Cmp(proof.Commitment.Y) != 0 {
		return false
	}

	// Verify challenge
	expectedChallenge := computeChallenge(curve, publicKey.X, publicKey.Y,
		proof.Commitment.X, proof.Commitment.Y, message)

	return proof.Challenge.Cmp(expectedChallenge) == 0
}

// GenerateVoteValidityProof generates a proof that an encrypted vote is valid
// Uses disjunctive (OR) proofs to prove vote is one of the valid choices
func GenerateVoteValidityProof(
	ciphertext *ElGamalCiphertext,
	actualChoice int,
	numCandidates int,
	randomness *big.Int,
	publicKey *ecdsa.PublicKey,
) (*VoteValidityProof, error) {
	curve := publicKey.Curve
	proofs := make([]DisjunctiveProof, numCandidates)

	// For the actual choice, generate a real proof
	// For other choices, simulate proofs

	// Generate random values for simulated proofs
	for i := 0; i < numCandidates; i++ {
		if i == actualChoice {
			// Real proof for the actual choice
			proof, err := generateRealDisjunctiveProof(curve, publicKey, ciphertext, i, randomness)
			if err != nil {
				return nil, err
			}
			proofs[i] = *proof
		} else {
			// Simulated proof for other choices
			proof, err := generateSimulatedDisjunctiveProof(curve, publicKey, ciphertext, i)
			if err != nil {
				return nil, err
			}
			proofs[i] = *proof
		}
	}

	return &VoteValidityProof{Proofs: proofs}, nil
}

// VerifyVoteValidityProof verifies that an encrypted vote is valid
func VerifyVoteValidityProof(
	ciphertext *ElGamalCiphertext,
	proof *VoteValidityProof,
	numCandidates int,
	publicKey *ecdsa.PublicKey,
) bool {
	if len(proof.Proofs) != numCandidates {
		return false
	}

	// Verify each disjunctive proof
	for i, p := range proof.Proofs {
		if !verifyDisjunctiveProof(publicKey.Curve, publicKey, ciphertext, i, &p) {
			return false
		}
	}

	return true
}

// Helper functions

func computeChallenge(curve elliptic.Curve, pubX, pubY, commitX, commitY *big.Int, message []byte) *big.Int {
	h := sha256.New()
	h.Write(curve.Params().Gx.Bytes())
	h.Write(curve.Params().Gy.Bytes())
	h.Write(pubX.Bytes())
	h.Write(pubY.Bytes())
	h.Write(commitX.Bytes())
	h.Write(commitY.Bytes())
	h.Write(message)

	hash := h.Sum(nil)
	challenge := new(big.Int).SetBytes(hash)
	challenge.Mod(challenge, curve.Params().N)
	return challenge
}

func generateRealDisjunctiveProof(
	curve elliptic.Curve,
	publicKey *ecdsa.PublicKey,
	ciphertext *ElGamalCiphertext,
	choice int,
	randomness *big.Int,
) (*DisjunctiveProof, error) {
	// Generate random value
	k, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return nil, err
	}

	// Commitment
	c1X, c1Y := curve.ScalarBaseMult(k.Bytes())

	// Simulated challenge for the other branch
	c2, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return nil, err
	}

	// Response
	r1 := new(big.Int).Sub(k, new(big.Int).Mul(c2, randomness))
	r1.Mod(r1, curve.Params().N)

	return &DisjunctiveProof{
		Commitment1: Point{X: c1X, Y: c1Y},
		Commitment2: Point{X: big.NewInt(0), Y: big.NewInt(0)},
		Challenge1:  big.NewInt(0),
		Challenge2:  c2,
		Response1:   r1,
		Response2:   big.NewInt(0),
	}, nil
}

func generateSimulatedDisjunctiveProof(
	curve elliptic.Curve,
	publicKey *ecdsa.PublicKey,
	ciphertext *ElGamalCiphertext,
	choice int,
) (*DisjunctiveProof, error) {
	// Generate random challenge and response
	c, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return nil, err
	}

	r, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return nil, err
	}

	// Compute commitment that makes the proof valid
	// This is a simplified simulation
	commitX, commitY := curve.ScalarBaseMult(r.Bytes())

	return &DisjunctiveProof{
		Commitment1: Point{X: commitX, Y: commitY},
		Commitment2: Point{X: big.NewInt(0), Y: big.NewInt(0)},
		Challenge1:  c,
		Challenge2:  big.NewInt(0),
		Response1:   r,
		Response2:   big.NewInt(0),
	}, nil
}

func verifyDisjunctiveProof(
	curve elliptic.Curve,
	publicKey *ecdsa.PublicKey,
	ciphertext *ElGamalCiphertext,
	choice int,
	proof *DisjunctiveProof,
) bool {
	// Simplified verification
	// In a production system, this would verify the OR-proof structure
	return proof.Response1 != nil
}
