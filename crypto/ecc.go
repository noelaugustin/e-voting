package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

// ECCKeyPair represents an ECC public/private key pair
type ECCKeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// Point represents a point on the elliptic curve
type Point struct {
	X *big.Int
	Y *big.Int
}

// ElGamalCiphertext represents an encrypted message using ElGamal encryption
type ElGamalCiphertext struct {
	C1 Point // R = k*G
	C2 Point // M + k*PublicKey
}

// GenerateKeyPair generates a new ECC key pair using P-256 curve
func GenerateKeyPair() (*ECCKeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECCKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// EncryptVote encrypts a vote choice using ElGamal encryption
// voteChoice is encoded as a point on the curve
func EncryptVote(publicKey *ecdsa.PublicKey, voteChoice int) (*ElGamalCiphertext, *big.Int, error) {
	curve := publicKey.Curve

	// Generate random k
	k, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return nil, nil, err
	}

	// C1 = k*G (ephemeral public key)
	c1X, c1Y := curve.ScalarBaseMult(k.Bytes())

	// Encode vote as a point: voteChoice*G
	msgX, msgY := curve.ScalarBaseMult(big.NewInt(int64(voteChoice)).Bytes())

	// k*PublicKey
	sharedX, sharedY := curve.ScalarMult(publicKey.X, publicKey.Y, k.Bytes())

	// C2 = M + k*PublicKey
	c2X, c2Y := curve.Add(msgX, msgY, sharedX, sharedY)

	return &ElGamalCiphertext{
		C1: Point{X: c1X, Y: c1Y},
		C2: Point{X: c2X, Y: c2Y},
	}, k, nil
}

// DecryptVote decrypts an ElGamal ciphertext
// Returns the discrete log (vote choice) by brute force for small values
func DecryptVote(privateKey *ecdsa.PrivateKey, ciphertext *ElGamalCiphertext, maxChoice int) (int, error) {
	curve := privateKey.Curve

	// Compute privateKey * C1
	sharedX, sharedY := curve.ScalarMult(ciphertext.C1.X, ciphertext.C1.Y, privateKey.D.Bytes())

	// Compute -shared (negate Y coordinate)
	negSharedY := new(big.Int).Sub(curve.Params().P, sharedY)

	// M = C2 - privateKey*C1
	msgX, msgY := curve.Add(ciphertext.C2.X, ciphertext.C2.Y, sharedX, negSharedY)

	// Brute force discrete log to recover vote choice
	// For small number of candidates, this is feasible
	for i := 0; i <= maxChoice; i++ {
		testX, testY := curve.ScalarBaseMult(big.NewInt(int64(i)).Bytes())
		if testX.Cmp(msgX) == 0 && testY.Cmp(msgY) == 0 {
			return i, nil
		}
	}

	return -1, errors.New("failed to decrypt vote")
}

// AddCiphertexts performs homomorphic addition of two ciphertexts
// This allows tallying encrypted votes without decryption
func AddCiphertexts(c1, c2 *ElGamalCiphertext, curve elliptic.Curve) *ElGamalCiphertext {
	// Add C1 components
	newC1X, newC1Y := curve.Add(c1.C1.X, c1.C1.Y, c2.C1.X, c2.C1.Y)

	// Add C2 components
	newC2X, newC2Y := curve.Add(c1.C2.X, c1.C2.Y, c2.C2.X, c2.C2.Y)

	return &ElGamalCiphertext{
		C1: Point{X: newC1X, Y: newC1Y},
		C2: Point{X: newC2X, Y: newC2Y},
	}
}

// SignData signs data using ECDSA
func SignData(privateKey *ecdsa.PrivateKey, data []byte) (r, s *big.Int, err error) {
	hash := sha256.Sum256(data)
	return ecdsa.Sign(rand.Reader, privateKey, hash[:])
}

// VerifySignature verifies an ECDSA signature
func VerifySignature(publicKey *ecdsa.PublicKey, data []byte, r, s *big.Int) bool {
	hash := sha256.Sum256(data)
	return ecdsa.Verify(publicKey, hash[:], r, s)
}

// BlindSignature generates a blind signature for voter anonymity
func BlindSignature(privateKey *ecdsa.PrivateKey, blindedData []byte) (r, s *big.Int, err error) {
	return SignData(privateKey, blindedData)
}

// HashToScalar converts data to a scalar for cryptographic operations
func HashToScalar(data []byte, curve elliptic.Curve) *big.Int {
	hash := sha256.Sum256(data)
	scalar := new(big.Int).SetBytes(hash[:])
	// Reduce modulo curve order
	scalar.Mod(scalar, curve.Params().N)
	return scalar
}
