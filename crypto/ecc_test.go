package crypto

import (
	"crypto/elliptic"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	if keyPair.PrivateKey == nil {
		t.Error("Private key is nil")
	}

	if keyPair.PublicKey == nil {
		t.Error("Public key is nil")
	}

	if keyPair.PublicKey.Curve != elliptic.P256() {
		t.Error("Expected P-256 curve")
	}
}

func TestEncryptDecryptVote(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test encryption and decryption for multiple vote choices
	testCases := []int{1, 2, 3, 5, 10}

	for _, voteChoice := range testCases {
		// Encrypt
		ciphertext, _, err := EncryptVote(keyPair.PublicKey, voteChoice)
		if err != nil {
			t.Fatalf("Failed to encrypt vote %d: %v", voteChoice, err)
		}

		// Decrypt
		decrypted, err := DecryptVote(keyPair.PrivateKey, ciphertext, 20)
		if err != nil {
			t.Fatalf("Failed to decrypt vote: %v", err)
		}

		if decrypted != voteChoice {
			t.Errorf("Expected %d, got %d", voteChoice, decrypted)
		}
	}
}

func TestHomomorphicAddition(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Encrypt two votes
	vote1 := 2
	vote2 := 3
	expectedSum := vote1 + vote2

	ciphertext1, _, err := EncryptVote(keyPair.PublicKey, vote1)
	if err != nil {
		t.Fatalf("Failed to encrypt vote 1: %v", err)
	}

	ciphertext2, _, err := EncryptVote(keyPair.PublicKey, vote2)
	if err != nil {
		t.Fatalf("Failed to encrypt vote 2: %v", err)
	}

	// Add ciphertexts
	sumCiphertext := AddCiphertexts(ciphertext1, ciphertext2, keyPair.PrivateKey.Curve)

	// Decrypt sum
	decryptedSum, err := DecryptVote(keyPair.PrivateKey, sumCiphertext, 20)
	if err != nil {
		t.Fatalf("Failed to decrypt sum: %v", err)
	}

	if decryptedSum != expectedSum {
		t.Errorf("Expected sum %d, got %d", expectedSum, decryptedSum)
	}
}

func TestSignAndVerify(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	data := []byte("test vote data")

	// Sign
	r, s, err := SignData(keyPair.PrivateKey, data)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Verify
	valid := VerifySignature(keyPair.PublicKey, data, r, s)
	if !valid {
		t.Error("Signature verification failed")
	}

	// Verify with wrong data
	wrongData := []byte("wrong data")
	valid = VerifySignature(keyPair.PublicKey, wrongData, r, s)
	if valid {
		t.Error("Signature should not verify with wrong data")
	}
}

func TestHashToScalar(t *testing.T) {
	data := []byte("test data")
	curve := elliptic.P256()

	scalar := HashToScalar(data, curve)

	if scalar == nil {
		t.Error("Scalar is nil")
	}

	// Verify scalar is within curve order
	if scalar.Cmp(curve.Params().N) >= 0 {
		t.Error("Scalar exceeds curve order")
	}
}
