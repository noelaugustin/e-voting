package crypto

import (
	"testing"
)

func TestGenerateSchnorrProof(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("test message")

	proof, err := GenerateSchnorrProof(keyPair.PrivateKey, message)
	if err != nil {
		t.Fatalf("Failed to generate Schnorr proof: %v", err)
	}

	if proof == nil {
		t.Error("Proof is nil")
	}

	if proof.Commitment.X == nil || proof.Commitment.Y == nil {
		t.Error("Commitment is incomplete")
	}

	if proof.Challenge == nil || proof.Response == nil {
		t.Error("Challenge or Response is nil")
	}
}

func TestVerifySchnorrProof(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("test message")

	proof, err := GenerateSchnorrProof(keyPair.PrivateKey, message)
	if err != nil {
		t.Fatalf("Failed to generate Schnorr proof: %v", err)
	}

	// Verify valid proof
	valid := VerifySchnorrProof(keyPair.PublicKey, proof, message)
	if !valid {
		t.Error("Valid proof failed verification")
	}

	// Verify with wrong message
	wrongMessage := []byte("wrong message")
	valid = VerifySchnorrProof(keyPair.PublicKey, proof, wrongMessage)
	if valid {
		t.Error("Proof should not verify with wrong message")
	}
}

func TestGenerateVoteValidityProof(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	actualChoice := 2
	numCandidates := 5

	ciphertext, randomness, err := EncryptVote(keyPair.PublicKey, actualChoice)
	if err != nil {
		t.Fatalf("Failed to encrypt vote: %v", err)
	}

	proof, err := GenerateVoteValidityProof(
		ciphertext,
		actualChoice,
		numCandidates,
		randomness,
		keyPair.PublicKey,
	)
	if err != nil {
		t.Fatalf("Failed to generate vote validity proof: %v", err)
	}

	if proof == nil {
		t.Error("Proof is nil")
	}

	if len(proof.Proofs) != numCandidates {
		t.Errorf("Expected %d proofs, got %d", numCandidates, len(proof.Proofs))
	}
}

func TestVerifyVoteValidityProof(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	actualChoice := 3
	numCandidates := 5

	ciphertext, randomness, err := EncryptVote(keyPair.PublicKey, actualChoice)
	if err != nil {
		t.Fatalf("Failed to encrypt vote: %v", err)
	}

	proof, err := GenerateVoteValidityProof(
		ciphertext,
		actualChoice,
		numCandidates,
		randomness,
		keyPair.PublicKey,
	)
	if err != nil {
		t.Fatalf("Failed to generate vote validity proof: %v", err)
	}

	// Verify proof
	valid := VerifyVoteValidityProof(
		ciphertext,
		proof,
		numCandidates,
		keyPair.PublicKey,
	)
	if !valid {
		t.Error("Valid proof failed verification")
	}
}
