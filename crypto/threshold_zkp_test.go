package crypto

import (
	"math/big"
	"testing"
)

// TestPartialDecryptionProof tests that honest authorities generate valid proofs
func TestPartialDecryptionProof(t *testing.T) {
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

	// Each authority generates partial decryption with proof
	for i, share := range shares {
		partial, err := PartialDecrypt(share, ciphertext)
		if err != nil {
			t.Fatalf("Failed partial decryption for authority %d: %v", i+1, err)
		}

		// Verify proof is included
		if partial.Proof == nil {
			t.Errorf("Authority %d: proof is nil", i+1)
			continue
		}

		// Verify the proof
		if !VerifyPartialDecryption(partial, ciphertext, publicInfo) {
			t.Errorf("Authority %d: honest authority's proof failed verification!", i+1)
		}
	}
}

// TestCheatingAuthorityDetection tests that we can detect a cheating authority
func TestCheatingAuthorityDetection(t *testing.T) {
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

	// Test case: Authority 2 tries to cheat by using wrong share value
	cheatingAuthorityIndex := 1 // Authority 2 (index 1)

	for i, share := range shares {
		var partial *PartialDecryptionShare

		if i == cheatingAuthorityIndex {
			// Authority 2 cheats by using wrong share value
			wrongShare := &ThresholdKeyShare{
				Index:      share.Index,
				ShareValue: big.NewInt(999999), // Wrong value!
				PublicKey:  share.PublicKey,
			}

			partial, err = PartialDecrypt(wrongShare, ciphertext)
			if err != nil {
				t.Fatalf("Failed to generate cheating partial: %v", err)
			}
		} else {
			// Honest authorities
			partial, err = PartialDecrypt(share, ciphertext)
			if err != nil {
				t.Fatalf("Failed partial decryption for authority %d: %v", i+1, err)
			}
		}

		// Verify the partial
		isValid := VerifyPartialDecryption(partial, ciphertext, publicInfo)

		if i == cheatingAuthorityIndex {
			if isValid {
				t.Errorf("FAIL: Cheating authority %d was NOT detected!", i+1)
			} else {
				t.Logf("SUCCESS: Cheating authority %d correctly identified", i+1)
			}
		} else {
			if !isValid {
				t.Errorf("FALSE POSITIVE: Honest authority %d incorrectly flagged", i+1)
			}
		}
	}
}

// TestForgedProofDetection tests that forged proofs are rejected
func TestForgedProofDetection(t *testing.T) {
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

	// Generate honest partial for authority 1
	partial, err := PartialDecrypt(shares[0], ciphertext)
	if err != nil {
		t.Fatalf("Failed to generate partial: %v", err)
	}

	// Verify it's initially valid
	if !VerifyPartialDecryption(partial, ciphertext, publicInfo) {
		t.Fatal("Honest partial should be valid")
	}

	// Test 1: Modify the response value (forged proof)
	originalResponse := partial.Proof.Response
	partial.Proof.Response = big.NewInt(12345)

	if VerifyPartialDecryption(partial, ciphertext, publicInfo) {
		t.Error("FAIL: Forged proof with modified response was accepted!")
	} else {
		t.Log("OK: Forged proof with modified response rejected")
	}

	// Restore and test 2: Modify the challenge
	partial.Proof.Response = originalResponse
	originalChallenge := partial.Proof.Challenge
	partial.Proof.Challenge = big.NewInt(67890)

	if VerifyPartialDecryption(partial, ciphertext, publicInfo) {
		t.Error("FAIL: Forged proof with modified challenge was accepted!")
	} else {
		t.Log("OK: Forged proof with modified challenge rejected")
	}

	// Restore and verify it's valid again
	partial.Proof.Challenge = originalChallenge
	if !VerifyPartialDecryption(partial, ciphertext, publicInfo) {
		t.Error("Restoration failed: proof should be valid again")
	}
}

// TestMultipleCheatingAuthorities tests handling of multiple cheating authorities
func TestMultipleCheatingAuthorities(t *testing.T) {
	k, n := 5, 9
	shares, publicInfo, err := GenerateThresholdKeys(k, n)
	if err != nil {
		t.Fatalf("Failed to generate threshold keys: %v", err)
	}

	voteChoice := 2
	ciphertext, _, err := EncryptVote(publicInfo.MasterPublicKey, voteChoice)
	if err != nil {
		t.Fatalf("Failed to encrypt vote: %v", err)
	}

	// Simulate: Authorities 2, 4, and 6 are cheating
	cheatingAuthorities := map[int]bool{1: true, 3: true, 5: true}

	validPartials := []*PartialDecryptionShare{}

	for i, share := range shares {
		var partial *PartialDecryptionShare

		if cheatingAuthorities[i] {
			// Cheating authority uses wrong share
			wrongShare := &ThresholdKeyShare{
				Index:      share.Index,
				ShareValue: big.NewInt(int64(i * 12345)),
				PublicKey:  share.PublicKey,
			}
			partial, _ = PartialDecrypt(wrongShare, ciphertext)
		} else {
			// Honest authority
			partial, _ = PartialDecrypt(share, ciphertext)
		}

		// Verify and filter
		if VerifyPartialDecryption(partial, ciphertext, publicInfo) {
			validPartials = append(validPartials, partial)
			t.Logf("Authority %d: accepted (honest)", i+1)
		} else {
			t.Logf("Authority %d: rejected (cheating detected)", i+1)
		}
	}

	// Should have exactly 6 valid partials (9 total - 3 cheating)
	expectedValid := n - len(cheatingAuthorities)
	if len(validPartials) != expectedValid {
		t.Errorf("Expected %d valid partials, got %d", expectedValid, len(validPartials))
	}

	// Should still be able to decrypt with remaining honest authorities
	if len(validPartials) >= k {
		result, err := CombinePartialDecryptions(validPartials, ciphertext, publicInfo, 10)
		if err != nil {
			t.Errorf("Failed to decrypt with honest authorities: %v", err)
		}
		if result != voteChoice {
			t.Errorf("Decryption gave wrong result: expected %d, got %d", voteChoice, result)
		} else {
			t.Logf("System correctly decrypted using %d honest authorities (threshold=%d)", len(validPartials), k)
		}
	} else {
		t.Error("Not enough honest authorities to decrypt (system failure)")
	}
}
