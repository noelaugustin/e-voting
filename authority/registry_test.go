package authority

import (
	"testing"

	"github.com/naugustin/e-voting/crypto"
)

func TestNewAuthorityRegistry(t *testing.T) {
	k, n := 3, 5
	registry, err := NewAuthorityRegistry(k, n)

	if err != nil {
		t.Fatalf("Failed to create authority registry: %v", err)
	}

	if registry.GetThreshold() != k {
		t.Errorf("Expected threshold %d, got %d", k, registry.GetThreshold())
	}

	if registry.GetAuthorityCount() != n {
		t.Errorf("Expected %d authorities, got %d", n, registry.GetAuthorityCount())
	}

	if registry.GetActiveAuthorityCount() != n {
		t.Errorf("Expected %d active authorities, got %d", n, registry.GetActiveAuthorityCount())
	}
}

func TestGetAuthority(t *testing.T) {
	registry, _ := NewAuthorityRegistry(3, 5)

	// Valid authority
	auth, err := registry.GetAuthority("authority-1")
	if err != nil {
		t.Errorf("Failed to get authority: %v", err)
	}
	if auth.ID != "authority-1" {
		t.Errorf("Wrong authority returned: %s", auth.ID)
	}

	// Invalid authority
	_, err = registry.GetAuthority("invalid")
	if err == nil {
		t.Error("Should error on invalid authority ID")
	}
}

func TestSetAuthorityActive(t *testing.T) {
	registry, _ := NewAuthorityRegistry(3, 5)

	// Deactivate one authority
	err := registry.SetAuthorityActive("authority-1", false)
	if err != nil {
		t.Errorf("Failed to deactivate authority: %v", err)
	}

	if registry.GetActiveAuthorityCount() != 4 {
		t.Errorf("Expected 4 active authorities after deactivation, got %d",
			registry.GetActiveAuthorityCount())
	}

	auth, _ := registry.GetAuthority("authority-1")
	if auth.Active {
		t.Error("Authority should be inactive")
	}

	// Reactivate
	err = registry.SetAuthorityActive("authority-1", true)
	if err != nil {
		t.Errorf("Failed to reactivate authority: %v", err)
	}

	if registry.GetActiveAuthorityCount() != 5 {
		t.Errorf("Expected 5 active authorities after reactivation, got %d",
			registry.GetActiveAuthorityCount())
	}
}

func TestCanDecrypt(t *testing.T) {
	registry, _ := NewAuthorityRegistry(3, 5)

	// Initially should be able to decrypt (5 active, need 3)
	if !registry.CanDecrypt() {
		t.Error("Should be able to decrypt with 5/5 active authorities")
	}

	// Deactivate 2 authorities (3 left, exactly threshold)
	registry.SetAuthorityActive("authority-1", false)
	registry.SetAuthorityActive("authority-2", false)

	if !registry.CanDecrypt() {
		t.Error("Should be able to decrypt with 3/5 active authorities (exactly threshold)")
	}

	// Deactivate one more (2 left, below threshold)
	registry.SetAuthorityActive("authority-3", false)

	if registry.CanDecrypt() {
		t.Error("Should NOT be able to decrypt with 2/5 active authorities (below threshold)")
	}
}

func TestDecryptWithAuthorities(t *testing.T) {
	k, n := 3, 5
	registry, _ := NewAuthorityRegistry(k, n)

	// Encrypt a vote
	voteChoice := 2
	ciphertext, _, err := crypto.EncryptVote(registry.GetPublicInfo().MasterPublicKey, voteChoice)
	if err != nil {
		t.Fatalf("Failed to encrypt vote: %v", err)
	}

	// Decrypt using first k authorities
	authorityIDs := []string{"authority-1", "authority-2", "authority-3"}
	decrypted, err := registry.DecryptWithAuthorities(ciphertext, authorityIDs, 10)

	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != voteChoice {
		t.Errorf("Expected %d, got %d", voteChoice, decrypted)
	}
}

func TestDecryptWithDifferentAuthoritySets(t *testing.T) {
	k, n := 3, 5
	registry, _ := NewAuthorityRegistry(k, n)

	voteChoice := 1
	ciphertext, _, err := crypto.EncryptVote(registry.GetPublicInfo().MasterPublicKey, voteChoice)
	if err != nil {
		t.Fatalf("Failed to encrypt vote: %v", err)
	}

	tests := []struct {
		authorityIDs []string
		desc         string
	}{
		{[]string{"authority-1", "authority-2", "authority-3"}, "authorities 1,2,3"},
		{[]string{"authority-2", "authority-3", "authority-4"}, "authorities 2,3,4"},
		{[]string{"authority-1", "authority-3", "authority-5"}, "authorities 1,3,5"},
		{[]string{"authority-1", "authority-2", "authority-3", "authority-4"}, "authorities 1,2,3,4 (more than k)"},
	}

	for _, tt := range tests {
		decrypted, err := registry.DecryptWithAuthorities(ciphertext, tt.authorityIDs, 10)
		if err != nil {
			t.Errorf("Failed to decrypt with %s: %v", tt.desc, err)
		}
		if decrypted != voteChoice {
			t.Errorf("Wrong result with %s: expected %d, got %d", tt.desc, voteChoice, decrypted)
		}
	}
}

func TestDecryptInsufficientAuthorities(t *testing.T) {
	k, n := 3, 5
	registry, _ := NewAuthorityRegistry(k, n)

	voteChoice := 1
	ciphertext, _, _ := crypto.EncryptVote(registry.GetPublicInfo().MasterPublicKey, voteChoice)

	// Try with only 2 authorities (below threshold of 3)
	authorityIDs := []string{"authority-1", "authority-2"}
	_, err := registry.DecryptWithAuthorities(ciphertext, authorityIDs, 10)

	if err == nil {
		t.Error("Should fail with insufficient authorities")
	}
}

func TestDecryptWithInactiveAuthority(t *testing.T) {
	k, n := 3, 5
	registry, _ := NewAuthorityRegistry(k, n)

	voteChoice := 1
	ciphertext, _, _ := crypto.EncryptVote(registry.GetPublicInfo().MasterPublicKey, voteChoice)

	// Deactivate one authority
	registry.SetAuthorityActive("authority-2", false)

	// Try to use the inactive authority
	authorityIDs := []string{"authority-1", "authority-2", "authority-3"}
	_, err := registry.DecryptWithAuthorities(ciphertext, authorityIDs, 10)

	if err == nil {
		t.Error("Should fail when using inactive authority")
	}
}

func TestDecryptWithAnyAuthorities(t *testing.T) {
	k, n := 3, 5
	registry, _ := NewAuthorityRegistry(k, n)

	voteChoice := 2
	ciphertext, _, err := crypto.EncryptVote(registry.GetPublicInfo().MasterPublicKey, voteChoice)
	if err != nil {
		t.Fatalf("Failed to encrypt vote: %v", err)
	}

	// Decrypt using any available authorities
	decrypted, err := registry.DecryptWithAnyAuthorities(ciphertext, 10)

	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != voteChoice {
		t.Errorf("Expected %d, got %d", voteChoice, decrypted)
	}
}

func TestDecryptWithAnyAuthoritiesInsufficientActive(t *testing.T) {
	k, n := 3, 5
	registry, _ := NewAuthorityRegistry(k, n)

	voteChoice := 1
	ciphertext, _, _ := crypto.EncryptVote(registry.GetPublicInfo().MasterPublicKey, voteChoice)

	// Deactivate authorities until below threshold
	registry.SetAuthorityActive("authority-1", false)
	registry.SetAuthorityActive("authority-2", false)
	registry.SetAuthorityActive("authority-3", false)
	// Now only 2 active (below threshold of 3)

	_, err := registry.DecryptWithAnyAuthorities(ciphertext, 10)

	if err == nil {
		t.Error("Should fail with insufficient active authorities")
	}
}

func TestUpdateAuthorityName(t *testing.T) {
	registry, _ := NewAuthorityRegistry(3, 5)

	newName := "Election Commission HQ"
	err := registry.UpdateAuthorityName("authority-1", newName)

	if err != nil {
		t.Errorf("Failed to update authority name: %v", err)
	}

	auth, _ := registry.GetAuthority("authority-1")
	if auth.Name != newName {
		t.Errorf("Expected name '%s', got '%s'", newName, auth.Name)
	}
}

func TestListAuthorities(t *testing.T) {
	k, n := 3, 5
	registry, _ := NewAuthorityRegistry(k, n)

	// Update some names
	registry.UpdateAuthorityName("authority-1", "Election Commission")
	registry.UpdateAuthorityName("authority-2", "Supreme Court")

	list := registry.ListAuthorities()

	if len(list) != n {
		t.Errorf("Expected %d authorities in list, got %d", n, len(list))
	}

	if list["authority-1"] != "Election Commission" {
		t.Error("Authority name not updated in list")
	}
}

// Benchmark decryption with threshold authorities
func BenchmarkDecryptWithAuthorities(b *testing.B) {
	k, n := 5, 9
	registry, _ := NewAuthorityRegistry(k, n)

	ciphertext, _, _ := crypto.EncryptVote(registry.GetPublicInfo().MasterPublicKey, 1)
	authorityIDs := []string{"authority-1", "authority-2", "authority-3", "authority-4", "authority-5"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = registry.DecryptWithAuthorities(ciphertext, authorityIDs, 10)
	}
}
