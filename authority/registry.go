package authority

import (
	"errors"
	"fmt"
	"sync"

	"github.com/naugustin/e-voting/crypto"
)

// Authority represents a single decryption authority
type Authority struct {
	ID       string
	Name     string
	KeyShare *crypto.ThresholdKeyShare
	Active   bool // Whether this authority is currently active
}

// AuthorityRegistry manages all registered authorities
type AuthorityRegistry struct {
	authorities map[string]*Authority
	threshold   int // k: minimum authorities needed
	totalShares int // n: total authorities
	publicInfo  *crypto.ThresholdPublicInfo
	mu          sync.RWMutex
}

// NewAuthorityRegistry creates a new authority registry
func NewAuthorityRegistry(k, n int) (*AuthorityRegistry, error) {
	// Generate threshold keys
	shares, publicInfo, err := crypto.GenerateThresholdKeys(k, n)
	if err != nil {
		return nil, fmt.Errorf("failed to generate threshold keys: %w", err)
	}

	registry := &AuthorityRegistry{
		authorities: make(map[string]*Authority),
		threshold:   k,
		totalShares: n,
		publicInfo:  publicInfo,
	}

	// Pre-create authorities with their shares
	// In production, shares would be distributed via secure channels
	for i, share := range shares {
		authorityID := fmt.Sprintf("authority-%d", i+1)
		registry.authorities[authorityID] = &Authority{
			ID:       authorityID,
			Name:     fmt.Sprintf("Authority %d", i+1),
			KeyShare: share,
			Active:   true, // All authorities start active
		}
	}

	return registry, nil
}

// GetAuthority retrieves an authority by ID
func (ar *AuthorityRegistry) GetAuthority(id string) (*Authority, error) {
	ar.mu.RLock()
	defer ar.mu.RUnlock()

	authority, exists := ar.authorities[id]
	if !exists {
		return nil, fmt.Errorf("authority not found: %s", id)
	}

	return authority, nil
}

// GetActiveAuthorities returns all currently active authorities
func (ar *AuthorityRegistry) GetActiveAuthorities() []*Authority {
	ar.mu.RLock()
	defer ar.mu.RUnlock()

	active := make([]*Authority, 0)
	for _, auth := range ar.authorities {
		if auth.Active {
			active = append(active, auth)
		}
	}

	return active
}

// GetAuthorityCount returns total number of authorities
func (ar *AuthorityRegistry) GetAuthorityCount() int {
	ar.mu.RLock()
	defer ar.mu.RUnlock()
	return len(ar.authorities)
}

// GetActiveAuthorityCount returns number of active authorities
func (ar *AuthorityRegistry) GetActiveAuthorityCount() int {
	ar.mu.RLock()
	defer ar.mu.RUnlock()

	count := 0
	for _, auth := range ar.authorities {
		if auth.Active {
			count++
		}
	}
	return count
}

// GetThreshold returns the minimum authorities needed (k)
func (ar *AuthorityRegistry) GetThreshold() int {
	return ar.threshold
}

// GetPublicInfo returns the threshold public information
func (ar *AuthorityRegistry) GetPublicInfo() *crypto.ThresholdPublicInfo {
	return ar.publicInfo
}

// SetAuthorityActive sets whether an authority is active
func (ar *AuthorityRegistry) SetAuthorityActive(id string, active bool) error {
	ar.mu.Lock()
	defer ar.mu.Unlock()

	authority, exists := ar.authorities[id]
	if !exists {
		return fmt.Errorf("authority not found: %s", id)
	}

	authority.Active = active
	return nil
}

// UpdateAuthorityName updates an authority's display name
func (ar *AuthorityRegistry) UpdateAuthorityName(id, name string) error {
	ar.mu.Lock()
	defer ar.mu.Unlock()

	authority, exists := ar.authorities[id]
	if !exists {
		return fmt.Errorf("authority not found: %s", id)
	}

	authority.Name = name
	return nil
}

// ListAuthorities returns all authority IDs and names
func (ar *AuthorityRegistry) ListAuthorities() map[string]string {
	ar.mu.RLock()
	defer ar.mu.RUnlock()

	list := make(map[string]string)
	for id, auth := range ar.authorities {
		list[id] = auth.Name
	}
	return list
}

// CanDecrypt checks if we have enough active authorities for decryption
func (ar *AuthorityRegistry) CanDecrypt() bool {
	return ar.GetActiveAuthorityCount() >= ar.threshold
}

// DecryptWithAuthorities performs threshold decryption using specified authorities
// This is a simplified version - in production, authorities would participate asynchronously
func (ar *AuthorityRegistry) DecryptWithAuthorities(
	ciphertext *crypto.ElGamalCiphertext,
	authorityIDs []string,
	maxChoice int,
) (int, error) {
	if len(authorityIDs) < ar.threshold {
		return -1, errors.New("insufficient authorities for decryption")
	}

	// Collect partial decryptions from specified authorities
	partials := make([]*crypto.PartialDecryptionShare, 0, len(authorityIDs))

	for _, id := range authorityIDs {
		authority, err := ar.GetAuthority(id)
		if err != nil {
			return -1, fmt.Errorf("authority %s error: %w", id, err)
		}

		if !authority.Active {
			return -1, fmt.Errorf("authority %s is not active", id)
		}

		// Authority performs partial decryption
		partial, err := crypto.PartialDecrypt(authority.KeyShare, ciphertext)
		if err != nil {
			return -1, fmt.Errorf("partial decryption failed for %s: %w", id, err)
		}

		// Verify the partial decryption
		if !crypto.VerifyPartialDecryption(partial, ciphertext, ar.publicInfo) {
			return -1, fmt.Errorf("partial decryption verification failed for %s", id)
		}

		partials = append(partials, partial)

		// Stop when we have enough shares
		if len(partials) >= ar.threshold {
			break
		}
	}

	// Combine partial decryptions
	result, err := crypto.CombinePartialDecryptions(partials, ciphertext, ar.publicInfo, maxChoice)
	if err != nil {
		return -1, fmt.Errorf("failed to combine partial decryptions: %w", err)
	}

	return result, nil
}

// DecryptWithAnyAuthorities performs decryption using any available active authorities
func (ar *AuthorityRegistry) DecryptWithAnyAuthorities(
	ciphertext *crypto.ElGamalCiphertext,
	maxChoice int,
) (int, error) {
	activeAuthorities := ar.GetActiveAuthorities()

	if len(activeAuthorities) < ar.threshold {
		return -1, fmt.Errorf("insufficient active authorities: have %d, need %d",
			len(activeAuthorities), ar.threshold)
	}

	// Use first k active authorities
	authorityIDs := make([]string, ar.threshold)
	for i := 0; i < ar.threshold; i++ {
		authorityIDs[i] = activeAuthorities[i].ID
	}

	return ar.DecryptWithAuthorities(ciphertext, authorityIDs, maxChoice)
}
