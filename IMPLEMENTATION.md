# E-Voting System - Implementation Guide

Complete technical reference for implementing and using the e-voting system.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Architecture](#architecture)
3. [Project Structure](#project-structure)
4. [API Reference](#api-reference)
5. [Testing](#testing)
6. [Deployment & Scalability](#deployment--scalability)
7. [Security Implementation](#security-implementation)

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd e-voting

# Run tests
make test

# Run scalability tests
make test-scalability
```

### Basic Usage

```go
package main

import "github.com/naugustin/e-voting"

func main() {
    // Initialize system
    system, _ := evoting.NewVotingSystem()
    
    // Register voters
    voter1, _ := system.RegisterVoter("alice", "Booth-A")
    voter2, _ := system.RegisterVoter("bob", "Booth-A")
    
    // Register candidates
    system.RegisterCandidate("Candidate-A")
    system.RegisterCandidate("Candidate-B")
    
    // Cast votes
    system.CastVote(voter1, "Candidate-A")
    system.CastVote(voter2, "Candidate-B")
    
    // Publish votes (before counting)
    system.PublishVotes()
    
    // Voters verify their votes
    system.VerifyVoterVote("alice", "Candidate-A", voter1.Secret)
    
    // Count votes (requires authority cooperation)
    results, _ := system.CountVotes()
}
```

---

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────┐
│                  E-Voting System                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐    │
│  │Voter Registry│  │Vote Manager │  │Verification  │    │
│  │              │  │             │  │  System      │    │
│  │- KeyGen      │  │- Encryption │  │- Merkle Tree │    │
│  │- Booth ID    │  │- ZKP Gen    │  │- Publishing  │    │
│  └──────┬───────┘  └──────┬──────┘  └──────┬───────┘    │
│         │                 │                 │           │
│         └────────┬────────┘                 │           │
│                  │                          │           │
│        ┌─────────▼──────────┐               │           │
│        │  Crypto Layer      │               │           │
│        │  - ECC             │               │           │
│        │  - ZKP             │               │           │
│        │  - Merkle          │               │           │
│        └─────────┬──────────┘               │           │
│                  │                          │           │
│        ┌─────────▼──────────────────────────▼───┐       │
│        │      Analytics Engine                  │       │
│        │      - Homomorphic Aggregation         │       │
│        │      - Booth Analytics                 │       │
│        └────────────────────────────────────────┘       │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Data Flow

**Registration Phase**:
```
User → Register → Generate Keys → Assign Booth → Store in Registry
```

**Voting Phase**:
```
Voter → Select Candidate → Encrypt Vote → Generate ZKP → 
Create Commitment → Store Vote → Return Receipt
```

**Publication Phase**:
```
All Votes → Build Merkle Tree → Publish Root → Enable Verification
```

**Counting Phase**:
```
Encrypted Votes → Homomorphic Aggregation → Threshold Decrypt → 
Publish Results
```

---

## Project Structure

```
e-voting/
├── evoting.go              # Main system integration
├── evoting_test.go         # Integration tests
│
├── crypto/
│   ├── ecc.go             # Elliptic curve operations
│   ├── ecc_test.go
│   ├── zkp.go             # Zero-knowledge proofs
│   ├── zkp_test.go
│   ├── merkle.go          # Merkle tree implementation
│   └── merkle_test.go
│
├── voter/
│   └── registry.go        # Voter management
│
├── vote/
│   └── manager.go         # Vote handling
│
├── verification/
│   └── system.go          # Verification & publishing
│
├── analytics/
│   └── engine.go          # Vote counting & analytics
│
├── example/
│   └── main.go            # Example usage
│
└── docs/
    ├── ELI5.md            # User-friendly explanation
    └── IMPLEMENTATION.md  # This file
```

### Core Packages

**`crypto/`** - Cryptographic primitives
- `ecc.go`: P-256 curve operations, ElGamal encryption, homomorphic addition
- `zkp.go`: Schnorr proofs, vote validity proofs
- `merkle.go`: Binary hash tree, proof generation/verification

**`voter/`** - Voter management
- Registration
- Key pair generation
- Blind signature tokens

**`vote/`** - Vote operations
- Candidate registration
- Vote encryption
- ZKP generation
- Vote invalidation (for revotes)

**`verification/`** - Public verification
- Vote publishing
- Merkle tree construction
- Commitment verification
- Tamper detection

**`analytics/`** - Vote aggregation
- Homomorphic vote counting
- Booth-level statistics
- Result computation

---

## API Reference

### VotingSystem

Main system interface.

#### `NewVotingSystem() (*VotingSystem, error)`

Creates a new voting system instance.

```go
system, err := evoting.NewVotingSystem()
if err != nil {
    log.Fatal(err)
}
```

#### `RegisterVoter(voterID, boothID string) (*Voter, error)`

Registers a new voter with a unique ID and booth assignment.

```go
voter, err := system.RegisterVoter("alice", "Booth-A")
// voter.ID: "alice"
// voter.BoothID: "Booth-A"
// voter.KeyPair: Generated ECC keys
```

#### `RegisterCandidate(candidateID string) error`

Registers a candidate for the election.

```go
err := system.RegisterCandidate("Candidate-A")
```

#### `CastVote(voter *Voter, candidateID string) error`

Casts a vote for a candidate. If voter has voted before, previous vote is invalidated.

```go
err := system.CastVote(voter, "Candidate-A")
// Returns error if votes are already published
```

#### `PublishVotes() error`

Publishes all votes to Merkle tree for verification. Must be called before counting.

```go
err := system.PublishVotes()
// After this, no more votes can be cast
```

#### `GetMerkleRoot() string`

Returns the Merkle tree root hash for tamper detection.

```go
root := system.GetMerkleRoot()
// Example: "abc123def456..."
// Publish this widely (newspapers, blockchain, etc.)
```

#### `VerifyVoterVote(voterID, candidateID, secret string) (bool, error)`

Allows a voter to verify their own vote.

```go
isValid, err := system.VerifyVoterVote("alice", "Candidate-A", secret)
// Returns true if vote was recorded correctly
```

#### `CountVotes() (map[string]int, error)`

Counts all votes and returns results by candidate.

```go
results, err := system.CountVotes()
// map[string]int{
//     "Candidate-A": 1234,
//     "Candidate-B": 5678,
// }
```

#### `GetBoothAnalytics(boothID string) int`

Returns total vote count for a specific booth.

```go
count := system.GetBoothAnalytics("Booth-A")
```

#### `GetBoothCandidateAnalytics(boothID string) (map[string]int, error)`

Returns candidate-wise vote counts for a booth.

```go
boothResults, err := system.GetBoothCandidateAnalytics("Booth-A")
```

#### `DetectTampering(expectedRootHash string) bool`

Checks if votes have been tampered with.

```go
tampered := system.DetectTampering(publishedRoot)
// Returns false if root hashes match (no tampering)
```

### Crypto API

#### ECC Operations

```go
// Generate key pair
keyPair, err := crypto.GenerateKeyPair()

// Encrypt vote
ciphertext, randomness, err := crypto.EncryptVote(publicKey, voteChoice)

// Decrypt vote
voteChoice, err := crypto.DecryptVote(privateKey, ciphertext, maxCandidates)

// Add ciphertexts (homomorphic)
sum := crypto.AddCiphertexts(ct1, ct2, curve)

// Sign data
r, s, err := crypto.SignData(privateKey, data)

// Verify signature
valid := crypto.VerifySignature(publicKey, data, r, s)
```

#### Zero-Knowledge Proofs

```go
// Generate Schnorr proof
proof, err := crypto.GenerateSchnorrProof(privateKey, message)

// Verify Schnorr proof
valid := crypto.VerifySchnorrProof(publicKey, proof, message)

// Generate vote validity proof
proof, err := crypto.GenerateVoteValidityProof(
    ciphertext, actualChoice, numCandidates, randomness, publicKey,
)

// Verify vote validity
valid := crypto.VerifyVoteValidityProof(
    ciphertext, proof, numCandidates, publicKey,
)
```

#### Merkle Tree

```go
// Create tree
tree := crypto.NewMerkleTree(voteData)

// Get root hash
root := tree.GetRootHash()

// Generate proof for a vote
proof, err := tree.GenerateProof(leafIndex)

// Verify proof
valid := crypto.VerifyProof(voteData, proof, rootHash)

// Add new leaf
tree.AddLeaf(newVoteData)
```

---

## Testing

### Running Tests

```bash
# All tests
go test ./... -v

# Specific package
go test ./crypto -v

# With coverage
go test ./... -cover

# Integration tests
go test -v

# Scalability tests
go test -run TestScalability* -v
```

### Test Coverage

**crypto/ecc_test.go**:
- ✓ Key generation
- ✓ Vote encryption/decryption
- ✓ Homomorphic addition
- ✓ Signature generation/verification

**crypto/zkp_test.go**:
- ✓ Schnorr proof generation/verification
- ✓ Vote validity proofs

**crypto/merkle_test.go**:
- ✓ Tree construction
- ✓ Proof generation/verification
- ✓ Tamper detection

**evoting_test.go**:
- ✓ Complete voting workflow
- ✓ Vote invalidation on revote
- ✓ Voter verification
- ✓ Booth analytics
- ✓ Tamper detection

**scalability_test.go**:
- ✓ 1M votes processing
- ✓ Parallel vote encryption
- ✓ Merkle tree performance
- ✓ Memory profiling

### Example Test

```go
func TestCompleteVotingFlow(t *testing.T) {
    system, _ := evoting.NewVotingSystem()
    
    // Register
    voter1, _ := system.RegisterVoter("v1", "Booth-A")
    system.RegisterCandidate("Candidate-A")
    
    // Vote
    system.CastVote(voter1, "Candidate-A")
    
    // Publish
    system.PublishVotes()
    
    // Verify
    valid, _ := system.VerifyVoterVote("v1", "Candidate-A", voter1.Secret)
    assert.True(t, valid)
}
```

---

## Deployment & Scalability

### For Billion-User Scale

#### 1. Horizontal Sharding

Partition voters by geography:

```
State 1 → Shard 1 → [Districts 1-10]
State 2 → Shard 2 → [Districts 11-20]
...
```

Each shard handles:
- Voter registration
- Vote encryption
- Local Merkle tree

#### 2. Hierarchical Merkle Trees

```
             Global Root
            /     |     \
    State1     State2   State3
    /   \      /   \
  D1   D2    D3   D4
```

Benefits:
- Parallel tree construction
- Regional verification
- Incremental publishing

#### 3. Distributed Architecture

**Components**:

```yaml
Load Balancer:
  - nginx/HAProxy
  - Geographic routing

Vote Processors (Horizontal):
  - Go services (stateless)
  - Auto-scaling by load
  - 100K votes/sec target

Storage:
  - Primary: CockroachDB/Cassandra
  - Sharded by booth/district
  - Replication factor: 3

Cache:
  - Redis for voter sessions
  - Booth-level aggregates

CDN:
  - Serve published votes
  - Merkle proofs
  - Public verification data
```

#### 4. Performance Targets

| Metric | Target | Strategy |
|--------|--------|----------|
| Vote throughput | 100K/sec | Horizontal scaling |
| Vote encryption | <10ms | Parallel processing |
| ZKP verification | <50ms | Batch verification |
| Merkle tree build | <5 min for 100M | Parallel construction |
| Voter verification | <1 sec | CDN + caching |
| Availability | 99.99% | Multi-region deployment |

#### 5. Optimization Techniques

**Batch ZKP Verification**:
```go
// Instead of verifying one by one
for _, vote := range votes {
    VerifyProof(vote.Proof)  // 100 votes = 100 * 50ms = 5s
}

// Batch verify
BatchVerifyProofs(votes)  // 100 votes = 200ms
```

**Parallel Merkle Tree Construction**:
```go
// Build subtrees in parallel
var wg sync.WaitGroup
for _, shard := range shards {
    wg.Add(1)
    go func(s Shard) {
        s.BuildLocalTree()
        wg.Done()
    }(shard)
}
wg.Wait()

// Combine into global tree
globalTree := CombineTrees(shards)
```

**Incremental Vote Publishing**:
```go
// Don't wait for all votes
publishEvery := 1_000_000
for i, vote := range votes {
    AddToTree(vote)
    if i % publishEvery == 0 {
        PublishInterimRoot()
    }
}
```

#### 6. Database Schema (Example)

```sql
-- Sharded by booth_id
CREATE TABLE votes (
    vote_id UUID PRIMARY KEY,
    voter_public_key BYTEA,
    ciphertext_c1_x BYTEA,
    ciphertext_c1_y BYTEA,
    ciphertext_c2_x BYTEA,
    ciphertext_c2_y BYTEA,
    validity_proof JSONB,
    booth_id VARCHAR(50),
    timestamp TIMESTAMPTZ,
    commitment BYTEA,
    INDEX idx_booth (booth_id),
    INDEX idx_timestamp (timestamp)
) PARTITION BY HASH(booth_id);

-- Merkle tree nodes
CREATE TABLE merkle_nodes (
    node_id UUID PRIMARY KEY,
    hash BYTEA,
    left_child UUID,
    right_child UUID,
    level INT,
    INDEX idx_level (level)
);
```

---

## Security Implementation

### Cryptographic Guarantees

#### 1. Vote Privacy (ECDLP-based)

**Security Level**: 128-bit

```
Breaking privacy requires:
- Solving ECDLP on P-256 curve
- Best attack: Pollard's rho
- Complexity: O(√n) = 2^128 operations
- Estimated time: > 10^20 years on current hardware
```

**Implementation**:
```go
// P-256 curve (secp256r1)
curve := elliptic.P256()

// Private key: 256-bit random number
privateKey, _ := rand.Int(rand.Reader, curve.Params().N)

// Public key: privateKey * G
publicKeyX, publicKeyY := curve.ScalarBaseMult(privateKey.Bytes())
```

#### 2. Vote Integrity (SHA-256-based)

**Security Level**: 128-bit collision resistance

```
Tampering requires:
- Finding SHA-256 collision
- Best attack: Birthday attack
- Complexity: 2^128 operations
- Practically infeasible
```

**Implementation**:
```go
func BuildMerkleTree(votes [][]byte) *MerkleTree {
    leaves := make([]*MerkleNode, len(votes))
    for i, vote := range votes {
        hash := sha256.Sum256(vote)  // 256-bit hash
        leaves[i] = &MerkleNode{Hash: hash[:]}
    }
    return buildTree(leaves)
}
```

#### 3. Vote Authenticity (ECDSA)

**Implementation**:
```go
// Sign vote
r, s, _ := ecdsa.Sign(rand.Reader, privateKey, voteHash)

// Verify signature
valid := ecdsa.Verify(publicKey, voteHash, r, s)
```

### Threat Mitigation

#### Database Compromise

**Attack**: Attacker gains database access

**Impact**:
- ✗ Can't read vote contents (encrypted)
- ✗ Can't modify votes (Merkle detection)
- ✗ Can't delete votes (voter verification)
- ✓ Can see metadata (booth, timing)

**Mitigation**:
```go
// Encrypt database at rest
// Use TLS for connections
// Audit logging
// Regular Merkle root verification
```

#### Insider Threat

**Attack**: Election official manipulation

**Impact**:
- ✗ Can't decrypt alone (threshold crypto)
- ✗ Can't modify published votes
- ✗ Can't add fake votes

**Mitigation**:
```go
// Threshold decryption (k-of-n authorities)
// Public Merkle root
// Voter verification period
// Multi-party oversight
```

#### DDoS Attack

**Attack**: Overwhelm system

**Mitigation**:
```go
// Rate limiting
rateLimiter := rate.NewLimiter(1000, 5000)  // 1000/sec, burst 5000

// Geographic distribution
// CDN for static content
// Auto-scaling
// Backup voting channels
```

### Best Practices

1. **Key Management**:
   ```go
   // Use HSM for authority keys
   // FIPS 140-2 Level 3+
   // Key rotation every election
   // Multi-sig for critical operations
   ```

2. **Network Security**:
   ```go
   // TLS 1.3 for all connections
   // Certificate pinning
   // API authentication (OAuth 2.0)
   ```

3. **Audit Trail**:
   ```go
   // Log all operations
   // Immutable audit log
   // Regular integrity checks
   // Public verification API
   ```

4. **Secure Randomness**:
   ```go
   // Use crypto/rand, never math/rand
   random, err := rand.Int(rand.Reader, max)
   
   // Verify entropy source
   // Hardware RNG when available
   ```

---

## Production Deployment Checklist

- [ ] Multi-region deployment
- [ ] Database sharding configured
- [ ] CDN for public data
- [ ] Rate limiting enabled
- [ ] TLS certificates configured
- [ ] HSM for authority keys
- [ ] Monitoring & alerting
- [ ] Backup & disaster recovery
- [ ] Load testing completed
- [ ] Security audit performed
- [ ] Penetration testing done
- [ ] Documentation updated
- [ ] Runbooks prepared
- [ ] On-call rotation set

---

## Performance Benchmarks

From `scalability_test.go`:

```
1 Million Votes:
- Registration: ~30s
- Encryption: ~45s (parallel)
- ZKP Generation: ~60s (parallel)
- Merkle Tree Build: ~2s
- Memory Usage: ~2GB

Peak Throughput:
- Vote encryption: ~100K/sec (16-core)
- ZKP verification: ~50K/sec (batch)
```

---

## License

MIT License - See LICENSE file for details.
