# E-Voting System - Implementation Guide

Complete technical reference for implementing and using the e-voting system library and CLI.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Project Structure](#project-structure)
3. [Library API Reference](#library-api-reference)
4. [Testing](#testing)
5. [Security Implementation](#security-implementation)

---

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────┐
│                  E-Voting Library                       │
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
├── evoting.go              # Main system integration facade
├── evoting_test.go         # Integration tests
│
├── cmd/
│   └── cli/               # CLI application
│
├── crypto/
│   ├── ecc.go             # Elliptic curve operations
│   ├── threshold.go       # Threshold schemes
│   ├── zkp.go             # Zero-knowledge proofs
│   └── merkle.go          # Merkle tree implementation
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
├── authority/
│   └── registry.go        # Authority key management
│
└── analytics/
    └── engine.go          # Vote counting & analytics
```

### Core Packages

**`crypto/`** - Cryptographic primitives
- `ecc.go`: P-256 curve operations, ElGamal encryption, homomorphic addition
- `threshold.go`: Shamir's secret sharing and threshold decryption
- `zkp.go`: Schnorr proofs, vote validity proofs
- `merkle.go`: Binary hash tree, proof generation/verification

**`voter/`** - Voter management
- Registration
- Key pair generation

**`vote/`** - Vote operations
- Candidate registration
- Vote encryption
- ZKP generation

**`verification/`** - Public verification
- Vote publishing
- Merkle tree construction
- Commitment verification

**`authority/`** - Authority management
- Threshold key generation
- Distributed key management

**`analytics/`** - Vote aggregation
- Homomorphic vote counting
- Result computation

---

## Library API Reference

### VotingSystem

Main system interface defined in `evoting.go`.

#### `NewVotingSystem() (*VotingSystem, error)`

Creates a new voting system instance.

```go
system, err := evoting.NewVotingSystem()
```

#### `RegisterVoter(voterID, boothID string) (*Voter, error)`

Registers a new voter with a unique ID and booth assignment.

```go
voter, err := system.RegisterVoter("alice", "Booth-A")
```

#### `CastVote(voter *Voter, candidateID string) (*EncryptedVote, error)`

Casts a vote for a candidate.

```go
encryptedVote, err := system.CastVote(voter, "Candidate-A")
```

#### `PublishVotes() error`

Publishes all votes to Merkle tree for verification. Must be called before counting.

```go
err := system.PublishVotes()
```

#### `VerifyVoterVote(voterID, candidateID, secret string) (bool, error)`

Allows a voter to verify their own vote using the secret receipt.

```go
isValid, err := system.VerifyVoterVote("alice", "Candidate-A", secret)
```

#### `CountVotes() (map[string]int, error)`

Counts all votes and returns results by candidate using threshold decryption.

```go
results, err := system.CountVotes()
```

---

## Testing

### Running Tests

```bash
# All tests
make test

# Integration tests (CLI)
make test-cli

# With coverage
make test-coverage
```

---

## Security Implementation

### Cryptographic Guarantees

#### 1. Vote Privacy (ECDLP-based)

**Security Level**: 128-bit
Breaking privacy requires solving ECDLP on P-256 curve (practically infeasible).

#### 2. Vote Integrity (SHA-256-based)

**Security Level**: 128-bit collision resistance
Merkle trees ensure that any tampering with the vote history changes the root hash.

#### 3. Threshold Security

Decryption requires cooperation of `k` out of `n` authorities. No single authority can decrypt any vote.
