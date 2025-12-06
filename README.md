# Verifiable E-Voting System

A cryptographically secure electronic voting system featuring threshold cryptography, zero-knowledge proofs, and Merkle tree-based audit trails for verifiable, anonymous, and tamper-proof elections.

## 🎯 Key **Features:**

- Threshold Cryptography - Distributed trust requiring k-of-n authorities for vote decryption  
- Voter Privacy - No single party can learn individual voter choices  
- Individual Verifiability - Voters verify their votes using Merkle inclusion proofs  
- Universal Verifiability - Anyone can audit the complete election  
- Offline Verification - Download complete audit package with all cryptographic proofs  
- Zero-Knowledge Proofs - Prove validity without revealing sensitive information  
- Tamper-Proof - Merkle tree commitments detect any vote manipulation  
- Production Ready - Web interface, REST API, and CLI audit tools  

## 📖 Documentation

📄 **[PAPER.md](./PAPER.md)** - Academic paper with complete system design, cryptographic protocols, security analysis, and performance evaluation

📚 **[ELI5.md](./ELI5.md)** - Accessible explanation of features and cryptography for non-technical readers

🔧 **[IMPLEMENTATION.md](./IMPLEMENTATION.md)** - Technical implementation guide with API reference and deployment instructions

## Quick Start

## Quick Start

### Build

```bash
# Build all components
make all

# Or build individually
make server   # API server with web interface
make cli      # CLI verification tool
make example  # Demo application
```

### Run Server

```bash
# Start the server
./bin/evoting-server

# Access web interface at http://localhost:8080
```

### Run CLI Audit Tool

```bash
# Download audit package
./bin/evoting-verify download

# Verify your vote
./bin/evoting-verify verify <voterID> <secret>

# Display audit package info
./bin/evoting-verify info audit-package.json
```

### Run Example

```bash
# Complete election demonstration
./bin/evoting-example
```

## 💻 System Components

### 1. Web Interface (`web/`)
- Complete election management dashboard
- Voter registration and vote casting
- Real-time election status
- Audit package download and verification

### 2. REST API (`api/`)
- Election lifecycle management
- Vote casting and verification
- Threshold decryption coordination
- Audit and verification endpoints

### 3. CLI Tool (`verify/`)
- Offline audit package verification
- Vote verification with Merkle proofs
- Election data inspection

### 4. Core Library
- **Voting System** (`evoting.go`) - Election management
- **Threshold Crypto** (`crypto/threshold.go`) - Distributed decryption
- **Zero-Knowledge Proofs** (`crypto/zkp.go`) - Validity proofs
- **Merkle Trees** (`crypto/merkle.go`) - Audit trails
- **Verification** (`verification/system.go`) - Bulletin board

## 🔬 Example Usage

```go
// Initialize system with threshold (k=3, n=5)
system, _ := evoting.NewVotingSystem()

// Register candidates
system.RegisterCandidate("Alice")
system.RegisterCandidate("Bob")

// Register voters
secret1, _ := system.RegisterVoter("voter1", "booth-1")
secret2, _ := system.RegisterVoter("voter2", "booth-2")

// Cast votes
receipt1, _ := system.CastVote("voter1", secret1, "Alice")
receipt2, _ := system.CastVote("voter2", secret2, "Bob")

// Publish votes to bulletin board
system.PublishVotes()

// Verify individual vote with Merkle proof
result, _ := system.VerifyMyVote("voter1", receipt1.Secret)
fmt.Printf("Vote verified! Candidate: %s\n", result.CandidateID)

// Download audit package
auditPkg := system.GetAuditPackage()
fmt.Printf("Merkle root: %s\n", auditPkg.MerkleRoot)

// Initiate threshold counting (requires k authorities)
requestID, _ := system.InitiateCounting()

// Authorities submit partial decryptions
for i := 1; i <= k; i++ {
    system.SubmitPartialDecryption(requestID, i)
}

// Get final results
results, _ := system.CountVotes()
```

## 🧪 Testing

```bash
# Run all tests
go test ./... -v

# Run with race detection
go test ./... -race

# Run specific tests
go test ./crypto -v
go test ./verification -v

# Run benchmarks
go test -bench=. ./...
```

## 🏗️ Architecture

```
┌─────────────┐
│  Web UI     │
└──────┬──────┘
       │
┌──────▼──────┐      ┌─────────────────┐
│  REST API   │◄─────┤  CLI Tool       │
└──────┬──────┘      └─────────────────┘
       │
┌──────▼──────────────────────────────┐
│      Voting System Core              │
│  ┌────────────┐  ┌────────────────┐ │
│  │ Threshold  │  │  Zero-Knowledge│ │
│  │   Crypto   │  │     Proofs     │ │
│  └────────────┘  └────────────────┘ │
│  ┌────────────┐  ┌────────────────┐ │
│  │  Merkle    │  │  Verification  │ │
│  │   Trees    │  │     System     │ │
│  └────────────┘  └────────────────┘ │
└───────────────────────────────────────┘
```

## 🔐 Technology Stack

- **Elliptic Curve**: secp256k1 (128-bit security)
- **Encryption**: ElGamal on elliptic curves
- **Threshold Scheme**: Shamir's Secret Sharing
- **Hash Function**: SHA-256
- **Zero-Knowledge**: Schnorr protocol (Fiat-Shamir)
- **Language**: Go 1.21+ (stdlib only)

## Performance

- **Vote Casting**: ~2.3ms per vote
- **Vote Verification**: ~0.15ms with Merkle proof
- **Threshold Decryption**: ~8.7ms (k=3)
- **Scalability**: 10,000+ voters tested
- **Proof Size**: O(log n) hashes

See [PAPER.md](./PAPER.md) for detailed performance evaluation.

## 🔒 Security Properties

- **Vote Privacy**: Threshold assumption, DDH hardness
- **Vote Integrity**: Merkle tree, collision resistance
- **Individual Verifiability**: Merkle inclusion proofs
- **Universal Verifiability**: Public bulletin board audit
- **Tamper Detection**: Cryptographic commitments

See [PAPER.md](./PAPER.md) for complete security analysis.

## 📝 API Endpoints

**Election Management**
- `POST /api/election` - Create election
- `GET /api/election/info` - Get status

**Voting**
- `POST /api/vote` - Cast vote
- `POST /api/votes/publish` - Publish to bulletin board

**Audit & Verification**
- `GET /api/audit/package` - Download audit package
- `POST /api/audit/verify-my-vote` - Verify with Merkle proof
- `GET /api/audit/merkle-root` - Get Merkle root

**Counting**
- `POST /api/count/initiate` - Start threshold decryption
- `POST /api/count/partial` - Submit partial decryption
- `GET /api/count/status` - Get counting status

See [IMPLEMENTATION.md](./IMPLEMENTATION.md) for complete API reference.

## 📦 Project Structure

```
e-voting/
├── evoting.go              # Core voting system
├── evoting_test.go         # System tests
├── crypto/                 # Cryptographic primitives
│   ├── ecc.go             # Elliptic curve operations
│   ├── threshold.go       # Threshold cryptography
│   ├── zkp.go             # Zero-knowledge proofs
│   └── merkle.go          # Merkle trees
├── verification/           # Bulletin board & audit
│   └── system.go
├── api/                    # REST API
│   ├── handlers_election.go
│   ├── handlers_audit.go
│   └── types.go
├── cmd/server/            # HTTP server
│   └── main.go
├── verify/                # CLI audit tool
│   └── main.go
├── web/                   # Web interface
│   ├── index.html
│   ├── js/app.js
│   └── css/style.css
├── example/               # Demo application
│   └── main.go
├── PAPER.md              # Academic paper
├── ELI5.md               # Accessible explanation
└── IMPLEMENTATION.md     # Technical guide
```

## 🤝 Contributing

Contributions welcome! Please ensure:
- All tests pass (`go test ./...`)
- Code is formatted (`go fmt ./...`)
- Documentation is updated
- Security considerations are addressed

## 📄 License

MIT
