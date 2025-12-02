# Quick Reference Guide

## 🚀 Getting Started in 5 Minutes

### 1. Build Everything
```bash
make all
```

### 2. Start the Server
```bash
make run-server
# Open http://localhost:8080 in your browser
```

### 3. Run Example Election
```bash
./bin/evoting-example
```

---

## 📋 Common Commands

### Building
```bash
make all          # Build all binaries
make server       # Build API server only
make cli          # Build CLI tool only
make example      # Build example only
```

### Running
```bash
make run-server   # Start web server
make run-example  # Run demo election
./bin/evoting-verify download  # Download audit package
```

### Testing
```bash
make test              # Run all tests
make test-race         # Test with race detection
make test-coverage     # Generate coverage report
```

### Maintenance
```bash
make clean        # Remove build artifacts
make format       # Format Go code
make lint         # Run linter
```

---

## 🌐 Web Interface

Access at: **http://localhost:8080**

### Tabs:
1. **Setup Election** - Create election, register candidates
2. **Register Voters** - Add voters with booth assignments
3. **Cast Vote** - Encrypted voting interface
4. **Verify Vote** - Check vote inclusion
5. **Count Votes** - Threshold decryption process
6. **Audit** - Download merkle tree & verify votes ⭐ NEW
7. **Proofs** - Zero-knowledge proofs

---

## 🔌 API Endpoints

### Election Management
```bash
# Create election
POST /api/election
{
  "name": "Election 2025",
  "k": 3,
  "n": 5
}

# Get election info
GET /api/election/info
```

### Voting
```bash
# Cast vote
POST /api/vote
{
  "voterId": "alice",
  "token": "secret123",
  "candidateId": "Alice"
}

# Publish votes to bulletin board
POST /api/votes/publish
```

### Audit & Verification ⭐ NEW
```bash
# Download complete audit package
GET /api/audit/package

# Verify your vote with Merkle proof
POST /api/audit/verify-my-vote
{
  "voterId": "alice",
  "secret": "commitment_secret"
}

# Get Merkle root
GET /api/audit/merkle-root
```

### Counting
```bash
# Initiate threshold decryption
POST /api/count/initiate

# Submit partial decryption
POST /api/count/partial
{
  "requestId": "req123",
  "authorityIndex": 1
}

# Get counting status
GET /api/count/status
```

---

## 🛠️ CLI Tool Usage

### Download Audit Package
```bash
./bin/evoting-verify download
# Creates: audit-package-<timestamp>.json
```

### Verify Your Vote
```bash
./bin/evoting-verify verify alice my_secret_key
# Output: Vote verified with Merkle proof
```

### Display Package Info
```bash
./bin/evoting-verify info audit-package.json
# Shows: Election details, results, vote count
```

### Set Custom Server
```bash
export EVOTING_SERVER=https://voting.example.com
./bin/evoting-verify download
```

---

## 📊 Performance Benchmarks

| Operation | Time | Notes |
|-----------|------|-------|
| Vote Encryption | 2.3ms | Per vote |
| Vote Decryption | 8.7ms | k=3 threshold |
| Merkle Proof Gen | 0.15ms | 1000 votes |
| Merkle Proof Verify | 0.12ms | Constant time |
| ZKP Generation | 1.8ms | Schnorr protocol |
| ZKP Verification | 1.5ms | Proof check |

---

## 🔒 Security Parameters

| Parameter | Value | Security Level |
|-----------|-------|----------------|
| Curve | secp256k1 | 128-bit |
| Hash | SHA-256 | 256-bit |
| Threshold | k ≥ 2 | Configurable |
| ZKP Challenge | 256 bits | 128-bit soundness |

---

## 📖 Documentation Files

| File | Purpose |
|------|---------|
| **PAPER.md** | Academic paper (50 pages) |
| **README.md** | Project overview & quick start |
| **IMPLEMENTATION.md** | Technical implementation details |
| **ELI5.md** | Beginner-friendly explanation |
| **Requirements.md** | Original specifications |
| **CHANGELOG.md** | Version history |
| **QUICK_REFERENCE.md** | This file |

---

## 🔧 Troubleshooting

### Port Already in Use
```bash
lsof -ti:8080 | xargs kill -9
make run-server
```

### Build Errors
```bash
make clean
go mod tidy
make all
```

### Test Failures
```bash
# Run specific package tests
go test ./crypto -v
go test ./api -v

# Check for race conditions
make test-race
```

### CLI Can't Connect
```bash
# Check server is running
curl http://localhost:8080/api/election/info

# Verify server URL
export EVOTING_SERVER=http://localhost:8080
./bin/evoting-verify download
```

---

## 💡 Tips & Tricks

### Development Workflow
```bash
# Terminal 1: Run server with auto-reload
make run-server

# Terminal 2: Run tests on save
watch -n 2 make test

# Terminal 3: Format before commit
make format && git add -A
```

### Quick Demo
```bash
# One-command demo
./bin/evoting-example

# Manual web demo
make run-server
# Visit http://localhost:8080
# Follow the 6 tabs sequentially
```

### Audit Workflow
```bash
# 1. Cast some votes via web interface
# 2. Publish votes (tab 5)
# 3. Download audit package (tab 6)
# 4. Verify offline
./bin/evoting-verify info audit-package-*.json
./bin/evoting-verify verify <your-voter-id> <your-secret>
```

---

## 🎯 Common Use Cases

### Running a Test Election
1. `make run-server`
2. Create election (threshold k=2, n=3)
3. Register 3 candidates
4. Register 5 voters
5. Cast 5 votes
6. Publish votes
7. Submit 2 partial decryptions
8. View results

### Auditing an Election
1. Download audit package from web UI
2. Save to `audit-package.json`
3. Run: `./bin/evoting-verify info audit-package.json`
4. Verify individual votes
5. Check Merkle root matches published value

### Integrating with Your System
```go
import "github.com/naugustin/e-voting"

// Initialize
system, _ := evoting.NewVotingSystem()

// Register & Vote
secret, _ := system.RegisterVoter("alice", "booth-1")
receipt, _ := system.CastVote("alice", secret, "Candidate-A")

// Verify
result, _ := system.VerifyMyVote("alice", receipt.Secret)
```

---

## 📞 Support & Resources

- **Documentation**: See PAPER.md for complete details
- **API Reference**: See IMPLEMENTATION.md
- **Examples**: Check `example/main.go`
- **Tests**: See `*_test.go` files for usage patterns

---

**Last Updated**: December 3, 2025  
**Version**: 2.0.0  
**License**: MIT
