# Verifiable E-Voting System

A cryptographically secure electronic voting system featuring threshold cryptography, zero-knowledge proofs, and audit trails for verifiable, anonymous, and tamper-proof elections.

> **Note**: This project focuses on the core cryptographic library and a CLI tool for election management.
> Web interfaces and REST APIs have been removed to focus on the core protocol implementation.

## 🎯 Key Features

- **Threshold Cryptography**: Distributed trust requiring k-of-n authorities for vote decryption.
- **Voter Privacy**: No single party can learn individual voter choices (ElGamal Encryption).
- **Individual Verifiability**: Voters can verify their vote inclusion.
- **Zero-Knowledge Proofs**: Prove validity without revealing sensitive information.
- **Tamper-Proof**: Cryptographic commitments ensure integrity.

## 📖 Documentation

- **[IMPLEMENTATION.md](./IMPLEMENTATION.md)**: Technical implementation details.

## Quick Start (CLI)

### Build

```bash
make build
```

This ensures the CLI tool is built at `bin/cli`.

### CLI Usage

The CLI supports the full election lifecycle:

1.  **Create Election**
    ```bash
    ./bin/cli election create --name "My Election" --candidates "Alice,Bob" --n 5 --k 3
    ```

2.  **Add Voters**
    ```bash
    ./bin/cli voter add --id "voter-1" --booth "booth-A"
    ```

3.  **Cast Votes**
    ```bash
    ./bin/cli vote cast --voter "voter-1" --candidate "Alice"
    ```

4.  **Release Authority Keys** (Simulation of threshold decryption)
    ```bash
    ./bin/cli keys release
    ```

5.  **Tally Results**
    ```bash
    ./bin/cli results
    ```
    *Output should show the counted votes.*

## 💻 Core Library

The core logic is designed to be used as a Go library:

- **`evoting`**: Main system package.
- **`crypto`**: Elliptic curve operations, threshold schemes, ZK proofs.
- **`authority`**: Authority management and key generation.
- **`vote`**: Vote management.
- **`voter`**: Voter registry.
- **`verification`**: Verification utilities.

### Example Library Usage

```go
import (
    "fmt"
    "github.com/naugustin/e-voting"
)

func main() {
    // Initialize system with threshold (k=3, n=5)
    system, _ := evoting.NewVotingSystem()
    system.SetupThresholdAuthorities(3, 5)

    // Register candidates
    system.RegisterCandidate("Alice")
    system.RegisterCandidate("Bob")

    // Register voter
    voter, _ := system.RegisterVoter("voter1", "booth-1")

    // Cast vote
    encryptedVote, _ := system.CastVote(voter, "Alice")
    fmt.Printf("Vote cast! ID: %s\n", encryptedVote.VoteID)
}
```

## 🧪 Testing

This project emphasizes testing integrity:

```bash
# Run core library unit tests
make test

# Run CLI integration tests (Python)
make test-cli
```

## 📦 Project Structure

```
e-voting/
├── evoting.go              # Core voting system facade
├── cmd/
│   └── cli/                # CLI application source
├── crypto/                 # Cryptographic primitives (ECC, Threshold, ZKP)
├── authority/              # Authority management
├── vote/                   # Vote logic
├── voter/                  # Voter registry
├── verification/           # Verification logic
├── analytics/              # Analytics engine
└── cli_test.py             # Integration test suite
```

## 🔐 Security Properties

- **Vote Privacy**: Hardness of Discrete Logarithm (Elliptic Curve).
- **Vote Integrity**: Votes cannot be modified once cast.
- **Anonymity**: Separated by threshold keys.

## 📄 License

MIT
