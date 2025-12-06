# E‑Voting Demo CLI

This repo provides a complete, self‑contained CLI demo of a threshold‑encrypted e‑voting system. It shows how to set up an election, register voters, cast votes with zero‑knowledge validity proofs, release threshold decryption shares, and compute results.

Use this README as a hands‑on guide. It explains both how to run the demo and how each feature works under the hood with pointers to the source files.

## Quick Start
- Prerequisites: Go 1.21+, macOS/Linux.
- Build the CLI:
    - `go build -o bin/evoting-cli ./cmd/cli`
- Run help:
    - `./bin/evoting-cli`

Environment:
- Data is stored in `data/` by default. Override with `EVOTING_DATA_DIR`.

## CLI Overview
`evoting-cli <command> [subcommand] [flags]`
- `election`: create/reset the election and threshold keys.
- `voter`: add voters and (demo) freeze list.
- `vote`: cast encrypted votes with validity proofs; publish/verify (demo).
- `keys`: release authority partial decryptions.
- `results`: combine partials to decrypt votes and count.
- `booth` and `export`: placeholders in this demo.

Entry point: `cmd/cli/main.go`. State and storage: `cmd/cli/state.go`.

## Demo Walkthrough
### 1) Create Election (Threshold Setup)
Command:
- `./bin/evoting-cli election create --name "Demo" --candidates Alice,Bob,Charlie --n 3 --k 2`

What happens:
- Generates threshold key shares for `n` authorities with decryption threshold `k` using `authority.NewAuthorityRegistry(k, n)`.
- Stores the master public key and authority info in `data/election.json`, `data/authorities.json`, and private shares in `data/keys.json` (demo only).
- Candidates are persisted in `election.json`.

Relevant code:
- `cmd/cli/cmd_election.go:createElection`
- `authority/registry.go` (key share generation)
- `cmd/cli/state.go` (JSON persistence)

Sequence (threshold setup):
```mermaid
sequenceDiagram
    autonumber
    participant CLI
    participant AuthorityRegistry as Authority Registry
    participant Store as Data Store
    CLI->>AuthorityRegistry: NewAuthorityRegistry(k, n)
    AuthorityRegistry-->>CLI: Key shares (indices, private shares)
    CLI->>Store: Save authorities.json (public info)
    CLI->>Store: Save keys.json (private shares, demo)
    CLI->>Store: Save election.json (name, k, n, master pubkey, candidates)
```

### 2) Register Voters
Command:
- `./bin/evoting-cli voter add --id V1 --booth B1`
- `./bin/evoting-cli voter add --id V2 --booth B1`

What happens:
- Generates a fresh ECDSA keypair per voter with `crypto.GenerateKeyPair()`.
- Stores `publicKey`, demo `privateKey`, and a simple `votingToken` in `data/voters.json`.

Relevant code:
- `cmd/cli/cmd_voter.go:addVoter`
- `crypto/ecc.go:GenerateKeyPair` (called via `crypto.GenerateKeyPair`)

### 3) Cast Votes (Encryption + ZK Proof)
Command:
- `./bin/evoting-cli vote cast --voter V1 --candidate Alice`
- `./bin/evoting-cli vote cast --voter V2 --candidate Bob`

What happens:
- Loads the master public key from `election.json`.
- Maps the chosen candidate to an index.
- Encrypts a per‑candidate vector with ElGamal on P‑256: chosen candidate encrypts `1`, others `0`.
- Generates a composite one‑hot validity proof (demo placeholder) proving the vector has exactly one `1`.
- Saves the vote to `data/votes.json`. If a voter re‑casts, the demo enforces “last vote counts” by replacing prior entries.

Relevant code:
- `cmd/cli/cmd_vote.go:castVote`
- `crypto/ecc.go` and `crypto/zkp.go` implementations invoked via `crypto/*.go`

Sequence (cast vote):
```mermaid
sequenceDiagram
    autonumber
    participant Voter
    participant CLI
    participant Crypto as Crypto (ElGamal + ZKP)
    participant Store as Data Store
    Voter->>CLI: vote cast --voter Vx --candidate C
    CLI->>Store: Load election.json (master public key, candidates)
    CLI->>Crypto: Encrypt per-candidate vector (1/0)
    Crypto-->>CLI: Ciphertexts[], randomness (chosen)
    CLI->>Crypto: GenerateOneHotProof(ciphertexts, chosenIndex, randomness)
    Crypto-->>CLI: One-hot validity proof
    CLI->>Store: Save votes.json (voteId, voterId, ciphertexts[], proof)
```

### 4) Release Threshold Shares (Authorities)
Command:
- `./bin/evoting-cli keys release`

What happens:
- Loads `election.json`, `votes.json`, and the demo `keys.json` containing `k` private shares.
- For each vote, computes `k` partial decryptions: `crypto.PartialDecrypt(share, ciphertext)`.
- Saves all partials to `data/partials.json`.

Relevant code:
- `cmd/cli/cmd_results.go:releaseKeys`
- `crypto/threshold.go:PartialDecrypt` and related types

Sequence (release keys and partials):
```mermaid
sequenceDiagram
    autonumber
    participant CLI
    participant Store as Data Store
    participant Authorities as k Authorities
    CLI->>Store: Load election.json, votes.json, keys.json
    loop for each vote
        CLI->>Authorities: PartialDecrypt(share_i, ciphertext)
        Authorities-->>CLI: Partial decryption share
    end
    CLI->>Store: Save partials.json (VoteID -> k shares)
```

### 5) Compute Results (Homomorphic Tally)
Command:
- `./bin/evoting-cli results`

What happens:
- Each vote is a per‑candidate ciphertext vector: chosen candidate encrypts `1`, others `0`.
- The CLI homomorphically adds ciphertexts component‑wise to produce aggregated ciphertexts per candidate (`crypto.AddCiphertexts`).
- Authorities release partial decryptions over aggregated ciphertexts (`keys release`).
- The CLI combines `k` partials per candidate to recover the plaintext tally count (`crypto.CombinePartialDecryptions`).

Relevant code:
- `cmd/cli/cmd_results.go:handleResultsCommand`
- `crypto/threshold.go:CombinePartialDecryptions`

Sequence (aggregate + count):
    CLI-->>CLI: Print final tallies
```

## 🧠 How it Works: Homomorphic Counting

For those new to crypto voting, here is the "magic" that allows us to count votes without decrypting them individually.

### 1. The Challenge
We want to know the total votes for each candidate, but we **must not** decrypt individual votes to preserve voter privacy.

### 2. The Solution: Vector Encryption
Instead of encrypting "Candidate A", we encrypt a **vector** (a list of numbers) representing the choice.
If we have 3 candidates (Alice, Bob, Charlie) and you vote for **Bob** (index 1), your vote looks like this:

| Alice | Bob | Charlie |
|-------|-----|---------|
| 0     | 1   | 0       |

We encrypt *each* of these numbers separately using **ElGamal Encryption**.
- Encrypted Alice: $E(0)$
- Encrypted Bob:   $E(1)$
- Encrypted Charlie: $E(0)$

### 3. The Magic: Homomorphic Addition
ElGamal on Elliptic Curves has a special property: if you "add" two encrypted ciphertexts, the result is the encryption of their **sum**.

$$ E(v_1) + E(v_2) = E(v_1 + v_2) $$

So, the authorities (or the server) can take all the encrypted votes and add them up **without having the private key**.

#### Example Tally
**Voter 1 (Bob)**: $[E(0), E(1), E(0)]$
**Voter 2 (Bob)**: $[E(0), E(1), E(0)]$
**Voter 3 (Alice)**: $[E(1), E(0), E(0)]$

**Sum**: $[E(0+0+1), E(1+1+0), E(0+0+0)] = [E(1), E(2), E(0)]$

### 4. The Result
We end up with one aggregated ciphertext per candidate.
- Alice's Tally: $E(1)$
- Bob's Tally: $E(2)$
- Charlie's Tally: $E(0)$

Only *now* do the authorities use their shared private keys to decrypt these **aggregated** totals. They learn that Alice got 1 vote, Bob got 2, and Charlie got 0. They *never* saw who voted for whom.

```mermaid
graph LR
    subgraph Voter
    V[Vote for Bob] --> Vec[Vector: 0, 1, 0]
    Vec --> Enc[Encrypt: E(0), E(1), E(0)]
    end
    
    subgraph "Ballot Box (Server)"
    Enc --> Agg[Homomorphic Sum]
    end
    
    subgraph "Authorities"
    Agg --> Dec[Decrypt Sums]
    Dec --> Res[Result: Alice=1, Bob=2]
    end
```

## Feature Details
- Eligibility Proofs: Each vote includes a composite one‑hot validity proof that the per‑candidate vector encrypts exactly one 1 and all other 0s (demo placeholder built atop disjunctive proofs). See `crypto/zkp.go`, invoked from `cmd/cli/cmd_vote.go` and verified via `vote verify`.

- Double Voting Handling: The system uses an **Append-Only Log** backed by a Merkle Tree. All votes are preserved for audit. Tallying logic (`cmd_results.go`) filters out superseded votes based on `VoterHash` and Timestamp, counting only the latest vote per voter.

- **Infrastructure Identity**:
    - **Election Admin**: Root of trust. Signs Booth identities.
    - **Booths**: Physical locations. Sign Machine identities.
    - **Machines**: Voting terminals. Sign every vote with an ECDSA key.
    - This creates a Chain of Trust: Election -> Booth -> Machine -> Vote.

- **Voter Authentication & Anonymity**:
    - **Authentication**: Voters sign their vote with a private key (generated during registration). The system verifies this signature to prevent impersonation.
    - **Anonymity**: Voter identities are hashed (`SHA256`) in the public vote record. The link between real identity and vote is pseudonymous.

- Threshold Encryption: Votes are encrypted under a master ElGamal public key derived from `n` authorities; any `k` shares can decrypt via partial decryptions combined later. See `authority/registry.go`, `crypto/threshold.go`, and CLI glue in `cmd/cli/cmd_election.go`, `cmd/cli/cmd_results.go`.

- Partial Decryptions: `keys release` computes partial decryptions for each aggregated candidate ciphertext and verifies them against authority verification points before saving. See `cmd/cli/cmd_results.go:releaseKeys` and `crypto/threshold.go:VerifyPartialDecryption`.

- Tallying Approach: Votes are encoded as a per‑candidate vector of ciphertexts (chosen candidate = 1, others = 0). Ciphertexts are homomorphically added component‑wise, and the aggregated ciphertexts are threshold‑decrypted to yield counts.

- Storage & State: All entities persist as JSON in `data/`: `election.json`, `authorities.json`, `keys.json`, `voters.json`, `votes.json`, `partials.json`, `machines.json`, `booth_keys.json`, `machine_keys.json`, `voter_keys.json`.

## End‑to‑End Demo Script
```zsh
# 0) Build
go build -o bin/evoting-cli ./cmd/cli

# 1) Create election
./bin/evoting-cli election create --name "Demo" --candidates Alice,Bob,Charlie --n 3 --k 2

# 2) Setup Infrastructure (Booth & Machine)
./bin/evoting-cli booth create --id "B1" --location "Library"
./bin/evoting-cli booth add-machine --booth "B1" --id "M1"

# 3) Register Voters (Generates keys)
./bin/evoting-cli voter add --id V1 --booth B1
./bin/evoting-cli voter add --id V2 --booth B1

# 4) Cast Votes (Authenticated & Anonymized)
./bin/evoting-cli vote cast --voter V1 --candidate Alice --machine M1
./bin/evoting-cli vote cast --voter V2 --candidate Bob --machine M1

# 5) Verify Integrity (Signatures + Merkle Tree)
./bin/evoting-cli vote verify --tamper=true

# 6) Release Keys & Tally
./bin/evoting-cli keys release
./bin/evoting-cli results
```

## Notes for Experts
- Curve and ElGamal setup: P‑256, with ciphertexts and points stored via JSON; master public key serialized as concatenated hex `X||Y` in `election.json` (64+64 hex chars).
- Security notes: The demo now includes a full **PKI Chain** (Election->Booth->Machine->Vote) and **Hierarchical Merkle Audit** (Machine->Booth->Election).
- Extensibility: For homomorphic tallying without per‑vote decryption, use vector or exponential ElGamal encoding and either per‑candidate ciphertext or compressed encodings with range proofs; add verification points and signatures to validate authority partials.

## Troubleshooting
- “Did you run 'keys release'?”: `results` requires `data/partials.json` generated by `keys release`.
- Invalid candidate error: Ensure the candidate name is in `election.json`.
- Change data dir: `EVOTING_DATA_DIR=/tmp/evote ./bin/evoting-cli ...`

## Repo Pointers
- CLI commands: `cmd/cli/*.go`
- Crypto and ZK proofs: `crypto/*.go`
- Threshold authority setup: `authority/registry.go`
- Core demo programmatic API: `evoting.go`
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
