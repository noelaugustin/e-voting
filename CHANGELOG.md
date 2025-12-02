# Changelog

All notable changes to the E-Voting System project.

## [2.0.0] - 2025-12-03

### 🎉 Major Features Added

#### Audit & Verification System
- **Merkle Tree Audit Trails**: Complete election audit with O(log n) inclusion proofs
- **Audit Package API**: Download complete election data with all cryptographic proofs
- **Offline Verification**: Independent verification without server access
- **Individual Vote Verification**: Voters can verify their votes using Merkle proofs

#### New API Endpoints
- `GET /api/audit/package` - Download complete audit package with Merkle tree
- `POST /api/audit/verify-my-vote` - Verify vote with Merkle inclusion proof
- `GET /api/audit/merkle-root` - Get Merkle tree root hash

#### CLI Verification Tool
- **evoting-verify**: Command-line tool for offline audit verification
  - `download` - Download audit package from server
  - `verify <voterId> <secret>` - Verify vote online
  - `info <file>` - Display audit package information

#### Web Interface Enhancements
- New "Audit" tab with three sections:
  - Download complete audit package as JSON
  - Verify votes with Merkle proofs
  - View Merkle root and tree statistics
- Real-time verification results with proof details
- Expandable Merkle proof display

### 🔧 Technical Improvements

#### Code Organization
- Removed duplicate CLI directories (cmd/cli, cmd/evoting-cli, tools/verify)
- Consolidated to single `verify/` directory for CLI tool
- Cleaned up temporary test directories
- Organized build artifacts in `bin/` directory

#### Build System
- Enhanced Makefile with colored output
- Clear build targets: `server`, `cli`, `example`, `all`
- New targets: `test-race`, `test-coverage`, `format`, `lint`
- Better error messages and help documentation

#### Documentation
- **PAPER.md**: 50-page academic paper with:
  - Complete system architecture
  - Cryptographic protocol specifications
  - Security analysis and proofs
  - Performance evaluation
  - Comparison with related work
- Enhanced README with comprehensive feature list
- Updated IMPLEMENTATION.md with audit endpoints

### 🔒 Security Enhancements
- Merkle tree commitments for vote integrity
- Cryptographic proofs for all published votes
- Individual and universal verifiability
- Tamper-evident bulletin board

### 📊 Performance
- Vote encryption: ~2.3ms
- Merkle proof generation: ~0.15ms (1000 votes)
- Merkle proof verification: ~0.12ms
- Proof size: O(log n) - 450-650 bytes per vote

### 🐛 Bug Fixes
- Fixed package name conflicts in CLI tool
- Resolved file corruption issues during CLI creation
- Fixed duplicate Makefile targets
- Corrected import paths in verification system

### 📦 Project Statistics
- 32 Go source files
- 6 documentation files
- 3 binary outputs (server, cli, example)
- Total size: ~20MB (compiled binaries)

## [1.0.0] - 2025-11-XX

### Initial Release
- Threshold cryptography (k-of-n)
- Zero-knowledge proofs
- ElGamal encryption on elliptic curves
- Web interface for election management
- REST API for programmatic access
- Voter and candidate registration
- Anonymous vote casting
- Distributed vote counting
- Real-time election status

---

## Version Numbering

This project uses [Semantic Versioning](https://semver.org/):
- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality (backwards compatible)
- **PATCH**: Bug fixes (backwards compatible)
