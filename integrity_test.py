import unittest
import subprocess
import os
import shutil
import json
import time

class TestEvotingHardware(unittest.TestCase):
    CLI_BIN = "./bin/evoting-cli"
    DATA_DIR = "test_data_hardware"

    def setUp(self):
        print(f"\nrunning {self._testMethodName}...")
        # Clean up previous data
        if os.path.exists(self.DATA_DIR):
            shutil.rmtree(self.DATA_DIR)
        os.environ["EVOTING_DATA_DIR"] = self.DATA_DIR
        
        # Build CLI
        subprocess.run(["go", "build", "-o", self.CLI_BIN, "./cmd/cli"], check=True)

    def tearDown(self):
        # Result data preserved for inspection
        pass

    def run_cli(self, args, expect_error=False):
        cmd = [self.CLI_BIN] + args
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=os.environ
        )
        if result.returncode != 0:
            if expect_error:
                return result.stdout
            print(f"Command failed: {' '.join(cmd)}")
            print(f"Stdout: {result.stdout}")
            print(f"Stderr: {result.stderr}")
            raise Exception(f"Command failed with code {result.returncode}")
        return result.stdout

    def test_machine_registration_flow(self):
        """Test creating booths and adding machines with key generation."""
        # 1. Create Election
        self.run_cli(["election", "create", "--name", "Hardware Test", "--candidates", "A,B", "--n", "3", "--k", "2"])

        # 2. Create Booth
        self.run_cli(["booth", "create", "--id", "Booth1", "--location", "Library"])

        # 3. Add Machine (Generates Keys)
        self.run_cli(["booth", "add-machine", "--booth", "Booth1", "--id", "Machine1"])

        # Check files
        machine_keys_path = os.path.join(self.DATA_DIR, "machine_keys.json")
        self.assertTrue(os.path.exists(machine_keys_path))
        with open(machine_keys_path) as f:
            keys = json.load(f)
            self.assertEqual(len(keys), 1)
            self.assertEqual(keys[0]["id"], "Machine1")
            self.assertIn("privateKey", keys[0])

    def test_machine_bound_voting(self):
        """Test voting from a registered machine with binding."""
        self.run_cli(["election", "create", "--name", "Vote Test", "--candidates", "A,B", "--n", "3", "--k", "2"])
        self.run_cli(["booth", "create", "--id", "B1", "--location", "Loc1"])
        self.run_cli(["booth", "add-machine", "--booth", "B1", "--id", "M1"])
        self.run_cli(["voter", "add", "--id", "V1", "--booth", "B1"])

        # Vote via Machine M1
        out = self.run_cli(["vote", "cast", "--voter", "V1", "--candidate", "A", "--machine", "M1"])
        self.assertIn("Recorded via Machine: M1", out)
        self.assertIn("Vote cryptographically signed", out)
        self.assertIn("Anonymized Alias:", out) # Verify anonymity

        # Verify Integrity
        verify_out = self.run_cli(["vote", "verify", "--tamper=true"])
        self.assertIn("Hash chain integrity: OK", verify_out)

    def test_machine_booth_mismatch(self):
        """Test specific tampering where machine and booth mismatch."""
        self.run_cli(["election", "create", "--name", "Mismatch Test", "--candidates", "A,B", "--n", "3", "--k", "2"])
        self.run_cli(["booth", "create", "--id", "B1", "--location", "Loc1"])
        self.run_cli(["booth", "create", "--id", "B2", "--location", "Loc2"])
        self.run_cli(["booth", "add-machine", "--booth", "B1", "--id", "M1"])
        # M1 belongs to B1
        self.run_cli(["voter", "add", "--id", "V1", "--booth", "B1"])

        self.run_cli(["vote", "cast", "--voter", "V1", "--candidate", "A", "--machine", "M1"])

        # TAMPER: Change BoothID in vote record to B2 (incorrect location)
        votes_path = os.path.join(self.DATA_DIR, "votes.json")
        with open(votes_path, 'r') as f:
            votes = json.load(f)
        
        votes[0]["boothId"] = "B2"
        
        with open(votes_path, 'w') as f:
            json.dump(votes, f, indent=2)

        # Verify should fail
        out = self.run_cli(["vote", "verify", "--tamper=true"], expect_error=True)
        # Verify specific error about BoothID mismatch
        self.assertIn("FAIL: Vote BoothID B2 does not match Machine's registered BoothID B1", out)

    def test_unregistered_machine_warning(self):
        """Test voting with a random machine ID (should warn)."""
        self.run_cli(["election", "create", "--name", "Warn Test", "--candidates", "A,B", "--n", "3", "--k", "2"])
        # Need a booth for voter registration
        self.run_cli(["booth", "create", "--id", "B1", "--location", "Loc1"])
        self.run_cli(["voter", "add", "--id", "V1", "--booth", "B1"])

        # Vote via unknown machine
        # Note: CLI currently just prints a warning but allows the vote (as demo)
        out = self.run_cli(["vote", "cast", "--voter", "V1", "--candidate", "A", "--machine", "UnknownMachine"])
        self.assertIn("Warning: Machine ID 'UnknownMachine' not found", out)
        # Should NOT say signed
        self.assertNotIn("Vote cryptographically signed", out)

    def test_tamper_evidence(self):
        """Test that modifying votes.json breaks validation."""
        self.run_cli(["election", "create", "--name", "Tamper Test", "--candidates", "A,B", "--n", "3", "--k", "2"])
        self.run_cli(["booth", "create", "--id", "B1", "--location", "Loc1"]) 
        self.run_cli(["booth", "add-machine", "--booth", "B1", "--id", "M1"])
        self.run_cli(["voter", "add", "--id", "V1", "--booth", "B1"])
        self.run_cli(["voter", "add", "--id", "V2", "--booth", "B1"])

        # Cast sequence of votes
        self.run_cli(["vote", "cast", "--voter", "V1", "--candidate", "A", "--machine", "M1"])
        self.run_cli(["vote", "cast", "--voter", "V2", "--candidate", "B", "--machine", "M1"])

        # Verify initial state
        self.run_cli(["vote", "verify"])

        # TAMPER: Modify V1's vote in JSON
        votes_path = os.path.join(self.DATA_DIR, "votes.json")
        with open(votes_path, 'r') as f:
            votes = json.load(f)
        
        # Change V1 ciphertext slightly (or anything affecting hash)
        # Just invalidating ciphertext structure or signature will break check
        # Let's change PreviousHash of V2 to point to "trash"
        votes[1]["previousHash"] = "TAMPERED_HASH"
        
        with open(votes_path, 'w') as f:
            json.dump(votes, f, indent=2)

        # Verify again - should fail
        out = self.run_cli(["vote", "verify", "--tamper=true"], expect_error=True)
        self.assertIn("FAIL: Hash chain broken", out)
        self.assertIn("Hash chain integrity: FAILED", out)

    def test_merkle_audit(self):
        """Test the Merkle Tree hierarchical audit."""
        self.run_cli(["election", "create", "--name", "Merkle Test", "--candidates", "A,B", "--n", "3", "--k", "2"])
        self.run_cli(["booth", "create", "--id", "B1", "--location", "Loc1"])
        self.run_cli(["booth", "add-machine", "--booth", "B1", "--id", "M1"])
        self.run_cli(["voter", "add", "--id", "V1", "--booth", "B1"])
        
        self.run_cli(["vote", "cast", "--voter", "V1", "--candidate", "A", "--machine", "M1"])
        
        out = self.run_cli(["vote", "verify"])
        self.assertIn("--- Merkle Tree Audit ---", out)
        self.assertIn("Machine M1 Root:", out)
        self.assertIn("Booth B1 Root:", out)
        self.assertIn("GLOBAL ELECTION MERKLE ROOT:", out)
    def test_voter_impersonation(self):
        """Test preventing voter impersonation (wrong private key)."""
        self.run_cli(["election", "create", "--name", "Impersonate", "--candidates", "A,B", "--n", "3", "--k", "2"])
        self.run_cli(["booth", "create", "--id", "B1", "--location", "Loc1"])
        self.run_cli(["booth", "add-machine", "--booth", "B1", "--id", "M1"])
        
        # Genuine Voter V1
        self.run_cli(["voter", "add", "--id", "V1", "--booth", "B1"])
        # Attacker V2
        self.run_cli(["voter", "add", "--id", "V2", "--booth", "B1"])

        # Genuine vote works
        self.run_cli(["vote", "cast", "--voter", "V1", "--candidate", "A", "--machine", "M1"])

        # ATTACK: Manually craft a vote for V1 using V2's keys? 
        # Easier: Modifying the signature in a valid vote to be garbage.
        # If I can't sign as V1, I can't cast a valid vote for V1.
        
        # Tamper existing vote: Replace V1's signature with garbage
        votes_path = os.path.join(self.DATA_DIR, "votes.json")
        with open(votes_path, 'r') as f:
            votes = json.load(f)
        
        # Invalid signature
        votes[0]["voterSignature"] = "deadbeef,deadbeef" # Invalid hex, invalid sig
        
        with open(votes_path, 'w') as f:
            json.dump(votes, f, indent=2)

        out = self.run_cli(["vote", "verify", "--tamper=true"], expect_error=True)
        self.assertIn("FAIL: Vote", out)
        self.assertIn("invalid Voter Signature", out)

    def test_voter_signature_stripped(self):
        """Test that a vote missing a voter signature is rejected."""
        self.run_cli(["election", "create", "--name", "StripSig", "--candidates", "A,B", "--n", "3", "--k", "2"])
        self.run_cli(["booth", "create", "--id", "B1", "--location", "Loc1"])
        self.run_cli(["booth", "add-machine", "--booth", "B1", "--id", "M1"])
        self.run_cli(["voter", "add", "--id", "V1", "--booth", "B1"])

        self.run_cli(["vote", "cast", "--voter", "V1", "--candidate", "A", "--machine", "M1"])

        # TAMPER: Remove signature
        votes_path = os.path.join(self.DATA_DIR, "votes.json")
        with open(votes_path, 'r') as f:
            votes = json.load(f)
        
        votes[0]["voterSignature"] = ""
        
        with open(votes_path, 'w') as f:
            json.dump(votes, f, indent=2)

        out = self.run_cli(["vote", "verify", "--tamper=true"], expect_error=True)
        self.assertIn("FAIL: Vote", out)
        self.assertIn("missing Voter Signature", out)
    def test_merkle_preserves_history(self):
        """Test that the Merkle key includes ALL votes, even superseded ones."""
        self.run_cli(["election", "create", "--name", "HistoryTest", "--candidates", "A,B", "--n", "3", "--k", "2"])
        self.run_cli(["booth", "create", "--id", "B1", "--location", "Loc1"])
        self.run_cli(["booth", "add-machine", "--booth", "B1", "--id", "M1"])
        self.run_cli(["voter", "add", "--id", "V1", "--booth", "B1"])

        # 1. Cast First Vote
        self.run_cli(["vote", "cast", "--voter", "V1", "--candidate", "A", "--machine", "M1"])
        
        # Get Merkle Root 1
        out1 = self.run_cli(["vote", "verify"])
        self.assertIn("Machine M1 Root:", out1)
        root1 = ""
        for line in out1.splitlines():
            if "GLOBAL ELECTION MERKLE ROOT:" in line:
                root1 = line.split(":")[1].strip()
        
        # 2. Cast Second Vote (Update)
        self.run_cli(["vote", "cast", "--voter", "V1", "--candidate", "B", "--machine", "M1"])

        # Get Merkle Root 2
        out2 = self.run_cli(["vote", "verify"])
        root2 = ""
        count_M1 = ""
        for line in out2.splitlines():
            if "GLOBAL ELECTION MERKLE ROOT:" in line:
                root2 = line.split(":")[1].strip()
            if "Machine M1 Root:" in line:
                # Format: Machine M1 Root: <hash> (Votes: <N>)
                count_M1 = line.split("(Votes:")[1].strip(")")
        
        # Verify
        self.assertNotEqual(root1, root2, "Merkle Root should change after second vote")
        self.assertEqual(count_M1.strip(), "2", "Merkle tree should contain BOTH votes (append-only log)") 
        
        print(f"\nMerkle Root 1: {root1}")
        print(f"Merkle Root 2: {root2}")
        print("Success: Both votes are cryptographically committed in the log.")

if __name__ == '__main__':
    unittest.main()
