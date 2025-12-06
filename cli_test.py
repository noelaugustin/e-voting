
import unittest
import subprocess
import os
import shutil
import json
import time

CLI_BIN = os.path.abspath("./cli")

class TestEvotingCLI(unittest.TestCase):
    def setUp(self):
        # Create unique data directory for each test
        self.test_name = self._testMethodName
        self.data_dir = os.path.abspath(f"test_data_{self.test_name}")
        if os.path.exists(self.data_dir):
            shutil.rmtree(self.data_dir)
        os.makedirs(self.data_dir)
        
        # Environment for CLI to use correct data dir
        self.env = os.environ.copy()
        self.env["EVOTING_DATA_DIR"] = self.data_dir

    def tearDown(self):
        # Cleanup
        if os.path.exists(self.data_dir):
            shutil.rmtree(self.data_dir)

    def run_cli(self, args, input_str=None, expect_error=False):
        cmd = [CLI_BIN] + args
        try:
            result = subprocess.run(
                cmd,
                input=input_str.encode() if input_str else None,
                capture_output=True,
                check=True,
                env=self.env
            )
            return result.stdout.decode()
        except subprocess.CalledProcessError as e:
            if expect_error:
                return e.stdout.decode() + e.stderr.decode()
            print(f"\nCommand failed: {' '.join(cmd)}")
            print(f"Stdout: {e.stdout.decode()}")
            print(f"Stderr: {e.stderr.decode()}")
            raise e

    def get_results(self):
        output = self.run_cli(["results"])
        results = {}
        lines = output.split('\n')
        parsing = False
        for line in lines:
            if "Election Results:" in line:
                parsing = True
                continue
            if parsing and ":" in line:
                parts = line.split(":")
                if len(parts) == 2:
                    results[parts[0].strip()] = int(parts[1].strip())
        return results

    def test_basic_flow(self):
        """Test the basic election flow with one voter"""
        print(f"\nrunning test_basic_flow in {self.data_dir}...")
        self.run_cli(["election", "create", "--name", "Basic", "--candidates", "Alice,Bob", "--n", "3", "--k", "2"])
        self.run_cli(["voter", "add", "--id", "v1", "--booth", "b1"])
        self.run_cli(["vote", "cast", "--voter", "v1", "--candidate", "Alice"])
        self.run_cli(["keys", "release"])
        
        results = self.get_results()
        self.assertEqual(results["Alice"], 1)
        self.assertEqual(results["Bob"], 0)

    def test_multiple_voters(self):
        """Test with multiple voters choosing different candidates"""
        print(f"\nrunning test_multiple_voters in {self.data_dir}...")
        self.run_cli(["election", "create", "--name", "Multi", "--candidates", "Alice,Bob,Charlie", "--n", "3", "--k", "2"])
        
        voters = ["v1", "v2", "v3", "v4", "v5"]
        for v in voters:
            self.run_cli(["voter", "add", "--id", v, "--booth", "b1"])
        
        # Votes: Alice: 2, Bob: 2, Charlie: 1
        votes = [
            ("v1", "Alice"),
            ("v2", "Bob"),
            ("v3", "Alice"),
            ("v4", "Charlie"),
            ("v5", "Bob")
        ]
        
        for v, c in votes:
            self.run_cli(["vote", "cast", "--voter", v, "--candidate", c])
            
        self.run_cli(["keys", "release"])
        results = self.get_results()
        
        self.assertEqual(results["Alice"], 2)
        self.assertEqual(results["Bob"], 2)
        self.assertEqual(results["Charlie"], 1)

    def test_last_vote_counts(self):
        """Test that if a voter votes twice, only the last vote counts"""
        print(f"\nrunning test_last_vote_counts in {self.data_dir}...")
        self.run_cli(["election", "create", "--name", "Revote", "--candidates", "Yes,No", "--n", "3", "--k", "2"])
        self.run_cli(["voter", "add", "--id", "v1", "--booth", "b1"])
        
        # First vote for Yes
        self.run_cli(["vote", "cast", "--voter", "v1", "--candidate", "Yes"])
        
        # Change mind to No
        self.run_cli(["vote", "cast", "--voter", "v1", "--candidate", "No"])
        
        self.run_cli(["keys", "release"])
        results = self.get_results()
        
        self.assertEqual(results["Yes"], 0)
        self.assertEqual(results["No"], 1)

    def test_scalability(self):
        """Test with many voters and many candidates"""
        print(f"\nrunning test_scalability in {self.data_dir}...")
        
        # 12 Candidates
        candidates_list = [f"C{i}" for i in range(12)]
        candidates_str = ",".join(candidates_list)
        
        self.run_cli(["election", "create", "--name", "Scale", "--candidates", candidates_str, "--n", "5", "--k", "3"])
        
        # 30 Voters
        num_voters = 30
        for i in range(num_voters):
            self.run_cli(["voter", "add", "--id", f"v{i}", "--booth", "b1"])
            
            # Vote for Candidates in round-robin: 0, 1, ..., 11, 0, ...
            # C0 should get 3 votes (0, 12, 24)
            # C6 should get 2 votes (6, 18) - actually 30/12 is 2.5, so:
            # 0..11 (1 each)
            # 12..23 (1 each) - Total 2 each
            # 24..29 (6 voters) -> C0..C5 get +1 (Total 3)
            # So C0-C5: 3 votes, C6-C11: 2 votes
            
            choice = candidates_list[i % 12]
            self.run_cli(["vote", "cast", "--voter", f"v{i}", "--candidate", choice])
            
        self.run_cli(["keys", "release"])
        results = self.get_results()
        
        for i in range(6):
            self.assertEqual(results[f"C{i}"], 3, f"Candidate C{i} count mismatch")
        for i in range(6, 12):
            self.assertEqual(results[f"C{i}"], 2, f"Candidate C{i} count mismatch")

if __name__ == '__main__':
    # Increase parallelism if needed, but sequential is fine for now
    unittest.main()
