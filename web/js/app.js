// API Base URL
const API_BASE = '/api';

// State management
let currentElection = null;
let currentVotingToken = null;
let currentVoteSecret = null;

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    loadElectionInfo();
    loadCandidatesForVoting();
});

// Tab management
function showTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
    });

    // Show selected tab
    document.getElementById(`${tabName}-tab`).classList.add('active');
    event.target.classList.add('active');
}

// Load election info
async function loadElectionInfo() {
    try {
        const response = await fetch(`${API_BASE}/election/info`);
        if (response.ok) {
            const data = await response.json();
            currentElection = data;
            displayElectionInfo(data);
        }
    } catch (error) {
        console.log('No election created yet');
    }
}

function displayElectionInfo(data) {
    document.getElementById('electionStatus').classList.remove('hidden');
    document.getElementById('electionName').textContent = data.name;
    document.getElementById('status').textContent = data.status;
    document.getElementById('status').className = `badge ${data.status}`;
    document.getElementById('thresholdDisplay').textContent = data.threshold;
    document.getElementById('totalAuthoritiesDisplay').textContent = data.totalAuthorities;
    document.getElementById('masterKeyHash').textContent = data.masterPublicKeyHash.substring(0, 16) + '...';
    document.getElementById('candidateCount').textContent = data.candidates?.length || 0;
    document.getElementById('voterCount').textContent = data.totalVoters || 0;
    document.getElementById('voteCount').textContent = data.votesCast || 0;
}

// Create election
async function createElection(event) {
    event.preventDefault();

    const name = document.getElementById('electionNameInput').value;
    const kValue = document.getElementById('threshold').value;
    const nValue = document.getElementById('totalAuth').value;

    const k = parseInt(kValue, 10);
    const n = parseInt(nValue, 10);

    if (isNaN(k) || isNaN(n)) {
        showResult('createResult', 'Please enter valid numbers for threshold and total authorities', 'error');
        return;
    }

    if (k > n) {
        showResult('createResult', 'Threshold cannot be greater than total authorities', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/election`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, k, n })
        });

        const data = await response.json();

        if (response.ok) {
            showResult('createResult',
                `✅ Election created successfully!<br>
                <strong>Election ID:</strong> ${data.electionId}<br>
                <strong>Threshold:</strong> ${data.threshold} of ${data.totalAuthorities}<br>
                <strong>Master Key Hash:</strong> <code>${data.masterPublicKeyHash.substring(0, 20)}...</code>`,
                'success'
            );
            await loadElectionInfo();
        } else {
            showResult('createResult', `❌ Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showResult('createResult', `❌ Network error: ${error.message}`, 'error');
    }
}

// Register candidate
async function registerCandidate(event) {
    event.preventDefault();

    const candidateId = document.getElementById('candidateId').value;

    try {
        const response = await fetch(`${API_BASE}/candidates`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ candidateId })
        });

        const data = await response.json();

        if (response.ok) {
            showResult('candidateResult',
                `✅ Candidate registered: ${data.candidateId} (Index: ${data.index})`,
                'success'
            );
            document.getElementById('candidateId').value = '';
            await loadCandidates();
            await loadCandidatesForVoting();
            await loadElectionInfo();
        } else {
            showResult('candidateResult', `❌ Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showResult('candidateResult', `❌ Network error: ${error.message}`, 'error');
    }
}

// Load candidates
async function loadCandidates() {
    try {
        const response = await fetch(`${API_BASE}/candidates`);
        if (response.ok) {
            const candidates = await response.json();
            const list = document.getElementById('candidates');
            list.innerHTML = '';

            candidates.forEach(candidate => {
                const li = document.createElement('li');
                li.innerHTML = `<strong>${candidate.candidateId}</strong> - Index: ${candidate.index}`;
                list.appendChild(li);
            });

            document.getElementById('candidateList').classList.remove('hidden');
        }
    } catch (error) {
        console.error('Error loading candidates:', error);
    }
}

// Load candidates for voting dropdown
async function loadCandidatesForVoting() {
    try {
        const response = await fetch(`${API_BASE}/candidates`);
        if (response.ok) {
            const candidates = await response.json();
            const select = document.getElementById('candidateChoice');

            // Clear existing options except first
            while (select.options.length > 1) {
                select.remove(1);
            }

            candidates.forEach(candidate => {
                const option = document.createElement('option');
                option.value = candidate.candidateId;
                option.textContent = candidate.candidateId;
                select.appendChild(option);
            });
        }
    } catch (error) {
        console.error('Error loading candidates:', error);
    }
}

// Load authorities
async function loadAuthorities() {
    try {
        const response = await fetch(`${API_BASE}/authorities`);
        if (response.ok) {
            const authorities = await response.json();
            const list = document.getElementById('authorities');
            list.innerHTML = '';

            authorities.forEach(auth => {
                const li = document.createElement('li');
                li.innerHTML = `
                    <strong>Authority ${auth.index}</strong> - ${auth.name}<br>
                    <small>Verification Point Hash: <code>${auth.verificationPointHash}</code></small>
                `;
                list.appendChild(li);
            });

            document.getElementById('authoritiesList').classList.remove('hidden');
        }
    } catch (error) {
        console.error('Error loading authorities:', error);
    }
}

// Register voter
async function registerVoter(event) {
    event.preventDefault();

    const voterId = document.getElementById('voterId').value;
    const boothId = document.getElementById('boothId').value;

    try {
        const response = await fetch(`${API_BASE}/voters`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ voterId, boothId })
        });

        const data = await response.json();

        if (response.ok) {
            currentVotingToken = data.votingToken;
            showResult('voterResult',
                `✅ Voter registered successfully!<br>
                <div class="receipt-box">
                    <h3>🎫 Save Your Voting Token</h3>
                    <p><strong>Voter ID:</strong> ${data.voterId}</p>
                    <p><strong>Booth:</strong> ${data.boothId}</p>
                    <p><strong>Voting Token:</strong><br><code>${data.votingToken}</code></p>
                    <small>⚠️ Keep this token safe! You'll need it to vote.</small>
                </div>`,
                'success'
            );
            document.getElementById('voterId').value = '';
            document.getElementById('boothId').value = '';
            await loadElectionInfo();
        } else {
            showResult('voterResult', `❌ Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showResult('voterResult', `❌ Network error: ${error.message}`, 'error');
    }
}

// Cast vote
async function castVote(event) {
    event.preventDefault();

    const voterId = document.getElementById('voterIdVote').value;
    const votingToken = document.getElementById('votingToken').value;
    const candidateId = document.getElementById('candidateChoice').value;

    if (!candidateId) {
        showResult('voteResult', '❌ Please select a candidate', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/votes`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ voterId, votingToken, candidateId })
        });

        const data = await response.json();

        if (response.ok) {
            currentVoteSecret = data.secret;
            showResult('voteResult',
                `✅ Vote cast successfully! Your vote is encrypted and anonymous.<br>
                <div class="receipt-box">
                    <h3>📝 Vote Receipt</h3>
                    <p><strong>Vote ID:</strong> ${data.voteId}</p>
                    <p><strong>Commitment:</strong><br><code>${data.commitment.substring(0, 40)}...</code></p>
                    <p><strong>Timestamp:</strong> ${data.timestamp}</p>
                    <p><strong>Secret (for verification):</strong><br><code>${data.secret}</code></p>
                    <small>⚠️ Save this secret to verify your vote later!</small>
                </div>
                <p>💡 You can cast another vote to change your choice. Only your last vote counts.</p>`,
                'success'
            );
            await loadElectionInfo();
        } else {
            if (response.status === 429) {
                showResult('voteResult', '⏱️ Rate limit exceeded. Please wait 10 seconds before voting again.', 'error');
            } else {
                showResult('voteResult', `❌ Error: ${data.error}`, 'error');
            }
        }
    } catch (error) {
        showResult('voteResult', `❌ Network error: ${error.message}`, 'error');
    }
}

// Verify vote
async function verifyVote(event) {
    event.preventDefault();

    const voterId = document.getElementById('voterIdVerify').value;
    const secret = document.getElementById('secret').value;

    try {
        const response = await fetch(`${API_BASE}/votes/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ voterId, secret })
        });

        const data = await response.json();

        if (response.ok) {
            if (data.valid) {
                showResult('verifyResult',
                    `✅ Vote verification successful!<br>
                    <strong>Candidate:</strong> ${data.candidateId}<br>
                    <strong>Booth:</strong> ${data.boothId}<br>
                    <p>Your vote was recorded correctly and will be counted.</p>`,
                    'success'
                );
            } else {
                const errorMsg = data.error || 'Vote verification failed';
                showResult('verifyResult',
                    `❌ Vote verification failed<br>
                    <strong>Reason:</strong> ${errorMsg}${data.candidateId ? `<br><strong>Attempted candidate:</strong> ${data.candidateId}` : ''}`,
                    'error'
                );
            }
        } else {
            showResult('verifyResult', `❌ Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showResult('verifyResult', `❌ Network error: ${error.message}`, 'error');
    }
}

// Initiate count
async function initiateCount() {
    try {
        const response = await fetch(`${API_BASE}/count/initiate`, {
            method: 'POST'
        });

        const data = await response.json();

        if (response.ok) {
            showResult('countInitResult',
                `✅ Vote counting initiated!<br>
                <strong>Request ID:</strong> <code>${data.requestId}</code><br>
                <strong>Status:</strong> ${data.status}<br>
                <strong>Awaiting authorities:</strong> ${data.awaitingAuthorities.join(', ')}<br>
                <p>Waiting for ${data.awaitingAuthorities.length} authorities to submit partial decryptions...</p>`,
                'success'
            );
            document.getElementById('requestId').value = data.requestId;
        } else {
            showResult('countInitResult', `❌ Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showResult('countInitResult', `❌ Network error: ${error.message}`, 'error');
    }
}

// Submit partial decryption
async function submitPartial(event) {
    event.preventDefault();

    const requestId = document.getElementById('requestId').value;
    const authorityIndex = parseInt(document.getElementById('authorityIndex').value);

    try {
        const response = await fetch(`${API_BASE}/count/partial`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ requestId, authorityIndex })
        });

        const data = await response.json();

        if (response.ok) {
            if (data.remainingAuthorities.length === 0) {
                showResult('partialResult',
                    `✅ Authority ${authorityIndex} partial accepted! All partials received - counting complete!`,
                    'success'
                );
                setTimeout(() => getCountStatus(), 1000);
            } else {
                showResult('partialResult',
                    `✅ Authority ${authorityIndex} partial accepted!<br>
                    <strong>Remaining authorities:</strong> ${data.remainingAuthorities.join(', ')}`,
                    'success'
                );
            }
        } else {
            showResult('partialResult', `❌ Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showResult('partialResult', `❌ Network error: ${error.message}`, 'error');
    }
}

// Get count status
async function getCountStatus() {
    try {
        const response = await fetch(`${API_BASE}/count/status`);

        if (response.ok) {
            const data = await response.json();

            let html = `<strong>Status:</strong> ${data.status}<br>`;

            if (data.awaitingAuthorities.length > 0) {
                html += `<strong>Awaiting authorities:</strong> ${data.awaitingAuthorities.join(', ')}<br>`;
            }

            if (data.rejectedAuthorities.length > 0) {
                html += `<strong>Rejected authorities:</strong> ${data.rejectedAuthorities.join(', ')}<br>`;
            }

            if (data.results) {
                html += `<h3>🎉 Final Results</h3>`;
                html += `<table class="results-table">
                    <thead>
                        <tr>
                            <th>Candidate</th>
                            <th>Votes</th>
                        </tr>
                    </thead>
                    <tbody>`;

                for (const [candidate, votes] of Object.entries(data.results)) {
                    html += `<tr>
                        <td>${candidate}</td>
                        <td>${votes}</td>
                    </tr>`;
                }

                html += `</tbody></table>`;
            }

            showResult('countStatus', html, data.results ? 'success' : 'info');
            await loadElectionInfo();
        } else {
            const data = await response.json();
            showResult('countStatus', `❌ Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showResult('countStatus', `❌ Network error: ${error.message}`, 'error');
    }
}

// Get authority proof
async function getAuthorityProof(event) {
    event.preventDefault();

    const index = document.getElementById('authIndex').value;

    try {
        const response = await fetch(`${API_BASE}/authorities/proof?index=${index}`);
        const data = await response.json();

        if (response.ok) {
            showResult('authorityProofResult',
                `✅ Authority Proof<br>
                <strong>Authority:</strong> ${data.name} (Index: ${data.authorityIndex})<br>
                <strong>Verification Point Hash:</strong> <code>${data.verificationPointHash}</code><br>
                <strong>Proof Hash:</strong> <code>${data.proofHash}</code><br>
                <p>✓ This authority can prove they hold a valid share of the master key.</p>`,
                'success'
            );
        } else {
            showResult('authorityProofResult', `❌ Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showResult('authorityProofResult', `❌ Network error: ${error.message}`, 'error');
    }
}

// Get candidate proof
async function getCandidateProof(event) {
    event.preventDefault();

    const candidateId = document.getElementById('candidateIdProof').value;

    try {
        const response = await fetch(`${API_BASE}/candidates/proof?candidateId=${candidateId}`);
        const data = await response.json();

        if (response.ok) {
            showResult('candidateProofResult',
                `✅ Candidate Proof<br>
                <strong>Candidate:</strong> ${data.candidateId}<br>
                <strong>Proof Hash:</strong> <code>${data.proofHash}</code><br>
                <strong>Valid:</strong> ${data.valid ? '✓ Yes' : '✗ No'}<br>
                <p>✓ This candidate is cryptographically linked to the election.</p>`,
                'success'
            );
        } else {
            showResult('candidateProofResult', `❌ Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showResult('candidateProofResult', `❌ Network error: ${error.message}`, 'error');
    }
}

// Get voter proof
async function getVoterProof(event) {
    event.preventDefault();

    const voterId = document.getElementById('voterIdProof').value;

    try {
        const response = await fetch(`${API_BASE}/voters/proof?voterId=${voterId}`);
        const data = await response.json();

        if (response.ok) {
            showResult('voterProofResult',
                `✅ Voter Proof<br>
                <strong>Voter ID:</strong> ${data.voterId}<br>
                <strong>Booth:</strong> ${data.boothId}<br>
                <strong>Proof Hash:</strong> <code>${data.proofHash}</code><br>
                <strong>Valid:</strong> ${data.valid ? '✓ Yes' : '✗ No'}<br>
                <p>✓ This voter is registered and eligible to vote.</p>`,
                'success'
            );
        } else {
            showResult('voterProofResult', `❌ Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showResult('voterProofResult', `❌ Network error: ${error.message}`, 'error');
    }
}

// Download audit package
async function downloadAuditPackage() {
    try {
        showResult('auditDownloadResult', '📦 Downloading audit package...', 'info');

        const response = await fetch(`${API_BASE}/audit/package`);

        if (!response.ok) {
            const data = await response.json();
            showResult('auditDownloadResult', `❌ Error: ${data.error}`, 'error');
            return;
        }

        const data = await response.json();

        // Create downloadable file
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `audit-package-${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        showResult('auditDownloadResult',
            `✅ Audit Package Downloaded!<br>
            <strong>Election:</strong> ${data.electionName}<br>
            <strong>Status:</strong> ${data.status}<br>
            <strong>Total Votes:</strong> ${data.totalVotes}<br>
            <strong>Merkle Root:</strong> <code>${data.merkleRoot.substring(0, 20)}...</code><br>
            <strong>Votes with Proofs:</strong> ${data.votes.length}<br>
            <p>✓ Use the CLI tool for offline verification:<br>
            <code>./bin/evoting-verify info audit-package-*.json</code></p>`,
            'success'
        );
    } catch (error) {
        showResult('auditDownloadResult', `❌ Network error: ${error.message}`, 'error');
    }
}

// Verify vote with merkle proof
async function verifyMerkleVote(event) {
    event.preventDefault();

    const voterId = document.getElementById('voterIdMerkle').value;
    const secret = document.getElementById('secretMerkle').value;

    try {
        showResult('merkleVerifyResult', '🔍 Verifying vote...', 'info');

        const response = await fetch(`${API_BASE}/audit/verify-my-vote`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ voterId, secret })
        });

        const data = await response.json();

        if (response.ok && data.found && data.valid) {
            showResult('merkleVerifyResult',
                `✅ Vote Verified Successfully!<br>
                <strong>Voter ID:</strong> ${data.voterId}<br>
                <strong>Candidate:</strong> ${data.candidateId}<br>
                <strong>Vote Index:</strong> ${data.voteIndex}<br>
                <strong>Merkle Proof Path:</strong> ${data.merkleProof.length} hashes<br>
                <strong>Merkle Root:</strong> <code>${data.merkleRoot.substring(0, 20)}...</code><br>
                <p>✓ Your vote is included in the merkle tree and counted correctly!</p>
                <details>
                    <summary>Show Merkle Proof</summary>
                    <pre>${JSON.stringify(data.merkleProof, null, 2)}</pre>
                </details>`,
                'success'
            );
        } else if (!data.found) {
            showResult('merkleVerifyResult', `❌ Vote not found: ${data.error}`, 'error');
        } else {
            showResult('merkleVerifyResult', `❌ Verification failed: ${data.error}`, 'error');
        }
    } catch (error) {
        showResult('merkleVerifyResult', `❌ Network error: ${error.message}`, 'error');
    }
}

// Get merkle root
async function getMerkleRoot() {
    try {
        showResult('merkleRootResult', '🌳 Fetching merkle root...', 'info');

        const response = await fetch(`${API_BASE}/audit/merkle-root`);
        const data = await response.json();

        if (response.ok) {
            showResult('merkleRootResult',
                `✅ Merkle Root Retrieved<br>
                <strong>Root Hash:</strong> <code>${data.merkleRoot}</code><br>
                <strong>Total Votes:</strong> ${data.totalVotes}<br>
                <strong>Tree Height:</strong> ~${Math.ceil(Math.log2(data.totalVotes || 1))} levels<br>
                <p>This hash represents the cryptographic commitment to all ${data.totalVotes} votes in the election.</p>`,
                'success'
            );
        } else {
            showResult('merkleRootResult', `❌ Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showResult('merkleRootResult', `❌ Network error: ${error.message}`, 'error');
    }
}

// Show result message
function showResult(elementId, message, type) {
    const element = document.getElementById(elementId);
    element.innerHTML = message;
    element.className = `result ${type}`;
    element.classList.remove('hidden');

    // Scroll to result
    element.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
