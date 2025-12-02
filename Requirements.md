I need a web application and a Go backend for this.

We can work with an in memory version for the time being

1. Create an election
   1. create a set of authorities of k, n where k is the minimum folks required for quorum, and n is the total number of authorities
   1. The list of authorities to be published and should be cryptographically verifiable
   1. Authorities should be able to prove publically that  they hold a share of the key
   1. Authorities who don't input their share should be correctly identified and their share should be ignored
   1. Should be able to identify the authority with a public portion of the key
   1. Create candidates. Each should be cryptographically linkable to the election and authority whenever possible
   1. Candidate should be able to prove publically that they are a valid candidate
   
1. Create voters
   1. Each voter should be able to prove publically that they are a valid voter
   1. Each voter would have only one booth across the country
   1. Each voter 
1. Cast votes
   1. Each vote should be encrypted
   1. Each vote should be able to prove publically that it is a valid vote
   1. Rate limiting to be done per voter to avoid choking the system
   1. Last vote of a voter is the only one to take effect
   1. Voter should be able to identify their vote and verify the candidate to which they voted
1. Count votes
   1. Votes are decrypted after quorum from authorities
   1. Votes should not be linkable to a specific voter



