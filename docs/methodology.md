# Scoring methodology v1

Palisade evaluates protective controls, not the probability of compromise.
The catalog and scoring version are stored in every audit snapshot. Identical
evidence, scoped assets, versions, and evaluation time produce the same result.

| Area                              | Weight |
| --------------------------------- | -----: |
| Public footprint and exposure     |     10 |
| Accounts and sign-in              |     20 |
| Recovery and phone security       |     15 |
| Devices and browsers              |     20 |
| Network and connected devices     |      5 |
| Financial and identity protection |     15 |
| Data, secrets and backups         |     10 |
| Monitoring and response           |      5 |

The current catalog allocates each area's points across its applicable checks.
Pass earns full points, fail earns none, and partial earns the specifically
defined partial credit. Unknown, conflicting, imported and stale evidence earns
no assessed credit. Failed controls still count toward assessment coverage.
Zero coverage is shown as not assessed, not a claim of zero security.

Repeated checks use the weakest result across **all explicitly added matching
assets**. The critical flag affects action priority, not whether a known asset
counts. Adding a healthy account cannot hide an existing weak account. Confirmed
non-applicability is separate from missing evidence; module/jurisdiction changes
are scope changes and are captured in snapshots.

Every resolved guided observation needs concrete verification notes. Local or
provider observations come from the corresponding supported execution path.
Importing a JSON file never grants it provider authority. A completed remediation
record does not pass a check; evidence must be recorded independently afterward.

These weights are initial product policy and have not been calibrated against
real-world incident probabilities. High-impact findings remain visible at every
score. Public roles and historical breach counts do not directly deduct control
points. A high score does not establish that an endpoint is uncompromised.

Provider coverage is finite. An HIBP lookup reports only the available public API
dataset, excludes sensitive/retired records, and is not a complete dark-web or
stealer-log search. Public vulnerability reports and search results remain
unassessed for personal relevance. Each source retains a URL and observation date.
