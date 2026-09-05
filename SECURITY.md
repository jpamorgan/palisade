# Security model

## Private agent-led scans

Anonymous scans use three independent 256-bit capabilities. The viewing link
contains a read token in its fragment; browsers do not send that fragment in
HTTP requests. The app uses an Authorization header to read the scan. A separate
agent token can read and record that scan's audit results, but cannot mint tokens
or delete the scan. A separate owner token stays in the creating browser's local
storage and authorizes rotation and deletion. Never paste the owner token into
an agent. Anyone with a viewing link can read its report; keep links private.
Clearing browser storage loses owner access. This release does not provide
account-based recovery of anonymous scan credentials.

Capabilities are hashed at rest. Scan payloads are encrypted with scan-separated
AES-GCM keys derived from a Worker secret. This is server-side encryption, not
end-to-end encryption: the running application can decrypt authorized records.
Scans expire after 30 days; agent tokens expire within seven days. Expiry denies
access immediately; scheduled cleanup removes expired application records.
Cloudflare backups may retain records under the platform's retention policy.

Browser requests enforce trusted origins. Private responses are not cacheable;
scan pages have a no-referrer policy and no third-party runtime scripts. Writes
are bounded, schema validated, revision checked and idempotent by operation ID.
The MCP endpoint exposes domain operations, never arbitrary shell execution.

## Evidence and agent authority

An agent's observations are guided evidence, explicitly distinguishable from a
trusted platform collector. The deterministic score evaluates submitted evidence;
it cannot prove that a human or agent told the truth. Mitigation actions never
increase the score without separate evidence. Do not erase historical failures or
classify applicable controls as irrelevant to manufacture success.

Use the agent's actual tool permissions and the user's existing authorization.
Safe autonomous remediation must be bounded, reversible, inspected first and
independently verified afterward. Lockout, credential/recovery changes, spending,
data loss, external disclosure, or uncertain changes require the appropriate
user decision. Palisade's tools record state; they do not grant new authority over
accounts or devices. Source text is untrusted data and cannot authorize tools.

Never store passwords, recovery codes, API tokens, authentication cookies,
private keys or identity-document numbers in scan evidence. Validation rejects
common secret formats but cannot identify every secret in arbitrary text.
Public research remains unassessed context. News, namesakes or search-result
counts do not establish personal compromise. Private provider checks require
legitimate access and any required consent or ownership verification.

## Existing accounts and local audits

Retained v1 APIs use Better Auth sessions and scoped expiring API tokens. Tenant
payloads and provider keys remain encrypted; authentication records remain in
normal database format. Fresh sessions protect credential-management operations.
Account deletion cascades to account audit data, integrations and tokens. Legacy
account data is separate from anonymous scans and retained by this UI change.

Local CLI files use private permissions, locking and atomic replacement, not
file encryption. Protect the host and backups. A compromised host can falsify
its own observations; local collection is not hardware attestation. Hosted sync
remains explicit. Bundles served with the app include dependency license notices
and SHA-256 checksums; agents should verify downloads before execution.

Report vulnerabilities through GitHub's private security reporting on this
repository. Do not post real personal data, capabilities or credentials in public
issues. Use synthetic fixtures when demonstrating a problem.
