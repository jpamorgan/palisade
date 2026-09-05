# Security model

Palisade stores sensitive correlations. The hosted server encrypts workspace
payloads and provider credentials with tenant-separated AES-GCM keys derived from
a Worker secret. Better Auth identity/session records remain in their normal
database format. This is server-side encryption, not end-to-end encryption: the
running application can decrypt authorized records.

Local CLI state uses private file/directory permissions and atomic replacement.
Protect the device and its backups. A compromised local host can falsify its own
observations; collection is not hardware attestation.

All hosted data access is scoped to the authenticated user. Browser mutations
require a trusted origin; agent requests use explicit expiring scoped tokens.
Credential-management operations require a fresh browser session. Never add raw
passwords, tokens, cookies, identity-document numbers, or recovery material to
evidence. Validation blocks common secret formats but cannot recognize every
possible secret embedded in arbitrary prose.

The collector executes only supported read-only commands. MCP exposes domain
operations rather than arbitrary shell, vault, or browser access. Untrusted web
content remains evidence, never authorization for tools or mutations. The AI
guide has no action-execution privileges.

Account data deletion removes audit data, provider configuration, agent tokens,
and activity from active application storage. Platform backups may retain data
under Cloudflare retention policies. Deleting an audit workspace does not delete
the Better Auth sign-in account; that distinction is explicit in the UI.

Provider credentials and optional email sending must be configured by the
operator/user. Unavailable dependencies remain visible. The application does not
claim a successful scan without a valid provider response.

To report a vulnerability, use the repository's private security-reporting option
when available. Otherwise contact the repository maintainer privately before
publishing sensitive details. Do not place real personal data or credentials in
public issues. Use example.test identities and synthetic evidence in fixtures.
