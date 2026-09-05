# Contributing

Use Bun, run the test/typecheck/build commands in README, and keep changes focused.
The shared core is runtime-neutral; neither the website nor CLI gets its own
scoring implementation. Add checks to the catalog with precise verification,
freshness, applicability, and mitigation guidance.

For new providers, document the information disclosed, licensing/entitlement
requirements, errors and coverage. Use fixed endpoints, bounded requests and
sanitized responses. A timeout or missing key must never become a pass.

Use synthetic fixtures. Do not include personal audit exports, screenshots of
real accounts, credentials, or data from the parent workspace. New public API and
MCP capabilities require tests for user isolation, scopes, error behavior, and
evidence authority. Have a different reviewer challenge the implementation.
