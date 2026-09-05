# Palisade development

Before starting work, generate a random seed using a Bash string for fresh ideas.

Read docs/BUILD-CONTRACT.md and preserve the shared core/service boundaries.
Use separate reviewers for substantial security, scoring and permission changes.
Build in this repository only. Never import, copy or publish personal audit data
from a parent directory. Fixtures and screenshots must use synthetic examples.

Cloudflare infrastructure uses Alchemy and the globally configured default
profile. Do not use OAuth, request credentials or store Cloudflare tokens in
project files. Report authentication failures without changing methods.

Keep exactly two product routes: a bold landing page with one copy-agent-prompt
action, and a private live scan with clear score, coverage and scannable results.
Agents own research, verification and safe authorized fixes. Do not add account
onboarding, settings, provider forms, dashboards or duplicate product interfaces.

Run meaningful tests. Never fabricate provider success, personal compromise or
scores. Palisade tools record evidence and actions; external agents may implement
only safe fixes within their actual authorization and must reverify afterward.
