# Palisade development

Read docs/BUILD-CONTRACT.md and preserve the shared core/service boundaries.
Use separate reviewers for substantial security, scoring and permission changes.
Build in this repository only. Never import, copy or publish personal audit data
from a parent directory. Fixtures and screenshots must use synthetic examples.

Cloudflare infrastructure uses Alchemy and the globally configured default
profile. Do not use OAuth, request credentials or store Cloudflare tokens in
project files. Report authentication failures without changing methods.

Keep the web product a simple grouped checklist with clear priority and progress.
Put advanced tools behind secondary actions. Do not add dashboards or duplicate
interfaces that obscure the next useful check.

Run meaningful tests. Never fabricate provider success, personal compromise or
scores. Do not automatically change account/device security settings. Guided
mitigations require separate evidence verification.
