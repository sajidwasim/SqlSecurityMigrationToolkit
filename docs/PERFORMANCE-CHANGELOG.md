# Performance Changelog

## 2026-09-20

- Added explicit profile-controlled common-template execution.
- Added optional template source and target scopes.
- Replaced repeated role coverage queries with per-database indexes.
- Replaced per-membership action-list rescans with a single dependency index.
- Fixed Windows PowerShell 5.1 parsing in the database discovery helper for an interpolated variable followed by a colon.

Not included: object catalog contract changes, persistence format changes, SQL connection pooling changes, or parallel inventory. Those require measured equivalence evidence.
