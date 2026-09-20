# Genericization boundary and current evidence

The reusable engine's supported security model is SQL Server Database Engine metadata. Instances, databases, identity mappings, exclusions and operator external-ownership decisions are inputs, not application heuristics. There is no application adapter in the current project layout.

The profile-driven wrapper supports connection-free `-ValidateOnly` and delegates to the canonical engine. The BAT launcher prompts for a profile and Plan/Apply mode, without historical server/database defaults. The wrapper uses `try/finally` to delete its own mapping files and restore an inherited environment variable. `config/local/` and `Results/` are ignored by Git.

## Remaining qualification

Generic design does not mean all configuration-schema options are implemented in the canonical engine. The SQL connection path currently uses Windows Integrated authentication and fixed connection options; review options such as SQL authentication/pooling before use. The engine's SQL application-name string still includes an organization-specific label and should be changed in a separately tested code edit. It does not introduce an application adapter, but it is not fully neutral branding.

The current engine inventories destination ONLINE user databases beyond the named source list and derives a template even if the profile disables template policy. This is a real behavioral gap requiring a code fix, contract tests and scope review; documentation must not conceal it. Historical migration reports were excluded from the current repository tree in the documentation cleanup, but previous Git commits remain reachable until an independently reviewed history cleanup is performed. Do not regard current-tree deletion as removal from Git history or approval to store former employer data externally.

No live APPLY integration, full SQL security equivalence or five-minute PLAN benchmark is established by this document. See [known gaps](KNOWN-GAPS.md) and [performance runbook](PERFORMANCE-RUNBOOK.md).
