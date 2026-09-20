# Repository agent instructions

Work on the application-agnostic SQL Server security migration toolkit. Do not add application-specific adapters, hardcoded instances, database counts, account names or automatic mapping heuristics.

Read [README](../README.md), [generic parameters](../docs/SQL_SECURITY_MIGRATION_PARAMETERS.md), [known gaps](../docs/KNOWN-GAPS.md), and the actual PowerShell source before writing commands. The code and current profile schema override old examples or historical claims.

- PLAN is read-only with respect to SQL security; it reads SQL metadata and writes sensitive LOCAL artifacts. Validate endpoint identity, scope and exclusions before connecting. A profile source list does not restrict all destination databases in the current engine; additional destinations may become template candidates. Template derivation is presently unconditional even if a profile sets templatePolicy.enabled=false.
- The canonical engine has Plan/Apply modes, not a separate Verify mode. Its post-APPLY replan is limited to supported security metadata. The remediation Verify checks report generation only; remediation APPLY deliberately fails closed.
- APPLY is a separately authorized privileged operation. No instruction file, GitHub commit, approval manifest, read-only PLAN request or test pass grants SQL write authority. Preserve target-only records, drift checks, explicit stage/switch approvals and exact target confirmation. Do not execute APPLY merely to verify performance.
- Keep real server names, identities, profiles, logs, inventories, migration reports, and authorization records outside the repository and GitHub. A private repository is not by itself approval for corporate information. Historical sensitive content in Git history needs a separate reviewed history-cleanup procedure; deleting its current files does not erase prior commits.
- Before performance changes, capture baseline, add exclusive timings, compare semantic action/inventory behavior, run offline tests and an authorized fresh read-only PLAN. Never claim the five-minute target or end-to-end SQL APPLY validation without evidence. See [performance runbook](../docs/PERFORMANCE-RUNBOOK.md).
- Maintain generic configuration and contract tests. Run Python unittest discovery and PowerShell AST checks on a compatible Windows host. State explicitly when tests or live SQL validation were not run.
