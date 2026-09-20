# Release notes and evidence status

## Generic toolkit baseline

The repository contains a profile-driven wrapper, the canonical SQL Server security migration engine, remediation reporting, schema/example profiles, tests, and local performance/scope-discovery helpers. Current operation modes of the canonical engine are `Plan` and `Apply`; the remediation command separately exposes `Plan`, `Verify` (report-production check), and `Apply` (deliberately fails closed). There is no independently validated, standalone SQL VERIFY command.

## Current changes and limitations

- Generic source/target selection comes from configuration and operator-supplied scope. No application adapter is required.
- The wrapper has `try/finally` cleanup for files it creates and restores a pre-existing external-ownership environment variable.
- Read-only candidate discovery, PLAN-action CSV comparison and session-timeline helper scripts are available.
- Current documentation no longer presents historical migration counts, application-specific database lists or previous environment decisions as generic instructions.
- **Performance refactoring of the canonical engine remains incomplete and unbenchmarked.** Helper tools are not evidence of a faster PLAN.
- **Live SQL APPLY has not been validated through the repository evidence inspected for this release.** Static contract/AST tests cannot establish successful database execution or effective access equivalence.
- The engine currently derives a common template even when the profile's template policy is disabled and still considers other nonexcluded ONLINE destination user databases; review scope explicitly before PLAN.

See [README](README.md), [architecture](docs/ARCHITECTURE.md), [known gaps](docs/KNOWN-GAPS.md), and [performance runbook](docs/PERFORMANCE-RUNBOOK.md). No production certification, application support guarantee, or completed performance target is asserted here.
