# PLAN performance engineering runbook

## Current implementation status

This repository contains an offline PLAN action comparator (`tools/Compare_PlanActions.py`), a session timeline analyzer (`tools/Analyze_PlanSession.py`), and a read-only two-instance scope discovery helper (`tools/Get-SqlDatabaseCandidates.ps1`). The profile wrapper also restores inherited environment state and deletes only its own temporary mapping files on normal and exceptional exits.

The engine now has a measured, behavior-preserving optimization slice: common-template derivation and application are explicit profile opt-in; role coverage and membership dependency checks use per-database indexes; SQL logs separate connection and fetch time; and database planning logs elapsed planner time. Remediation identity inventory and decision generation also use principal indexes. The expensive catalog collection and serialization paths remain unoptimized and no five-minute runtime is claimed. This document remains an implementation handoff for the remaining work, not a performance-completion certificate.

## Baseline and offline regression

Preserve the old PLAN under ignored local `Results/` with secure local access. Do not commit migration data, identities, logs, mapping decisions or source/target instance names. Record the checked-out Git SHA and the exact resolved profile locally.

```powershell
python .\tools\Analyze_PlanSession.py '.\Results\BASELINE_SESSION\Session.log'
python .\tools\Compare_PlanActions.py '.\Results\BASELINE_SESSION\Plan01_Plan.csv' '.\Results\CANDIDATE_SESSION\Plan01_Plan.csv'
python -m unittest -q tests.test_plan_action_comparator tests.test_plan_session_analyzer
```

The comparator preserves duplicate rows, checks action order, and compares every supplied field. Equality of PLAN CSV files alone does not prove scope or inventory equivalence, approval integrity, APPLY correctness or SQL writes. Compare manifest schemas/hashes, scope, metadata completeness, dependency evidence, target-only records and drift protections separately. Compare offline artifacts captured from the same database state; fresh live runs may legitimately differ if security state changes.

The timing analyzer reports the union of recorded POSTPLAN phase intervals separately from their inclusive durations. It does not add SQL ElapsedMs to wall time or call uninstrumented time CPU time. For exact exclusive phase breakdown, add monotonic nested Stopwatch instrumentation in the canonical engine.

## Remaining optimization work (not implemented by the helper tools)

1. Instrument exclusive normalization, source/destination serialization, common-template, fingerprint/file hash, manifest and reporting durations. SQL connect/query/fetch and per-database planner timings are now emitted in `Session.log`; reconcile them to total wall time.
2. Replace repeated per-permission/per-role linear PowerShell scans with per-database collation-appropriate indexes and cached canonical keys; keep action identity/status/order unchanged.
3. Trim full object/column inventory only after proving destination existence for permission-referenced objects that have **zero** explicit target permissions. Preserve ownership, column/type, completeness and APPLY drift evidence. Version and validate decision-complete persistence before changing the contract.
4. Skip common-template derivation unless explicitly opted in; do not plan a template for additional databases solely because MODE=PLAN. The generic wrapper passes `scope.templatePolicy.enabled`, optional `sourceDatabases`, and optional `targetDatabases` to the engine. Intersect indexed security records only when enabled.
5. Benchmark pooling and optional bounded parallel inventory **after** sequential optimizations. Keep connections isolated; perform deterministic merge, planner and manifest publication on the main thread.
6. Independently repair typed identity lookup caching in remediation; do not turn a performance refactor into silent identity-reconciliation behavior changes.
7. Run the existing full test suite and PowerShell 5.1 AST/parser checks, targeted behavioral tests, baseline comparison and one fresh authorized read-only PLAN. Report actual before/after runtime, memory, SQL work and differences.

Do not execute APPLY merely to benchmark PLAN. Do not push corporate inventories or environment-specific connection profiles to this repository.

## Read-only scope discovery

Use `tools/Get-SqlDatabaseCandidates.ps1` with **explicit** source, destination and `-DatabaseLikePattern`. It runs a parameterized equivalent of `SELECT @@SERVERNAME AS SQLInstance, name AS DatabaseName, state_desc FROM sys.databases WHERE name LIKE @DatabasePattern` on both servers. The result is a candidate report, not permission to infer rename mappings, automatically template target-only databases or migrate nonmatching databases. Review ONLINE status on both sides, exact name matching, exclusions and metadata visibility before building a locally ignored PLAN profile.
