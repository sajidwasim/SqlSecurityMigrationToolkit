# Generic test strategy and evidence

## Offline tests currently available

The repository contains Python static/contract tests under `tests/test_*.py`, a Windows PowerShell parser smoke test at `tests/SmokeTest.ps1`, and helper-specific tests for PLAN action comparison and session analysis. These check selected source-text invariants and offline behavior, **not** successful live SQL migration. No test pass is claimed by this document unless a dated execution log and commit SHA are supplied.

```powershell
python -m unittest discover -s tests -p 'test_*.py'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\SmokeTest.ps1
```

Run PowerShell checks on a compatible Windows host. Record revision, platform, command, return code and failures.

## Required behavioral fixtures

Use synthetic metadata covering missing vs present-with-zero-permissions destination objects, column permissions, DENY, GRANT WITH GRANT OPTION, owners and role ownership, login/user SID conflicts, source/target name mappings, excluded and additional destination databases, duplicate/case-sensitive identities, disconnected/insufficient-metadata states and target-only preservation. Compare normalized action identity, kind, status, reason, SQL semantics, dependencies, inventory scope/completeness and manifest evidence. Equal action counts or identical CSV exports alone are insufficient.

## Performance checks

Capture exclusive nonoverlapping phases, wall-clock time, SQL reads/load, memory, artifact sizes and deterministic output on the same baseline fixtures. Do algorithmic work before parallelism. Run an authorized read-only live PLAN only after offline equivalence tests pass. A runtime goal is not a measured result.

## Disposable SQL lab before APPLY claims

Provision deliberately small synthetic source/target SQL instances and accounts. Test PLAN under read-only security permissions, source drift, manifest/plan tampering, exact instance/scope/approval gates, SID conflicts, stage isolation, SQL write interception/audit, partial failure and fresh post-stage reconciliation. Never use a real target as a disposable lab or interpret a no-op APPLY preview as proof that actual DDL/DCL works. Validate supported SQL Server versions and security semantics explicitly.

The engine's standalone Verify mode is absent; remediation Verify checks report generation only, and remediation Apply throws intentionally. See [known gaps](KNOWN-GAPS.md) and [integration checklist](../tests/Integration-Checklist.md).
