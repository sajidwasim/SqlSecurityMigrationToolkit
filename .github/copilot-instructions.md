# Copilot instructions for this repository

This project is a privileged SQL Server migration toolkit. The workflow is intentionally conservative.

## Working assumptions

- Read [../docs/SQL_SECURITY_MIGRATION_PARAMETERS.md](../docs/SQL_SECURITY_MIGRATION_PARAMETERS.md) completely before any SQL Security Migration Toolkit task. Treat it as the project’s migration profile and parameter reference.
- The implementation lives in [Invoke-SqlSecurityMigration.ps1](../Invoke-SqlSecurityMigration.ps1).
- PLAN is read-only; APPLY requires a previously approved `SourceInventory` folder and a fresh target comparison.
- Treat instances, databases, identities, exclusions, and mappings as profile inputs. Historical environment values are not runtime defaults.
- Destination scope is profile-defined. One-to-many common templates require explicit source/target sets, evidence, applicability, and approval; no database counts are assumed.
- The tool must not silently overwrite a destination identity or remove target-only objects.
- Inventory integrity is verified using manifest hashes and snapshot fingerprints. Source drift detection is part of the APPLY guardrail.
- The BAT launcher requires separate approval for privileged role assignments and privileged permission changes; do not coalesce them into a single approval without explicit user direction.

## Before proposing code changes

1. Confirm whether the change is a documentation-only task or a code-path change.
2. Trace the existing function flow (`Verify-Preflight`, `Build-Plan`, `Execute-Phase`, `Finalize-Session`).
3. Add or adjust tests in [tests](../tests) to capture the behavior.
4. Avoid changes that bypass the explicit approvals or target confirmation prompts.

## Validation

- Use the static test suite in [tests](../tests) to validate repository contracts.
- Prefer `python -m unittest -q tests.test_static tests.test_v2_contract` for the current repo.
- Do not claim live SQL Server validation without a disposable lab environment and explicit authorization.
