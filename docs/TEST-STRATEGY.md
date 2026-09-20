# Complete destination coverage

Static contracts cover the 15 exact matches, 15 additional destinations, common-template derivation, missing target securables, SID conflicts, repeated APPLY safeguards, partial execution and full 30-database manifest fields. Disposable SQL integration tests must additionally provision 15 source and 30 destination databases, verify exact-match and common-template planning, rerun APPLY to confirm idempotency, simulate conflicts and drift, and assert final reconciliation across all 30 databases. No live SQL validation is claimed in this repository run.

# Test strategy and validation status

## Current validation in the repository

- [tests/SmokeTest.ps1](../tests/SmokeTest.ps1): verifies the PowerShell script parses successfully with the Windows AST parser.
- [tests/test_static.py](../tests/test_static.py): tests lexical balance, artifact existence, contract expectations, and a few guardrail checks.
- [tests/test_v2_contract.py](../tests/test_v2_contract.py): validates the pinned-inventory contract and safety flags.

## What these tests do not cover

- connectivity to SQL Server
- real identity mapping and SID conflict behavior
- database role creation and permission execution
- cross-version hash compatibility
- source drift simulation
- production-grade migration compliance

## Recommended next test layer

1. disposable SQL Server integration tests in a lab environment
2. source drift and tampering tests against the inventory
3. multi-stage `APPLY` dry-run execution with no DDL on a restored target
4. failure-continuation tests to confirm independent operations do not poison the rest of the migration
5. final reconciliation verification after a staged migration

## Acceptance criteria before production use

- all static tests pass
- AST parse tests pass on Windows PowerShell 5.1
- disposable integration checklist passes for PLAN and APPLY
- identity mapping, SID conflict, and permission guardrails are verified against real servers
- a fully reviewed, approved plan is used for each APPLY run

The repository currently supports this as a candidate implementation, not a production-certified migration engine.
