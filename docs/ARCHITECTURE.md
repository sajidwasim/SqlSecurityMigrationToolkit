# Architecture

## Repository inventory

- [Invoke-SqlSecurityMigration.ps1](../Invoke-SqlSecurityMigration.ps1): primary PowerShell implementation.
- [Run-SqlSecurityMigration.bat](../Run-SqlSecurityMigration.bat): interactive launcher, preflight syntax checks, and explicit approval prompts.
- [README.md](../README.md): project overview and operational guidance.
- [RELEASE_NOTES.md](../RELEASE_NOTES.md): migration-engine changes from the previous draft.
- [tests/SmokeTest.ps1](../tests/SmokeTest.ps1): parse-only validation of the PowerShell script.
- [tests/test_static.py](../tests/test_static.py): static invariant checks.
- [tests/test_v2_contract.py](../tests/test_v2_contract.py): pinned-inventory contract tests.

## Execution flow

1. Parameter validation in the script entry block rejects invalid source/target pairs, mode mismatches, and unsupported APPLY conditions.
2. `Verify-Preflight` inventories all 15 source databases and all 30 destination databases, classifying 15 exact matches and 15 additional destinations.
3. `Build-Plan` captures source metadata, compares exact matches, derives a common template from the complete source inventory, and creates the action matrix for additional databases without assuming source-specific securables are universal.
4. `Save-InventoryManifest` writes a source inventory folder containing `Manifest.json`, XML snapshots, and readable CSV exports.
5. `Load-ApprovedInventory` is used only for APPLY and verifies hash and fingerprint integrity before any SQL change.
6. `Execute-Phase` re-runs planning logic, executes only `Planned` actions for the selected phase, and records execution results.
7. `Finalize-Session` compares the final target state against the approved source inventory and writes `Summary.json` plus execution logs.

## Key functions and responsibilities

- `Build-Plan`: creates the migration plan and reports.
- `Derive-CommonTemplate`: computes common principals, schemas, roles, memberships and permissions across all source databases and emits source-evidence classifications.
- `ApplyCommonTemplate`: plans the approved common template against each additional destination database.
- `Verify-Preflight`: validates server/database identity, connectivity, and scope.
- `Load-ApprovedInventory`: validates a prior PLAN inventory before APPLY.
- `Verify-SourceUnchanged`: prevents drift from the approved source inventory.
- `Plan-ServerSecurity`: compares server logins, roles, memberships, and permissions.
- `Plan-Database`: compares database principals, users, roles, schemas, and explicit permissions.
- `Execute-Phase`: executes approved SQL for a single stage.
- `Finalize-Session`: writes execution and reconciliation output.

## Evidence-based architecture summary

The implementation is intentionally not a blind SQL replay engine. It is a read-only planner that binds APPLY to a previously generated, hashed inventory of all 15 source and 30 destination databases, requires explicit approval of `CommonTemplate.json`, and revalidates before each stage. Exact matches and additional destinations have different planning semantics; source-specific object and permission references remain blocked or manual-review items for additional databases.
