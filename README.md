# Generic SQL Server Security Migration Toolkit

This repository provides a configuration-driven SQL Server Database Engine security inventory, comparison, plan, approval, migration, and verification toolkit. It contains no application adapter and does not infer application ownership from names, roles, databases, or identities.

## Safety Status

PLAN and VERIFY are read-only. APPLY requires a complete, integrity-checked PLAN inventory, explicit stage approvals, exact target confirmation, and a designated disposable lab or separately authorized target. No SQL write is authorized by this repository review. Static and offline behavioral tests do not prove live SQL APPLY behavior.

## Entry Points

- `Invoke-SqlSecurityMigration-Generic.ps1` loads and validates a profile, resolves safe defaults, and invokes the canonical engine.
- `Invoke-SqlSecurityMigration.ps1` is the PowerShell 5.1-compatible migration engine.
- `Invoke-SqlSecurityRemediation.ps1` produces generic external-ownership, identity, dependency, and approval worklists from a PLAN.
- `Run-SqlSecurityMigration.bat` is a thin profile-driven launcher with no environment defaults.

## Profile Validation Dry Run

Use `-ValidateOnly` to validate configuration and print the resolved redacted profile without connecting to SQL:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-SqlSecurityMigration-Generic.ps1 `
  -ProfilePath .\config\examples\one-to-one.json -ValidateOnly
```

Sanitized profiles cover discovery-only, one-to-one, renamed subset, one-to-many template, SQL authentication workflow, Windows identity mapping, and explicit external-ownership decisions. Replace all placeholder instances and databases before PLAN.

## PLAN

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Invoke-SqlSecurityMigration-Generic.ps1 `
  -ProfilePath .\config\examples\one-to-one.json -Mode Plan
```

PLAN collects SQL metadata, normalizes scalar records, creates a pinned source inventory and destination snapshot, derives only explicitly configured template evidence, and writes review artifacts. It never performs target security DDL.

## APPLY Template

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Invoke-SqlSecurityMigration-Generic.ps1 `
  -ProfilePath .\config\local\approved-profile.json -Mode Apply `
  -InventoryPath 'C:\Secure\Results\ApprovedSession\SourceInventory'
```

Do not use this template until the exact PLAN, target, scope, mapping hash, capability result, approval record, and lab/write authority are independently confirmed. Target-only objects are preserved; DROP, REVOKE, implicit identity remapping, AD writes, and application provisioning are not performed.

## Testing

```powershell
python -m unittest -q tests.test_static tests.test_v2_contract tests.test_plan_apply_contract tests.test_remediation_contract tests.test_generic_contract
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\SmokeTest.ps1
```

The tests are offline contracts and AST checks. SQL APPLY integration remains unverified until an explicitly designated disposable SQL Server lab is available. The repository supports Windows Integrated Authentication by default and does not persist SQL password hashes.

## Scope Limits

The engine compares explicit SQL Server security metadata. effective AD group nesting, application behavior, external provisioning, unsupported securables, SQL Agent credentials, certificate/key material, and cross-database rollback require separate evidence and are reported as unsupported or external prerequisites. Legacy engine versions and cloud services require capability-specific validation; no version is considered live-supported solely from static tests.
