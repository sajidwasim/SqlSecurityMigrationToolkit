# SQL Server Security Migration Toolkit

A profile-driven toolkit for SQL Server Database Engine security inventory, comparison, read-only PLAN reporting and guarded, separately authorized APPLY. The core is application-agnostic; there are no application adapters or hardcoded server/database names.

## Current verification status

The canonical engine (`Invoke-SqlSecurityMigration.ps1`) exposes `-Mode Plan` and `-Mode Apply`; it does **not** expose a standalone `Verify` mode. After APPLY, `Finalize-Session` rechecks source drift and replans against fresh target metadata within the supported scope. The remediation script has a `Verify` mode that checks report production, **not** independent SQL security equivalence; its remediation APPLY deliberately fails closed. Static tests are not proof of a successful live SQL APPLY. See [known gaps](docs/KNOWN-GAPS.md).

The performance helper scripts and wrapper cleanup changes are present. The canonical engine now skips common-template derivation unless `scope.templatePolicy.enabled` is explicitly true and avoids repeated role/action scans during planning. The full inventory and serialization paths remain workload-dependent and have not been demonstrated to meet a five-minute target. See [performance runbook](docs/PERFORMANCE-RUNBOOK.md).

## Components

- `Invoke-SqlSecurityMigration-Generic.ps1`: validates a JSON profile and passes supported settings to the canonical engine.
- `Invoke-SqlSecurityMigration.ps1`: SQL inventory, planning, manifest, guarded APPLY and post-stage reconciliation.
- `Invoke-SqlSecurityRemediation.ps1`: derives remediation worklists; its own APPLY is not implemented.
- `modules/Config.psm1`, `config/schema/profile.schema.json`, and `config/examples/`: configuration processing, schema and sanitized examples.
- `tools/Get-SqlDatabaseCandidates.ps1`: read-only, two-instance database candidate discovery.
- `Run-SqlSecurityMigration.bat`: simple profile/mode launcher; it does not independently perform AST validation or approve individual SQL operations.

## Validate a profile without connecting to SQL

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-SqlSecurityMigration-Generic.ps1 `
  -ProfilePath .\config\examples\one-to-one.json -ValidateOnly
```

The example contains placeholders. **Do not execute PLAN using an unreviewed example.** Copy it into ignored `config/local/`, populate approved instances, database scope and exclusions, check schema validation, and confirm the resolved profile. SQL connection logic in the current engine uses Windows Integrated authentication and encrypted transport. Profile options are not evidence that other authentication or connection behaviors are implemented end to end.

## Read-only PLAN

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Invoke-SqlSecurityMigration-Generic.ps1 `
  -ProfilePath .\config\local\reviewed-profile.json -Mode Plan
```

PLAN reads SQL metadata and writes **sensitive local** session artifacts in `Results/` or an approved restricted output directory; it does not issue security DDL. The operator must inspect scope on **both** instances before running. Current preflight considers all ONLINE user databases on the destination, minus exclusions; additional destination databases are inventoried for completeness, but common-template actions are generated only when `scope.templatePolicy.enabled` is true. When enabled, `sourceDatabases` and `targetDatabases` can further restrict template evidence and application. No rename or identity mapping may be inferred automatically.

## APPLY boundary

APPLY requires a reviewed, complete, integrity-checked PLAN inventory with a pinned source inventory (`SourceInventory`), integrity checks, source-drift validation, a fresh target comparison, appropriate switches, interactive `REVIEWED` acknowledgement and exact target confirmation. SQL APPLY integration remains unverified. It must be separately authorized for a specific destination and stage. Do not run it based on this README or a PLAN request. Target-only security is preserved by the engine; effective AD access, externally provisioned security and unsupported securables are not established by PLAN alone.

## Tests

```powershell
python -m unittest -q tests.test_static tests.test_v2_contract
python -m unittest discover -s tests -p 'test_*.py'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\SmokeTest.ps1
```

These offline contracts cover scope, identity, manifest integrity, and wrapper behavior; they are not live SQL tests. Effective AD group nesting, application behavior, and SQL APPLY integration remain unverified. Known limits include effective AD group nesting, password hashes never being written to reports or committed, and no cross-database rollback. Run the PowerShell test on a compatible Windows host. A disposable SQL lab is required before claiming end-to-end APPLY correctness; a disposable SQL Server lab is required before claiming live APPLY behavior. See [test strategy](docs/TEST-STRATEGY.md), [workflow](docs/MIGRATION-WORKFLOW.md) and [parameter guide](docs/SQL_SECURITY_MIGRATION_PARAMETERS.md). Never commit real profiles, inventories, logs, identity decisions or session reports to GitHub.
