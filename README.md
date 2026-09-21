# SQL Server Security Migration Toolkit

A profile-driven toolkit for SQL Server Database Engine security inventory, comparison, read-only PLAN reporting and guarded, separately authorized APPLY. The core is application-agnostic; there are no application adapters or hardcoded server/database names.

## Current verification status

The canonical engine (`Invoke-SqlSecurityMigration.ps1`) exposes `-Mode Plan` and `-Mode Apply`; it does **not** expose a standalone `Verify` mode. After APPLY, `Finalize-Session` rechecks source drift and replans against fresh target metadata within the supported scope. The remediation script has a `Verify` mode that checks report production, **not** independent SQL security equivalence; its remediation APPLY deliberately fails closed. Static tests are not proof of a successful live SQL APPLY. See [known gaps](docs/KNOWN-GAPS.md).

The performance helper scripts and wrapper cleanup changes are present. The canonical engine now skips common-template derivation unless `scope.templatePolicy.enabled` is explicitly true and avoids repeated role/action scans during planning. The full inventory and serialization paths remain workload-dependent and have not been demonstrated to meet a five-minute target. See [performance runbook](docs/PERFORMANCE-RUNBOOK.md).

**Review-branch addition:** the new audit collector and JSON-to-Excel reconciliation are independent, read-only companion workflows. Windows integration, SQL integration, output security and application acceptance have not yet been verified. The migration engine is unchanged. See [security audit runbook](docs/SECURITY-AUDIT.md).

## Components

- `Invoke-SqlSecurityMigration-Generic.ps1`: validates a JSON profile and passes supported settings to the canonical engine.
- `Invoke-SqlSecurityMigration.ps1`: SQL inventory, planning, manifest, guarded APPLY and post-stage reconciliation.
- `Invoke-SqlSecurityRemediation.ps1`: derives remediation worklists; its own APPLY is not implemented.
- `Invoke-SqlSecurityAudit.ps1`: new generic multi-instance, read-only security metadata collection, incident evidence and local XLSX/JSON export (review candidate).
- `Compare-SqlSecurityAudit.ps1`: new offline, read-only comparison of two completed local audit inventories; outputs differences and coverage as an Excel workbook, not executable SQL (review candidate).
- `modules/SecurityAudit.psm1`, `modules/AuditExcel.psm1`: audit-specific reusable SQL metadata and dependency-free XLSX functions. Existing migration engine has not been refactored to use these modules.
- `modules/Config.psm1`, `config/schema/profile.schema.json`, and `config/examples/`: configuration processing, schema and sanitized examples.
- `tools/Get-SqlDatabaseCandidates.ps1`: read-only, two-instance database candidate discovery.
- `tools/Test-SqlConnection.ps1`: read-only, parameterized SQL connectivity and endpoint-identity validation.
- `Run-SqlSecurityMigration.bat`: simple profile/mode launcher; it does not independently perform AST validation or approve individual SQL operations.

## Security audit (review candidate)

Invoke the read-only audit from an existing authorized Windows account, with explicitly selected instances and database scope:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-SqlSecurityAudit.ps1 `
  -SqlInstances 'EXAMPLE-SQL-01' -DatabaseName 'ExampleDatabase' `
  -AccountName 'EXAMPLE\service' -ObjectSchema 'dbo' -ObjectName 'proc_example'
```

No credentials are passed, permissions changed or APPLY called. Outputs contain sensitive metadata and remain in an ACL-restricted local directory outside Git. Any certificate exception requires separate approval for its exact endpoint; TLS encryption remains enabled. Reconciliation consumes complete local JSON snapshots and generates a review workbook, not remediation scripts. **See [runbook and limitations](docs/SECURITY-AUDIT.md) before executing.** Do not run on production merely because the scripts exist on a feature branch.

## Agent SQL Connectivity Procedure

When an agent needs a SQL connection, it must first read and use `tools/Test-SqlConnection.ps1` from this repository. Do not create an ad-hoc connection script or hardcode server names, database names, credentials, or certificate settings. The security audit is a separate reviewed workflow, not an agent connectivity probe.

Use caller-supplied values and validate the canonical endpoint returned by SQL Server:

```powershell
$tool = Join-Path (Get-Location) 'tools\Test-SqlConnection.ps1'
$instance = '<approved-instance>'
$canonicalName = '<expected-canonical-server-name>'

powershell.exe -NoProfile -ExecutionPolicy Bypass -File $tool `
  -ServerInstance $instance `
  -ExpectedServerName $canonicalName
```

The helper uses Windows Integrated Authentication and encrypted transport. It performs only read-only validation queries and returns structured JSON with a success exit code. Use `-TrustServerCertificate` only when a human has explicitly approved that exact endpoint exception; it retains encryption but does not validate certificate identity. Treat endpoint mismatch, login failure, incomplete metadata, or encryption failure as blockers. Store any output in an ACL-protected, ignored local results directory and never publish it.

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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-SqlSecurityAudit.ps1
```

The new audit smoke tests cover parsing, native XLSX structure and one synthetic comparison only. They do not prove Windows or SQL integration; run them on a compatible Windows host and review the separate SQL integration checklist in the audit runbook. The existing offline contracts cover scope, identity, manifest integrity, and wrapper behavior; they are not live SQL tests. Effective AD group nesting, application behavior, and SQL APPLY integration remain unverified. A disposable SQL lab is required before claiming end-to-end APPLY correctness. See [test strategy](docs/TEST-STRATEGY.md), [workflow](docs/MIGRATION-WORKFLOW.md), [audit runbook](docs/SECURITY-AUDIT.md) and [parameter guide](docs/SQL_SECURITY_MIGRATION_PARAMETERS.md). Never commit real profiles, inventories, logs, identity decisions or session reports to GitHub.
