# Generic SQL Security Audit and Reconciliation (candidate feature)

**Status: review branch; Windows PowerShell, live SQL, and application acceptance are NOT verified. Do not merge as production-ready on the strength of code inspection alone.**

## Scope and design

`Invoke-SqlSecurityAudit.ps1` is a read-only companion to the migration engine. It uses `modules/SecurityAudit.psm1` for SQL metadata and `modules/AuditExcel.psm1` for native XLSX. `Compare-SqlSecurityAudit.ps1` compares two completed local JSON inventories; it neither connects to SQL nor produces executable remediation. The existing migration engine and `Invoke-SqlSecurityRemediation.ps1` are intentionally unchanged; remediation APPLY remains unsupported in the latter. Future migration-engine refactoring requires separate regression and SQL integration gates.

The collector is application-agnostic: no actual company names, server names, service identities, passwords, inventories or incident data are committed. Specify scope explicitly. Outputs contain sensitive security metadata and must remain local.

## Requirements

Windows PowerShell 5.1, an existing authorized Windows process identity, SQL Server metadata visibility, and access to SQL Server 2012 or later. Start PowerShell under the approved SQL inventory account. The audit does not accept passwords or perform impersonation. Do not create logins, expand permissions or grant `sysadmin` merely to make an audit connect. Insufficient catalog visibility marks collection incomplete.

SQL uses Windows Integrated Security and `Encrypt=True`. Certificate verification is on by default. **Only after security approval**, add exact selected endpoints to `-TrustCertificateForInstances`; this maintains encryption but skips certificate identity validation for those endpoints. No implicit fallback or all-server bypass is available. The returned `SERVERPROPERTY('ServerName')` must match the requested name, unless an operator explicitly supplies `-ExpectedCanonicalNames` for a known alias. The collector also checks `sys.dm_exec_connections.encrypt_option`; failures are reported rather than treated as success.

## Run a targeted read-only incident audit

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-SqlSecurityAudit.ps1 `
  -SqlInstances 'EXAMPLE-SQL-01','EXAMPLE-SQL-02' `
  -DatabaseLikePattern 'ExampleApp%' `
  -AccountName 'EXAMPLE\service-account' `
  -ObjectSchema 'dbo' -ObjectName 'proc_example'
```

To audit explicit database names, use `-DatabaseName 'ExampleDbA','ExampleDbB'`. Use `-ExcludedDatabaseName` to suppress unwanted databases. The pattern is a PowerShell wildcard, **not** SQL `LIKE` syntax. A lone `%` is rejected. A database listed explicitly is selected even if it does not match the pattern, unless it is excluded. The collector enumerates all user databases first and records SELECTED, EXCLUDED, OUT_OF_SCOPE, NOT_ONLINE or DATABASE_SNAPSHOT. It scans only selected, ONLINE, non-snapshot databases. Require the selection and error rows to match the intended authorization.

For an explicitly approved TLS exception on a selected endpoint:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-SqlSecurityAudit.ps1 `
  -SqlInstances 'EXAMPLE-SQL-01' -DatabaseName 'ExampleDbA' `
  -TrustCertificateForInstances 'EXAMPLE-SQL-01'
```

For a reviewed DNS alias, add `-ExpectedCanonicalNames @{'EXAMPLE-ALIAS'='EXAMPLE-SQL-01'}` from an interactive PowerShell call; the `-File` invocation may require quoting the hashtable, so prefer invoking the script directly within an authorized session.

## Evidence

A run creates `SqlSecurityAudit_<timestamp>_<runid>.xlsx` and a same-named `.json` in an ACL-restricted local directory under the current user's LocalAppData by default. Existing files are not overwritten. The collector refuses output inside a Git checkout and fails before connecting if it cannot restrict the output folder ACL. Upload neither the workbook nor JSON to GitHub. Purge according to the organization's retention policy.

Worksheets: `RunInfo`, `Databases`, `ServerLogins`, `ServerRoles`, `ServerPermissions`, `DatabaseUsers`, `DatabaseRoles`, `DatabasePermissions`, `Schemas`, `Objects`, `Findings`, `Errors`. The database metadata includes explicit object/column, schema and database permissions, roles, users and object owner context; server metadata includes principals, roles and explicit server permissions. Password hashes and SQL password material are not queried. Excel values are written as text cells, not formulas. JSON supports later comparison.

A nonzero status (exit code `2`) means incomplete collection; an unexpected fatal error terminates with a failure. Review `RunInfo`, `Errors`, all requested instances and database scope before using findings. Access to catalogs can be restricted even when some queries succeed. A scan marked completed is evidence of successful query execution, not confirmation of complete effective security.

## Reconciliation

Collect a separate source and target snapshot using approved access and scope. Both snapshots must report `Complete=true`. Compare one explicitly paired instance at a time:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Compare-SqlSecurityAudit.ps1 `
  -SourceInventoryPath 'C:\ApprovedLocalFolder\source.json' `
  -TargetInventoryPath 'C:\ApprovedLocalFolder\target.json' `
  -SourceInstance 'EXAMPLE-SOURCE' -TargetInstance 'EXAMPLE-TARGET'
```

Optional CSV columns: `-DatabaseMapCsv` requires `SourceDatabase,TargetDatabase`; `-IdentityMapCsv` requires `SourceIdentity,TargetIdentity`. Exact names are compared by default. Each record is compared using stable names, relevant principal attributes and permission state (not destination-specific object IDs). The workbook includes `Coverage`, `Differences`, `TargetFindings`, `Caveats`. A difference is a review item, **not** an automatically identified fault; it generates no `GRANT`, `ALTER USER`, `DENY`, `REVOKE` or APPLY. Missing/extra target databases are flagged in coverage and result in exit code `2`.

## Incident interpretation and known limits

When `-AccountName` and `-ObjectName` are supplied, `Findings` checks matching objects, recorded database principals, explicit database/schema/object `EXECUTE` or `CONTROL`, `DENY`, public and recorded transitive database-role membership. It deliberately does NOT assert SQL effective permissions: Windows group token access, external identity nesting, module signing, impersonation, ownership chaining, fixed-role implicit permissions and actual application execution require separate assessment. Missing recorded grant paths must never trigger automatic broad grants or `db_owner`.

Server permissions on securable classes other than LOGIN may still require class-specific identifier normalization; compare such differences manually. The audit compares catalog metadata, not row-level security predicates, Azure/Entra permissions, module definitions, secrets, credentials, linked-server passwords, or SharePoint-specific configuration. No assertion is made that every kind of securable is fully covered.

## Tests and release gates

1. Run `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-SqlSecurityAudit.ps1` on Windows. The test parses all new PowerShell files, creates a synthetic XLSX, checks text-only cells and verifies one synthetic missing role-membership discrepancy without SQL connections.
2. Run the repository's full existing regression suite and Windows smoke tests. Confirm existing PLAN/APPLY behavior is unchanged.
3. In an explicitly authorized SQL lab, test catalog visibility restrictions, TLS valid/rejected/approved exception, denied Windows login, aliases, ONLINE/OFFLINE databases, SQL 2012+ metadata queries, all permission classes, large workbooks and interrupted scans. Verify `SELECT`-only execution via Extended Events.
4. Obtain review of source/target name and identity mapping, group-derived access limits, output ACLs and report retention. Require a real incident case to pass application-owner validation before claiming production readiness.

**No production APPLY or SQL security change is authorized by these scripts or documentation.**
