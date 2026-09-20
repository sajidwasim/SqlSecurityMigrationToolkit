# Generic configuration and parameter guide

This is a **current generic reference**, not a historical migration profile, database list, approval record or execution authorization. Source instances, destination instances, database scope, exclusions, ownership decisions and identities are operator-supplied and must not be hardcoded in this repository. The PowerShell scripts and [profile schema](../config/schema/profile.schema.json) are authoritative if they change.

## Recommended entry point

`Invoke-SqlSecurityMigration-Generic.ps1 -ProfilePath <reviewed-local-json> [-Mode Plan|Apply] [-ValidateOnly] [-Stage Prompt|Logins|Users|Roles|ServerSecurity|All] [-InventoryPath <path>] [-OutputDirectory <path>] [-TrustServerCertificate] [-ConnectTimeoutSeconds <1..120>] [-CommandTimeoutSeconds <1..1800>]`.

Defaults currently include `-Mode Plan`, `-Stage Prompt`, connection timeout 15 seconds, command timeout 120 seconds, and no certificate-validation bypass unless explicitly configured. `-ValidateOnly` validates/prints configuration without making SQL connections. `-InventoryPath` is required by the wrapper for APPLY and must identify the reviewed PLAN's `SourceInventory` directory. The wrapper delegates to the canonical engine and restores the inherited external-ownership environment variable and its own temporary files in `finally`.

The profile schema supplies source/target endpoints, connection options, authentication configuration, scope, database/identity mappings, template policy, operation policies, and artifact policy. **The current canonical SQL connection builder uses Windows Integrated authentication, `Encrypt=True`, and pooling disabled; do not assume schema fields for SQL authentication, custom application name or pooling are implemented end-to-end.** Verify behavior in code and an authorized environment before relying on such fields.

## Canonical engine parameters

`Invoke-SqlSecurityMigration.ps1` currently accepts the following:

| Category | Parameters and defaults |
|---|---|
| Required endpoints | `-SourceInstance`, `-TargetInstance` (different SQL Server instances) |
| Mode/stage | `-Mode Plan` (or `Apply`); `-Stage Prompt` (or `Logins`, `Users`, `Roles`, `ServerSecurity`, `All`) |
| Scope and mappings | `-DatabaseName` (optional array), `-ExcludedDatabaseName` (optional array), `-IdentityMapCsv ''`, `-DatabaseMapCsv ''` |
| Artifacts/connectivity | `-InventoryPath ''`, `-OutputDirectory ''`, `-TrustServerCertificate` (off), `-ConnectTimeoutSeconds 15`, `-CommandTimeoutSeconds 120` |
| Identity controls | `-AllowWindowsLogins`, `-AllowSqlLogins`, `-AllowMachineAccounts`, `-AllowIdentityMapping`, `-IncludeAllServerLogins` (all off) |
| Database/role controls | `-AllowCustomRoles`, `-AllowSchemas`, `-AllowDefaultSchemaChanges`, `-AllowDatabasePermissions`, `-AllowPrivilegedPermissions`, `-AllowDenies`, `-AllowPrivilegedRoles` (all off) |
| Other controls | `-AllowServerSecurity`, `-ApproveCommonTemplate` (both off) |

Do **not** use `-AllowApplicationRoles` or `-AllowSharePointInfrastructureDatabases`: neither parameter appears in the currently published canonical engine. Never invent unsupported switches or application-specific exceptions. There is no `-Mode Verify` in this engine. The BAT launcher prompts for a profile path and Plan/Apply mode only; SQL-stage approvals reside in the engine, not the BAT file.

## PLAN scope and current limitations

Supply a reviewed `scope.databases` exact list and exclusions in a local profile. Preflight verifies each selected source database and its mapped/exact-name destination exist as ONLINE user databases. If no source list is supplied, preflight selects source/target exact-name matches. It also enumerates the destination's ONLINE user databases independently: nonexcluded, nonmatching databases can be classified as additional template candidates. A source list or SQL LIKE discovery alone **does not** constrain destination inventory to only those names. Review the entire source/destination discovery output, include explicit exclusions for unrelated destination databases, and treat unmatched names as review items. Explicit mappings require a reviewed CSV/profile; never guess rename mappings.

The engine currently derives the common template and marks template evidence required in the manifest even when `scope.templatePolicy.enabled` is false; disabling that profile property alone does not turn template processing off. This is an implementation gap, not an approval. Review [known gaps](KNOWN-GAPS.md) before planning on an instance with unrelated databases.

The engine requires sufficiently complete metadata (including sysadmin in server inventory), compares selected source and target SQL security records and writes sensitive reports locally. `TrustServerCertificate` retains encrypted transport but bypasses certificate identity validation; use only where expressly approved. SQL server/catalog capabilities require actual inspection, not version assumptions.

## Read-only discovery and PLAN sequence

1. Run [the discovery helper](../tools/Get-SqlDatabaseCandidates.ps1) against both explicitly approved endpoints with an explicit `-DatabaseLikePattern`. It queries `sys.databases` using a parameterized LIKE pattern and returns matches, states and differences. Discovery does not authorize a mapping, template or PLAN scope.
2. Review ONLINE status, exact matching, other destination databases, exclusions, metadata visibility, collation and TLS. Create a local, ignored JSON profile from `config/examples/one-to-one.json` with only approved values.
3. Run the wrapper with `-ValidateOnly`. Verify the resolved configuration and inspect the current code/tests. Then run `-Mode Plan` **only** under the separately authorized read-only scope.
4. Keep the entire `Results/<session>` directory restricted and intact, including `SourceInventory/`, `Plan01_Plan.csv`, logs and summary. Review every planned, blocked, deferred, manual and target-only item. Reports are evidence, not approvals.

## APPLY (not authorized by documentation)

The engine's APPLY requires a reviewed, compatible `SourceInventory` directory from that exact source/target/scope; verifies hashes/fingerprints and source drift; replans the target; requires `REVIEWED` and exact target confirmation; and restricts operations through separate switches/stages. `All` is not blanket authorization. Changing any material scope, identity mapping, inventory format or policy calls for a new PLAN and review. Remediation-script APPLY is intentionally unimplemented. Live SQL APPLY remains integration-unverified in this repository; use a disposable lab and explicit operation-specific authorization before attempting it on any real target.
