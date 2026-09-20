# Architecture — generic SQL Server security migration

## Core components

- [`Invoke-SqlSecurityMigration-Generic.ps1`](../Invoke-SqlSecurityMigration-Generic.ps1): JSON-profile validation and mapping to the legacy engine parameter contract, with temporary mapping-file cleanup.
- [`modules/Config.psm1`](../modules/Config.psm1): configuration validation and resolution using the [schema](../config/schema/profile.schema.json).
- [`Invoke-SqlSecurityMigration.ps1`](../Invoke-SqlSecurityMigration.ps1): canonical SQL Server metadata inventory, planning, reporting, manifest persistence and guarded APPLY.
- [`Invoke-SqlSecurityRemediation.ps1`](../Invoke-SqlSecurityRemediation.ps1): local worklists, identity/exception handling and report-only Verify; its separate Apply function intentionally throws rather than executing SQL.
- [`Run-SqlSecurityMigration.bat`](../Run-SqlSecurityMigration.bat): thin profile/Plan-or-Apply launcher without its own AST preflight or SQL privilege approval logic.
- [`tools/`](../tools): connection testing, parameterized database-candidate discovery, offline PLAN CSV comparison and log timing analysis.

## Actual execution and scope

The engine validates source and target as distinct SQL instances and requires complete server metadata. `Verify-Preflight` identifies ONLINE user databases on both instances; a selected source list must have corresponding ONLINE exact-name/mapped destinations. Independently, the nonexcluded destination ONLINE user databases form the destination classification/inventory scope. Other destination databases can be classified as additional common-template candidates even if not named in a selected source list. Explicitly exclude unrelated databases and review the complete destination inventory before PLAN. Some excluded databases may still be read by the current `Build-Plan` excluded-database loop; exclusions primarily govern migration eligibility, not a strict no-read boundary.

`Build-Plan` generates actions by comparing server and database principals, schemas, memberships, permissions, securables and ownership evidence. Source/destination differences are classified as already correct, planned, blocked, deferred, manual review, target only or failed. The current implementation calls `Derive-CommonTemplate` during PLAN regardless of a disabled profile template policy; applying the derived template to additional destinations also occurs during PLAN to produce proposed actions. Template evidence is **not** SQL-write authorization.

`Save-InventoryManifest` writes typed source XML, normalized destination JSON, readable CSVs, manifest and completion marker. `Load-ApprovedInventory` checks pinned hashes/fingerprints and approved scope before APPLY. `Verify-SourceUnchanged` compares fresh source metadata with saved fingerprints. `Execute-Phase` executes only stage-eligible planned SQL under APPLY authorization and replans between relevant passes. `Finalize-Session` produces a supported-scope reconciliation using a fresh target comparison after APPLY. It is not a standalone Verify command and does not establish effective AD or application security equivalence.

## Trust boundary and evidence

PLAN reads SQL metadata and writes restricted **local** artifacts, without executing security DDL. APPLY can issue SQL writes and requires an independently reviewed inventory, current drift checks, approved switches/stage and interactive target confirmation; no instruction file authorizes APPLY. SHA256 hashes detect changed artifacts when the manifest is trusted, not malicious replacement of both evidence and manifest. Never upload instance inventory, identities, execution reports, approved mappings or profiles to GitHub. See [security model](SECURITY-MODEL.md) and [known gaps](KNOWN-GAPS.md).
