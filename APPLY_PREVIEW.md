# APPLY Preview

This is a read-only preview. APPLY was not executed.

## Environment
- Source: `SOURCE_SERVER`
- Destination: `TARGET_SERVER`
- Execution identity observed during PLAN: `DOMAIN\operator`
- SQL versions observed: source 15, target 17

## Approved database scope
- 15 matching databases using their corresponding source inventories.
- 14 additional candidates using only the filtered generic template.
- Excluded: `TargetDB_Metadata_Delete`, `DBA_Maintenance`, and source POC `SourceDB_POC`.
- Total destination inventories: 31; intended database-level migration scope: 29.

## PLAN validation
- Session: `<SESSION_PATH>/SOURCE_SERVER__TO__TARGET_SERVER_<TIMESTAMP>`
- Completion marker: `PLAN_COMPLETED_WITH_EXCEPTIONS`
- Inventory: 15 source XML and 31 destination JSON artifacts; manifest complete.
- Summary status: `PLAN_COMPLETED_WITH_EXCEPTIONS`; exceptions=645; planned=0; target-only=13502.
- APPLY scope gate: `ScopeResolvedForApply=true`

## Filtered common template
- Included generic evidence rows: 3536
- Excluded evidence rows: 37
- Full row-level report: `FilteredCommonTemplate.csv` and `FilteredCommonTemplate.json` in the PLAN session.
- Excluded items remain recorded with classification, dependency, applicability, and reason.

## Potentially eligible actions
- Planned database-user actions: 0; stage `Users`.
- Exact Users action list: empty. Former service-account creations are preserved as managed/manual-review exceptions.
- No login, server-role, privileged-permission, schema, custom-role, DENY, machine-account, identity-map, or infrastructure switch is enabled in the proposed command.

## Remaining blockers
- 192 blocked, 298 deferred, and 160 manual-review actions remain outside automatic execution.
- `DOMAIN\admin_account` SID conflict and machine/farm identity mappings remain unresolved.
- Shell_Access, farm identities, SearchDBAdmin ownership, Config/CentralAdmin, and Search crawl/links operations remain separately managed or excluded.
- Target-only security (13,502 records) is retained; no DROP, REVOKE, DENY, or ownership replacement is proposed.

## Proposed command for later authorization

```powershell
.\Invoke-SqlSecurityMigration.ps1 `
  -SourceInstance 'SOURCE_SERVER' `
  -TargetInstance 'TARGET_SERVER' `
  -TrustServerCertificate `
  -Mode Apply `
  -Stage Prompt `
  -InventoryPath '<SESSION_PATH>/SourceInventory' `
  -ApproveCommonTemplate
```

`-TrustServerCertificate` preserves the connection exception used by the validated PLAN; it keeps transport encryption but does not validate certificate identity. No optional `Allow*` parameter is inferred. The command remains subject to interactive `REVIEWED` confirmation, exact target confirmation, source-drift validation, fresh target comparison, and stage-by-stage authorization.

## Verification and recovery
- Revalidate manifest hashes, source drift, canonical identities, and destination scope immediately before each stage.
- Replan after each stage and verify actual destination metadata, not merely SQL return status.
- Preserve `Execution.csv`, `ExecutionFailures.csv`, Plan reports, and final reconciliation.
- On systemic failure, stop and preserve the session; isolated failures may continue only with dependency-aware recording.
- There is no cross-database rollback; use the preserved reports and coordinated recovery procedure.
