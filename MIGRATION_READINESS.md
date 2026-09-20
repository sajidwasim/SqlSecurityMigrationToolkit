# Migration Readiness

## Evidence

Validated session:

`<SESSION_PATH>/SOURCE_SERVER__TO__TARGET_SERVER_<TIMESTAMP>`

No SQL connection, APPLY operation, generated SQL review file, or application operation was executed.

## PLAN integrity

| Check | Result |
|---|---|
| Source / target | `SOURCE_SERVER` -> `TARGET_SERVER` |
| Completion marker | `PLAN_COMPLETED_WITH_EXCEPTIONS` |
| Source XML inventories | 15 present; manifest count 15 |
| Destination JSON inventories | 31 present; manifest count 31 |
| Manifest and artifact SHA256 hashes | PASS; 0 mismatches |
| CommonTemplate.json | Present and hash-valid; 3,573 source-evidence rows |
| Review plan hash | Manifest contains the pinned `Plan01_Plan.csv` hash |
| ScopeResolvedForApply | `true` |

The final `Summary.json` reports `PLAN_COMPLETED_WITH_EXCEPTIONS`, `Unresolved=645`, `Planned=0`, and `TargetOnly=13502`. The earlier `589` value was not an error count; it combined exceptions and planned actions before managed identity filtering.

## Database scope

The SQL inventory contains 31 databases:

- 15 matching databases, each paired with its corresponding source inventory.
- 14 additional migration candidates eligible for common-template review.
- 1 explicitly excluded `TargetDB_Metadata_Delete`, outside database-level APPLY.
- `DBA_Maintenance` is explicitly excluded.

The manifest also records `SourceDB_POC` as explicitly excluded. No total-database hardcoding was used in this validation.

## Action accounting

| Category | Count | Meaning |
|---|---:|---|
| Already correct | 18,396 | Informational |
| Blocked | 192 | Exception |
| Deferred | 298 | Exception pending prerequisite or replan |
| Manual review | 160 | Exception requiring evidence or decision |
| Planned | 0 | No Users-stage actions remain eligible |
| Target-only | 13,502 | Separate reconciliation category; never removed automatically |
| Failed | 0 | No PLAN action failures |
| Exceptions | 645 | Blocked + deferred + manual review + failed |

The final PLAN has no planned Users actions. All service-account candidates are preserved as manual-review exceptions.

## Dependency projection

The dependency chain is:

`login/SID -> database user -> schema/owner and custom role -> securable -> permission grantee -> role membership`

The largest deferred group is 167 role memberships whose role or member is not yet present. These are dependent records, not 167 independent root causes. Other important groups are 105 schema creations awaiting `-AllowSchemas`, 29 database-user SID conflicts for `DOMAIN\admin_account`, 29 permissions deferred because that grantee is absent, and 18 server permission identity conflicts.

Eligible after authorization and prerequisite resolution:

- No database-user creation is eligible in the `Users` stage. The exact action list is empty.
- Later schema, permission, and membership operations only after a fresh replan proves their prerequisites and approvals; none are currently eligible for APPLY without their separate execution switches and decisions.

Blocked or deferred collectively:

- Missing logins, SID/type conflicts, and identity mappings block affected users, permissions, schemas, and memberships.
- Missing principals or securables defer permissions and memberships until the earlier stage succeeds and a replan is run.
- Role-owner and database-owner differences remain review items; ownership is not overwritten automatically.
- `DOMAIN\admin_account` has a target SID conflict and cannot be resolved by matching account name.

The implementation's staged execution retries independent operations and replans between stages. It skips blocked operations and their dependents without suppressing the root cause.

## Identity and exceptions

- `DOMAIN\admin_account`: source and target SIDs differ; authoritative AD evidence and intended destination identity are required. Proposed default: preserve the target identity and do not overwrite the login or SID.
- Machine identities such as `DOMAIN\machine_account$` require an approved source-to-target farm mapping.
- `Shell_Access` is managed and requires supported provisioning such as application-specific admin commands; SQL role creation is insufficient.
- `SearchDBAdmin` and farm-account ownership differences require destination-farm confirmation; source farm identities must not be copied automatically.
- Config and Content_CentralAdmin operations require separate infrastructure approval.
- Search crawl/links databases are application-rebuilt and remain outside legacy SQL replay.

## Common-template applicability

`CommonTemplate.json` is present, hash-valid, and derived from all 15 source inventories. Its 3,573 source-evidence rows support common principals, schemas, memberships, permissions, objects, and types only where present across the source set. The filtered report includes 3,536 generic rows and excludes 37 managed, unsupported, instance-level, or conflict-dependent rows. Matching databases use their corresponding source inventory. Additional candidates use only the filtered generic template; object-specific source permissions are not replicated into unrelated databases. See `APPLY_PREVIEW.md` and the session's `FilteredCommonTemplate.csv`.

`TargetDB_Metadata_Delete` is explicitly excluded and is not APPLY-eligible. The filtered common template still requires explicit approval through `-ApproveCommonTemplate` after review.

## Destination-only security

The 13,502 target-only records are preserved as reconciliation data. The largest database groups are `TargetDB_Content_CentralAdmin` (6,502), `TargetDB_Search` (2,204), and `TargetDB_Profile` (1,195). They include target-only users, roles, memberships, schemas, and permissions. No revoke, delete, or overwrite is authorized.

## Exact APPLY prerequisites

APPLY is currently **not eligible**. The exact blockers are:

1. Common-template evidence and the 3,536-row filtered approval must be reviewed and explicitly approved.
2. `DOMAIN\admin_account` and all other SID conflicts require authoritative identity evidence; no same-name inference is acceptable.
3. Administrator decisions are required for farm identities, shell access, Search databases, SearchDBAdmin ownership, infrastructure databases, and machine-account mappings.
4. Target-only security requires explicit reconciliation acceptance; no automatic deletion is proposed.
5. Each execution switch and stage requires separate authorization; no optional `Allow*` switch is currently inferred.

After those decisions, the proposed staged command is:

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

This is a proposed command for later authorization, not an instruction to execute. `-TrustServerCertificate` preserves the connection exception used by the validated PLAN; it keeps transport encryption but does not validate certificate identity. No optional `Allow*` switch is inferred. APPLY must still pass its interactive review, target confirmation, source-drift check, and fresh target comparison.
