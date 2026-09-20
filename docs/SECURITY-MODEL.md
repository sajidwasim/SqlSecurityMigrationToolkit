# Security model and authority boundaries

## SQL operations

PLAN reads SQL metadata, creates local files and does not execute security DDL. APPLY can change target SQL security through `Apply-Sql` and `Execute-Phase`; it requires a separately approved destination, reviewed pinned PLAN inventory, required approval switches and stage selection, interactive plan review and exact target confirmation. The BAT launcher only asks for a JSON profile and Plan/Apply mode; it does **not** independently perform AST checks or obtain individual privilege approvals. Use the actual engine safeguards and external change control, not a launcher prompt, as authority boundaries.

## Evidence integrity

Source snapshots include typed XML, a manifest with file SHA256 and DataSet fingerprints, destination inventory hashes and a pinned PLAN report hash. `Load-ApprovedInventory` validates those artifacts; `Verify-SourceUnchanged` checks for source metadata drift. SHA256 detects changes relative to a trusted manifest, but the manifest is unsigned: it does not prove who approved the plan or prevent simultaneous malicious replacement of evidence and manifest.

The engine's source snapshot and readable exports are intended to exclude SQL password hashes. SQL metadata reports still include logins, roles, SIDs, permissions, owners and potentially sensitive database names. Restrict local output ACLs and do not upload operational session artifacts or real configuration to personal or unapproved GitHub storage.

## Identity and scope protections

Source/target instance identity, selected DB presence, SID/type conflicts, ownership, privileged roles/permissions and target-only records are part of planning safeguards. Unsupported operations and dependencies must be reviewed rather than bypassed. Target-only security is never automatically deleted. Metadata visibility and collation limitations can invalidate completeness and must fail closed for APPLY.

Current scope caveat: the canonical engine may classify additional nonexcluded ONLINE destination databases as template candidates even when the profile's template switch is disabled. Review the full destination list and explicit exclusions before PLAN. An exclusion may still be inventoried by current code; do not claim it prevents all metadata reads.

## Residual risks

`TrustServerCertificate` encrypts transport without validating the certificate identity. There is no signed approval manifest, full effective AD/application access equivalence, or cross-database rollback guarantee. Integration testing is incomplete; authorization for live APPLY must not be inferred from repository contents. Historical confidential material may remain in Git history after current-tree cleanup.
