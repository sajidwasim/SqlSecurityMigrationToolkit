# v2.0 migration-engine changes from v1.0.1

1. PLAN saves typed, complete source-side server/database metadata in `SourceInventory` as XML with schema and readable per-database CSVs. It does not store SQL login password hashes.
2. PLAN produces SHA256 inventory/plan manifest, root-cause grouping and source-target role coverage. PLAN is read-only; duplicate end-of-plan SQL collection is removed.
3. APPLY requires the exact source inventory directory from a reviewed PLAN; snapshot XML, PLAN CSV and optional mapping CSVs are verified before executing. Cannot change original source/target/database scope, nor disable source-drift checking.
4. At start and before each stage, live source metadata is checked against PLAN; target is re-inventoried and remaining eligible actions are recalculated. SQL hash read only during LOGINS phase in-memory and verified against the snapshot's non-hash metadata.
5. Database owner SID differences are explicit manual-review records, rather than automatically blocking all user changes. Actual SID/role-owner conflicts still block sensitive dependent changes.
6. Equal explicit role-permission states do not produce one blocker per permission just because role owner differs. The owner discrepancy is reported once per role/database; unsafe new memberships remain gated.
7. Missing SharePoint_Shell_Access is NOT created using CREATE ROLE. SharePoint provisioning is required. New-farm machine identities require approved explicit identity mappings rather than treating AllowMachineAccounts=Y as proof of membership.
8. BAT asks for approved PLAN SourceInventory path in APPLY, detects Mark of the Web with approval, parses PowerShell before connections, never changes global execution policy, and prompts separately for sensitive operations.

**Verification:** Python static checks and ZIP CRC only; no Windows PowerShell AST or live SQL execution has been performed by the author. Mandatory Windows/SQL integration checklist is in tests/. This is not a production-certified release.
