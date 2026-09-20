# Approved 15-to-30 workflow

PLAN is read-only and must inventory all 15 source databases plus all 30 destination databases. It identifies 15 exact name matches and 15 additional destination databases. Matching databases use their corresponding source inventory. Additional databases use only the derived common template, which is built from evidence present across the complete source inventory.

Before APPLY, review `CommonTemplate.json` and approve it with `-ApproveCommonTemplate`. Source-specific permissions, application-managed securables, unsupported object references and conflicting identities remain blocked, deferred or manual review. APPLY must consume the hashed manifest and destination inventory artifacts, execute in dependency order, continue independent eligible operations, and reconcile every destination database.

# Migration workflow

## PLAN

PLAN is read-only and is the canonical inventory build step. It executes the logic in `Build-Plan`, reads both source and target server metadata, and writes `Results/<session>/SourceInventory` plus report files.

The process includes:

- server inventory and selected database inventory
- login comparison, mapping, and conflict detection
- database principal and role inventory
- schema and permission comparison
- root-cause grouping and exception reporting

The script writes plan artifacts such as `*_Plan.csv`, `*_Exceptions.csv`, `*_RootCauses.csv`, `*_RoleCoverage.csv`, `*_RoleSummary.csv`, `*_UserMappings.csv`, and `*_Logins.csv` plus a session log and summary.

## APPLY

APPLY requires an approved source inventory and validates:

- inventory integrity (`Manifest.json`, SHA256 file hashes, dataset fingerprints)
- source instance identity
- target identity and database mapping
- source drift before execution
- explicit approvals for privileged or permission-changing stages

The script blocks a mismatch between a requested target or database scope and the approved PLAN. It also re-runs the plan before each phase and does not silently replay a stale SQL script.

## VERIFY

After execution, `Finalize-Session` compares the fresh target state with the pinned source inventory and records:

- executed stages
- failed DDL
- unresolved or blocked items
- target-only differences
- final status in `Summary.json`

A zero exit code means no detected source gaps in the supported scope, not total equivalence of all effective access. This is a documented caveat in the script and README.
