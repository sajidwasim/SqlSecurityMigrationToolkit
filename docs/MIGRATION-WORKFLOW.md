# Generic migration workflow

## 1. Review endpoint and database scope

Use `tools/Get-SqlDatabaseCandidates.ps1` or independently approved read-only SQL to inspect candidate databases on **both** instances. Review exact matches, state, source/destination visibility, every destination ONLINE user database, explicit exclusions and any separately approved mappings. A `LIKE` filter from discovery does not by itself restrict the engine's destination inventory; the engine currently classifies other nonexcluded destination databases as additional candidates. The selected source DBs must be ONLINE with valid destination matches or explicit mappings. Do not infer mappings or approve a common template merely because a database exists.

## 2. Validate configuration offline

Copy a sanitized profile into ignored `config/local/`, enter only approved values, and run `Invoke-SqlSecurityMigration-Generic.ps1 -ProfilePath <local-profile> -ValidateOnly`. Inspect resolved scope, excludes, certificate choice and actual engine capabilities. The current engine derives common-template evidence even if `templatePolicy.enabled` is false. Explicitly account for nonmatching destination databases before execution.

## 3. PLAN — SQL read-only

Run the generic entry point with `-Mode Plan` under separately approved read-only scope. The engine collects source/target SQL security metadata, generates action/exception/root-cause reports and role coverage, persists typed source XML, destination snapshots, a manifest, and summary under a restricted local session directory. PLAN does not run target security DDL; local files contain sensitive corporate metadata. Preserve the whole session, including the parent `Plan01_Plan.csv` and `SourceInventory` directory. Check completion and completeness, not just the process exit code.

## 4. Independent review

Review selected/mapped/excluded/unmatched databases, login and user SID/type conflicts, ownership, explicit GRANT/DENY/GRANT OPTION, roles and memberships, unsupported securables, planned SQL, template evidence, dependencies and target-only metadata. A derived template is a proposal, never an authorization or an assumption of universal object existence. Fix scope and evidence defects with a fresh PLAN rather than editing the pinned artifacts.

## 5. APPLY — separately authorized SQL writes

Only an operator with explicit authority over the precise destination, database scope and stage may initiate APPLY. The canonical engine reads the reviewed pinned inventory, verifies hashes/fingerprints and source drift, replans against fresh target metadata and requires interactive `REVIEWED` plus exact target confirmation and applicable switches. Staged execution can partially succeed; it is not an atomic transaction across databases. Do not enable `All`, privileged switches, template approval or `TrustServerCertificate` automatically. Never treat this documentation or a PLAN request as APPLY authorization.

## 6. Reconciliation and external acceptance

`Finalize-Session` performs a supported-scope post-APPLY source-drift check and fresh target comparison, recording executed/failed and unresolved items. **The canonical engine has no standalone Verify mode.** The separate remediation Verify checks report production only and its Apply is intentionally unimplemented. Confirm effective access and external/application requirements independently in a disposable lab and under approved operations; a zero exit status is not complete security equivalence.
