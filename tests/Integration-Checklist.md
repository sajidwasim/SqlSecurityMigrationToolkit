# Lab integration checklist, mandatory before production

Use a disposable SQL Server test instance and two disposable databases. Back up first, snapshot before each APPLY, and use non-production test accounts only. Do not test against production databases.

- [ ] `SmokeTest.ps1` passes on Windows PowerShell 5.1.
- [ ] PLAN with valid connections and explicit DB list runs without write permissions on source; outputs 360-view CSVs and `Summary.json`.
- [ ] Wrong source alias, same canonical instance, unknown database, duplicate database mappings and case-sensitive collation fail closed.
- [ ] SQL login missing: creation preserves SID/password verifier, hash never occurs in exported SQL/CSV/log; source disabled login remains disabled.
- [ ] SQL login already exists with conflicting SID or password hash: blocked; no overwrite.
- [ ] Windows machine-account cloning and managed roles blocked without explicit consent.
- [ ] Missing database user created only when target server-login type/SID valid; user-SID collision blocked.
- [ ] Missing schema owned by a missing user: USERS first, SCHEMAS after, then approved default schema changes.
- [ ] Generic role with non-dbo owner, explicit GRANT, DENY and role membership replicates only with the intended switches.
- [ ] Missing or unsupported role permission blocks new role memberships. Extra permissions and nested memberships already on target block additional role members.
- [ ] Source/target database-name CSV maps into the intended target, never changes source.
- [ ] Existing target-only principal/permission never dropped. Unsupported permissions are recorded as manual reviews.
- [ ] Introduce one failing operation; subsequent eligible independent actions continue, error CSV/log show the failure and exit code is 2.
- [ ] Verify two successive PLAN runs after APPLY converge for supported source-side differences, accounting for deliberate exceptions.
- [ ] Farm owner approves farm accounts and role semantics separately from SQL metadata. New-farm config DB and Search database upgrade rules verified.

## v2.0 pinned-inventory checks (mandatory)

- [ ] PLAN produces `SourceInventory/Manifest.json`, `server.xml`, `DB_###.xml`, `Readable` CSV files and `Plan01_RootCauses.csv`. Inspect manifest's 15 exact source-target database pairs and identity map.
- [ ] Without `-InventoryPath`, APPLY exits before opening target DDL. Passing the parent session path instead of `SourceInventory` also fails.
- [ ] APPLY with unchanged snapshot and server names passes SHA256 and source-drift checks. Empty `-DatabaseName` reuses exactly the manifest's database scope.
- [ ] Duplicate source database names, changed map CSV, omitted or added database, modified Plan01 CSV, modified XML, missing XML and mismatched instance aliases are all rejected before DDL.
- [ ] Create a harmless extra source security object **after PLAN**. APPLY should halt with SOURCE DRIFT before DDL. Revert the lab change and collect a new PLAN.
- [ ] Create/modify a target-only principal after PLAN; APPLY must re-read the current target rather than blindly replay old SQL; never delete target-only metadata.
- [ ] With distinct database owner SIDs, PLAN flags the difference as Manual review **without** blanket-blocking an unrelated safe CREATE USER. Owner/identity conflicts that affect a specific role or grant must still block its dependent changes.
- [ ] With a role already carrying the same 100+ GRANTs but a different owner, PLAN groups role-owner conflict in a root-cause report rather than generating 100+ redundant matching-permission failures. Role membership stays guarded.
- [ ] A missing Shell_Access cannot be created by SQL even if all APPLY approval switches are enabled. Provision through the application and rerun PLAN.
- [ ] A legacy machine account with `AllowMachineAccounts` but **without** a reviewed identity map is blocked; with an approved map to an existing valid target login it may create the correctly mapped user after other checks.
- [ ] Test in-memory SQL-login verifier migration only with two supported, disposable accounts. Search all files in Results for the password verifier; none may persist. Verify a wrong-SID existing target login is blocked.
- [ ] After a partial USERS run, rerun PLAN and review remaining ROLES candidates; a second APPLY of the same inventory rechecks target and skips already completed operations. Do not label partial exit code 2 as migration success.
