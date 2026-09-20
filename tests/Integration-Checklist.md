# Disposable SQL Server integration checklist

**Not an execution authorization.** This is a test specification; check boxes are not evidence of completion. Use isolated, disposable instances/databases and synthetic identities only. Take recoverable snapshots/backups before approved APPLY exercises. Do not test SQL DDL/DCL on production or a corporate migration target.

## Setup and PLAN

- [ ] Capture tested Git SHA, Windows PowerShell version, SQL major versions and permissions.
- [ ] Run full Python tests and Windows PowerShell AST smoke tests; record exact results.
- [ ] Test `-ValidateOnly` without SQL connections and reject invalid/unknown configuration keys.
- [ ] Verify canonical source/target differ, metadata visibility is complete and selected source database mapping resolves to ONLINE target databases.
- [ ] Demonstrate current additional-destination/template-policy behavior; after any fix, prove template disabled means no derivation or target-only template planning.
- [ ] Test exact matching, explicit renames, one-to-many *only when configured*, exclusion semantics, missing databases and incomplete inventory fail-closed behavior.
- [ ] Confirm PLAN makes no SQL security writes using statement-level audit/interception, while writing complete restricted local artifacts.
- [ ] Validate manifest counts against observed **dynamic** DB scope and compare normalized actions/permissions, role coverage, target-only records and dependencies.
- [ ] Verify missing destination securables are distinguished from existing target objects/columns with no explicit permissions.

## Manifest, permissions and identity

- [ ] Test tampered/missing XML, destination JSON, review PLAN, mapping CSV, template file, marker and incompatible manifest versions.
- [ ] Change source security after PLAN; APPLY must reject drift before DDL/DCL. Change destination security and ensure fresh comparison preserves target-only records.
- [ ] Test login/user type and SID conflict, approved and unapproved mapping, missing principals, schema/role ownership and dependency ordering.
- [ ] Test database/object/column permission classes, GRANT, DENY, GRANT OPTION, unsupported securables and intended grantor limitations.
- [ ] Test role memberships with incomplete role permissions, privileged permission and role approvals independently, and missing dependencies.
- [ ] Verify SQL password verifier bytes remain in memory only when a separately approved lab test requires them and do not appear in persisted files.

## APPLY and reconciliation — separately authorized disposable lab only

- [ ] Verify absent approvals, invalid target confirmation, missing inventory and incompatible scope all block SQL writes.
- [ ] With synthetic approved operations, verify successful individual stages, idempotent replanning, partial failures, dependency isolation and accurate SQL audit output.
- [ ] Independently inspect actual destination SQL security metadata after each stage and compare the supported scope to pinned source evidence.
- [ ] Confirm remediation Apply remains fail-closed and remediation Verify does not assert independent SQL equivalence.
- [ ] Document residual external/AD/application limitations, incomplete capabilities and a recoverable procedure; do not claim full production readiness from a green checklist alone.
