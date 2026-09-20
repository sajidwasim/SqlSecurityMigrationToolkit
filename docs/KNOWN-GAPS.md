# Known gaps and verification limits

This file records implementation observations in the current repository. A feature's appearance in the schema, README or tests is **not** proof that its full SQL execution path is implemented or integration-tested.

## Confirmed current-code discrepancies

1. `Invoke-SqlSecurityMigration.ps1` has only Plan/Apply modes; its final replan after APPLY is not an independent Verify mode. Remediation `Verify` confirms report generation; remediation Apply intentionally throws before SQL execution.
2. `Build-Plan` derives common-template evidence unconditionally and proposes it for additional destination databases in PLAN even when profile `templatePolicy.enabled` is false; the manifest also unconditionally sets `RequireTemplateApproval=true`. Fix and version the contract with regression tests before describing the policy switch as effective.
3. `Verify-Preflight` considers all ONLINE destination user databases minus exclusions independently of the selected source list. Additional databases may become template candidates. The excluded-database path in `Build-Plan` may still collect metadata; exclusion must not be marketed as a no-read guarantee.
4. The profile schema includes SQL authentication, pooling and connection settings, but the canonical `Query-Sql` path currently uses Windows Integrated authentication, `Encrypt=True`, and `Pooling=false`. Validate or implement configuration propagation rather than describing all schema fields as active.
5. The SQL connection application-name string in the canonical engine and connection-test helper contains organization-specific branding. This is a cosmetic genericization issue, not evidence of an application adapter; change it in a tested code update.
6. The canonical engine's inventory, role-coverage, serialization and common-template paths remain performance hot spots. The five-minute PLAN goal has not been benchmark-verified.

## Outstanding safety and testing evidence

- No complete disposable-lab PLAN/APPLY integration and effective permission reconciliation evidence has been established here; static or AST tests are insufficient.
- Identity SID conflicts, composite-key Windows SID translation, unsupported securables/grantor semantics, collation behavior and server-role permissions require additional targeted evidence.
- Effective AD group nesting, application/external provisioning, SQL Agent credentials and certificate/key material are outside this SQL-metadata equivalence guarantee.
- No atomic cross-database rollback. Require a separate approved recovery plan before any real APPLY.
- `TrustServerCertificate` bypasses certificate identity verification even when the connection is encrypted.
- Manifest/file SHA256 does not protect against an attacker who can rewrite both artifacts and manifest. Restrict report access and maintain independent approvals.
- Historical operational documentation removed from the current tree can remain in prior Git commits. A separately approved history-cleanup/migration procedure is needed if that content was not authorized for storage.

## Evidence required before an operational release

Use versioned semantic regression fixtures, full static/AST checks, exclusive timing, approved read-only PLAN comparison, representative disposable-lab APPLY, metadata visibility and identity-conflict tests, manifest tampering/drift tests, and independently reviewed recovery/approval procedures. Report precise results, not an overall readiness claim based on passing static tests.
