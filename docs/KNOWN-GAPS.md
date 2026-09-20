# Confirmed gaps and unresolved requirements

## Implementation evidence vs. intended design

The repository shows a conservative, inventory-pinned implementation candidate, but it does not yet prove production-grade equivalence to the design goals in the onboarding brief.

## Confirmed gaps

- No end-to-end lab validation against a disposable SQL Server pair is available in this environment.
- The project uses static tests only; no live Windows PowerShell/SQL Server execution has been proved here.
- `TrustServerCertificate` is explicitly allowed for encrypted transport, but it disables certificate validation; the README calls this out as a deployment risk.
- The project still flags SharePoint-managed provisioning as outside the scope of SQL-only DDL, which means some application-specific roles remain manual-farm steps.
- Role and permission logic is carefully guarded, but the repository does not implement proofs of full security equivalence or complete cross-version compatibility.

## Risk areas

- effective AD group membership is not reconstructed
- application-managed security is not recreated by plain SQL DDL
- unsupported securable classes and grantor identity are intentionally not guaranteed
- no cross-database rollback is available

## Highest-priority missing evidence

1. disposable database integration tests for PLAN and APPLY
2. source drift simulation against inventoried metadata
3. identity conflict tests covering SID mismatches and mapped login names
4. role ownership and schema dependency validation
5. final verification against a controlled destination state
