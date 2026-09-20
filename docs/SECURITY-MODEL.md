# Security model and safeguards

## Security boundaries

This project operates at the SQL Server instance level and therefore handles privileged metadata and potentially sensitive identity information. The core safeguards are documented in the PowerShell entry logic and in the README.

- Password hashes are never written to the `SourceInventory` plan files.
- `Write-ReadableTable` strips the `PasswordHash` column before exporting CSVs.
- A `Manifest.json` with SHA256 values and dataset fingerprints controls inventory integrity.
- The `RUN` script preflights script parsing and prompts for review before any stage executes.

## Identity and permission controls

The script blocks unsafe changes by default:

- login type mismatch
- SID conflict
- target database user SID mismatch
- schema/role ownership mismatch
- missing target principal in permission grants
- privileged roles and permissions without explicit approval flags
- target-only object removal is never automatic

## Production safety

- APPLY uses a saved plan, not a blanket live-source replay.
- `Verify-SourceUnchanged` prevents drift from the approved source inventory.
- `Confirm-Apply` requires an exact target instance name before a phase executes.
- Powershell script parsing and Windows file unblock checks happen before the actual migration logic runs.

## Residual risk

This is not a cryptographically signed artifact. The project relies on access control, restricted storage, and review of the approved inventory folder. It does not guarantee complete equivalence for effective AD group membership, application-managed security, or unsupported securables.
