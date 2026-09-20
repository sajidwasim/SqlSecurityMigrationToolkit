# Genericization Baseline

This baseline records the review of the current workspace. Historical application-specific reports and parameter registers remain evidence only; they are not runtime configuration.

## Findings Fixed

| Area | Finding | Fix | Verification |
|---|---|---|---|
| Launcher | Interactive BAT supplied historical instances, database counts, and application approvals | Replaced with a profile-driven thin launcher | Static launcher contract test |
| Generic entry point | Passed unsupported legacy parameters and had no connection-free validation path | Added `-ValidateOnly`, removed unsupported arguments, and passed profile exclusions | Seven profile dry runs |
| Config module | Failed on Windows PowerShell 5.1, mishandled false defaults, and did not reject unknown keys | Removed unsupported JSON depth usage, used safe PSObject access, and added recursive schema key checks | PowerShell 5.1 validation |
| Discovery profile | Used identical source and target values while the migration engine rejects same endpoints | Marked the profile `discoveryOnly`; same-instance validation is allowed only for that mode | Discovery dry run |
| Remediation | Contained application-specific classifiers, names, and worklists | Replaced with generic external-ownership terminology; no adapter or heuristic is loaded | Remediation AST and contract tests |
| Output safety | Local profile and result locations were not explicitly excluded | Added `.gitignore` entries for local profiles, inventories, credentials, and logs | Required-file check |

## Remaining Historical Evidence

Historical reports, the parameter decision register, and prior test-output captures may contain old environment identifiers. They are not imported by the generic runtime and must not be used as defaults, approval, or proof of current state. A disposable SQL Server lab is still required for live APPLY verification.

## Current Generic Boundary

The active runtime uses SQL Server metadata, validated profile data, explicit mappings, and operator-supplied external-ownership decisions only. It does not create, load, infer, or require an application adapter.
