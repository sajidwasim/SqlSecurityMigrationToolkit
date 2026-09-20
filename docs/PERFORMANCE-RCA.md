# PLAN Performance RCA

## Baseline evidence

The preserved local session timeline reports approximately 1,243 seconds between the first and last log entries. The timing analyzer reports a union of 825 seconds for recorded post-processing intervals; the intervals overlap and must not be summed as independent wall-clock costs.

Observed inclusive intervals in that session were:

- `PersistDestinationInventory`: approximately 445 seconds.
- `LoadSourceInventory`: approximately 201 seconds.
- `CommonTemplate`: approximately 175 seconds, mostly `DeriveCommonPermissions`.

The inventory queries returned approximately 102,000 object/column rows per large database. These are workload observations from a local historical session, not a production benchmark.

## Root cause

The dominant measured cost is materializing and repeatedly processing large object catalogs in PowerShell, JSON/XML persistence, template intersection, and fingerprinting. The current engine still retains these paths, so the full five-minute objective is not yet demonstrated.

## Implemented first slice

- Common-template derivation is now disabled unless the profile sets `scope.templatePolicy.enabled` to `true`.
- Optional `sourceDatabases` and `targetDatabases` template scopes are passed through the generic wrapper.
- Role coverage counts are built from per-database indexes instead of repeated full membership and permission scans.
- Role membership dependency checks build one incomplete-role index instead of scanning the complete action list for each membership.

These changes preserve the existing serial planner and manifest publication order. No SQL write path was added.

## Remaining work

Decision-complete catalog reduction, scalar persistence, canonical fingerprint reuse, connection pooling measurement, and bounded parallel collection require a separate benchmark and semantic comparator before implementation.
