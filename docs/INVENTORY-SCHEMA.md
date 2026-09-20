# Inventory schema and manifest contract

## Manifest structure

The `SourceInventory` folder contains a `Manifest.json` file created by `Save-InventoryManifest` in [Invoke-SqlSecurityMigration.ps1](../Invoke-SqlSecurityMigration.ps1). The manifest includes:

- `FormatVersion`: fixed to `2`.
- `Mode`: expected to be `PLAN`.
- `SourceInstance` and `TargetInstance`.
- Canonical source and target names and SQL major versions.
- Snapshot file hashes for `server.xml` and per-database XML files.
- `ReviewPlanHash` for the plan comparison artifact.
- `IdentityMapHash` and `DatabaseMapHash` when those CSV inputs were used.
- Database metadata entries with `SourceDatabase`, `TargetDatabase`, `File`, `FileHash`, and `Fingerprint`.
- `SourceDatabaseCount=15`, `DestinationDatabaseCount=30`, `MatchingDatabases`, and `AdditionalDestinationDatabases`.
- `DestinationDatabases` entries with classification and hashed `DEST_###.json` inventory files.
- `CommonTemplate=true`, `RequireTemplateApproval=true`, and hashed `CommonTemplate.json` evidence.

## Snapshot files

- `server.xml`: server inventory dataset, including sysadmin validation and server principal metadata.
- `DB_001.xml` through `DB_NNN.xml`: per-database inventory containing principals, schemas, memberships, permissions, objects, and types.
- `DEST_001.json` through `DEST_030.json`: normalized current security inventory for every destination database, including both exact matches and additional restored databases.
- `CommonTemplate.json`: common source evidence and classifications used for additional destinations; it is not an authorization by itself.
- `Readable/`: human-readable CSV export derived from the XML snapshots.
- Optional `IdentityMap.csv` and `DatabaseMap.csv`: preserved review copies used in APPLY.

## Fingerprint rules

`Dataset-Fingerprint` hashes the normalized table/column metadata and contents. The manifest uses these fingerprints to reject tampering and source drift before APPLY. It is intentionally a safety check, not a cryptographic signature.

## Sensitivity rules

- SQL login password hashes are not stored on disk.
- `Write-ReadableTable` strips `PasswordHash` before exporting readable CSVs.
- The source inventory is considered sensitive data and should be stored in a restricted location.
