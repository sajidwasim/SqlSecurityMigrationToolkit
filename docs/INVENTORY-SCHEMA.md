# Source inventory and manifest contract

The canonical engine's `Save-InventoryManifest` writes a `SourceInventory/Manifest.json` with `FormatVersion=2`, `Mode=PLAN`, source/target identities, source database entries, destination classification, artifact hashes, source fingerprints and template evidence. This is the **current code contract**, not an endorsement of a future optimized format; changing its decision-relevant evidence requires a versioned compatibility design and tests.

## Artifacts

- `server.xml` and `DB_###.xml`: typed source DataSet XML with schema; database tables include principals, schemas, memberships, permissions, objects/columns and types. Database counts and numbering are determined by the actual approved scope, not fixed values.
- `DEST_###.json`: captured destination inventory; destination records include metadata for comparative planning. Only the current manifest's declared artifacts and classifications establish collection completeness.
- `CommonTemplate.json`: derived source-common evidence. In the present engine template derivation and its manifest requirement are unconditional, even for profiles with template policy disabled. It is not permission to propagate permissions or run APPLY.
- `Readable/`: CSV exports for review. These are not the authoritative typed snapshot used by APPLY.
- Optional preserved map CSVs: explicit identity and database mapping evidence if supplied.
- `Plan01_Plan.csv` in the parent session directory and `Completion.marker`: part of the pinned-plan checks; keep the entire original session intact.

## Integrity and limitations

The manifest records SHA256 file hashes and per-DataSet fingerprints. `Dataset-Fingerprint` currently incorporates table/column and row data (including full object/column metadata for database datasets); dropping those tables without an equivalent decision-complete replacement weakens drift coverage. The server fingerprint omits its first informational dataset table by design. These hashes are integrity checks **not digital signatures**; a party able to rewrite both a manifest and its artifacts can recompute them.

`Load-ApprovedInventory` checks expected format/version, required files and hashes, source/target/scope, completeness, review plan and source fingerprints before APPLY. Preserve artifact filenames, schema and hash scope when refactoring unless a separately versioned contract and strict backward-compatibility rejection are implemented.

Reports contain sensitive SQL security metadata. Store only in an access-controlled local location; never commit real inventories or a manifest to GitHub. No SQL-login password hash should be persisted by the toolkit.
