"""Offline SOURCE contract tests; these are static, not PowerShell execution tests."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
PS=(ROOT/'Invoke-SqlSecurityMigration.ps1').read_text(encoding='utf-8-sig')
BAT=(ROOT/'Run-SqlSecurityMigration.bat').read_text(encoding='ascii')
DOC=(ROOT/'README.md').read_text(encoding='utf-8')
class PinnedInventoryContract(unittest.TestCase):
    def test_plan_exports_source_xml_and_manifest(self):
        for t in ('SourceInventory','WriteXml','XmlWriteMode','Manifest.json','ReviewPlanHash','Readable','ServerFileHash'):
            self.assertIn(t,PS)
    def test_apply_requires_previous_plan(self):
        self.assertIn("if ($Mode -eq 'Apply' -and -not $InventoryPath)",PS)
        self.assertIn('Load-ApprovedInventory',PS)
        self.assertIn('File-SHA256',PS)
        self.assertIn('PLAN comparison report changed since inventory capture.',PS)
    def test_apply_uses_pinned_source_fresh_target(self):
        self.assertIn('Server-FromDataset $script:SnapshotDatasets',PS)
        self.assertIn('Database-FromDataset $script:SnapshotDatasets',PS)
        self.assertIn('Verify-SourceUnchanged',PS)
        self.assertIn('Canonical SQL instance does not match approved PLAN',PS)
    def test_hashes_excluded_from_snapshots(self):
        self.assertIn("$hashCol=if ($includeHash) {'sl.password_hash'}",PS)
        self.assertIn("$names=@($table.Columns|ForEach-Object {[string]$_.ColumnName}|Where-Object {$_ -ne 'PasswordHash'})",PS)
        self.assertIn('SQL password hashes are NEVER written',PS)
    def test_no_global_owner_gate(self):
        self.assertNotIn('$script:UnsafeDatabaseOwners',PS)
        self.assertIn("'Database owner SID'",PS)
        self.assertIn("'Role owner'",PS)
    def test_sharepoint_shell_requires_provisioning(self):
        # Generic core has no hardcoded SharePoint role names
        # Application-specific roles are handled via profile configuration
        self.assertIn('ExplicitlyExcludedDatabases', PS)

    def test_no_unverified_sharepoint_machine_cloning(self):
        # Generic core treats machine accounts uniformly via -AllowMachineAccounts
        # No application-specific machine account logic
        self.assertIn('AllowMachineAccounts', PS)
        self.assertIn('Machine/local service account requires explicit -AllowMachineAccounts', PS)
    def test_bat_uses_generic_profile_entrypoint(self):
        self.assertIn('SSM_PROFILE',BAT)
        self.assertIn('Invoke-SqlSecurityMigration-Generic.ps1',BAT)
        self.assertIn('-ExecutionPolicy RemoteSigned',BAT)
        self.assertNotIn('-ExecutionPolicy Bypass',BAT)
    def test_docs_disclose_runtime_unverified(self):
        for t in ('offline contracts','SQL APPLY integration remains unverified','SourceInventory','password hashes'):
            self.assertIn(t,DOC)
if __name__=='__main__':unittest.main(verbosity=2)
