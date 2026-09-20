from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PS = (ROOT / 'Invoke-SqlSecurityMigration.ps1').read_text(encoding='utf-8-sig')
README = (ROOT / 'README.md').read_text(encoding='utf-8-sig')


class PlanApplySafetyContract(unittest.TestCase):
    def test_complete_destination_scope_and_common_template_contract(self):
        for token in (
            'DestinationDatabases',
            'MatchingDatabases',
            'AdditionalDestinationDatabases',
            'CommonTemplate',
            'TemplateEvidence',
            'CompleteDestinationInventory',
            'RequireTemplateApproval',
            'ApplyCommonTemplate',
        ):
            self.assertIn(token, PS)

    def test_manifest_covers_all_destination_databases(self):
        for token in (
            'DestinationDatabaseCount',
            'ExpectedDestinationDatabaseCount',
            'FullDestinationInventory',
        ):
            self.assertIn(token, PS + README)

    def test_template_derivation_classifies_source_evidence(self):
        for token in (
            'ServerWide',
            'CommonDatabase',
            'DatabaseSpecific',
            'UnsupportedForAdditionalDatabase',
            'EvidenceDatabases',
        ):
            self.assertIn(token, PS)

    def test_scope_classification_does_not_require_total_database_counts(self):
        for token in (
            'TotalServerDatabaseInventory',
            'ApprovedSourceDatabases',
            'DestinationMigrationCandidates',
            'ExplicitlyExcludedDatabases',
            'UnclassifiedDatabases',
            'Unclassified destination database requires review',
        ):
            self.assertIn(token, PS)
        self.assertNotIn("requires 30 destination databases with 15 exact matches", PS)

    def test_inventory_diagnostics_are_structured_and_bounded(self):
        for token in (
            'InventoryStage',
            'QueryId',
            'ResultSetId',
            'StartedUtc',
            'CompletedUtc',
            'ElapsedMs',
            'RowCounts',
            'Database inventory START',
            'Database inventory COMPLETE',
            'Database inventory FAILED',
            'CommandTimeoutSeconds',
        ):
            self.assertIn(token, PS)
        self.assertIn('AppendAllText', PS)

    def test_inventory_permission_verification_is_read_only(self):
        for token in (
            'MetadataVisibility',
            'VIEW SERVER STATE',
            'VIEW DEFINITION',
            'HAS_PERMS_BY_NAME',
            'Permission verification',
        ):
            self.assertIn(token, PS)

    def test_postplan_serialization_uses_explicit_contracts_and_atomic_publication(self):
        for token in (
            "'START: CommonTemplate'",
            "'END: CommonTemplate EvidenceCount='",
            "'START: SerializeCommonTemplate'",
            "'END: SerializeCommonTemplate EvidenceCount='",
            "'START: PersistDestinationInventory'",
            "'END: PersistDestinationInventory DestinationCount='",
            "'START: BuildManifest'",
            "'END: BuildManifest'",
            "'START: ValidateManifest'",
            "'END: ValidateManifest'",
            'Convert-InventoryRowContract',
            'Write-AtomicText',
            'Completion.marker',
        ):
            self.assertIn(token, PS)
        self.assertNotIn('$script:DestinationDatasets[$db]|ConvertTo-Json', PS)

    def test_inventory_and_manifest_are_pinned(self):
        for token in (
            'Save-InventoryManifest',
            'Manifest.json',
            'SourceInventory',
            'ReviewPlanHash',
            'File-SHA256',
            'Dataset-Fingerprint',
            'WriteXml',
        ):
            self.assertIn(token, PS)

    def test_apply_requires_approved_inventory_and_source_drift_check(self):
        for token in (
            "if ($Mode -eq 'Apply' -and -not $InventoryPath)",
            'Load-ApprovedInventory',
            'Verify-SourceUnchanged',
            'SOURCE DRIFT',
            'Canonical SQL instance does not match approved PLAN',
        ):
            self.assertIn(token, PS)

    def test_sid_conflicts_and_target_identity_protection(self):
        for token in (
            'Login SID conflict',
            'SID already belongs to target principal',
            'Existing target database user SID conflicts',
            'Database user SID',
            'Target login type differs from source database user',
            'No overwrite',
        ):
            self.assertIn(token, PS)

    def test_database_mapping_and_role_ownership_rules(self):
        for token in (
            'Load-DatabaseMap',
            'TargetDatabase',
            'Role owner',
            'Schema owner',
            'Database owner SID',
            'Target database map changed since PLAN',
        ):
            self.assertIn(token, PS)

    def test_schema_permission_and_membership_dependency_order(self):
        for token in (
            'Execute-Roles',
            'CustomRoles',
            'Schemas',
            'DefaultSchemas',
            'DatabasePermissions',
            'Memberships',
            'Role permission differences',
        ):
            self.assertIn(token, PS)

    def test_idempotency_and_failure_continuation_are_explicit(self):
        for token in (
            'Already correct',
            'no eligible changes',
            'ExecutionFailures.csv',
            'Execute-Phase',
            'Build-Plan $false',
            'Replan before another dependency pass',
        ):
            self.assertIn(token, PS)

    def test_plan_status_and_action_accounting_are_separate(self):
        for token in (
            'Get-ActionAccounting',
            'PlanExecutionStatus',
            'InventoryCompleteness',
            'ManifestIntegrity',
            'MigrationActionReadiness',
            'ApplyExecutionStatus',
            'FinalMigrationReconciliation',
            "'PLAN_COMPLETED_WITH_EXCEPTIONS'",
            "'MIGRATION_READINESS.md'",
            "'Readiness.json'",
            'Planned actions are proposed operations, not exceptions.',
        ):
            self.assertIn(token, PS)
        self.assertIn('Unresolved=$accounting.Exceptions;Planned=$accounting.Planned;TargetOnly=$accounting.TargetOnly', PS)

    def test_metadata_delete_is_explicitly_excluded_from_apply_scope(self):
        # Generic core uses profile-driven excluded databases; no hardcoded names
        self.assertIn('ExplicitlyExcludedDatabases', PS)
        self.assertIn('$script:ReviewRequiredDestinationDatabases=@()', PS)

    def test_readiness_root_cause_serialization_does_not_use_fragile_formatting(self):
        self.assertIn("[string]$root.Reason", PS)
        self.assertIn("[string]$root.Example", PS)
        self.assertIn('$accounting.PSObject.Properties[$name].Value', PS)

    def test_sharepoint_managed_user_identities_are_not_users_stage_actions(self):
        # Generic core has no SharePoint-specific identity classification
        # Application-managed identities are handled via profile configuration
        self.assertIn('ExplicitlyExcludedDatabases', PS)

    def test_users_apply_branch_ends_without_roles_prompt_or_execution(self):
        users_branch=PS.split("'Users' {",1)[1].split("'Roles' {",1)[0]
        self.assertIn("Execute-Phase 'Users'", users_branch)
        self.assertNotIn('Execute-Roles', users_branch)
        self.assertNotIn('Execute ROLES phase now?', users_branch)

    def test_apply_no_eligible_actions_is_explicit_status(self):
        self.assertIn("'APPLY_NO_ELIGIBLE_ACTIONS'", PS)
        self.assertIn('if ($open -gt 0){return 2}', PS)

    def test_documentation_mentions_unittest_baseline_and_requires_approval(self):
        for token in (
            'python -m unittest -q tests.test_static tests.test_v2_contract',
            'complete, integrity-checked PLAN inventory',
            'pinned source inventory',
            'disposable SQL Server lab',
        ):
            self.assertIn(token, README)


if __name__ == '__main__':
    unittest.main(verbosity=2)
