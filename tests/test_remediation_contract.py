from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PS = (ROOT / 'Invoke-SqlSecurityRemediation.ps1').read_text(encoding='utf-8-sig')


class RemediationContract(unittest.TestCase):
    def test_required_artifacts_and_modes_exist(self):
        for token in (
            "ValidateSet('Plan','Apply','Verify')",
            'Manifest.json',
            'CommonTemplate.json',
            'FilteredCommonTemplate.json',
            'Plan01_Exceptions.csv',
            'Plan01_Plan.csv',
            'UserMappings',
            'RoleCoverage',
            'RootCauses',
        ):
            self.assertIn(token, PS)

    def test_remediation_reports_are_declared(self):
        for name in (
            'RemediationPlan.csv',
            'RootCauseSummary.csv',
            'IdentityConflicts.csv',
            'SchemaRemediation.csv',
            'ExternalOwnershipWorklist.csv',
            'DependencyGraph.csv',
            'RemediationExecution.csv',
            'RemediationFailures.csv',
            'FinalReconciliation.csv',
            'REMEDIATION_SUMMARY.md',
            'VerifiedIdentityInventory.csv',
            'IdentityMappingDecisions.csv',
            'ExternalOwnershipWorklist.csv',
            'ApprovedCandidateSQL.csv',
            'RemediationApprovalManifest.json',
            'UpdatedDependencyGraph.csv',
            'REMEDIATION_EXECUTION_PREVIEW.md',
        ):
            self.assertIn(name, PS)

    def test_issue_model_fields_exist(self):
        for field in (
            'IssueId',
            'RootCauseId',
            'SourceInstance',
            'TargetInstance',
            'Database',
            'Principal',
            'ObjectType',
            'SourceIdentity',
            'TargetIdentity',
            'RequiredDependency',
            'ProposedCorrection',
            'RiskClassification',
            'ApprovalStatus',
            'ExecutionStatus',
            'VerificationResult',
            'OriginalRowNumber',
        ):
            self.assertIn(field, PS)

    def test_identity_and_sid_safeguards_are_explicit(self):
        for token in (
            'BlockedIdentityConflict',
            'Source user SID and target login SID differ',
            'Do not overwrite SID',
            'ValidateDirectoryIdentities',
            'DirectoryIdentity',
            'Verified target login and matching SID',
        ):
            self.assertIn(token, PS)

    def test_schema_role_permission_and_external_ownership_routing(self):
        for token in (
            'CREATE SCHEMA requires owner validation',
            'ALTER ROLE ',
            'RequiresSeparatePrivilegedApproval',
            'ExternalProvisioningRequired',
            'ExternalOwnershipWorklist.csv',
            'RequiresExternalProvisioning',
        ):
            self.assertIn(token, PS)

    def test_apply_is_separately_authorized_and_fail_closed(self):
        for token in (
            'AuthorizeRemediationApply',
            'ApprovalManifest',
            'AuthorizationToken',
            'CanonicalTarget',
            'No SQL changes made',
            'fail-closed',
            'disposable lab validation',
        ):
            self.assertIn(token, PS)

    def test_scope_and_manifest_integrity_are_preserved(self):
        for token in (
            'ExplicitlyExcludedDatabases',
            'ReviewPlanHash',
            'TemplateEvidenceHash',
            'Destination inventory changed since capture',
            'Target-only records preserved',
        ):
            self.assertIn(token, PS)

    def test_retry_and_dependency_language_exists(self):
        for token in (
            'MaxRetryPerFailureSignature',
            'FailureSignatures',
            'DependencyGraph',
            'BlockedWhenMissing',
            'Fresh target metadata verification',
            'not counted as resolved until fresh target metadata verifies',
        ):
            self.assertIn(token, PS)

    def test_executable_preview_keeps_sql_unapproved(self):
        for token in (
            'InitialPlanExceptions',
            'FinalApplyPreviewExceptions',
            'DistinctRootCauseDecisions',
            'IndependentlyEligibleSqlOperations',
            'ApprovedOperations=@()',
            'This manifest currently approves zero SQL operations',
            'Do not execute review SQL files directly',
            'No SQL remediation operation is independently eligible',
        ):
            self.assertIn(token, PS)

    def test_identity_and_external_decision_outputs_exist(self):
        for token in (
            'New-IdentityInventory',
            'New-IdentityMappingDecisions',
            'DirectoryVerificationRequired',
            'BlockedNoOverwrite',
            'RequiresExternalProvisioning',
            'New-ExternalOwnershipWorklist',
            'SqlActionAllowed',
        ):
            self.assertIn(token, PS)


if __name__ == '__main__':
    unittest.main(verbosity=2)
