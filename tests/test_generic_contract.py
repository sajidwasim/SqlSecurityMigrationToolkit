from pathlib import Path
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]
GENERIC = (ROOT / 'Invoke-SqlSecurityMigration-Generic.ps1').read_text(encoding='utf-8-sig')
CONFIG = (ROOT / 'modules' / 'Config.psm1').read_text(encoding='utf-8-sig')
BAT = (ROOT / 'Run-SqlSecurityMigration.bat').read_text(encoding='utf-8-sig')
ENGINE = (ROOT / 'Invoke-SqlSecurityMigration.ps1').read_text(encoding='utf-8-sig')


class GenericContractTests(unittest.TestCase):
    def test_generic_entrypoint_has_connection_free_validation(self):
        self.assertIn('[switch]$ValidateOnly', GENERIC)
        self.assertIn("Status = 'CONFIGURATION_VALIDATED'", GENERIC)
        self.assertIn('Invoke-SqlSecurityMigration-Generic.ps1', BAT)

    def test_config_module_supports_ps51_and_rejects_unknown_keys(self):
        self.assertIn('Windows PowerShell 5.1 has no -Depth parameter', CONFIG)
        self.assertIn('Unknown configuration key:', CONFIG)
        self.assertIn("$prop.PSObject.Properties['default']", CONFIG)

    def test_template_policy_reaches_engine_and_is_opt_in(self):
        self.assertIn('EnableCommonTemplate = [bool]$config.scope.templatePolicy.enabled', GENERIC)
        self.assertIn('TemplateSourceDatabase = @($config.scope.templatePolicy.sourceDatabases)', GENERIC)
        self.assertIn('TemplateTargetDatabase = @($config.scope.templatePolicy.targetDatabases)', GENERIC)
        self.assertIn('$script:TemplateEnabled=[bool]$EnableCommonTemplate', ENGINE)
        self.assertIn("if($script:TemplateEnabled){", ENGINE)
        self.assertIn("PostPlan-Log 'SKIP: CommonTemplate disabled by profile policy'", ENGINE)

    def test_sanitized_examples_are_json_and_no_application_adapter(self):
        examples = sorted((ROOT / 'config' / 'examples').glob('*.json'))
        self.assertGreaterEqual(len(examples), 6)
        for path in examples:
            text = path.read_text(encoding='utf-8-sig')
            data = json.loads(text)
            self.assertIn('source', data)
            self.assertIn('target', data)
            self.assertNotIn('SharePoint', text)


if __name__ == '__main__':
    unittest.main()
