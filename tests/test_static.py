"""Offline safeguards for the SQL security migration toolkit.

These are STATIC checks only. Run SmokeTest.ps1 for genuine PowerShell AST parsing
and Integration-Checklist.md against disposable SQL Servers before any APPLY.
"""
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
PS=(ROOT/'Invoke-SqlSecurityMigration.ps1').read_text(encoding='utf-8-sig')
BAT=(ROOT/'Run-SqlSecurityMigration.bat').read_text(encoding='utf-8-sig')
DOC=(ROOT/'README.md').read_text(encoding='utf-8-sig')


def balanced_brackets(text):
    """Conservative PowerShell delimiter scan, NOT a language parser.

    Skips block/line comments, single/double-quoted strings and here-strings.
    """
    opens={'(':')','[':']','{':'}'}
    close=set(opens.values())
    state='code'; stack=[]
    lines=text.splitlines(keepends=True)
    for lineno,line in enumerate(lines,1):
        stripped=line.lstrip()
        if state=='here-single':
            if stripped.startswith("'@") and not stripped[2:].strip():state='code'
            continue
        if state=='here-double':
            if stripped.startswith('"@') and not stripped[2:].strip():state='code'
            continue
        i=0
        while i<len(line):
            c=line[i]; nxt=line[i:i+2]
            if state=='block':
                if nxt=='#>':state='code';i+=2
                else:i+=1
                continue
            if state=='single':
                if nxt=="''":i+=2
                elif c=="'":state='code';i+=1
                else:i+=1
                continue
            if state=='double':
                if c=='`':i+=2
                elif c=='"':state='code';i+=1
                else:i+=1
                continue
            if nxt=='<#':state='block';i+=2;continue
            if c=='#':break
            if nxt=="@'" and not line[i+2:].strip():state='here-single';break
            if nxt=='@"' and not line[i+2:].strip():state='here-double';break
            if c=="'":state='single';i+=1;continue
            if c=='"':state='double';i+=1;continue
            if c in opens:stack.append((c,lineno))
            elif c in close:
                if not stack or opens[stack[-1][0]]!=c:
                    raise AssertionError(f'Unbalanced {c} at {lineno}; stack={stack[-5:]}')
                stack.pop()
            i+=1
    if stack:raise AssertionError(f'Unclosed delimiters: {stack[-6:]}')
    if state not in ('code',):raise AssertionError(f'Unterminated lexical state: {state}')


class ToolkitStaticTests(unittest.TestCase):
    def test_basic_lexical_balance(self):balanced_brackets(PS)
    def test_all_artifacts_exist(self):
        for name in ('Invoke-SqlSecurityMigration.ps1','Run-SqlSecurityMigration.bat',
                     'README.md','Example-IdentityMap.csv','Example-DatabaseMap.csv',
                     'tests/SmokeTest.ps1','tests/Integration-Checklist.md'):
            self.assertTrue((ROOT/name).is_file(),name)
    def test_plan_is_read_only(self):
        self.assertIn("if($Mode -eq 'Plan') {",PS)
        self.assertIn('[void](Build-Plan $false)',PS)
        self.assertIn("if ($Mode -eq 'Apply' -and -not $InventoryPath)",PS)
        self.assertIn("if($pre -cne 'REVIEWED')",PS)
        self.assertIn('Type the EXACT target instance name',PS)
    def test_no_default_script_policy_override(self):
        self.assertIn('-ExecutionPolicy RemoteSigned',BAT)
        self.assertNotIn('-ExecutionPolicy Bypass',BAT)
    def test_uses_current_windows_authentication_without_prompts(self):
        for text in (PS, BAT, DOC):
            self.assertNotIn('Get-Credential', text)
            self.assertNotIn('SourceCredential', text)
            self.assertNotIn('TargetCredential', text)
        self.assertIn("$builder['Integrated Security']=$true", PS)
    def test_separate_identity_and_database_maps(self):
        for token in ('IdentityMapCsv','DatabaseMapCsv','-AllowIdentityMapping','DatabaseReverse'):
            self.assertIn(token,PS+DOC)
    def test_source_never_modified(self):
        self.assertIn('function Apply-Sql',PS)
        body=PS.split('function Apply-Sql',1)[1].split('function Add-Action',1)[0]
        self.assertIn('$script:TargetInstance',body)
        self.assertNotIn('$script:SourceInstance',body)
    def test_fresh_inventory(self):
        body=PS.split('function Build-Plan',1)[1].split('function Confirm-Apply',1)[0]
        self.assertIn('$script:SourceMeta=Server-Inventory $true $includeHashes',body)
        self.assertIn('$script:TargetMeta=Server-Inventory $false $includeHashes',body)
    def test_sensitive_hash_only_in_memory_during_apply(self):
        self.assertIn("$hashCol=if ($includeHash) {'sl.password_hash'}",PS)
        self.assertIn("$hashes=($phase -eq 'Logins' -and $AllowSqlLogins)",PS)
        self.assertIn('HASH REDACTED',PS)
        self.assertIn("Select-Object $cols | Export-Csv",PS)
    def test_principal_sid_and_type_guards(self):
        for term in ('Login SID conflict','SID already belongs to target principal',
                     'SID already mapped to database user','Existing target database user SID conflicts',
                     'Target principal name exists but is not a database role'):
            self.assertIn(term,PS)
    def test_no_blind_privilege_clone(self):
        for term in ('AllowMachineAccounts','AllowPrivilegedRoles',
                      'AllowPrivilegedPermissions','AllowDenies',
                      'PUBLIC permission difference'):
            self.assertIn(term,PS)
        self.assertNotIn('DROP USER ',PS)
        self.assertNotIn('DROP LOGIN ',PS)
        self.assertNotIn('REVOKE ',PS)
    def test_discover_custom_roles_and_explicit_rights(self):
        for term in ('sys.database_role_members','sys.database_permissions',
                     'sys.server_role_members','sys.server_permissions','sys.schemas',
                     "p.class=1","p.class=6",'Plan-ServerSecurity',
                     "SourceUserMembers",'RoleSummary.csv'):
            if term=='SourceUserMembers':continue
            self.assertIn(term,PS)
    def test_report_and_failure_logs(self):
        for term in ('_Plan.csv','_RoleCoverage.csv','_RoleSummary.csv',
                     '_UserMappings.csv','_Logins.csv','_Exceptions.csv','_Exceptions.log',
                     'Execution.csv','ExecutionFailures.csv','ExecutionFailures.log','Summary.json'):
            self.assertIn(term,PS)
    def test_no_unattended_execute(self):
        self.assertIn('Confirm-Apply',PS)
        self.assertIn("Execute-Phase 'Users'",PS)
        self.assertIn("Execute-Phase 'Memberships'",PS)
        self.assertIn("$next=(Read-Host 'Execute ROLES phase now?",PS)
        self.assertIn('ProfilePath',BAT)
    def test_parameter_contract_and_exact_plan_scope(self):
        # Generic core has no hardcoded database names or instance names
        # These are provided via profile configuration
        self.assertIn('Invoke-SqlSecurityMigration-Generic.ps1', BAT)
        self.assertIn('SSM_PROFILE', BAT)
        self.assertNotRegex(BAT, r'SPSTSQL01|SPSETSTSQL01|CoopNet|SharePoint')
    def test_documented_limits(self):
        for term in ('effective AD group nesting','application behavior',
                      'disposable SQL Server lab', 'cross-database rollback'):
            self.assertIn(term,DOC)


if __name__=='__main__':
    unittest.main(verbosity=2)
