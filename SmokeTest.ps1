#requires -Version 5.1
# Offline AST parse smoke test. Does not execute the migration file or connect to SQL.
param([string]$ScriptFile='')
$ErrorActionPreference='Stop'
if ([string]::IsNullOrWhiteSpace($ScriptFile)) {
    $testDir=Split-Path -Parent $MyInvocation.MyCommand.Path
    $ScriptFile=Join-Path (Split-Path -Parent $testDir) 'Invoke-SqlSecurityMigration.ps1'
}
if (-not (Test-Path -LiteralPath $ScriptFile -PathType Leaf)) {
    throw "Migration script not found: $ScriptFile"
}
$tokens=$null
$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($ScriptFile,[ref]$tokens,[ref]$errors)
if($errors.Count){
    foreach($e in $errors){Write-Host ("{0}: {1}" -f $e.Extent.StartLineNumber,$e.Message) -ForegroundColor Red}
    exit 1
}
$names=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$true) | ForEach-Object {$_.Name})
foreach($required in @('Build-Plan','Verify-Preflight','Execute-Phase','Plan-Database','Plan-ServerSecurity','Finalize-Session')) {
    if($names -notcontains $required){throw "Missing function: $required"}
}
Write-Host ("PASS: PowerShell AST syntax valid, {0} functions found. No SQL connections made." -f $names.Count) -ForegroundColor Green
exit 0
