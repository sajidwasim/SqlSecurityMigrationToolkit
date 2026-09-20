<#
.SYNOPSIS
SQL Security Migration Toolkit - Profile-driven entry point
.DESCRIPTION
Generic entry point that loads a configuration profile and invokes the migration engine.
This replaces the hardcoded scenario-specific defaults with profile-driven behavior.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$ProfilePath,

    [ValidateSet('Plan','Apply')]
    [string]$Mode = 'Plan',

    [switch]$ValidateOnly,

    [ValidateSet('Prompt','Logins','Users','Roles','ServerSecurity','All')]
    [string]$Stage = 'Prompt',

    [string]$InventoryPath = '',

    [string]$OutputDirectory = '',

    [switch]$TrustServerCertificate,

    [ValidateRange(1,120)]
    [int]$ConnectTimeoutSeconds = 15,

    [ValidateRange(1,1800)]
    [int]$CommandTimeoutSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Import configuration module
$moduleRoot = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'modules'
$configModule = Join-Path $moduleRoot 'Config.psm1'
if (-not (Test-Path -LiteralPath $configModule)) {
    throw "Configuration module not found: $configModule"
}
Import-Module $configModule -Force

# Load and validate profile
Write-Host "Loading profile: $ProfilePath" -ForegroundColor Cyan
$profile = Validate-Profile -ProfilePath $ProfilePath
$profile = Merge-ProfileWithDefaults $profile

# Build CLI overrides
$cliOverrides = @{}
if ($TrustServerCertificate) {
    $cliOverrides['source.connection.trustServerCertificate'] = $true
    $cliOverrides['target.connection.trustServerCertificate'] = $true
}
if ($ConnectTimeoutSeconds -ne 15) {
    $cliOverrides['source.connection.connectTimeoutSeconds'] = $ConnectTimeoutSeconds
    $cliOverrides['target.connection.connectTimeoutSeconds'] = $ConnectTimeoutSeconds
}
if ($CommandTimeoutSeconds -ne 120) {
    $cliOverrides['source.connection.commandTimeoutSeconds'] = $CommandTimeoutSeconds
    $cliOverrides['target.connection.commandTimeoutSeconds'] = $CommandTimeoutSeconds
}
if ($OutputDirectory) {
    $cliOverrides['artifactPolicy.outputDirectory'] = $OutputDirectory
}

# Resolve effective configuration
$config = Resolve-EffectiveConfig -Profile $profile -CliOverrides $cliOverrides
Show-EffectiveConfig $config

if ($ValidateOnly) {
    [pscustomobject]@{
        Status = 'CONFIGURATION_VALIDATED'
        Profile = $config.profileName
        Source = $config.source.instance
        Target = $config.target.instance
        ScopeMode = $config.scope.mode
        DatabaseCount = @($config.scope.databases).Count
        MappingCount = @($config.scope.databaseMappings).Count
        TemplateEnabled = [bool]$config.scope.templatePolicy.enabled
        Authentication = $config.authentication.mode
    } | ConvertTo-Json -Depth 5
    exit 0
}

# Validate mode-specific requirements
if ($Mode -eq 'Apply') {
    if (-not $InventoryPath) {
        throw "APPLY requires -InventoryPath pointing to a previously reviewed PLAN session."
    }
    if (-not $config.operationPolicies.approveCommonTemplate -and $config.scope.templatePolicy.enabled) {
        Write-Warning "Template policy is enabled but -ApproveCommonTemplate not set. Template actions will be blocked."
    }
}

# Convert config to legacy parameter format for backward compatibility
$legacyParams = @{
    SourceInstance = $config.source.instance
    TargetInstance = $config.target.instance
    Mode = $Mode
    Stage = $Stage
    DatabaseName = $config.scope.databases
    IdentityMapCsv = ''  # Will be generated from config.identityMappings if needed
    DatabaseMapCsv = ''  # Will be generated from config.scope.databaseMappings if needed
    InventoryPath = $InventoryPath
    OutputDirectory = $config.artifactPolicy.outputDirectory
    TrustServerCertificate = $config.source.connection.trustServerCertificate
    AllowWindowsLogins = $config.operationPolicies.allowWindowsLogins
    AllowSqlLogins = $config.operationPolicies.allowSqlLogins
    AllowMachineAccounts = $config.operationPolicies.allowMachineAccounts
    AllowCustomRoles = $config.operationPolicies.allowCustomRoles
    AllowSchemas = $config.operationPolicies.allowSchemas
    AllowDefaultSchemaChanges = $config.operationPolicies.allowDefaultSchemaChanges
    AllowDatabasePermissions = $config.operationPolicies.allowDatabasePermissions
    AllowPrivilegedPermissions = $config.operationPolicies.allowPrivilegedPermissions
    AllowDenies = $config.operationPolicies.allowDenies
    AllowPrivilegedRoles = $config.operationPolicies.allowPrivilegedRoles
    AllowServerSecurity = $config.operationPolicies.allowServerSecurity
    AllowIdentityMapping = $config.operationPolicies.allowIdentityMapping
    IncludeAllServerLogins = $config.operationPolicies.includeAllServerLogins
    ApproveCommonTemplate = $config.operationPolicies.approveCommonTemplate
    ConnectTimeoutSeconds = $config.source.connection.connectTimeoutSeconds
    CommandTimeoutSeconds = $config.source.connection.commandTimeoutSeconds
    ExcludedDatabaseName = @($config.scope.excludedDatabases)
}

# Generate temporary mapping CSVs if needed
if ($config.identityMappings.Count -gt 0) {
    $idMapPath = [IO.Path]::GetTempFileName()
    $config.identityMappings | Select-Object @{Name='SourceLogin';Expression={$_.sourceIdentity}}, @{Name='TargetLogin';Expression={$_.targetIdentity}} | Export-Csv -LiteralPath $idMapPath -NoTypeInformation -Encoding UTF8
    $legacyParams.IdentityMapCsv = $idMapPath
    Write-Host "Generated identity map CSV: $idMapPath" -ForegroundColor Gray
}

if ($config.scope.databaseMappings.Count -gt 0) {
    $dbMapPath = [IO.Path]::GetTempFileName()
    $config.scope.databaseMappings | Select-Object @{Name='SourceDatabase';Expression={$_.sourceDatabase}}, @{Name='TargetDatabase';Expression={$_.targetDatabase}} | Export-Csv -LiteralPath $dbMapPath -NoTypeInformation -Encoding UTF8
    $legacyParams.DatabaseMapCsv = $dbMapPath
    Write-Host "Generated database map CSV: $dbMapPath" -ForegroundColor Gray
}

# Generate external ownership decisions CSV if needed (for planner consumption)
if ($config.externalOwnershipDecisions.Count -gt 0) {
    $extOwnPath = [IO.Path]::GetTempFileName()
    $config.externalOwnershipDecisions | Export-Csv -LiteralPath $extOwnPath -NoTypeInformation -Encoding UTF8
    $env:SQL_MIGRATION_EXTERNAL_OWNERSHIP = $extOwnPath
    Write-Host "Generated external ownership decisions CSV: $extOwnPath" -ForegroundColor Gray
}

# Invoke the migration engine
$migrationScript = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'Invoke-SqlSecurityMigration.ps1'
Write-Host "Invoking migration engine..." -ForegroundColor Cyan
& $migrationScript @legacyParams
$exitCode = $LASTEXITCODE

# Cleanup temp files
if ($legacyParams.IdentityMapCsv -and (Test-Path $legacyParams.IdentityMapCsv)) {
    Remove-Item -LiteralPath $legacyParams.IdentityMapCsv -Force -ErrorAction SilentlyContinue
}
if ($legacyParams.DatabaseMapCsv -and (Test-Path $legacyParams.DatabaseMapCsv)) {
    Remove-Item -LiteralPath $legacyParams.DatabaseMapCsv -Force -ErrorAction SilentlyContinue
}
if ($env:SQL_MIGRATION_EXTERNAL_OWNERSHIP -and (Test-Path $env:SQL_MIGRATION_EXTERNAL_OWNERSHIP)) {
    Remove-Item -LiteralPath $env:SQL_MIGRATION_EXTERNAL_OWNERSHIP -Force -ErrorAction SilentlyContinue
}

exit $exitCode
