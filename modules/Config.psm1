<#
.SYNOPSIS
Configuration management module for SQL Security Migration Toolkit
.LOAD
Import-Module "$PSScriptRoot\modules\Config.psm1"
#>
Set-StrictMode -Version Latest

# Module manifest data
$script:ModuleRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:SchemaPath = Join-Path $script:ModuleRoot '..\config\schema\profile.schema.json'
$script:ExamplesPath = Join-Path $script:ModuleRoot '..\config\examples'
$script:LocalPath = Join-Path $script:ModuleRoot '..\config\local'

function Get-ConfigSchema {
    if (-not (Test-Path -LiteralPath $script:SchemaPath)) {
        throw "Configuration schema not found at $script:SchemaPath"
    }
    $json = Get-Content -LiteralPath $script:SchemaPath -Raw -Encoding UTF8
    return $json | ConvertFrom-Json
}

function Validate-Profile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProfilePath,

        [switch]$AllowUnknownKeys
    )
    if (-not (Test-Path -LiteralPath $ProfilePath)) {
        throw "Profile file not found: $ProfilePath"
    }
    $json = Get-Content -LiteralPath $ProfilePath -Raw -Encoding UTF8
    # ConvertFrom-Json in Windows PowerShell 5.1 has no -Depth parameter.
    $profile = $json | ConvertFrom-Json

    # Basic structural validation
    $required = @('profileName','source','target','scope','operationPolicies','artifactPolicy')
    foreach ($req in $required) {
        if (-not $profile.PSObject.Properties.Name -contains $req) {
            throw "Profile missing required section: $req"
        }
    }

    function Assert-KnownKeys($object, $schemaObject, [string]$path) {
        if ($null -eq $object -or $null -eq $schemaObject) { return }
        $allowed = @($schemaObject.properties.PSObject.Properties.Name)
        foreach ($property in $object.PSObject.Properties) {
            if ($allowed -notcontains $property.Name) {
                throw "Unknown configuration key: $path.$($property.Name)"
            }
            $schemaProperty = $schemaObject.properties.($property.Name)
            if ($schemaProperty.type -eq 'object') {
                Assert-KnownKeys $property.Value $schemaProperty "$path.$($property.Name)"
            } elseif ($schemaProperty.type -eq 'array' -and $schemaProperty.items.type -eq 'object') {
                $index = 0
                foreach ($item in @($property.Value)) {
                    Assert-KnownKeys $item $schemaProperty.items "$path.$($property.Name)[$index]"
                    $index++
                }
            }
        }
    }
    if (-not $AllowUnknownKeys) { Assert-KnownKeys $profile (Get-ConfigSchema) '$' }

    # Validate source/target instances
    if (-not $profile.source.instance -or -not $profile.target.instance) {
        throw "Source and target instance are required"
    }
    if ($profile.source.instance -eq $profile.target.instance -and $profile.scope.mode -ne 'discoveryOnly') {
        throw "Source and target instance must differ"
    }

    # Validate scope mode
    $validScopeModes = @('exactList','allOnlineUserDatabases','patternInclude','patternExclude','discoveryOnly')
    if ($validScopeModes -notcontains $profile.scope.mode) {
        throw "Invalid scope.mode: $($profile.scope.mode). Valid: $($validScopeModes -join ', ')"
    }
    if ($profile.scope.mode -eq 'exactList' -and (-not $profile.scope.databases -or $profile.scope.databases.Count -eq 0)) {
        throw "scope.databases is required when scope.mode is 'exactList'"
    }

    # Validate database mappings for duplicates
    if ($profile.scope.databaseMappings) {
        $srcSeen = @{}
        $tgtSeen = @{}
        foreach ($map in $profile.scope.databaseMappings) {
            if ($srcSeen.ContainsKey($map.sourceDatabase)) {
                throw "Duplicate source database in mappings: $($map.sourceDatabase)"
            }
            if ($tgtSeen.ContainsKey($map.targetDatabase)) {
                throw "Duplicate target database in mappings: $($map.targetDatabase)"
            }
            $srcSeen[$map.sourceDatabase] = $true
            $tgtSeen[$map.targetDatabase] = $true
        }
    }

    # Validate identity mappings for duplicates
    if ($profile.identityMappings) {
        $srcSeen = @{}
        $tgtSeen = @{}
        foreach ($map in $profile.identityMappings) {
            if ($srcSeen.ContainsKey($map.sourceIdentity)) {
                throw "Duplicate source identity in mappings: $($map.sourceIdentity)"
            }
            if ($tgtSeen.ContainsKey($map.targetIdentity)) {
                throw "Duplicate target identity in mappings: $($map.targetIdentity)"
            }
            $srcSeen[$map.sourceIdentity] = $true
            $tgtSeen[$map.targetIdentity] = $true
        }
    }

    # Validate external ownership decisions
    if ($profile.externalOwnershipDecisions) {
        foreach ($decision in $profile.externalOwnershipDecisions) {
            $validTypes = @('ExternallyManaged','OperatorVerified','RequiresProvisioning')
            if ($validTypes -notcontains $decision.decisionType) {
                throw "Invalid decisionType in externalOwnershipDecisions: $($decision.decisionType). Valid: $($validTypes -join ', ')"
            }
            $validScopes = @('Global','Database','Instance')
            if ($decision.scope -and $validScopes -notcontains $decision.scope) {
                throw "Invalid scope in externalOwnershipDecisions: $($decision.scope). Valid: $($validScopes -join ', ')"
            }
        }
    }

    # Validate operation policies (all boolean, no extra validation needed)

    return $profile
}

function Merge-ProfileWithDefaults {
    param(
        [Parameter(Mandatory=$true)]
        [pscustomobject]$Profile
    )
    function Get-SchemaDefaults($props) {
        $result = @{}
        foreach ($propName in $props.PSObject.Properties.Name) {
            $prop = $props.PSObject.Properties[$propName].Value
            $defaultProperty = $prop.PSObject.Properties['default']
            if ($null -ne $defaultProperty) {
                $result[$propName] = $defaultProperty.Value
            } elseif ($prop.type -eq 'object' -and $null -ne $prop.PSObject.Properties['properties']) {
                $result[$propName] = Get-SchemaDefaults $prop.PSObject.Properties['properties'].Value
            }
        }
        return $result
    }

    $schema = Get-ConfigSchema
    $defaults = Get-SchemaDefaults $schema.properties

    function Merge-Object($target, $source, $defaults) {
        foreach ($key in $defaults.Keys) {
            if ($source.PSObject.Properties.Name -contains $key) {
                $val = $source.$key
                if ($val -is [pscustomobject] -and $defaults[$key] -is [hashtable]) {
                    $target.$key = Merge-Object @{} $val $defaults[$key]
                } else {
                    $target.$key = $val
                }
            } else {
                $target.$key = $defaults[$key]
            }
        }
        # Copy any extra keys from source not in defaults (if allowed)
        foreach ($key in $source.PSObject.Properties.Name) {
            if (-not $defaults.ContainsKey($key)) {
                $target.$key = $source.$key
            }
        }
        return $target
    }

    $merged = @{}
    $merged = Merge-Object $merged $Profile $defaults
    return [pscustomobject]$merged
}

function Resolve-EffectiveConfig {
    param(
        [Parameter(Mandatory=$true)]
        [pscustomobject]$Profile,

        [hashtable]$CliOverrides = @{}
    )
    # Clone profile
    $config = $Profile | ConvertTo-Json -Depth 20 | ConvertFrom-Json

    # Apply CLI overrides (highest precedence)
    foreach ($key in $CliOverrides.Keys) {
        $value = $CliOverrides[$key]
        # Support nested keys like "source.instance"
        if ($key -like '*.*') {
            $parts = $key.Split('.')
            $obj = $config
            for ($i = 0; $i -lt $parts.Count - 1; $i++) {
                if (-not $obj.PSObject.Properties.Name -contains $parts[$i]) {
                    $obj.$($parts[$i]) = @{}
                }
                $obj = $obj.$($parts[$i])
            }
            $obj.$($parts[-1]) = $value
        } else {
            $config.$key = $value
        }
    }

    return $config
}

function Get-RedactedConfig {
    param(
        [Parameter(Mandatory=$true)]
        [pscustomobject]$Config
    )
    # Deep clone and redact sensitive fields
    $json = $Config | ConvertTo-Json -Depth 20
    $redacted = $json | ConvertFrom-Json

    # Redact connection passwords if present (should not be in profile)
    $credentials = $redacted.authentication.PSObject.Properties['sqlCredentials']
    if ($null -ne $credentials -and $null -ne $credentials.Value) {
        if ($credentials.Value.PSObject.Properties['sourcePasswordEnvVar']) {
            $credentials.Value.sourcePasswordEnvVar = '[REDACTED_ENV_VAR]'
        }
        if ($credentials.Value.PSObject.Properties['targetPasswordEnvVar']) {
            $credentials.Value.targetPasswordEnvVar = '[REDACTED_ENV_VAR]'
        }
    }

    return $redacted
}

function Show-EffectiveConfig {
    param(
        [Parameter(Mandatory=$true)]
        [pscustomobject]$Config
    )
    $redacted = Get-RedactedConfig $Config
    Write-Host "=== Effective Configuration ===" -ForegroundColor Cyan
    Write-Host "Profile: $($redacted.profileName)" -ForegroundColor Green
    Write-Host "Source: $($redacted.source.instance)" -ForegroundColor Yellow
    Write-Host "Target: $($redacted.target.instance)" -ForegroundColor Yellow
    Write-Host "Scope Mode: $($redacted.scope.mode)" -ForegroundColor Yellow
    if ($redacted.scope.databases) {
        Write-Host "Databases: $($redacted.scope.databases.Count) specified" -ForegroundColor Yellow
    }
    if ($redacted.scope.databaseMappings) {
        Write-Host "DB Mappings: $($redacted.scope.databaseMappings.Count)" -ForegroundColor Yellow
    }
    if ($redacted.identityMappings) {
        Write-Host "Identity Mappings: $($redacted.identityMappings.Count)" -ForegroundColor Yellow
    }
    if ($redacted.externalOwnershipDecisions) {
        Write-Host "External Ownership Decisions: $($redacted.externalOwnershipDecisions.Count)" -ForegroundColor Yellow
    }
    Write-Host "Operation Policies:" -ForegroundColor Yellow
    foreach ($p in $redacted.operationPolicies.PSObject.Properties) {
        Write-Host "  $($p.Name): $($p.Value)" -ForegroundColor Gray
    }
    Write-Host "==============================" -ForegroundColor Cyan
}

function New-ProfileFromTemplate {
    param(
        [Parameter(Mandatory=$true)]
        [string]$TemplateName,

        [Parameter(Mandatory=$true)]
        [string]$OutputPath,

        [hashtable]$Substitutions = @{}
    )
    $templatePath = Join-Path $script:ExamplesPath "${TemplateName}.json"
    if (-not (Test-Path -LiteralPath $templatePath)) {
        throw "Template not found: $templatePath"
    }
    $json = Get-Content -LiteralPath $templatePath -Raw -Encoding UTF8
    $profile = $json | ConvertFrom-Json -Depth 10

    # Apply substitutions
    foreach ($key in $Substitutions.Keys) {
        $value = $Substitutions[$key]
        if ($key -like '*.*') {
            $parts = $key.Split('.')
            $obj = $profile
            for ($i = 0; $i -lt $parts.Count - 1; $i++) {
                if (-not $obj.PSObject.Properties.Name -contains $parts[$i]) {
                    $obj.$($parts[$i]) = @{}
                }
                $obj = $obj.$($parts[$i])
            }
            $obj.$($parts[-1]) = $value
        } else {
            $profile.$key = $value
        }
    }

    # Validate
    # Write before validating so the generated file is the artifact being checked.
    $profile | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    $validated = Validate-Profile -ProfilePath $OutputPath -AllowUnknownKeys:$false -ErrorAction Stop
    return $profile
}

Export-ModuleMember -Function Validate-Profile, Merge-ProfileWithDefaults, Resolve-EffectiveConfig, Get-RedactedConfig, Show-EffectiveConfig, New-ProfileFromTemplate, Get-ConfigSchema
