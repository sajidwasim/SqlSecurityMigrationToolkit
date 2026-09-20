#requires -Version 5.1
<#
.SYNOPSIS
Discover candidate databases on two SQL Server instances without selecting a migration scope.
.DESCRIPTION
Runs a parameterized sys.databases LIKE query on each explicitly named instance using
Windows integrated authentication. Outputs JSON containing both complete matching lists,
state, exact-name matches and unmatched databases. No PLAN/APPLY or SQL writes occur.
The output is evidence for operator review, NOT an approved database mapping.
.EXAMPLE
.\tools\Get-SqlDatabaseCandidates.ps1 -SourceInstance SOURCE_SERVER -TargetInstance TARGET_SERVER -DatabaseLikePattern 'Example%'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$SourceInstance,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$TargetInstance,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$DatabaseLikePattern,
    [switch]$SourceTrustServerCertificate,
    [switch]$TargetTrustServerCertificate,
    [ValidateRange(1,120)][int]$ConnectTimeoutSeconds = 15,
    [ValidateRange(1,1800)][int]$CommandTimeoutSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($SourceInstance.Trim() -ieq $TargetInstance.Trim()) {
    throw 'Source and target must be distinct instances.'
}

function Invoke-DatabaseDiscovery {
    param([string]$Instance,[string]$Pattern,[bool]$TrustCertificate,[int]$ConnectTimeout,[int]$CommandTimeout)
    $connection = $null
    $command = $null
    $adapter = $null
    $data = New-Object System.Data.DataSet
    try {
        $builder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
        $builder['Data Source'] = $Instance
        $builder['Initial Catalog'] = 'master'
        $builder['Integrated Security'] = $true
        $builder['Encrypt'] = $true
        $builder['TrustServerCertificate'] = $TrustCertificate
        $builder['Connect Timeout'] = $ConnectTimeout
        $builder['Application Name'] = 'SQL Security Migration - Scope Discovery'
        $connection = New-Object System.Data.SqlClient.SqlConnection($builder.ConnectionString)
        $connection.Open()
        $command = $connection.CreateCommand()
        $command.CommandTimeout = $CommandTimeout
        $command.CommandText = @'
SET NOCOUNT ON;
SELECT @@SERVERNAME AS SQLInstance,
       CONVERT(int, SERVERPROPERTY('ProductMajorVersion')) AS MajorVersion,
       IS_SRVROLEMEMBER('sysadmin') AS IsSysadmin,
       (SELECT encrypt_option FROM sys.dm_exec_connections WHERE session_id = @@SPID) AS EncryptionOption;
SELECT @@SERVERNAME AS SQLInstance,
       name AS DatabaseName,
       state_desc
FROM sys.databases
WHERE name LIKE @DatabasePattern
ORDER BY name;
'@
        $parameter = $command.Parameters.Add('@DatabasePattern',[System.Data.SqlDbType]::NVarChar,128)
        $parameter.Value = $Pattern
        $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($command)
        [void]$adapter.Fill($data)
        if ($data.Tables.Count -ne 2 -or $data.Tables[0].Rows.Count -ne 1) {
            throw "Unexpected discovery result-set shape from $Instance."
        }
        $metadata = $data.Tables[0].Rows[0]
        $actualInstance = [string]$metadata['SQLInstance']
        if ([string]::IsNullOrWhiteSpace($actualInstance)) {
            throw "SQL Server did not report its identity for $Instance."
        }
        if ($actualInstance -ine $Instance) {
            throw "Requested instance '$Instance' resolved to '$actualInstance'; review the endpoint before continuing."
        }
        if ([int]$metadata['IsSysadmin'] -ne 1) {
            throw "Incomplete metadata risk on $Instance: execution account is not sysadmin."
        }
        if ([string]$metadata['EncryptionOption'] -ine 'TRUE') {
            throw "Connection to $Instance did not confirm transport encryption."
        }
        $databases = New-Object 'System.Collections.Generic.List[object]'
        foreach ($row in $data.Tables[1].Rows) {
            $databases.Add([pscustomobject]@{
                SQLInstance = [string]$row['SQLInstance']
                DatabaseName = [string]$row['DatabaseName']
                state_desc = [string]$row['state_desc']
            }) | Out-Null
        }
        return [pscustomobject]@{
            SQLInstance = $actualInstance
            MajorVersion = [int]$metadata['MajorVersion']
            EncryptionOption = [string]$metadata['EncryptionOption']
            Databases = @($databases.ToArray())
        }
    }
    finally {
        if ($null -ne $adapter) { $adapter.Dispose() }
        if ($null -ne $command) { $command.Dispose() }
        if ($null -ne $connection) { $connection.Dispose() }
        $data.Dispose()
    }
}

$source = Invoke-DatabaseDiscovery -Instance $SourceInstance -Pattern $DatabaseLikePattern -TrustCertificate ([bool]$SourceTrustServerCertificate) -ConnectTimeout $ConnectTimeoutSeconds -CommandTimeout $CommandTimeoutSeconds
$target = Invoke-DatabaseDiscovery -Instance $TargetInstance -Pattern $DatabaseLikePattern -TrustCertificate ([bool]$TargetTrustServerCertificate) -ConnectTimeout $ConnectTimeoutSeconds -CommandTimeout $CommandTimeoutSeconds

$sourceNames = @($source.Databases | ForEach-Object { $_.DatabaseName })
$targetNames = @($target.Databases | ForEach-Object { $_.DatabaseName })
$matched = @($source.Databases | Where-Object { $targetNames -ccontains $_.DatabaseName })
$sourceOnly = @($source.Databases | Where-Object { $targetNames -cnotcontains $_.DatabaseName })
$targetOnly = @($target.Databases | Where-Object { $sourceNames -cnotcontains $_.DatabaseName })
$onlineExactMatches = New-Object 'System.Collections.Generic.List[string]'
foreach ($item in $matched) {
    $targetRow = @($target.Databases | Where-Object { $_.DatabaseName -ceq $item.DatabaseName })[0]
    if ($item.state_desc -eq 'ONLINE' -and $targetRow.state_desc -eq 'ONLINE') {
        $onlineExactMatches.Add($item.DatabaseName) | Out-Null
    }
}

[pscustomobject]@{
    Status = 'DISCOVERY_COMPLETE_REVIEW_REQUIRED'
    ReadOnly = $true
    ScopeApproved = $false
    DatabaseLikePattern = $DatabaseLikePattern
    Source = $source
    Target = $target
    ExactNameMatches = @($matched | ForEach-Object { $_.DatabaseName })
    OnlineExactNameMatches = @($onlineExactMatches.ToArray())
    SourceOnly = $sourceOnly
    TargetOnly = $targetOnly
    ReviewNote = 'Review every state, exclusion, missing/renamed database and mapping. Discovery does not automatically authorize or run PLAN.'
} | ConvertTo-Json -Depth 7
