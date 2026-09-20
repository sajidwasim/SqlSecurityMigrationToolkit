<#
.SYNOPSIS
Tests SQL Server connectivity using the same connection pattern as the SQL Security Migration Toolkit.

.DESCRIPTION
Read-only validation of SQL Server connectivity using Windows Integrated Authentication,
encrypted connections, and the System.Data.SqlClient library. Returns structured results
and meaningful exit codes.

.PARAMETER ServerInstance
Target SQL Server instance name (e.g., SPSTSQL01).

.PARAMETER Database
Database to connect to for validation. Defaults to 'master'.

.PARAMETER TrustServerCertificate
If specified, trusts the server certificate without validation (for corporate instances
with known certificates). Default is $false.

.PARAMETER ConnectTimeoutSeconds
Connection timeout in seconds. Default 15.

.PARAMETER CommandTimeoutSeconds
Command timeout in seconds. Default 30.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$ServerInstance,

    [Parameter(Position=1)]
    [string]$Database = 'master',

    [switch]$TrustServerCertificate,

    [ValidateRange(1, 120)]
    [int]$ConnectTimeoutSeconds = 15,

    [ValidateRange(1, 1800)]
    [int]$CommandTimeoutSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Validation query matching the toolkit's requirements
$ValidationQuery = @"
SET NOCOUNT ON;
SELECT
    CONVERT(nvarchar(256), SERVERPROPERTY('ServerName')) AS ServerName,
    CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion')) AS ProductVersion,
    CONVERT(int, SERVERPROPERTY('ProductMajorVersion')) AS MajorVersion,
    ORIGINAL_LOGIN() AS OriginalLogin,
    SUSER_SNAME() AS ExecutionLogin,
    SYSTEM_USER AS SystemUser,
    IS_SRVROLEMEMBER('sysadmin') AS IsSysadmin,
    (
        SELECT COUNT(*)
        FROM sys.databases
        WHERE database_id > 4
        AND state_desc = 'ONLINE'
        AND source_database_id IS NULL
    ) AS OnlineUserDatabaseCount;
"@

# Encryption validation query (requires VIEW SERVER STATE)
$EncryptionQuery = @"
SET NOCOUNT ON;
SELECT
    encrypt_option,
    auth_scheme,
    client_net_address
FROM sys.dm_exec_connections
WHERE session_id = @@SPID;
"@

function Test-SqlConnectionInternal {
    param(
        [string]$Server,
        [string]$Db,
        [bool]$TrustCert,
        [int]$ConnectTimeout,
        [int]$CommandTimeout
    )

    $result = @{
        ServerInstance      = $Server
        Database            = $Db
        Success             = $false
        ErrorCategory       = $null
        ErrorMessage        = $null
        ServerName          = $null
        ProductVersion      = $null
        MajorVersion        = $null
        OriginalLogin       = $null
        ExecutionLogin      = $null
        SystemUser          = $null
        IsSysadmin          = $null
        OnlineUserDatabaseCount = $null
        EncryptionOption    = $null
        AuthScheme          = $null
        ClientNetAddress    = $null
        ConnectionTimeMs    = 0
        QueryTimeMs         = 0
    }

    $cn = $null
    $connectTimer = [Diagnostics.Stopwatch]::StartNew()
    
    try {
        $builder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
        $builder['Data Source'] = $Server
        $builder['Initial Catalog'] = $Db
        $builder['Integrated Security'] = $true
        $builder['Encrypt'] = $true
        $builder['TrustServerCertificate'] = $TrustCert
        $builder['Application Name'] = 'Coop SQL Security Migration Toolkit - Connectivity Test'
        $builder['Connect Timeout'] = $ConnectTimeout
        $builder['Pooling'] = $false

        $cn = New-Object System.Data.SqlClient.SqlConnection($builder.ConnectionString)
        $cn.Open()
        
        $connectTimer.Stop()
        $result.ConnectionTimeMs = $connectTimer.ElapsedMilliseconds

        # Execute validation query
        $queryTimer = [Diagnostics.Stopwatch]::StartNew()
        $cmd = $cn.CreateCommand()
        $cmd.CommandText = $ValidationQuery
        $cmd.CommandTimeout = $CommandTimeout
        $reader = $cmd.ExecuteReader()

        if ($reader.Read()) {
            $result.ServerName = $reader['ServerName']
            $result.ProductVersion = $reader['ProductVersion']
            $result.MajorVersion = [int]$reader['MajorVersion']
            $result.OriginalLogin = $reader['OriginalLogin']
            $result.ExecutionLogin = $reader['ExecutionLogin']
            $result.SystemUser = $reader['SystemUser']
            $result.IsSysadmin = [bool]$reader['IsSysadmin']
            $result.OnlineUserDatabaseCount = [int]$reader['OnlineUserDatabaseCount']
            $result.Success = $true
        }
        $reader.Close()
        $queryTimer.Stop()
        $result.QueryTimeMs = $queryTimer.ElapsedMilliseconds

        # Try encryption validation (may fail if no VIEW SERVER STATE)
        try {
            $encCmd = $cn.CreateCommand()
            $encCmd.CommandText = $EncryptionQuery
            $encCmd.CommandTimeout = $CommandTimeout
            $encReader = $encCmd.ExecuteReader()
            if ($encReader.Read()) {
                $result.EncryptionOption = $encReader['encrypt_option']
                $result.AuthScheme = $encReader['auth_scheme']
                $result.ClientNetAddress = $encReader['client_net_address']
            }
            $encReader.Close()
        } catch {
            # Encryption info not available - not a connection failure
            $result.EncryptionOption = 'UNAVAILABLE'
            $result.AuthScheme = 'UNAVAILABLE'
            $result.ClientNetAddress = 'UNAVAILABLE'
        }

    } catch {
        $connectTimer.Stop()
        $result.ConnectionTimeMs = $connectTimer.ElapsedMilliseconds
        $result.Success = $false
        
        $ex = $_.Exception
        $msg = $ex.Message
        
        # Categorize the error
        if ($msg -like '*network*' -or $msg -like '*timeout*' -or $msg -like '*server was not found*') {
            $result.ErrorCategory = 'Network'
        } elseif ($msg -like '*SSL*' -or $msg -like '*certificate*' -or $msg -like '*TLS*') {
            $result.ErrorCategory = 'TLS/Certificate'
        } elseif ($msg -like '*login*' -or $msg -like '*authentication*' -or $msg -like '*SSPI*') {
            $result.ErrorCategory = 'Authentication'
        } elseif ($msg -like '*database*' -or $msg -like '*catalog*') {
            $result.ErrorCategory = 'Database'
        } else {
            $result.ErrorCategory = 'Other'
        }
        $result.ErrorMessage = $msg
    } finally {
        if ($null -ne $cn -and $cn.State -eq 'Open') {
            $cn.Close()
        }
        if ($null -ne $cn) {
            $cn.Dispose()
        }
    }
    
    return $result
}

# Main execution
try {
    $testResult = Test-SqlConnectionInternal `
        -Server $ServerInstance `
        -Db $Database `
        -TrustCert $TrustServerCertificate `
        -ConnectTimeout $ConnectTimeoutSeconds `
        -CommandTimeout $CommandTimeoutSeconds

    # Output structured result
    $testResult | ConvertTo-Json -Depth 3

    # Exit codes: 0=success, 1=connection failed, 2=validation query failed, 3=unexpected error
    if ($testResult.Success) {
        exit 0
    } else {
        Write-Error "Connection failed: [$($testResult.ErrorCategory)] $($testResult.ErrorMessage)"
        exit 1
    }
} catch {
    Write-Error "Unexpected error: $($_.Exception.Message)"
    exit 3
}