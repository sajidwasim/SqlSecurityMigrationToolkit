#requires -Version 5.1
<#
.SYNOPSIS
Read-only, application-agnostic SQL Server security audit and incident evidence collector.
.DESCRIPTION
Uses the current Windows process identity. Run PowerShell as an existing authorized
SQL inventory account; this script does not accept passwords, impersonate, or grant access.
All output is sensitive local evidence. No SQL DDL, GRANT, REVOKE, DENY or APPLY.
.EXAMPLE
.\Invoke-SqlSecurityAudit.ps1 -SqlInstances 'SQL-A','SQL-B' -DatabaseLikePattern 'App%' -AccountName 'DOMAIN\svc' -ObjectSchema dbo -ObjectName proc_example
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$SqlInstances,
    [string]$DatabaseLikePattern='',
    [string[]]$DatabaseName=@(),
    [string[]]$ExcludedDatabaseName=@(),
    [string]$AccountName='',
    [string]$ObjectSchema='dbo',
    [string]$ObjectName='',
    [string[]]$TrustCertificateForInstances=@(),
    [hashtable]$ExpectedCanonicalNames=@{},
    [string]$OutputDirectory='',
    [ValidateRange(1,120)][int]$ConnectTimeoutSeconds=15,
    [ValidateRange(1,1800)][int]$CommandTimeoutSeconds=120
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $DatabaseLikePattern -and $DatabaseName.Count -eq 0){throw 'Specify -DatabaseLikePattern and/or -DatabaseName explicitly. Nothing collected.'}
if($DatabaseLikePattern -eq '%' -and $DatabaseName.Count -eq 0){throw 'For deliberate all-database collection use an explicit database list; wildcard % alone is too broad.'}
if($ObjectName -and -not $AccountName){throw '-ObjectName requires -AccountName.'}
if($SqlInstances.Count -ne @($SqlInstances|Select-Object -Unique).Count){throw 'Duplicate SQL instances are not allowed.'}
foreach($name in $TrustCertificateForInstances){if($SqlInstances -notcontains $name){throw "Certificate exception not in selected instances: $name"}}
foreach($name in $ExpectedCanonicalNames.Keys){if($SqlInstances -notcontains $name){throw "Unexpected canonical-name mapping for unselected instance: $name"}}
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $root 'modules\SecurityAudit.psm1') -Force
Import-Module (Join-Path $root 'modules\AuditExcel.psm1') -Force
if(-not $OutputDirectory){
    if(-not $env:LOCALAPPDATA){throw 'Specify a protected local output directory on Windows.'}
    $OutputDirectory=Join-Path $env:LOCALAPPDATA 'SqlSecurityAudit'
}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
$walk=$OutputDirectory
while($walk){
    if(Test-Path -LiteralPath (Join-Path $walk '.git')){throw 'Audit evidence must not be placed inside a Git checkout.'}
    $parent=Split-Path -Parent $walk
    if(-not $parent -or $parent -eq $walk){break};$walk=$parent
}
[void][IO.Directory]::CreateDirectory($OutputDirectory)
try {
    $user=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    foreach($id in @($user,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))){
        $rule=[Security.AccessControl.FileSystemAccessRule]::new($id,[Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    [IO.Directory]::SetAccessControl($OutputDirectory,$acl)
}catch {throw ('Failed to secure evidence directory; no SQL collection started: '+$_.Exception.Message)}
$runId=[guid]::NewGuid().ToString('N')
$stamp=Get-Date -Format 'yyyyMMdd_HHmmss_fff'
$path=Join-Path $OutputDirectory "SqlSecurityAudit_${stamp}_${runId}.xlsx"
$jsonPath=[IO.Path]::ChangeExtension($path,'.json')
$sheets=[ordered]@{}
foreach($name in @('RunInfo','Databases','ServerLogins','ServerRoles','ServerPermissions',
    'DatabaseUsers','DatabaseRoles','DatabasePermissions','Schemas','Objects','Findings','Errors')){
    $sheets[$name]=New-Object 'System.Collections.Generic.List[object]'
}
function Add-AuditRows([string]$Sheet,[System.Data.DataTable]$Table,[string]$Instance,[string]$Database){
    foreach($row in @(Convert-AuditRows -Table $Table -Instance $Instance -Database $Database)){
        $sheets[$Sheet].Add($row)
    }
}
function Add-AuditError([string]$Instance,[string]$Database,[string]$Stage,[string]$Message){
    $sheets['Errors'].Add([pscustomobject]@{Instance=$Instance;Database=$Database;Stage=$Stage;Error=$Message;TimeUtc=[DateTime]::UtcNow.ToString('o')})
    Write-Warning "[$Instance][$Database][$Stage] $Message"
}
function Test-AuditDatabaseScope([object]$Row){
    if($Row.State -ne 'ONLINE'){return 'NOT_ONLINE'}
    if($null -ne $Row.SourceDatabaseId){return 'DATABASE_SNAPSHOT'}
    if($ExcludedDatabaseName -contains $Row.DatabaseName){return 'EXCLUDED'}
    if($DatabaseName -contains $Row.DatabaseName){return 'SELECTED'}
    if($DatabaseLikePattern -and $Row.DatabaseName -like $DatabaseLikePattern){return 'SELECTED'}
    return 'OUT_OF_SCOPE'
}
function Add-IncidentFinding([string]$Instance,[string]$Db){
    if(-not $ObjectName){return}
    $users=@($sheets['DatabaseUsers']|Where-Object {$_.Instance -eq $Instance -and $_.Database -eq $Db})
    $roles=@($sheets['DatabaseRoles']|Where-Object {$_.Instance -eq $Instance -and $_.Database -eq $Db})
    $perms=@($sheets['DatabasePermissions']|Where-Object {$_.Instance -eq $Instance -and $_.Database -eq $Db})
    $objects=@($sheets['Objects']|Where-Object {$_.Instance -eq $Instance -and $_.Database -eq $Db -and $_.SchemaName -eq $ObjectSchema -and $_.ObjectName -eq $ObjectName})
    if($objects.Count -eq 0){return}
    $account=@($users|Where-Object {$_.PrincipalName -eq $AccountName})
    $principals=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [void]$principals.Add($AccountName);[void]$principals.Add('public')
    $changed=$true
    while($changed){
        $changed=$false
        foreach($membership in $roles){if($principals.Contains([string]$membership.MemberName)){
            if($principals.Add([string]$membership.RoleName)){$changed=$true}
        }}
    }
    $paths=@($perms|Where-Object {
        $principals.Contains([string]$_.Grantee) -and $_.PermissionName -in @('EXECUTE','CONTROL') -and
        (($_.PermissionClass -eq 'DATABASE') -or
         ($_.PermissionClass -eq 'SCHEMA' -and $_.SecurableSchema -eq $ObjectSchema) -or
         ($_.PermissionClass -eq 'OBJECT_OR_COLUMN' -and [int]$_.MinorId -eq 0 -and $_.SecurableSchema -eq $ObjectSchema -and $_.SecurableObject -eq $ObjectName))
    })
    $grants=@($paths|Where-Object {$_.PermissionState -in @('GRANT','GRANT_WITH_GRANT_OPTION')})
    $denies=@($paths|Where-Object {$_.PermissionState -eq 'DENY'})
    $status=if($account.Count -eq 0){'ACCOUNT_USER_NOT_FOUND_REVIEW_GROUP_ACCESS'}
        elseif($denies.Count -gt 0){'EXPLICIT_DENY_REVIEW'}
        elseif($grants.Count -gt 0){'RECORDED_GRANT_PATH_REVIEW_EFFECTIVE_ACCESS'}
        else{'NO_RECORDED_EXECUTE_PATH_REVIEW_GROUP_ACCESS'}
    $sheets['Findings'].Add([pscustomobject]@{
        Instance=$Instance;Database=$Db;Account=$AccountName;Schema=$ObjectSchema;Object=$ObjectName;
        Finding=$status;GrantPathCount=$grants.Count;DenyPathCount=$denies.Count;
        Limitation='Catalog permissions and direct/transitive DB roles only; AD group tokens, EXECUTE AS, ownership and actual execution unverified.'
    })
}
$selected=0;$completed=0;$partial=$false
$start=[DateTime]::UtcNow
$sheets['RunInfo'].Add([pscustomobject]@{Instance='COLLECTOR';Database='';Item='WindowsIdentity';Value=[Security.Principal.WindowsIdentity]::GetCurrent().Name})
$sheets['RunInfo'].Add([pscustomobject]@{Instance='COLLECTOR';Database='';Item='RunId';Value=$runId})
$sheets['RunInfo'].Add([pscustomobject]@{Instance='COLLECTOR';Database='';Item='StartUtc';Value=$start.ToString('o')})
foreach($instance in $SqlInstances){
    $trust=($TrustCertificateForInstances -contains $instance)
    $sheets['RunInfo'].Add([pscustomobject]@{Instance=$instance;Database='master';Item='CertificateValidation';Value=$(if($trust){'EXPLICIT_EXCEPTION_ENCRYPTED_NOT_VALIDATED'}else{'VALIDATED_ENCRYPTED'})})
    $cn=$null
    try {
        $cn=New-AuditSqlConnection -Instance $instance -TrustCertificate $trust -ConnectTimeoutSeconds $ConnectTimeoutSeconds
        $meta=Invoke-AuditMetadataQuery -Connection $cn -Query ServerInfo -CommandTimeoutSeconds $CommandTimeoutSeconds
        if($meta.Rows.Count -ne 1){throw 'Instance identity query returned unexpected row count.'}
        $actual=[string]$meta.Rows[0]['CanonicalInstance']
        $expected=if($ExpectedCanonicalNames.ContainsKey($instance)){[string]$ExpectedCanonicalNames[$instance]}else{$instance}
        if($actual -ine $expected){throw "Endpoint identity mismatch: requested '$instance', expected '$expected', actual '$actual'. No metadata scanned."}
        Add-AuditRows 'RunInfo' $meta $instance 'master'
        if([int]$meta.Rows[0]['IsSysadmin'] -ne 1){
            $partial=$true
            Add-AuditError $instance 'master' 'MetadataVisibility' 'Account is not sysadmin; completeness of catalog metadata cannot be established.'
        }
        try {
            $encryption=Invoke-AuditMetadataQuery -Connection $cn -Query ConnectionEncryption -CommandTimeoutSeconds $CommandTimeoutSeconds
            if($encryption.Rows.Count -ne 1 -or [string]$encryption.Rows[0]['EncryptOption'] -ine 'TRUE'){
                throw 'Server did not confirm encrypted SQL transport.'
            }
            Add-AuditRows 'RunInfo' $encryption $instance 'master'
        }catch{throw ('Unable to verify connection encryption: '+$_.Exception.Message)}
        foreach($query in @('Databases','ServerLogins','ServerRoles','ServerPermissions')){
            $table=Invoke-AuditMetadataQuery -Connection $cn -Query $query -CommandTimeoutSeconds $CommandTimeoutSeconds
            Add-AuditRows $query $table $instance 'master'
        }
        $databaseRows=@($sheets['Databases']|Where-Object {$_.Instance -eq $instance})
        foreach($database in $databaseRows){
            $db=[string]$database.DatabaseName
            $scope=Test-AuditDatabaseScope $database
            $sheets['RunInfo'].Add([pscustomobject]@{Instance=$instance;Database=$db;Item='DatabaseScope';Value=$scope})
            if($scope -ne 'SELECTED'){continue}
            $selected++
            $dbConnection=$null
            try {
                $dbConnection=New-AuditSqlConnection -Instance $instance -Database $db -TrustCertificate $trust -ConnectTimeoutSeconds $ConnectTimeoutSeconds
                $data=@{}
                foreach($query in @('DatabaseUsers','DatabaseRoles','DatabasePermissions','Schemas','Objects')){
                    $data[$query]=Invoke-AuditMetadataQuery -Connection $dbConnection -Query $query -CommandTimeoutSeconds $CommandTimeoutSeconds
                }
                foreach($query in @('DatabaseUsers','DatabaseRoles','DatabasePermissions','Schemas','Objects')){
                    Add-AuditRows $query $data[$query] $instance $db
                }
                $completed++
                Add-IncidentFinding $instance $db
                $sheets['RunInfo'].Add([pscustomobject]@{Instance=$instance;Database=$db;Item='DatabaseScan';Value='COMPLETED'})
            }catch{
                $partial=$true
                Add-AuditError $instance $db 'DatabaseScan' $_.Exception.Message
                $sheets['RunInfo'].Add([pscustomobject]@{Instance=$instance;Database=$db;Item='DatabaseScan';Value='FAILED'})
            }finally{if($null -ne $dbConnection){$dbConnection.Dispose()}}
        }
    }catch{
        $partial=$true
        Add-AuditError $instance 'master' 'InstanceScan' $_.Exception.Message
        $sheets['RunInfo'].Add([pscustomobject]@{Instance=$instance;Database='master';Item='InstanceScan';Value='FAILED_OR_INCOMPLETE'})
    }finally{if($null -ne $cn){$cn.Dispose()}}
}
$sheets['RunInfo'].Add([pscustomobject]@{Instance='COLLECTOR';Database='';Item='Completeness';Value="Selected=$selected;Completed=$completed;Errors=$($sheets['Errors'].Count)"})
$sheets['RunInfo'].Add([pscustomobject]@{Instance='COLLECTOR';Database='';Item='Limitation';Value='Recorded catalog metadata, not effective AD token permissions or application acceptance. Findings require review; no automatic remediation.'})
$sheets['RunInfo'].Add([pscustomobject]@{Instance='COLLECTOR';Database='';Item='EndUtc';Value=[DateTime]::UtcNow.ToString('o')})
try {
    Export-AuditWorkbook -Sheets $sheets -Path $path
    $export=[ordered]@{SchemaVersion=1;RunId=$runId;ReadOnly=$true;Complete=((-not $partial) -and $completed -eq $selected -and $sheets['Errors'].Count -eq 0);Sheets=$sheets}
    $json=$export|ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText($jsonPath,$json,[Text.UTF8Encoding]::new($false))
}catch{throw ('Evidence export failed: '+$_.Exception.Message)}
Write-Host "Workbook: $path" -ForegroundColor Green
Write-Host "Local JSON: $jsonPath" -ForegroundColor Green
Write-Host "Database scans: $completed / $selected; errors: $($sheets['Errors'].Count). No SQL writes." -ForegroundColor Cyan
if($partial -or $completed -ne $selected -or $sheets['Errors'].Count -gt 0){exit 2}
exit 0
