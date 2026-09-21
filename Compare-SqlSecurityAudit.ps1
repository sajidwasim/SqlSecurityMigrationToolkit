#requires -Version 5.1
<#
.SYNOPSIS
Compare two COMPLETE local JSON security inventories. Emits observations, never SQL fixes.
.DESCRIPTION
Explicit source and target instance pairing. Exact database names unless a reviewed
SourceDatabase,TargetDatabase CSV is supplied. Identity differences can be mapped using
SourceIdentity,TargetIdentity CSV. Metadata differences are not automatically defects.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourceInventoryPath,
    [Parameter(Mandatory)][string]$TargetInventoryPath,
    [Parameter(Mandatory)][string]$SourceInstance,
    [Parameter(Mandatory)][string]$TargetInstance,
    [string]$DatabaseMapCsv='',
    [string]$IdentityMapCsv=''
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $root 'modules\AuditExcel.psm1') -Force
function Read-AuditInventory([string]$Path){
    if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){throw "Inventory file missing: $Path"}
    $value=Get-Content -LiteralPath $Path -Raw -Encoding UTF8|ConvertFrom-Json
    if($value.SchemaVersion -ne 1 -or $value.ReadOnly -ne $true -or $value.Complete -ne $true){
        throw "Inventory incomplete or schema unsupported: $Path. Recollect with full metadata visibility."
    }
    return $value
}
$source=Read-AuditInventory $SourceInventoryPath
$target=Read-AuditInventory $TargetInventoryPath
$sourceInfo=@($source.Sheets.RunInfo|Where-Object {$_.Instance -eq $SourceInstance -and $_.Item -eq 'DatabaseScan' -and $_.Value -eq 'COMPLETED'})
$targetInfo=@($target.Sheets.RunInfo|Where-Object {$_.Instance -eq $TargetInstance -and $_.Item -eq 'DatabaseScan' -and $_.Value -eq 'COMPLETED'})
if($sourceInfo.Count -eq 0 -or $targetInfo.Count -eq 0){throw 'Both paired instances require at least one successfully scanned database.'}
$databaseMap=@{}
if($DatabaseMapCsv){
    foreach($row in @(Import-Csv -LiteralPath $DatabaseMapCsv)){
        if(-not $row.SourceDatabase -or -not $row.TargetDatabase){throw 'Database map requires SourceDatabase,TargetDatabase.'}
        if($databaseMap.ContainsKey($row.SourceDatabase)){throw 'Duplicate source database mapping.'}
        $databaseMap[$row.SourceDatabase]=$row.TargetDatabase
    }
}
$identityMap=@{}
if($IdentityMapCsv){
    foreach($row in @(Import-Csv -LiteralPath $IdentityMapCsv)){
        if(-not $row.SourceIdentity -or -not $row.TargetIdentity){throw 'Identity map requires SourceIdentity,TargetIdentity.'}
        if($identityMap.ContainsKey($row.SourceIdentity)){throw 'Duplicate source identity mapping.'}
        $identityMap[$row.SourceIdentity]=$row.TargetIdentity
    }
}
function Map-Principal([object]$Value){
    $name=[string]$Value
    if($identityMap.ContainsKey($name)){return [string]$identityMap[$name]}
    return $name
}
$diffs=[System.Collections.Generic.List[object]]::new()
$coverage=[System.Collections.Generic.List[object]]::new()
$sections=@(
    @{Name='ServerLogins';Fields=@('PrincipalName','PrincipalType','SidHex','IsDisabled','DefaultDatabase');Mapped=@('PrincipalName')},
    @{Name='ServerRoles';Fields=@('RoleName','MemberName');Mapped=@('RoleName','MemberName')},
    @{Name='ServerPermissions';Fields=@('Grantee','PermissionState','PermissionName','PermissionClass','SecurableName');Mapped=@('Grantee','SecurableName')},
    @{Name='DatabaseUsers';Fields=@('PrincipalName','PrincipalType','AuthenticationType','SidHex','DefaultSchema');Mapped=@('PrincipalName')},
    @{Name='DatabaseRoles';Fields=@('RoleName','MemberName');Mapped=@('RoleName','MemberName')},
    @{Name='DatabasePermissions';Fields=@('Grantee','PermissionState','PermissionName','PermissionClass','SecurableSchema','SecurableObject','SecurableColumn');Mapped=@('Grantee')},
    @{Name='Schemas';Fields=@('SchemaName','OwnerName');Mapped=@('OwnerName')},
    @{Name='Objects';Fields=@('SchemaName','ObjectName','ObjectType','ExplicitOrFallbackOwner');Mapped=@('ExplicitOrFallbackOwner')}
)
function Key-For([object]$Record,[object]$Section,[bool]$MapSource){
    $values=[System.Collections.Generic.List[string]]::new()
    foreach($field in $Section.Fields){
        $value=$Record.$field
        if($MapSource -and $Section.Mapped -contains $field){$value=Map-Principal $value}
        $text=if($null -eq $value){'<NULL>'}else{[string]$value}
        $values.Add([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text)))
    }
    return ($values -join ':')
}
function Compare-Section([object]$Section,[string]$SourceDatabase,[string]$TargetDatabase,[bool]$ServerLevel){
    $name=$Section.Name
    $sourceRows=@($source.Sheets.$name|Where-Object {$_.Instance -eq $SourceInstance -and ($ServerLevel -or $_.Database -eq $SourceDatabase)})
    $targetRows=@($target.Sheets.$name|Where-Object {$_.Instance -eq $TargetInstance -and ($ServerLevel -or $_.Database -eq $TargetDatabase)})
    $sourceKeys=[System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::Ordinal)
    $targetKeys=[System.Collections.Generic.Dictionary[string,int]]::new([StringComparer]::Ordinal)
    foreach($row in $sourceRows){$key=Key-For $row $Section $true;if(-not $sourceKeys.ContainsKey($key)){$sourceKeys[$key]=0};$sourceKeys[$key]++}
    foreach($row in $targetRows){$key=Key-For $row $Section $false;if(-not $targetKeys.ContainsKey($key)){$targetKeys[$key]=0};$targetKeys[$key]++}
    foreach($key in $sourceKeys.Keys){
        $targetCount=if($targetKeys.ContainsKey($key)){$targetKeys[$key]}else{0}
        if($sourceKeys[$key] -ne $targetCount){
            $record=@($sourceRows|Where-Object {(Key-For $_ $Section $true) -eq $key})[0]
            $diffs.Add([pscustomobject]@{Section=$name;SourceInstance=$SourceInstance;TargetInstance=$TargetInstance;
                SourceDatabase=$SourceDatabase;TargetDatabase=$TargetDatabase;Difference='SOURCE_RECORD_COUNT_DIFFERS';
                SourceCount=$sourceKeys[$key];TargetCount=$targetCount;Evidence=($record|ConvertTo-Json -Compress -Depth 4);
                Assessment='REVIEW_REQUIRED_NOT_AUTOMATIC_DEFECT'})
        }
    }
    foreach($key in $targetKeys.Keys){
        if(-not $sourceKeys.ContainsKey($key)){
            $record=@($targetRows|Where-Object {(Key-For $_ $Section $false) -eq $key})[0]
            $diffs.Add([pscustomobject]@{Section=$name;SourceInstance=$SourceInstance;TargetInstance=$TargetInstance;
                SourceDatabase=$SourceDatabase;TargetDatabase=$TargetDatabase;Difference='TARGET_ONLY_RECORD';
                SourceCount=0;TargetCount=$targetKeys[$key];Evidence=($record|ConvertTo-Json -Compress -Depth 4);
                Assessment='REVIEW_REQUIRED_NOT_AUTOMATIC_DEFECT'})
        }
    }
    $coverage.Add([pscustomobject]@{Section=$name;SourceDatabase=$SourceDatabase;TargetDatabase=$TargetDatabase;
        SourceRows=$sourceRows.Count;TargetRows=$targetRows.Count;Status='COMPARED_RECORDED_METADATA'})
}
foreach($section in $sections|Where-Object {$_.Name -in @('ServerLogins','ServerRoles','ServerPermissions')}){
    Compare-Section $section 'master' 'master' $true
}
$targetNames=@($targetInfo|ForEach-Object {$_.Database})
$paired=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach($item in $sourceInfo){
    $sourceDb=[string]$item.Database
    $targetDb=if($databaseMap.ContainsKey($sourceDb)){$databaseMap[$sourceDb]}else{$sourceDb}
    if($targetNames -notcontains $targetDb){
        $coverage.Add([pscustomobject]@{Section='DATABASE';SourceDatabase=$sourceDb;TargetDatabase=$targetDb;SourceRows=0;TargetRows=0;Status='TARGET_DATABASE_NOT_SCANNED_REVIEW_REQUIRED'})
        continue
    }
    if(-not $paired.Add($targetDb)){throw "Multiple source databases map to one destination: $targetDb"}
    foreach($section in $sections|Where-Object {$_.Name -notin @('ServerLogins','ServerRoles','ServerPermissions')}){
        Compare-Section $section $sourceDb $targetDb $false
    }
}
foreach($targetDb in $targetNames){
    if(-not $paired.Contains([string]$targetDb)){
        $coverage.Add([pscustomobject]@{Section='DATABASE';SourceDatabase='';TargetDatabase=$targetDb;SourceRows=0;TargetRows=0;Status='TARGET_ONLY_DATABASE_REVIEW_REQUIRED'})
    }
}
$destination=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($TargetInventoryPath))
$path=Join-Path $destination ('SqlSecurityComparison_'+(Get-Date -Format 'yyyyMMdd_HHmmss_fff')+'_'+[guid]::NewGuid().ToString('N')+'.xlsx')
$sheets=[ordered]@{Coverage=$coverage;Differences=$diffs;TargetFindings=@($target.Sheets.Findings|Where-Object {$_.Instance -eq $TargetInstance});
    Caveats=@([pscustomobject]@{Assessment='OBSERVATIONS_ONLY';Limitations='Catalog visibility, Windows group tokens, impersonation and runtime behavior unverified; SID and renamed principal differences need explicit review. No SQL is executed or generated.'})}
Export-AuditWorkbook -Sheets $sheets -Path $path
Write-Host "Comparison workbook: $path" -ForegroundColor Green
Write-Host "Observed differences: $($diffs.Count); database coverage entries: $($coverage.Count); no SQL was executed." -ForegroundColor Cyan
if(@($coverage|Where-Object {$_.Status -ne 'COMPARED_RECORDED_METADATA'}).Count -gt 0){exit 2}
exit 0
