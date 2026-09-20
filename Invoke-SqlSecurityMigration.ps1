#requires -Version 5.1
<#
SQL Security Migration Toolkit 2.0 (SQL Server 2012+ on-premises)
PLAN records source inventory and compares target. APPLY requires the reviewed PLAN inventory and target confirmation.
No SQL Server connection is made merely by downloading or opening this file.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SourceInstance,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TargetInstance,
  [ValidateSet('Plan','Apply')][string]$Mode='Plan',
  [ValidateSet('Prompt','Logins','Users','Roles','ServerSecurity','All')][string]$Stage='Prompt',
  [string[]]$DatabaseName,
  [string[]]$ExcludedDatabaseName,
  [string]$IdentityMapCsv='',
  [string]$DatabaseMapCsv='',
  [string]$InventoryPath='',
  [string]$OutputDirectory='',
  [switch]$TrustServerCertificate,
  [switch]$AllowWindowsLogins,
  [switch]$AllowSqlLogins,
  [switch]$AllowMachineAccounts,
  [switch]$AllowCustomRoles,
  [switch]$AllowSchemas,
  [switch]$AllowDefaultSchemaChanges,
  [switch]$AllowDatabasePermissions,
  [switch]$AllowPrivilegedPermissions,
  [switch]$AllowDenies,
  [switch]$AllowPrivilegedRoles,
  [switch]$AllowServerSecurity,
  [switch]$AllowIdentityMapping,
  [switch]$IncludeAllServerLogins,
  [switch]$ApproveCommonTemplate,
  [ValidateRange(1,120)][int]$ConnectTimeoutSeconds=15,
  [ValidateRange(1,1800)][int]$CommandTimeoutSeconds=120
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($SourceInstance.Trim() -ieq $TargetInstance.Trim()) {throw 'Source and target instance must differ.'}
if ($Mode -eq 'Apply' -and -not $InventoryPath) {throw 'APPLY requires -InventoryPath pointing to a previously reviewed PLAN session. No automatic live-source replay.'}
if ($Mode -eq 'Plan' -and $Stage -ne 'Prompt') {throw 'PLAN is read-only; do not specify an APPLY stage.'}
if ($Mode -eq 'Apply' -and $IdentityMapCsv -and -not $AllowIdentityMapping) {throw 'Identity mapping requires -AllowIdentityMapping and a reviewed mapping CSV.'}
$basedir=Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $OutputDirectory) {$OutputDirectory=Join-Path $basedir 'Results'}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$stamp=Get-Date -Format 'yyyyMMdd_HHmmss_fff'
$tag=(($SourceInstance+'__TO__'+$TargetInstance) -replace '[^a-zA-Z0-9_-]','_')+'_'+$stamp
$sessionDir=Join-Path $OutputDirectory $tag
[void][IO.Directory]::CreateDirectory($sessionDir)
# Protect reports: prefer a private directory and do not ever write SQL password hashes.
try { & icacls.exe $sessionDir /inheritance:r /grant:r ('{0}:(OI)(CI)F' -f [Security.Principal.WindowsIdentity]::GetCurrent().Name) | Out-Null; if($LASTEXITCODE -ne 0){throw ('icacls exit='+$LASTEXITCODE)} }
catch { Write-Warning 'Unable to tighten output ACLs. Choose a secured directory before collecting security reports.' }
$script:LogPath=Join-Path $sessionDir 'Session.log'
$script:Actions=New-Object System.Collections.Generic.List[object]
$script:Stages=New-Object System.Collections.Generic.List[object]
$script:WindowsIdentity=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$script:SourceInstance=$SourceInstance
$script:TargetInstance=$TargetInstance
$script:IdentityMap=@{}
$script:DatabaseMap=@{}
$script:DatabaseReverse=@{}
$script:PlanNumber=0
$script:SnapshotCapture=($Mode -eq 'Plan')
$script:PinnedInventory=($Mode -eq 'Apply')
$script:LiveSourceVerification=$false
$script:SnapshotDatasets=@{}
$script:DestinationDatasets=@{}
$script:SnapshotManifest=$null
$script:IdentityMapFromSnapshot=''
$script:DatabaseMapFromSnapshot=''
$script:SnapshotFolder=Join-Path $sessionDir 'SourceInventory'
if ($script:SnapshotCapture) {[void][IO.Directory]::CreateDirectory($script:SnapshotFolder)}

$script:SourceMajor=0
$script:TargetMajor=0
$script:SourceMeta=$null
$script:TargetMeta=$null
$script:SelectedDbs=@()
$script:DestinationDbs=@()
$script:MatchingDbs=@()
$script:AdditionalDestinationDbs=@()
$script:TotalServerDatabaseInventory=@()
$script:ApprovedSourceDatabases=@()
$script:DestinationMigrationCandidates=@()
$script:ExplicitlyExcludedDatabases=@($ExcludedDatabaseName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
$script:UnclassifiedDatabases=@()
$script:ApprovedSourceDatabases=@()
$script:ReviewRequiredDestinationDatabases=@()
$script:CommonTemplate=$null
$script:TemplateEvidence=@()
$script:RelevantLogins=@{}

function Scrub([string]$message){return ($message -replace '(?i)0x[0-9a-f]{64,}','[REDACTED_BINARY]')}
function Log([string]$level,[string]$message) {
  $message=Scrub $message
  $line='{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'),$level,$message
  try {
    [IO.File]::AppendAllText($script:LogPath,$line+[Environment]::NewLine,(New-Object Text.UTF8Encoding($false)))
  } catch {
    Write-Warning ('Unable to append Session.log: '+$_.Exception.Message)
  }
  if ($level -in @('ERROR','BLOCKED')) {Write-Host $line -ForegroundColor Red}
  elseif ($level -in @('WARN','REVIEW')) {Write-Host $line -ForegroundColor Yellow}
  elseif ($level -eq 'APPLIED') {Write-Host $line -ForegroundColor Green}
  else {Write-Host $line}
}
function PostPlan-Log([string]$message) {
  $process=Get-Process -Id $PID -ErrorAction SilentlyContinue
  $workingSet=if($null -ne $process){$process.WorkingSet64}else{0}
  Log INFO ('POSTPLAN '+$message+' WorkingSetBytes='+$workingSet)
}
function Convert-InventoryValue($value) {
  if($null -eq $value -or $value -is [DBNull]){return $null}
  if($value -is [byte[]]){return (Hex $value)}
  return $value
}
function Convert-InventoryRowContract($row) {
  $values=[ordered]@{}
  if($row -is [System.Data.DataRow]){
    foreach($column in $row.Table.Columns){$values[[string]$column.ColumnName]=Convert-InventoryValue $row[$column.ColumnName]}
  } else {
    foreach($property in $row.PSObject.Properties){$values[$property.Name]=Convert-InventoryValue $property.Value}
  }
  return [pscustomobject]$values
}
function Convert-InventoryContract($inventory) {
  $empty=[ordered]@{ServerWide=@();Principals=@();Schemas=@();Memberships=@();Permissions=@();Objects=@();Types=@()}
  if($null -eq $inventory -or $null -eq $inventory.PSObject -or $null -eq $inventory.PSObject.Properties){return $empty}
  return [ordered]@{
    ServerWide=$(if($inventory.PSObject.Properties.Name -contains 'ServerWide'){@($inventory.ServerWide)}else{@()})
    Principals=@($inventory.Principals|ForEach-Object {Convert-InventoryRowContract $_})
    Schemas=@($inventory.Schemas|ForEach-Object {Convert-InventoryRowContract $_})
    Memberships=@($inventory.Memberships|ForEach-Object {Convert-InventoryRowContract $_})
    Permissions=@($inventory.Permissions|ForEach-Object {Convert-InventoryRowContract $_})
    Objects=@($inventory.Objects|ForEach-Object {Convert-InventoryRowContract $_})
    Types=@($inventory.Types|ForEach-Object {Convert-InventoryRowContract $_})
  }
}
function Write-AtomicText([string]$path,[string]$content) {
  $temp=$path+'.tmp_'+[Guid]::NewGuid().ToString('N')
  try {
    [IO.File]::WriteAllText($temp,$content,(New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temp -Destination $path -Force
  } finally {
    if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue}
  }
}
function Qi([string]$name) {return '['+$name.Replace(']',']]')+']'}
function Qs([string]$value) {return "N'"+$value.Replace("'","''")+"'"}
function Val($v) {if ($null -eq $v -or $v -is [DBNull]) {return ''};return [string]$v}
function Hex($value) {if ($null -eq $value -or $value -is [DBNull]) {return ''};return '0x'+[BitConverter]::ToString([byte[]]$value).Replace('-','')}
function Key([string]$a,[string]$b) {return $a.ToUpperInvariant()+[char]31+$b.ToUpperInvariant()}
function TableRows($ds,[int]$index) {return @($ds.Tables[$index].Rows)}
function ByName($rows,[string]$column='Name') {
  $hash=@{};foreach($r in $rows){$n=[string]$r[$column];if($hash.ContainsKey($n)){throw ('Ambiguous principal/schema names under case-insensitive comparison: '+$n)};$hash[$n]=$r};return ,$hash
}
function Lookup($map,[string]$name) {if ($map.ContainsKey($name)){return $map[$name]};return $null}
function IsMachine([string]$name) {return $name.EndsWith('$') -or $name -match '^(NT SERVICE|NT AUTHORITY|BUILTIN)\\'}
function IsSensitiveRole([string]$name) {return $name -match '^(db_owner|db_securityadmin|db_accessadmin|db_ddladmin|db_datareader|db_datawriter|db_backupoperator|db_denydatareader|db_denydatawriter|sysadmin|securityadmin|serveradmin|setupadmin|processadmin|diskadmin|bulkadmin)$'}
function TargetDatabase([string]$db) {if ($script:DatabaseMap.ContainsKey($db)) {return $script:DatabaseMap[$db]};return $db}
function TargetLoginName([string]$sourceName) {
  if ($script:IdentityMap.ContainsKey($sourceName)) {return $script:IdentityMap[$sourceName]};return $sourceName
}
function UserDatabases($meta) {
  return @($meta.Databases|Where-Object {$_.database_id -gt 4 -and $_.state_desc -eq 'ONLINE' -and $_.source_database_id -is [DBNull]}|ForEach-Object {[string]$_.name})
}
function Inventory-RowKey($row,[string]$kind) {
  switch($kind){
    'Principals' {return (Key ((Val $row.Name)+'|'+(Val $row.Type)) (Val $row.LoginName))}
    'Schemas' {return (Key (Val $row.Name) (Val $row.OwnerName))}
    'Memberships' {return (Key (Val $row.RoleName) (Val $row.MemberName))}
    'Permissions' {return (Permission-Object $row '').Key}
    'Objects' {return (Key (Val $row.SchemaName) ((Val $row.ObjectName)+'|'+(Val $row.ColumnName)))}
    'Types' {return (Key (Val $row.SchemaName) (Val $row.TypeName))}
    default {throw ('Unsupported common-template inventory kind: '+$kind)}
  }
}
function Common-Rows($inventories,[string]$kind) {
  if(-not $inventories.Count){return @()}
  $first=@($inventories[0].$kind)
  $result=New-Object System.Collections.Generic.List[object]
  $sets=New-Object System.Collections.Generic.List[hashtable]
  foreach($inventory in $inventories){
    $set=@{}
    foreach($row in @($inventory.PSObject.Properties[$kind].Value)){$set[(Inventory-RowKey $row $kind)]=$true}
    $sets.Add($set)|Out-Null
  }
  foreach($row in $first){
    $signature=Inventory-RowKey $row $kind
    $present=$true
    foreach($set in $sets){
      if(-not $set.ContainsKey($signature)){$present=$false;break}
    }
    if($present){$result.Add($row)|Out-Null}
  }
  return @($result.ToArray())
}
function Derive-CommonTemplate($inventories) {
  $template=[ordered]@{ServerWide=@('ServerLogins','ServerRoleMemberships','ServerPermissions')}
  PostPlan-Log 'START: DeriveCommonUsers';$template.Principals=@(Common-Rows $inventories 'Principals'|Where-Object {$_.Type -in @('S','U','G','R')});PostPlan-Log ('END: DeriveCommonUsers Count='+$template.Principals.Count)
  PostPlan-Log 'START: DeriveCommonRoles';$template.Schemas=@(Common-Rows $inventories 'Schemas');PostPlan-Log ('END: DeriveCommonRoles Count='+$template.Schemas.Count)
  PostPlan-Log 'START: DeriveCommonMemberships';$template.Memberships=@(Common-Rows $inventories 'Memberships');PostPlan-Log ('END: DeriveCommonMemberships Count='+$template.Memberships.Count)
  PostPlan-Log 'START: DeriveCommonPermissions';$template.Permissions=@(Common-Rows $inventories 'Permissions');$template.Objects=@(Common-Rows $inventories 'Objects');$template.Types=@(Common-Rows $inventories 'Types');PostPlan-Log ('END: DeriveCommonPermissions Count='+$template.Permissions.Count)
  $evidence=New-Object System.Collections.Generic.List[object]
  foreach($item in $template.ServerWide){
    $evidence.Add([pscustomobject]@{Category='ServerWide';Kind='ServerSecurity';Name=$item;EvidenceDatabases=$inventories.Count;Classification='ServerWide'})|Out-Null
  }
  foreach($kind in @('Principals','Schemas','Memberships','Permissions','Objects','Types')){
    foreach($row in $template[$kind]){
      $name=switch($kind){
        'Principals' {(Val $row.Name)}
        'Schemas' {(Val $row.Name)}
        'Memberships' {(Val $row.RoleName)+' / '+(Val $row.MemberName)}
        'Permissions' {(Permission-Object $row '').Key}
        'Objects' {(Val $row.SchemaName)+'.'+(Val $row.ObjectName)}
        'Types' {(Val $row.SchemaName)+'.'+(Val $row.TypeName)}
      }
      $classification=if($kind -eq 'Permissions' -and -not (Permission-Object $row '').Supported){'UnsupportedForAdditionalDatabase'}else{'CommonDatabase'}
      $evidence.Add([pscustomobject]@{Category=$(if($classification -eq 'CommonDatabase'){'CommonDatabase'}else{'DatabaseSpecific'});Kind=$kind;Name=$name;EvidenceDatabases=$inventories.Count;Classification=$classification})|Out-Null
    }
  }
  $template.CommonTemplate=$true
  return [pscustomobject]@{Data=[pscustomobject]$template;Evidence=@($evidence.ToArray())}
}
function ApplyCommonTemplate([string]$db,$target) {
  if($null -eq $script:CommonTemplate){throw 'Common template has not been derived from the complete source inventory.'}
  Plan-Database $db $script:CommonTemplate $target
}

# Pinned PLAN snapshot: native DataSet XML retains varbinary SIDs and data types.
# No SQL password hashes are ever persisted. A SHA256 file hash detects accidental
# modification, not a malicious actor who can also rewrite the manifest.
function File-SHA256([string]$path) { return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
function Dataset-Fingerprint([System.Data.DataSet]$ds,[bool]$server=$false) {
  $lines=New-Object System.Collections.Generic.List[string]
  $start=if($server){1}else{0}
  for($ti=$start;$ti -lt $ds.Tables.Count;$ti++) {
    $tab=$ds.Tables[$ti]
    $cols=@($tab.Columns|ForEach-Object {[string]$_.ColumnName})
    $lines.Add(('TABLE:{0}:COLUMNS:{1}' -f $ti,($cols -join '|')))
    $all=New-Object System.Collections.Generic.List[string]
    foreach($row in $tab.Rows) {
      $values=New-Object System.Collections.Generic.List[string]
      foreach($col in $cols) {
        $v=$row[$col]
        $str=if($null -eq $v -or $v -is [DBNull]) {'<NULL>'}
             elseif($v -is [byte[]]) {[BitConverter]::ToString($v).Replace('-','')}
             elseif($v -is [bool]) {if($v){'1'}else{'0'}}
             else {[string]$v}
        $values.Add([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($str)))
      }
      $all.Add(($values -join '|'))
    }
    foreach($item in @($all|Sort-Object -CaseSensitive)) {$lines.Add($item)}
  }
  $sha=[Security.Cryptography.SHA256]::Create()
  try {$raw=[Text.Encoding]::UTF8.GetBytes([string]::Join("`n",$lines));return [BitConverter]::ToString($sha.ComputeHash($raw)).Replace('-','')}
  finally {$sha.Dispose()}
}
function Read-SnapshotDataset([string]$path,[int]$expected) {
  if(-not (Test-Path -LiteralPath $path -PathType Leaf)){throw ('Snapshot file missing: '+$path)}
  $ds=New-Object System.Data.DataSet
  try {[void]$ds.ReadXml($path,[System.Data.XmlReadMode]::ReadSchema)}
  catch {throw ('Snapshot XML invalid: '+$path+' / '+$_.Exception.Message)}
  if($ds.Tables.Count -ne $expected){throw ('Unexpected snapshot dataset table count: '+$path)}
  return ,$ds
}
function Server-FromDataset([System.Data.DataSet]$data) {
  if ($data.Tables.Count -ne 5 -or $data.Tables[0].Rows.Count -ne 1){throw 'Server snapshot result count incorrect.'}
  $info=$data.Tables[0].Rows[0]
  if ([int]$info.IsSysadmin -ne 1){throw ('Fail closed: source inventory was not collected as sysadmin: '+$info.ServerName)}
  return [pscustomobject]@{Info=$info;Databases=@(TableRows $data 1);Logins=@(TableRows $data 2);Members=@(TableRows $data 3);Permissions=@(TableRows $data 4)}
}
function Database-FromDataset([System.Data.DataSet]$data) {
  if($data.Tables.Count -ne 6){throw 'Database snapshot returned unexpected result-set count.'}
  return [pscustomobject]@{Principals=@(TableRows $data 0);Schemas=@(TableRows $data 1);Memberships=@(TableRows $data 2);Permissions=@(TableRows $data 3);Objects=@(TableRows $data 4);Types=@(TableRows $data 5)}
}
# Readable exports supplement the typed XML snapshot; only XML+manifest are
# consumed by APPLY. Never export password verifier fields.
function Write-ReadableTable([System.Data.DataTable]$table,[string]$path) {
  $names=@($table.Columns|ForEach-Object {[string]$_.ColumnName}|Where-Object {$_ -ne 'PasswordHash'})
  if(-not $names.Count){throw 'Cannot export metadata table with no non-secret columns.'}
  $rows=New-Object System.Collections.Generic.List[object]
  foreach($row in $table.Rows){
    $values=[ordered]@{}
    foreach($name in $names){
      $v=$row[$name]
      $values[$name]=if($null -eq $v -or $v -is [DBNull]){''}elseif($v -is [byte[]]){[BitConverter]::ToString($v).Replace('-','')}else{[string]$v}
    }
    $rows.Add([pscustomobject]$values)|Out-Null
  }
  if($rows.Count){$rows|Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8}
  else {('"'+($names -join '","')+'"')|Set-Content -LiteralPath $path -Encoding UTF8}
}
function Save-ReadableSource {
  $out=Join-Path $script:SnapshotFolder 'Readable'
  [void][IO.Directory]::CreateDirectory($out)
  $server=$script:SnapshotDatasets['server']
  $serverFiles=@('ServerInfo','Databases','Logins','ServerMemberships','ServerPermissions')
  for($i=0;$i -lt $serverFiles.Count;$i++){
    Write-ReadableTable $server.Tables[$i] (Join-Path $out ('Source_'+$serverFiles[$i]+'.csv'))
  }
  $dbFiles=@('Principals','Schemas','RoleMemberships','DatabasePermissions','ObjectsAndColumns','Types')
  for($i=0;$i -lt $script:SelectedDbs.Count;$i++){
    $db=[string]$script:SelectedDbs[$i]
    $folder=Join-Path $out ('Database_{0:D3}' -f ($i+1))
    [void][IO.Directory]::CreateDirectory($folder)
    $db|Set-Content -LiteralPath (Join-Path $folder 'SourceDatabaseName.txt') -Encoding UTF8
    $ds=$script:SnapshotDatasets[$db]
    # Object/column/type detail is preserved in the XML snapshot; the other
    # four files are sufficient for human security review.
    for($j=0;$j -lt 4;$j++){
      Write-ReadableTable $ds.Tables[$j] (Join-Path $folder ($dbFiles[$j]+'.csv'))
    }
  }
}
function Validate-SnapshotPath([string]$relative) {
  if($relative -notmatch '^(server\.xml|DB_[0-9]{3}\.xml|DEST_[0-9]{3}\.json|IdentityMap\.csv|DatabaseMap\.csv|CommonTemplate\.json)$') {throw ('Unsafe inventory file path: '+$relative)}
  return (Join-Path $script:SnapshotFolder $relative)
}
function Load-ApprovedInventory {
  $script:SnapshotFolder=[IO.Path]::GetFullPath($InventoryPath)
  if(-not (Test-Path -LiteralPath $script:SnapshotFolder -PathType Container)){throw ('PLAN inventory folder does not exist: '+$script:SnapshotFolder)}
  $manifestPath=Join-Path $script:SnapshotFolder 'Manifest.json'
  if(-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)){throw 'PLAN Manifest.json not found; APPLY requires an actual PLAN inventory, not a CSV export.'}
  $completionMarker=Join-Path $script:SnapshotFolder 'Completion.marker'
  if(-not (Test-Path -LiteralPath $completionMarker -PathType Leaf)){throw 'PLAN completion marker missing; inventory publication is incomplete.'}
  if((Get-Content -LiteralPath $completionMarker -Raw -Encoding UTF8).Trim() -ne 'PLAN_COMPLETED_WITH_EXCEPTIONS'){throw 'PLAN completion marker is invalid.'}
  $manifest=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
  if($manifest.FormatVersion -ne 2 -or $manifest.Mode -ne 'PLAN'){throw 'Unsupported or invalid source inventory manifest.'}
  if($manifest.SourceInstance -ine $SourceInstance -or $manifest.TargetInstance -ine $TargetInstance){throw 'Source/target instance mismatch against approved PLAN manifest.'}
  if(-not $DatabaseName -or -not $DatabaseName.Count){$script:SelectedDbs=@($manifest.Databases|ForEach-Object {$_.SourceDatabase});$script:FromManifestScope=$true}
  else {$script:SelectedDbs=@($DatabaseName|ForEach-Object {$_.Trim()});$script:FromManifestScope=$false}
  $expected=@($manifest.Databases|ForEach-Object {$_.SourceDatabase})
  if($script:SelectedDbs.Count -ne $expected.Count -or @($script:SelectedDbs|Select-Object -Unique).Count -ne $expected.Count){throw 'APPLY database scope must exactly match PLAN inventory with unique source names; rerun PLAN for another scope.'}
  foreach($name in $script:SelectedDbs){if($expected -notcontains $name){throw ('Source database not in PLAN inventory: '+$name)}}
  foreach($name in $expected){if($script:SelectedDbs -notcontains $name){throw ('Approved PLAN database omitted from APPLY scope: '+$name)}}
  if($manifest.IdentityMapHash){
    if(-not $IdentityMapCsv){$script:IdentityMapFromSnapshot=Join-Path $script:SnapshotFolder 'IdentityMap.csv'}
  } elseif($IdentityMapCsv) {throw 'PLAN used no identity map; run new PLAN with approved map.'}
  if($manifest.DatabaseMapHash){
    if(-not $DatabaseMapCsv){$script:DatabaseMapFromSnapshot=Join-Path $script:SnapshotFolder 'DatabaseMap.csv'}
  } elseif($DatabaseMapCsv) {throw 'PLAN used no database map; run new PLAN with desired map.'}
  $files=@(@{Name='server.xml';Sha=$manifest.ServerFileHash})
  foreach($d in $manifest.Databases){$files+=@{Name=[string]$d.File;Sha=[string]$d.FileHash}}
  if($manifest.IdentityMapHash){$files+=@{Name='IdentityMap.csv';Sha=$manifest.IdentityMapHash}}
  if($manifest.DatabaseMapHash){$files+=@{Name='DatabaseMap.csv';Sha=$manifest.DatabaseMapHash}}
  foreach($file in $files){$actual=File-SHA256 (Validate-SnapshotPath $file.Name);if($actual -ne $file.Sha){throw ('PLAN snapshot integrity check failed: '+$file.Name)}}
  if($manifest.CompleteDestinationInventory -ne $true -or $manifest.DestinationDatabaseCount -ne $manifest.ExpectedDestinationDatabaseCount){throw 'Approved PLAN does not contain a complete destination inventory.'}
  if($manifest.ScopeResolvedForApply -ne $true){throw 'Approved PLAN contains unresolved database classifications; APPLY is blocked.'}
  if($manifest.RequireTemplateApproval -and -not $manifest.CommonTemplate){throw 'Approved PLAN is missing its derived common security template.'}
  if($manifest.TemplateEvidenceFile -and (File-SHA256 (Validate-SnapshotPath $manifest.TemplateEvidenceFile)) -ne $manifest.TemplateEvidenceHash){throw 'Common template evidence changed since PLAN.'}
  foreach($d in $manifest.DestinationDatabases){
    if(-not $d.InventoryFile -or (File-SHA256 (Validate-SnapshotPath ([string]$d.InventoryFile))) -ne $d.InventoryHash){throw ('Destination inventory integrity check failed: '+$d.Database)}
  }
  $plan=Join-Path (Split-Path -Parent $script:SnapshotFolder) 'Plan01_Plan.csv'
  if((File-SHA256 $plan) -ne $manifest.ReviewPlanHash){throw 'PLAN comparison report changed since inventory capture.'}
  $serverFile=Validate-SnapshotPath 'server.xml'
  $serverDs=Read-SnapshotDataset $serverFile 5
  if((Dataset-Fingerprint $serverDs $true) -ne $manifest.ServerFingerprint){throw 'Source server snapshot fingerprint mismatch.'}
  $script:SnapshotDatasets['server']=$serverDs
  foreach($d in $manifest.Databases){
    $ds=Read-SnapshotDataset (Validate-SnapshotPath ([string]$d.File)) 6
    if((Dataset-Fingerprint $ds $false) -ne $d.Fingerprint){throw ('Source database snapshot fingerprint mismatch: '+$d.SourceDatabase)}
    $script:SnapshotDatasets[[string]$d.SourceDatabase]=$ds
  }
  $script:SnapshotManifest=$manifest
  Log INFO ('Approved PLAN inventory loaded: '+$script:SnapshotFolder+'; databases='+$manifest.Databases.Count)
}
function Save-InventoryManifest {
  if(-not $script:SnapshotCapture){return}
  PostPlan-Log 'START: LoadSourceInventory'
  $entries=New-Object System.Collections.Generic.List[object]
  for($i=0;$i -lt $script:SelectedDbs.Count;$i++){
    $db=[string]$script:SelectedDbs[$i];$file=('DB_{0:D3}.xml' -f ($i+1))
    $src=$script:SnapshotDatasets[$db]
    if($null -eq $src){throw ('Source dataset was not captured: '+$db)}
    $path=Join-Path $script:SnapshotFolder $file
    $src.WriteXml($path,[System.Data.XmlWriteMode]::WriteSchema)
    $entries.Add([pscustomobject]@{SourceDatabase=$db;TargetDatabase=(TargetDatabase $db);File=$file;FileHash=(File-SHA256 $path);Fingerprint=(Dataset-Fingerprint $src $false)})|Out-Null
  }
  PostPlan-Log ('END: LoadSourceInventory SourceCount='+$entries.Count)
  $serverFile=Join-Path $script:SnapshotFolder 'server.xml'
  $script:SnapshotDatasets['server'].WriteXml($serverFile,[System.Data.XmlWriteMode]::WriteSchema)
  $destinationEntries=New-Object System.Collections.Generic.List[object]
  $destinationIndex=0
  PostPlan-Log 'START: PersistDestinationInventory'
  foreach($db in $script:DestinationDbs){
    $destinationIndex++
    $destinationFile=('DEST_{0:D3}.json' -f $destinationIndex)
    $destinationPath=Join-Path $script:SnapshotFolder $destinationFile
    # A failed inventory must be recorded as not-captured, never crash publication.
    # APPLY still refuses incomplete destination inventories at load time.
    if(-not $script:DestinationDatasets.ContainsKey($db)){
      Log ERROR ('Destination inventory missing, recorded as not captured: '+$db)
      $destinationEntries.Add([pscustomobject]@{
        Database=$db
        Classification=$(if($script:MatchingDbs -contains $db){'MatchingDatabase'}elseif($script:ReviewRequiredDestinationDatabases -contains $db){'ReviewRequired'}elseif($script:ExplicitlyExcludedDatabases -contains $db){'ExplicitlyExcluded'}elseif($script:DestinationMigrationCandidates -contains $db){'AdditionalMigrationCandidate'}else{'Unclassified'})
        SourceDatabase=$(if($script:MatchingDbs -contains $db){$db}else{''})
        InventoryCaptured=$false
        InventoryFile=''
        InventoryHash=''
      })|Out-Null
      continue
    }
    $destinationContract=Convert-InventoryContract $script:DestinationDatasets[$db]
    $destinationJson=$destinationContract|ConvertTo-Json -Depth 8
    Write-AtomicText $destinationPath $destinationJson
    $destinationEntries.Add([pscustomobject]@{
      Database=$db
      Classification=$(if($script:MatchingDbs -contains $db){'MatchingDatabase'}elseif($script:ReviewRequiredDestinationDatabases -contains $db){'ReviewRequired'}elseif($script:ExplicitlyExcludedDatabases -contains $db){'ExplicitlyExcluded'}elseif($script:DestinationMigrationCandidates -contains $db){'AdditionalMigrationCandidate'}else{'Unclassified'})
      SourceDatabase=$(if($script:MatchingDbs -contains $db){$db}else{''})
      InventoryCaptured=$script:DestinationDatasets.ContainsKey($db)
      InventoryFile=$destinationFile
      InventoryHash=File-SHA256 $destinationPath
    })|Out-Null
  }
  PostPlan-Log ('END: PersistDestinationInventory DestinationCount='+$destinationEntries.Count)
  PostPlan-Log 'START: SerializeCommonTemplate'
  $templateFile=Join-Path $script:SnapshotFolder 'CommonTemplate.json'
  $templateContract=[ordered]@{Data=Convert-InventoryContract $script:CommonTemplate;Evidence=@($script:TemplateEvidence|ForEach-Object {Convert-InventoryRowContract $_})}
  Write-AtomicText $templateFile ($templateContract|ConvertTo-Json -Depth 8)
  PostPlan-Log ('END: SerializeCommonTemplate EvidenceCount='+$script:TemplateEvidence.Count)
  $identityHash='';$databaseHash=''
  if($IdentityMapCsv){$copy=Join-Path $script:SnapshotFolder 'IdentityMap.csv';Copy-Item -LiteralPath $IdentityMapCsv -Destination $copy -Force;$identityHash=File-SHA256 $copy}
  if($DatabaseMapCsv){$copy=Join-Path $script:SnapshotFolder 'DatabaseMap.csv';Copy-Item -LiteralPath $DatabaseMapCsv -Destination $copy -Force;$databaseHash=File-SHA256 $copy}
  $planFile=Join-Path $sessionDir 'Plan01_Plan.csv'
  PostPlan-Log 'START: BuildManifest'
  $manifest=[ordered]@{
    FormatVersion=2;Mode='PLAN';CreatedUtc=[DateTime]::UtcNow.ToString('o');
    SourceInstance=$SourceInstance;TargetInstance=$TargetInstance;
    CanonicalSource=[string]$script:SourceMeta.Info.ServerName;CanonicalTarget=[string]$script:TargetMeta.Info.ServerName;
    SourceMajor=[int]$script:SourceMeta.Info.MajorVersion;
    ServerFileHash=File-SHA256 $serverFile;ServerFingerprint=Dataset-Fingerprint $script:SnapshotDatasets['server'] $true;
    IdentityMapHash=$identityHash;DatabaseMapHash=$databaseHash;ReviewPlanHash=File-SHA256 $planFile;
    TotalSourceDatabaseCount=$script:TotalServerDatabaseInventory.SourceCount;TotalDestinationDatabaseCount=$script:TotalServerDatabaseInventory.DestinationCount;
    SourceDatabaseCount=$script:SelectedDbs.Count;DestinationDatabaseCount=$script:DestinationDbs.Count;
    ApprovedSourceDatabases=@($script:ApprovedSourceDatabases);DestinationMigrationCandidates=@($script:DestinationMigrationCandidates);
    ExplicitlyExcludedDatabases=@($script:ExplicitlyExcludedDatabases);ReviewRequiredDestinationDatabases=@($script:ReviewRequiredDestinationDatabases);UnclassifiedDatabases=@($script:UnclassifiedDatabases);
    ExpectedSourceDatabaseCount=$script:SelectedDbs.Count;ExpectedDestinationDatabaseCount=$script:DestinationDbs.Count;ExpectedAdditionalDestinationDatabaseCount=$script:AdditionalDestinationDbs.Count;
    CompleteDestinationInventory=($script:DestinationDatasets.Count -eq $script:DestinationDbs.Count);ScopeResolvedForApply=($script:UnclassifiedDatabases.Count -eq 0);FullDestinationInventory=$true;MatchingDatabases=@($script:MatchingDbs);AdditionalDestinationDatabases=@($script:AdditionalDestinationDbs);
    DestinationDatabases=@($destinationEntries.ToArray());CommonTemplate=$true;RequireTemplateApproval=$true;
    TemplateEvidenceFile='CommonTemplate.json';TemplateEvidenceHash=File-SHA256 $templateFile;
    Databases=@($entries.ToArray());
    Limitations='SHA256 detects accidental changes, not a malicious rewrite of both manifest and inventory; no password hashes stored; review every stage and validate external application provisioning where applicable.'
  }
  $manifestPath=Join-Path $script:SnapshotFolder 'Manifest.json'
  $manifestJson=$manifest|ConvertTo-Json -Depth 8
  PostPlan-Log 'END: BuildManifest'
  Save-ReadableSource
  Write-AtomicText $manifestPath $manifestJson
  PostPlan-Log 'START: ValidateManifest'
  if(-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)){throw 'Manifest publication failed.'}
  foreach($entry in $destinationEntries){
    if($entry.InventoryCaptured -and -not (Test-Path -LiteralPath (Join-Path $script:SnapshotFolder $entry.InventoryFile) -PathType Leaf)){throw ('Destination artifact missing: '+$entry.Database)}
  }
  if(-not (Test-Path -LiteralPath $templateFile -PathType Leaf)){throw 'Common template publication failed.'}
  PostPlan-Log 'END: ValidateManifest'
  Write-AtomicText (Join-Path $script:SnapshotFolder 'Completion.marker') ('PLAN_COMPLETED_WITH_EXCEPTIONS'+[Environment]::NewLine)
  PostPlan-Log 'END: Finalize'
  Log INFO ('Source inventory snapshot saved to '+$script:SnapshotFolder+'; store the WHOLE PLAN session securely for APPLY.')
}
function Verify-SourceUnchanged {
  if(-not $script:PinnedInventory){return}
  $script:LiveSourceVerification=$true
  try {
    $live=Server-Inventory $true $false
    if((Val $live.Info.ServerName) -ine [string]$script:SnapshotManifest.CanonicalSource){throw 'Source canonical server identity changed since PLAN.'}
    # The captured sysadmin identity may be different, but complete metadata is required in both runs.
    if((Dataset-Fingerprint $script:LastLiveServerDataset $true) -ne $script:SnapshotManifest.ServerFingerprint){throw 'SOURCE DRIFT: source server security metadata changed since PLAN. Rerun PLAN.'}
    foreach($db in $script:SelectedDbs){
      [void](Database-Inventory $db $true)
      $entry=@($script:SnapshotManifest.Databases|Where-Object {$_.SourceDatabase -eq $db})[0]
      if((Dataset-Fingerprint $script:LastLiveDatabaseDataset $false) -ne $entry.Fingerprint){throw ('SOURCE DRIFT in ['+$db+']: metadata changed since PLAN. Rerun PLAN.')}
    }
    Log INFO 'Source snapshot drift check passed for server security and all selected database security/object metadata.'
  } finally {$script:LiveSourceVerification=$false}
}
function Query-Sql {
  param([string]$Server,[string]$Database,[string]$Sql,
    [string]$QueryId='Unspecified',[string]$InventoryStage='SQL',[switch]$Write)
  $cn=$null
  $startedUtc=[DateTime]::UtcNow
  $timer=[Diagnostics.Stopwatch]::StartNew()
  Log INFO ('InventoryStage='+$InventoryStage+' QueryId='+$QueryId+' START Server='+$Server+' Database='+$Database+' StartedUtc='+$startedUtc.ToString('o'))
  try {
    $builder=New-Object System.Data.SqlClient.SqlConnectionStringBuilder
    $builder['Data Source']=$Server;$builder['Initial Catalog']=$Database
    $builder['Integrated Security']=$true;$builder['Encrypt']=$true
    $builder['TrustServerCertificate']=[bool]$TrustServerCertificate
    $builder['Application Name']='Coop SQL Security Migration Toolkit'
    $builder['Connect Timeout']=$ConnectTimeoutSeconds
    # Prevent reused pooled connections from crossing alternate network identities.
    $builder['Pooling']=$false
    $cn=[System.Data.SqlClient.SqlConnection]::new($builder.ConnectionString)
    $cn.Open()
    $cmd=$cn.CreateCommand();$cmd.CommandText=$Sql;$cmd.CommandTimeout=$CommandTimeoutSeconds
    if ($Write) {$n=$cmd.ExecuteNonQuery();return $n}
    $ds=New-Object System.Data.DataSet
    $adapter=[System.Data.SqlClient.SqlDataAdapter]::new($cmd)
    [void]$adapter.Fill($ds)
    $rowCounts=@($ds.Tables|ForEach-Object {$_.Rows.Count}) -join ','
    $resultSetIds='Principals,Schemas,RoleMemberships,DatabasePermissions,ObjectsAndColumns,Types'
    $timer.Stop()
    Log INFO ('InventoryStage='+$InventoryStage+' QueryId='+$QueryId+' ResultSetId='+$resultSetIds+' COMPLETE Server='+$Server+' Database='+$Database+' CompletedUtc='+[DateTime]::UtcNow.ToString('o')+' ElapsedMs='+$timer.ElapsedMilliseconds+' RowCounts='+$rowCounts)
    return ,$ds
  } catch {
    $timer.Stop()
    Log ERROR ('InventoryStage='+$InventoryStage+' QueryId='+$QueryId+' FAILED Server='+$Server+' Database='+$Database+' FailedUtc='+[DateTime]::UtcNow.ToString('o')+' ElapsedMs='+$timer.ElapsedMilliseconds+' Exception='+$_.Exception.Message)
    throw
  } finally {
    if ($null -ne $cn) {$cn.Dispose()}
  }
}
function Read-Source([string]$db,[string]$sql) {
  return ,(Query-Sql -Server $script:SourceInstance -Database $db -Sql $sql -QueryId 'DatabaseCatalog' -InventoryStage 'SourceDatabaseInventory')
}
function Read-Target([string]$db,[string]$sql) {
  return ,(Query-Sql -Server $script:TargetInstance -Database $db -Sql $sql -QueryId 'DatabaseCatalog' -InventoryStage 'TargetDatabaseInventory')
}
function Verify-MetadataVisibility([string]$server,[string]$db,[bool]$source) {
  $sql=@"
SET NOCOUNT ON;
SELECT SUSER_SNAME() AS ConnectedAs,
 HAS_PERMS_BY_NAME(NULL,NULL,'VIEW SERVER STATE') AS ViewServerState,
 HAS_PERMS_BY_NAME(NULL,NULL,'VIEW ANY DATABASE') AS ViewAnyDatabase;
USE $(Qi $db);
SELECT DB_NAME() AS DatabaseName,
 HAS_PERMS_BY_NAME(DB_NAME(),'DATABASE','VIEW DEFINITION') AS ViewDefinition,
 HAS_PERMS_BY_NAME(DB_NAME(),'DATABASE','CONTROL') AS ControlDatabase;
"@
  $label=if($source){'Source'}else{'Target'}
  $data=Query-Sql -Server $server -Database 'master' -Sql $sql -QueryId 'MetadataVisibility' -InventoryStage 'Permission verification'
  if($data.Tables.Count -ne 2 -or $data.Tables[0].Rows.Count -ne 1 -or $data.Tables[1].Rows.Count -ne 1){throw ('MetadataVisibility returned unexpected result sets for '+$label+' '+$db)}
  $serverRow=$data.Tables[0].Rows[0];$dbRow=$data.Tables[1].Rows[0]
  Log INFO ('Permission verification '+$label+' Server='+$server+' Database='+$db+' ConnectedAs='+$serverRow.ConnectedAs+' ViewServerState='+$serverRow.ViewServerState+' ViewAnyDatabase='+$serverRow.ViewAnyDatabase+' ViewDefinition='+$dbRow.ViewDefinition+' ControlDatabase='+$dbRow.ControlDatabase)
  if([int]$dbRow.ViewDefinition -ne 1){throw ('Metadata visibility insufficient: '+$label+' '+$db+' lacks VIEW DEFINITION.')}
}
function Apply-Sql([string]$db,[string]$sql) {
  # Each DDL operation is independent. A failing operation cannot silently roll back previous ones.
  [void](Query-Sql -Server $script:TargetInstance -Database $db -Sql $sql -QueryId 'ApplyStatement' -InventoryStage 'APPLY' -Write)
}
function Add-Action {
  param([string]$Db,[string]$Kind,[string]$Name,[string]$Stage,[string]$Status,
        [string]$Reason,[string]$Sql='', [string]$DisplaySql='',[string]$Principal='',[string]$Role='')
  $script:Actions.Add([pscustomobject]@{
    SourceDatabase=$(if ($script:DatabaseReverse.ContainsKey($Db)) {$script:DatabaseReverse[$Db]} else {$Db});
    Database=$Db;Kind=$Kind;Name=$Name;Principal=$Principal;Role=$Role;
    Stage=$Stage;Status=$Status;Reason=$Reason;Sql=$Sql;
    DisplaySql=$(if ($DisplaySql){$DisplaySql}else{$Sql})
  }) | Out-Null
}
function Add-Compare {
  param([string]$db,[string]$kind,[string]$name,[string]$stage,[bool]$present,
        [string]$sql='',[string]$reason='', [bool]$allowed=$true,[string]$principal='',[string]$role='')
  if ($present) {Add-Action $db $kind $name $stage 'Already correct' 'Exists on target.' '' '' $principal $role}
  elseif (-not $allowed) {Add-Action $db $kind $name $stage 'Blocked' $reason '' '' $principal $role}
  else {Add-Action $db $kind $name $stage 'Planned' $reason $sql '' $principal $role}
}
function Save-Report([string]$label) {
  $path=Join-Path $sessionDir ($label+'_Plan.csv')
  $cols='SourceDatabase','Database','Kind','Name','Principal','Role','Stage','Status','Reason'
  $script:Actions | Select-Object $cols | Export-Csv -LiteralPath $path -Encoding UTF8 -NoTypeInformation
  $exc=@($script:Actions|Where-Object {$_.Status -in @('Blocked','Manual review','Failed','Deferred')})
  $excPath=Join-Path $sessionDir ($label+'_Exceptions.csv')
  if ($exc.Count) {$exc|Select-Object $cols|Export-Csv -LiteralPath $excPath -Encoding UTF8 -NoTypeInformation}
  else {('"'+($cols -join '","')+'"')|Set-Content -LiteralPath $excPath -Encoding UTF8}
  $exceptionLog=Join-Path $sessionDir ($label+'_Exceptions.log')
  if($exc.Count){foreach($x in $exc){
    $e='[{0}] [{1}] [{2}] {3} / {4}: {5}' -f $x.Status,$x.Stage,$x.Database,$x.Kind,$x.Name,$x.Reason
    Add-Content -LiteralPath $exceptionLog -Value $e -Encoding UTF8
  }} else {'No blocked, deferred, failed, or manual-review actions in this plan.'|Set-Content -LiteralPath $exceptionLog -Encoding UTF8}
  $sqlPath=Join-Path $sessionDir ($label+'_Review.sql')
  $lines=New-Object System.Collections.Generic.List[string]
  $lines.Add('-- REVIEW ONLY. Generated SQL is not an approved deployment script.')
  $lines.Add('-- SQL password hashes are NEVER written to this file.')
  foreach($x in $script:Actions) {
    if ($x.Status -eq 'Planned') {
      $lines.Add('-- '+$x.Stage+' / '+$x.Database+' / '+$x.Kind+' / '+$x.Name)
      if ($x.DisplaySql) {$lines.Add('USE '+(Qi $(if ($x.Database){$x.Database}else{'master'}))+';');$lines.Add($x.DisplaySql)}
      else {$lines.Add('-- Operation requires interactive guarded APPLY.')}
      $lines.Add('GO')
    }
  }
  Set-Content -LiteralPath $sqlPath -Value $lines -Encoding UTF8
  $counts=@($script:Actions|Group-Object Status|Sort-Object Name|ForEach-Object {"$($_.Name)=$($_.Count)"}) -join '; '
  $root=@($exc | Group-Object Database,Kind,Reason | ForEach-Object {
    $first=$_.Group[0];[pscustomobject]@{Database=$first.Database;Kind=$first.Kind;Reason=$first.Reason;Count=$_.Count;Example=$first.Name;Status=$first.Status}
  } | Sort-Object Count -Descending)
  if($root.Count){$root|Export-Csv -LiteralPath (Join-Path $sessionDir ($label+'_RootCauses.csv')) -NoTypeInformation -Encoding UTF8}
  Log INFO "${label}: actions=$($script:Actions.Count); $counts; exceptions=$($exc.Count); root-causes=$($root.Count)"
  return $exc.Count
}

function Server-Inventory([bool]$source,[bool]$includeHash) {
  if($source -and $script:PinnedInventory -and -not $script:LiveSourceVerification -and -not $includeHash){return (Server-FromDataset $script:SnapshotDatasets['server'])}
  $hashCol=if ($includeHash) {'sl.password_hash'} else {'CONVERT(varbinary(256),NULL)'}
  $sql=@"
SET NOCOUNT ON;
SELECT CONVERT(nvarchar(256),SERVERPROPERTY('ServerName')) AS ServerName,
 CONVERT(nvarchar(128),SERVERPROPERTY('ProductVersion')) AS ProductVersion,
 CONVERT(int,SERVERPROPERTY('ProductMajorVersion')) AS MajorVersion,
 CONVERT(int,SERVERPROPERTY('EngineEdition')) AS EngineEdition,
 IS_SRVROLEMEMBER('sysadmin') AS IsSysadmin, SUSER_SNAME() AS ConnectedAs;
SELECT name,state_desc,source_database_id,database_id,collation_name,owner_sid,SUSER_SNAME(owner_sid) AS OwnerName,is_read_only,user_access_desc FROM sys.databases ORDER BY name;
SELECT sp.name AS Name,sp.type AS Type,sp.sid AS Sid,
 sp.is_disabled AS Disabled,sp.default_database_name AS DefaultDatabase,
 sp.default_language_name AS DefaultLanguage,sp.is_fixed_role AS FixedRole,
 owner.name AS OwnerName,sl.is_policy_checked AS PolicyChecked,
 sl.is_expiration_checked AS ExpirationChecked,$hashCol AS PasswordHash
FROM sys.server_principals sp
LEFT JOIN sys.server_principals owner ON owner.principal_id=sp.owning_principal_id
LEFT JOIN sys.sql_logins sl ON sl.principal_id=sp.principal_id
WHERE sp.principal_id>1 AND sp.type IN ('S','U','G','R','C','K','E','X')
ORDER BY sp.type,sp.name;
SELECT role.name AS RoleName,m.name AS MemberName
FROM sys.server_role_members rm
JOIN sys.server_principals role ON role.principal_id=rm.role_principal_id
JOIN sys.server_principals m ON m.principal_id=rm.member_principal_id;
SELECT p.class,p.class_desc,p.permission_name,p.state,
 g.name AS Grantee,p.grantor_principal_id,
 CASE WHEN p.class=100 THEN N'SERVER'
      WHEN p.class=101 THEN securable.name
      WHEN p.class=105 THEN ep.name ELSE NULL END AS SecurableName,
 grantor.name AS Grantor
FROM sys.server_permissions p
JOIN sys.server_principals g ON g.principal_id=p.grantee_principal_id
LEFT JOIN sys.server_principals securable ON p.class=101 AND securable.principal_id=p.major_id
LEFT JOIN sys.endpoints ep ON p.class=105 AND ep.endpoint_id=p.major_id
LEFT JOIN sys.server_principals grantor ON grantor.principal_id=p.grantor_principal_id;
"@
  if ($source) {$data=Read-Source master $sql} else {$data=Read-Target master $sql}
  if($source -and $script:SnapshotCapture -and -not $includeHash) {$script:SnapshotDatasets['server']=$data}
  if($source -and $script:LiveSourceVerification){$script:LastLiveServerDataset=$data}
  if($source -and $script:PinnedInventory -and $includeHash){
    # Separate NULL-verifier query checks unchanged source metadata without
    # mutating DataTable rows; sensitive bytes stay in memory only.
    $withoutHash=Read-Source master $sql.Replace('sl.password_hash','CONVERT(varbinary(256),NULL)')
    if((Dataset-Fingerprint $withoutHash $true) -ne $script:SnapshotManifest.ServerFingerprint){throw 'SOURCE DRIFT: refusing SQL-login hash transfer; rerun PLAN.'}
  }
  if ($data.Tables.Count -ne 5 -or $data.Tables[0].Rows.Count -ne 1) {throw 'Server metadata inventory returned unexpected result-set count.'}
  $info=$data.Tables[0].Rows[0]
  if ([int]$info.IsSysadmin -ne 1) {throw ('Fail closed: sysadmin required for complete metadata visibility on '+$info.ServerName)}
  if ([int]$info.MajorVersion -lt 11) {throw 'SQL Server 2008 or earlier is not supported by the APPLY engine. Inventory separately and upgrade/migrate first.'}
  if ([int]$info.EngineEdition -notin @(2,3,4)) {throw ('Unsupported engine edition '+$info.EngineEdition+'; designed for standalone/on-prem SQL Server, not Azure SQL/MI.')}
  $obj=[pscustomobject]@{
    Info=$info;Databases=@(TableRows $data 1);Logins=@(TableRows $data 2);
    Members=@(TableRows $data 3);Permissions=@(TableRows $data 4)
  }
  return $obj
}
function Database-Inventory([string]$db,[bool]$source) {
  $inventoryStarted=[DateTime]::UtcNow
  $inventoryTimer=[Diagnostics.Stopwatch]::StartNew()
  $inventoryServer=if($source){$script:SourceInstance}else{$script:TargetInstance}
  $inventoryStage=if($source){'SourceDatabaseInventory'}else{'TargetDatabaseInventory'}
  Log INFO ('Database inventory START InventoryStage='+$inventoryStage+' QueryId=DatabaseCatalog Server='+$inventoryServer+' Database='+$db+' StartedUtc='+$inventoryStarted.ToString('o'))
  try {
  if($source -and $script:PinnedInventory -and -not $script:LiveSourceVerification){
    if(-not $script:SnapshotDatasets.ContainsKey($db)){throw ('Database not included in approved inventory: '+$db)}
    $result=Database-FromDataset $script:SnapshotDatasets[$db]
    $inventoryTimer.Stop();Log INFO ('Database inventory COMPLETE InventoryStage='+$inventoryStage+' QueryId=DatabaseCatalog Server='+$inventoryServer+' Database='+$db+' CompletedUtc='+[DateTime]::UtcNow.ToString('o')+' ElapsedMs='+$inventoryTimer.ElapsedMilliseconds+' RowCounts='+(@($result.Principals.Count,$result.Schemas.Count,$result.Memberships.Count,$result.Permissions.Count,$result.Objects.Count,$result.Types.Count) -join ','))
    return $result
  }
  Verify-MetadataVisibility $inventoryServer $db $source
  # Catalog data is returned as named securables rather than object/principal IDs,
  # which are database-specific and cannot be compared across restored/rebuilt DBs.
  $sql=@'
SET NOCOUNT ON;
SELECT dp.name AS Name,dp.type AS Type,dp.sid AS Sid,
 dp.default_schema_name AS DefaultSchema,dp.authentication_type_desc AS AuthenticationType,
 dp.is_fixed_role AS FixedRole, owner.name AS OwnerName,
 sp.name AS LoginName,dp.principal_id AS PrincipalId
FROM sys.database_principals dp
LEFT JOIN sys.database_principals owner ON owner.principal_id=dp.owning_principal_id
LEFT JOIN master.sys.server_principals sp ON sp.sid=dp.sid AND sp.type IN ('S','U','G')
WHERE dp.principal_id>4
ORDER BY dp.type,dp.name;
SELECT s.name AS Name,dp.name AS OwnerName
FROM sys.schemas s
LEFT JOIN sys.database_principals dp ON dp.principal_id=s.principal_id
ORDER BY s.name;
SELECT role.name AS RoleName,member.name AS MemberName,member.type AS MemberType
FROM sys.database_role_members rm
JOIN sys.database_principals role ON rm.role_principal_id=role.principal_id
JOIN sys.database_principals member ON rm.member_principal_id=member.principal_id;
SELECT p.class,p.class_desc,p.permission_name,p.state,
 g.name AS Grantee,grantor.name AS Grantor,
 CASE WHEN p.class=1 THEN objectSchema.name
      WHEN p.class=3 THEN secSchema.name
      WHEN p.class=6 THEN typeSchema.name ELSE NULL END AS SchemaName,
 CASE WHEN p.class=1 THEN obj.name
      WHEN p.class=6 THEN typ.name ELSE NULL END AS ObjectName,
 col.name AS ColumnName,secPrincipal.name AS SecurablePrincipal,
 secPrincipal.type AS SecurablePrincipalType
FROM sys.database_permissions p
JOIN sys.database_principals g ON p.grantee_principal_id=g.principal_id
LEFT JOIN sys.database_principals grantor ON p.grantor_principal_id=grantor.principal_id
LEFT JOIN sys.all_objects obj ON p.class=1 AND p.major_id=obj.object_id
LEFT JOIN sys.schemas objectSchema ON objectSchema.schema_id=obj.schema_id
LEFT JOIN sys.columns col ON p.class=1 AND p.minor_id>0 AND col.object_id=p.major_id AND col.column_id=p.minor_id
LEFT JOIN sys.schemas secSchema ON p.class=3 AND secSchema.schema_id=p.major_id
LEFT JOIN sys.database_principals secPrincipal ON p.class=4 AND secPrincipal.principal_id=p.major_id
LEFT JOIN sys.types typ ON p.class=6 AND typ.user_type_id=p.major_id
LEFT JOIN sys.schemas typeSchema ON p.class=6 AND typeSchema.schema_id=typ.schema_id
WHERE (g.principal_id>4 OR g.name='public')
ORDER BY g.name,p.class,p.permission_name;
SELECT s.name AS SchemaName,o.name AS ObjectName,
 c.name AS ColumnName
FROM sys.all_objects o JOIN sys.schemas s ON s.schema_id=o.schema_id
LEFT JOIN sys.columns c ON c.object_id=o.object_id;
SELECT s.name AS SchemaName,t.name AS TypeName
FROM sys.types t JOIN sys.schemas s ON t.schema_id=s.schema_id
WHERE t.is_user_defined=1;
'@
  if ($source) {$data=Read-Source $db $sql} else {$data=Read-Target $db $sql}
  if($source -and $script:SnapshotCapture){$script:SnapshotDatasets[$db]=$data}
  if($source -and $script:LiveSourceVerification){$script:LastLiveDatabaseDataset=$data}
  if ($data.Tables.Count -ne 6) {throw ('Database inventory incomplete: '+$db)}
  $result=[pscustomobject]@{
    Principals=@(TableRows $data 0);Schemas=@(TableRows $data 1);
    Memberships=@(TableRows $data 2);Permissions=@(TableRows $data 3);
    Objects=@(TableRows $data 4);Types=@(TableRows $data 5)
  }
  $inventoryTimer.Stop();Log INFO ('Database inventory COMPLETE InventoryStage='+$inventoryStage+' QueryId=DatabaseCatalog Server='+$inventoryServer+' Database='+$db+' CompletedUtc='+[DateTime]::UtcNow.ToString('o')+' ElapsedMs='+$inventoryTimer.ElapsedMilliseconds+' RowCounts='+(@($result.Principals.Count,$result.Schemas.Count,$result.Memberships.Count,$result.Permissions.Count,$result.Objects.Count,$result.Types.Count) -join ','))
  return $result
  } catch {
    $inventoryTimer.Stop();Log ERROR ('Database inventory FAILED InventoryStage='+$inventoryStage+' QueryId=DatabaseCatalog Server='+$inventoryServer+' Database='+$db+' FailedUtc='+[DateTime]::UtcNow.ToString('o')+' ElapsedMs='+$inventoryTimer.ElapsedMilliseconds+' Exception='+$_.Exception.Message)
    throw
  }
}
function Permission-Object($r,[string]$db,[bool]$server=$false) {
  $klass=[int]$r.class
  if ($server) {
    if ($klass -eq 100) {$part='SERVER';$clause='';$supported=$true}
    else {$part='UNSUPPORTED:'+ $klass+':'+(Val $r.SecurableName);$clause='';$supported=$false}
  } else {
    $schema=Val $r.SchemaName;$object=Val $r.ObjectName;$col=Val $r.ColumnName;$sec=Val $r.SecurablePrincipal
    switch ($klass) {
      0 {$part='DATABASE';$clause='ON DATABASE::'+(Qi $db);$supported=$true}
      1 {$part='OBJECT:'+$schema+'.'+$object+':'+$col
         $clause=if ($schema -and $object) {'ON OBJECT::'+(Qi $schema)+'.'+(Qi $object)+$(if($col){' ('+(Qi $col)+')'}else{''})}else{''}
         $supported=[bool]$clause}
      3 {$part='SCHEMA:'+$schema;$clause=if($schema){'ON SCHEMA::'+(Qi $schema)}else{''};$supported=[bool]$clause}
      4 {$part='PRINCIPAL:'+$sec
         $kind=if ((Val $r.SecurablePrincipalType) -eq 'R') {'ROLE'}else{'USER'}
         $clause=if ($sec) {'ON '+$kind+'::'+(Qi $sec)}else{''};$supported=([bool]$clause -and (Val $r.SecurablePrincipalType) -in @('S','U','G','R'))}
      6 {$part='TYPE:'+$schema+'.'+$object
         $clause=if ($schema -and $object) {'ON TYPE::'+(Qi $schema)+'.'+(Qi $object)}else{''};$supported=[bool]$clause}
      default {$part='UNSUPPORTED:'+ $klass+':'+$schema+':'+$object;$clause='';$supported=$false}
    }
  }
  $permission=Val $r.permission_name;$state=Val $r.state
  $key=Key (Val $r.Grantee) ($part+'|'+$permission)
  return [pscustomobject]@{Key=$key;Part=$part;Clause=$clause;Permission=$permission;State=$state;Grantee=(Val $r.Grantee);Supported=$supported;Grantor=(Val $r.Grantor)}
}
function Permission-Sql($p) {
  if ($p.Permission -cnotmatch '^[A-Z][A-Z_ ]{0,127}$') {return ''}
  $grantee=Qi $p.Grantee
  if ($p.State -eq 'G') {return 'GRANT '+$p.Permission+' '+$p.Clause+' TO '+$grantee+';'}
  if ($p.State -eq 'W') {return 'GRANT '+$p.Permission+' '+$p.Clause+' TO '+$grantee+' WITH GRANT OPTION;'}
  if ($p.State -eq 'D') {return 'DENY '+$p.Permission+' '+$p.Clause+' TO '+$grantee+';'}
  return ''
}
function Load-IdentityMap {
  if (-not $IdentityMapCsv) {return}
  if (-not (Test-Path -LiteralPath $IdentityMapCsv -PathType Leaf)) {throw 'Identity map CSV does not exist.'}
  $rows=@(Import-Csv -LiteralPath $IdentityMapCsv)
  if (-not $rows.Count) {throw 'Identity map CSV empty; remove argument when no remapping is needed.'}
  $reverse=@{}
  foreach ($r in $rows) {
    $src=(Val $r.SourceLogin).Trim();$dst=(Val $r.TargetLogin).Trim()
    if (-not $src -or -not $dst) {throw 'Identity map requires SourceLogin and TargetLogin in every row.'}
    if ($script:IdentityMap.ContainsKey($src)) {throw ('Duplicate identity mapping: '+$src)}
    if ($reverse.ContainsKey($dst)) {throw ('Multiple identities map to one destination login: '+$dst)}
    $script:IdentityMap[$src]=$dst;$reverse[$dst]=$src
  }
  Log WARN ('Identity map loaded: '+$rows.Count+' explicit mappings. Existing user SID conflicts will NOT be automatically remapped.')
}
function Load-DatabaseMap {
  if (-not $DatabaseMapCsv) {return}
  if (-not (Test-Path -LiteralPath $DatabaseMapCsv -PathType Leaf)) {throw 'Database map CSV does not exist.'}
  foreach($r in @(Import-Csv -LiteralPath $DatabaseMapCsv)) {
    $src=(Val $r.SourceDatabase).Trim();$dst=(Val $r.TargetDatabase).Trim()
    if(-not $src -or -not $dst){throw 'Database map needs SourceDatabase,TargetDatabase in every row.'}
    if($script:DatabaseMap.ContainsKey($src) -or $script:DatabaseReverse.ContainsKey($dst)) {throw 'Duplicate source or target database map entry.'}
    $script:DatabaseMap[$src]=$dst;$script:DatabaseReverse[$dst]=$src
  }
  Log INFO ('Database map loaded: '+$script:DatabaseMap.Count+' source/target pairs.')
}
function Verify-Preflight {
  $script:SourceMeta=Server-Inventory $true $false
  $script:TargetMeta=Server-Inventory $false $false
  $s=[string]$script:SourceMeta.Info.ServerName;$t=[string]$script:TargetMeta.Info.ServerName
  if ($s -ieq $t) {throw "STOP: Source and target both resolve to same SQL Server [$s]."}
  $script:SourceMajor=[int]$script:SourceMeta.Info.MajorVersion
  $script:TargetMajor=[int]$script:TargetMeta.Info.MajorVersion
  if($script:PinnedInventory -and ($s -ine $script:SnapshotManifest.CanonicalSource -or $t -ine $script:SnapshotManifest.CanonicalTarget)) {throw 'Canonical SQL instance does not match approved PLAN; refusing APPLY.'}
  Log INFO "Source $s (SQL $script:SourceMajor) as $($script:SourceMeta.Info.ConnectedAs)"
  Log INFO "Target $t (SQL $script:TargetMajor) as $($script:TargetMeta.Info.ConnectedAs)"
  $src=@($script:SourceMeta.Databases|Where-Object {$_.database_id -gt 4 -and $_.state_desc -eq 'ONLINE' -and $_.source_database_id -is [DBNull]})
  $tgt=@($script:TargetMeta.Databases|Where-Object {$_.database_id -gt 4 -and $_.state_desc -eq 'ONLINE' -and $_.source_database_id -is [DBNull]})
  $sn=@($src|ForEach-Object {Val $_.name});$tn=@($tgt|ForEach-Object {Val $_.name})
  if (($DatabaseName -and $DatabaseName.Count) -or $script:PinnedInventory) {
    $requested=@($script:SelectedDbs)
    if(-not $script:PinnedInventory){$requested=@($DatabaseName|ForEach-Object {$_.Trim()}|Where-Object {$_}|Select-Object -Unique)}
    if(-not $script:PinnedInventory -and $requested.Count -ne @($DatabaseName|Where-Object {$_ -and $_.Trim()}).Count) {Log WARN 'Duplicate database names supplied; deduplicated.'}
    $missing=@($requested|Where-Object {$sn -notcontains $_ -or $tn -notcontains (TargetDatabase $_)})
    if ($missing.Count) {throw ('Database(s) absent/offline/not user databases on BOTH instances: '+($missing -join ', '))}
    $script:SelectedDbs=$requested
  } else {
    $script:SelectedDbs=@($sn|Where-Object {$tn -contains (TargetDatabase $_)})
  }
  if (-not $script:SelectedDbs.Count) {throw 'Zero matching source/target databases. Correct instance names and database scope.'}
  $script:TotalServerDatabaseInventory=[pscustomobject]@{Source=@($sn);Destination=@($tn);SourceCount=$sn.Count;DestinationCount=$tn.Count}
  # The validated source scope for this run is the approved source set. In APPLY it
  # comes from the pinned manifest; in PLAN from -DatabaseName or exact-name matching.
  if(-not $script:ApprovedSourceDatabases.Count){$script:ApprovedSourceDatabases=@($script:SelectedDbs)}
  $missingApproved=@($script:ApprovedSourceDatabases|Where-Object {$sn -notcontains $_})
  $script:ApprovedSourceDatabases=@($script:ApprovedSourceDatabases|Where-Object {$sn -contains $_})
  $script:ExplicitlyExcludedDatabases=@($script:ExplicitlyExcludedDatabases|Where-Object {$sn -contains $_ -or $tn -contains $_})
  # Explicitly excluded databases are fully out of scope: no inventory, no
  # comparison, no manifest snapshot, and no completeness requirement. They are
  # still recorded in the manifest so the exclusion is auditable. APPLY never
  # generates actions for them.
  $script:DestinationDbs=@($tn|Where-Object {$script:ExplicitlyExcludedDatabases -notcontains $_})
  $script:MatchingDbs=@($script:ApprovedSourceDatabases|Where-Object {$tn -contains $_})
  $script:DestinationMigrationCandidates=@($tn|Where-Object {$_ -notin $script:ExplicitlyExcludedDatabases -and $_ -notin $script:ReviewRequiredDestinationDatabases -and $script:MatchingDbs -notcontains $_})
  $script:UnclassifiedDatabases=@($tn|Where-Object {$_ -notin $script:ExplicitlyExcludedDatabases -and $script:MatchingDbs -notcontains $_ -and $script:DestinationMigrationCandidates -notcontains $_})
  $script:AdditionalDestinationDbs=@($script:DestinationMigrationCandidates)
  $script:SelectedDbs=@($script:ApprovedSourceDatabases)
  if($missingApproved.Count){throw ('PLAN requires approved source databases that are absent/offline: '+($missingApproved -join ', '))}
  if($script:UnclassifiedDatabases.Count){Log WARN ('Unclassified destination databases require review: '+($script:UnclassifiedDatabases -join ', '))}
  if($Mode -eq 'Apply' -and $script:UnclassifiedDatabases.Count){throw ('APPLY blocked: Unclassified destination database requires review: '+($script:UnclassifiedDatabases -join ', '))}
  foreach($db in $script:SelectedDbs){
    $sColl=Val (@($src|Where-Object {$_.name -eq $db})[0].collation_name)
    $tdb=TargetDatabase $db
    $tColl=Val (@($tgt|Where-Object {$_.name -eq $tdb})[0].collation_name)
    if($Mode -eq 'Apply' -and ($sColl -match '(?i)_(CS|BIN)' -or $tColl -match '(?i)_(CS|BIN)')){
      throw ('Case-sensitive/binary collation detected in '+$db+' / '+$tdb+'; identity comparison requires a dedicated case-sensitive implementation. No changes made.')
    }
    if($sColl -ine $tColl){Log WARN ('Collation differs: '+$db+'='+$sColl+'; '+$tdb+'='+$tColl+'. Confirm migration compatibility.')}
    $targetDbInfo=@($tgt|Where-Object {$_.name -eq $tdb})[0]
    if($Mode -eq 'Apply' -and ([bool]$targetDbInfo.is_read_only -or (Val $targetDbInfo.user_access_desc) -ne 'MULTI_USER')){
      throw ('Target database '+$tdb+' is read-only or not MULTI_USER; APPLY cannot proceed.')
    }
  }
  if($script:SourceMajor -ne $script:TargetMajor){Log WARN ('Different SQL major versions: '+$script:SourceMajor+' vs '+$script:TargetMajor+'. Built-in role behavior and SQL-login hash compatibility require review.')}
  if ($Mode -eq 'Apply' -and $script:SelectedDbs.Count -ne $script:SnapshotManifest.SourceDatabaseCount) {throw 'APPLY source database scope differs from approved PLAN.'}
  Log INFO ('Database classification source-approved='+$script:SelectedDbs.Count+', destination-total='+$tn.Count+', matching='+$script:MatchingDbs.Count+', candidates='+$script:DestinationMigrationCandidates.Count+', excluded='+$script:ExplicitlyExcludedDatabases.Count+', unclassified='+$script:UnclassifiedDatabases.Count)
}

function Server-Identity-Safe([string]$sourceName,[string]$destName) {
  $source=Lookup (ByName $script:SourceMeta.Logins) $sourceName
  $target=Lookup (ByName $script:TargetMeta.Logins) $destName
  if($null -eq $source -or $null -eq $target){return $false}
  if((Val $source.Type) -cne (Val $target.Type)){return $false}
  if((Val $source.Type) -notin @('S','U','G','R')){return $false}
  if((Val $source.Type) -eq 'R'){
    $so=Val $source.OwnerName;$to=Val $target.OwnerName
    if($so -ine $to){return $false}
    if(-not $so -or $so -ieq 'sa'){return $true}
    if($so -ieq $sourceName){return $false}
    return (Server-Identity-Safe $so $to)
  }
  if((Hex $source.Sid) -eq (Hex $target.Sid)){return $true}
  return ($AllowIdentityMapping -and $destName -ne $sourceName -and (Val $source.Type) -in @('U','G'))
}
function Plan-ServerSecurity([bool]$includeHashes) {
  $source=$script:SourceMeta;$target=$script:TargetMeta
  $tl=ByName $target.Logins
  $sourceNames=@{};foreach($l in $source.Logins){$sourceNames[(TargetLoginName (Val $l.Name))]=$true}
  foreach($l in $source.Logins) {
    $name=Val $l.Name;$type=Val $l.Type
    if ($name -match '^##MS_' -or $name -eq 'sa') {continue}
    if (-not $IncludeAllServerLogins -and -not $script:RelevantLogins.ContainsKey($name)) {continue}
    if ($type -eq 'R') {continue}
    if ($type -notin @('S','U','G')) {Add-Action '' 'Unsupported server principal' $name 'Logins' 'Manual review' ('Certificate/asymmetric/Entra principal type '+$type+' requires separate migration.');continue}
    $dest=TargetLoginName $name
    $existing=Lookup $tl $dest
    if ($null -ne $existing) {
      if ((Val $existing.Type) -cne $type) {Add-Action '' 'Login' $name 'Logins' 'Blocked' 'Existing target login type differs.' '' '' $dest;continue}
      if ((Hex $existing.Sid) -ne (Hex $l.Sid)) {
        if ($dest -ne $name -and $AllowIdentityMapping -and $type -in @('U','G')) {
          Add-Action '' 'Login identity mapping' $name 'Logins' 'Manual review' ('Explicit mapping to '+$dest+' changes SID: database users with old SID still require separate approval.') '' '' $dest
        } else {
          Add-Action '' 'Login SID conflict' $name 'Logins' 'Blocked' ('Target login '+$dest+' has a DIFFERENT SID. No overwrite.') '' '' $dest
        }
      } else {
        if($type -eq 'S' -and $includeHashes -and (Hex $l.PasswordHash) -ne (Hex $existing.PasswordHash)){
          Add-Action '' 'Login password hash' $name 'Logins' 'Blocked' 'SQL login exists with matching SID but different/hidden password hash. Do not overwrite automatically.' '' '' $dest
        } else {
          Add-Action '' 'Login' $name 'Logins' 'Already correct' $(if($type -eq 'S' -and -not $includeHashes){'SID/type match; password hash not compared in PLAN.'}else{'Login type and SID match.'}) '' '' $dest
        }
      }
      if ((Val $l.DefaultDatabase) -ne (Val $existing.DefaultDatabase)) {
        Add-Action '' 'Login default database' $name 'Logins' 'Manual review' ('Source '+(Val $l.DefaultDatabase)+'; target '+(Val $existing.DefaultDatabase))
      }
      if ([bool]$l.Disabled -ne [bool]$existing.Disabled) {
        Add-Action '' 'Login disabled state' $name 'Logins' 'Manual review' 'Disabled/enabled states differ; no existing-login modification.'
      }
      if ((Val $l.DefaultLanguage) -ne (Val $existing.DefaultLanguage)) {
        Add-Action '' 'Login default language' $name 'Logins' 'Manual review' 'Existing login default language differs; not modified.'
      }
      if ($type -eq 'S' -and ((Val $l.PolicyChecked) -ne (Val $existing.PolicyChecked) -or (Val $l.ExpirationChecked) -ne (Val $existing.ExpirationChecked))) {
        Add-Action '' 'Login password policy' $name 'Logins' 'Manual review' 'Existing SQL login policy/expiration differs; not modified.'
      }
      continue
    }
    if ($dest -ne $name) {Add-Action '' 'Login' $name 'Logins' 'Blocked' ('Mapped destination login '+$dest+' is missing. Create approved destination identity outside migration.');continue}
    $sidCollision=@($target.Logins|Where-Object {(Hex $_.Sid) -eq (Hex $l.Sid) -and (Hex $_.Sid) -and (Val $_.Name) -ine $dest})
    if($sidCollision.Count){Add-Action '' 'Login' $name 'Logins' 'Blocked' ('SID already belongs to target principal '+(Val $sidCollision[0].Name)+'; do not create a second login.');continue}
    if (IsMachine $name) {
      if (-not $AllowMachineAccounts) {Add-Action '' 'Login' $name 'Logins' 'Blocked' 'Machine/local service principal requires -AllowMachineAccounts and identity verification.';continue}
      if ($name -match '^(NT SERVICE|NT AUTHORITY|BUILTIN)\\') {Add-Action '' 'Login' $name 'Logins' 'Blocked' 'Local service identity must be designed for target machine, not copied verbatim.';continue}
    }
    if ($type -in @('U','G')) {
      if (-not $AllowWindowsLogins) {Add-Action '' 'Login' $name 'Logins' 'Blocked' 'Windows login migration requires -AllowWindowsLogins.';continue}
      $sql='CREATE LOGIN '+(Qi $name)+' FROM WINDOWS;'
      if ([bool]$l.Disabled) {$createBatch=$sql.Replace("'","''");$sql="SET XACT_ABORT ON; BEGIN TRY BEGIN TRANSACTION; EXEC sys.sp_executesql N'"+$createBatch+"'; ALTER LOGIN "+(Qi $name)+" DISABLE; COMMIT TRANSACTION; END TRY BEGIN CATCH IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION; THROW; END CATCH;"}
      Add-Action '' 'Login' $name 'Logins' 'Planned' 'Windows account must resolve in target domain.' $sql
      continue
    }
    if ($type -eq 'S') {
      if (-not $AllowSqlLogins) {Add-Action '' 'Login' $name 'Logins' 'Blocked' 'SQL login creation requires -AllowSqlLogins and sysadmin access to password hashes.';continue}
      $hash=Hex $l.PasswordHash
      if (-not $includeHashes) {
        Add-Action '' 'Login' $name 'Logins' 'Deferred' 'SQL hash is fetched in memory only during APPLY/Logins; no hash is exported.'
        continue
      }
      if (-not $hash) {Add-Action '' 'Login' $name 'Logins' 'Blocked' 'Password hash unavailable (permissions or source login hash missing).';continue}
      $version=[Convert]::ToInt32($hash.Substring(2,2),16)
      if ($version -ge 3 -and $script:TargetMajor -lt 17) {Add-Action '' 'Login' $name 'Logins' 'Blocked' 'SQL Server 2025 PBKDF login hash cannot be transferred to a pre-2025 instance.';continue}
      if ($version -lt 2) {Add-Action '' 'Login' $name 'Logins' 'Blocked' 'Legacy password hash requires manual compatibility review.';continue}
      $sid=Hex $l.Sid
      if (-not $sid) {Add-Action '' 'Login' $name 'Logins' 'Blocked' 'Source login SID unavailable.';continue}
      $policy=if ([bool]$l.PolicyChecked){'ON'}else{'OFF'}
      $expiry=if ([bool]$l.ExpirationChecked){'ON'}else{'OFF'}
      $sql='CREATE LOGIN '+(Qi $name)+' WITH PASSWORD = '+$hash+' HASHED, SID = '+$sid+', CHECK_POLICY = '+$policy+', CHECK_EXPIRATION = '+$expiry+';'
      if ([bool]$l.Disabled) {$createBatch=$sql.Replace("'","''");$sql="SET XACT_ABORT ON; BEGIN TRY BEGIN TRANSACTION; EXEC sys.sp_executesql N'"+$createBatch+"'; ALTER LOGIN "+(Qi $name)+" DISABLE; COMMIT TRANSACTION; END TRY BEGIN CATCH IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION; THROW; END CATCH;"}
      Add-Action '' 'Login' $name 'Logins' 'Planned' 'Sensitive hash used only in memory; not included in reports.' $sql '-- HASH REDACTED. Use interactive APPLY / LOGINS with -AllowSqlLogins.'
    }
  }
  foreach($l in $target.Logins) {
    if ((Val $l.Type) -eq 'R') {continue}
    if (-not $sourceNames.ContainsKey((Val $l.Name))) {Add-Action '' 'Target-only login' (Val $l.Name) 'Logins' 'Target only' 'Present only on target; never automatically removed.'}
  }
  $targetRoles=ByName @($target.Logins|Where-Object {$_.Type -eq 'R'})
  foreach($role in @($source.Logins|Where-Object {$_.Type -eq 'R' -and -not [bool]$_.FixedRole})) {
    $name=Val $role.Name
    $existing=Lookup $targetRoles $name
    if ($null -ne $existing) {
      if ((Val $existing.OwnerName) -ine (Val $role.OwnerName)) {Add-Action '' 'Server role owner' $name 'ServerSecurity' 'Manual review' 'Owner differs; never overwrite.'}
      else {Add-Action '' 'Server role' $name 'ServerSecurity' 'Already correct' 'Custom server role exists.'}
      continue
    }
    if($tl.ContainsKey($name)) {Add-Action '' 'Server role' $name 'ServerSecurity' 'Blocked' 'Target name exists as non-role server principal.';continue}
    if (-not $AllowServerSecurity) {Add-Action '' 'Server role' $name 'ServerSecurity' 'Blocked' 'Custom server role creation requires -AllowServerSecurity.';continue}
    $owner=Val $role.OwnerName
    if (-not $owner -or ($owner -ine 'sa' -and -not $tl.ContainsKey($owner))) {Add-Action '' 'Server role' $name 'ServerSecurity' 'Deferred' ('Role owner missing: '+$owner);continue}
    $sql='CREATE SERVER ROLE '+(Qi $name)+' AUTHORIZATION '+(Qi $owner)+';'
    Add-Action '' 'Server role' $name 'ServerSecurity' 'Planned' 'Custom server role creation.' $sql
  }
  $existingMembers=@{}
  foreach ($m in $target.Members) {$existingMembers[(Key (Val $m.RoleName) (Val $m.MemberName))]=$true}
  $sourceMemberSet=@{};foreach($m in $source.Members){$sourceMemberSet[(Key (Val $m.RoleName) (Val $m.MemberName))]=$true}
  foreach($m in $target.Members){if(-not $sourceMemberSet.ContainsKey((Key (Val $m.RoleName) (Val $m.MemberName)))){Add-Action '' 'Target-only server role membership' ((Val $m.RoleName)+' / '+(Val $m.MemberName)) 'Review' 'Target only' 'Additional server role membership; no removal.'}}
  foreach ($m in $source.Members) {
    $role=Val $m.RoleName;$member=Val $m.MemberName;$dest=TargetLoginName $member
    if ($existingMembers.ContainsKey((Key $role $dest))) {
      if(Server-Identity-Safe $member $dest){Add-Action '' 'Server role membership' ($role+' / '+$dest) 'ServerSecurity' 'Already correct' 'Membership exists with verified identity.' '' '' $dest $role}
      else{Add-Action '' 'Server role membership' ($role+' / '+$dest) 'ServerSecurity' 'Blocked' 'Role membership names match, but member SID/type/role ownership differs.' '' '' $dest $role}
      continue
    }
    if ((IsMachine $member) -and -not $AllowMachineAccounts) {
      Add-Action '' 'Server role membership' ($role+' / '+$dest) 'ServerSecurity' 'Blocked' 'Machine/local service principal assignment requires -AllowMachineAccounts.' '' '' $dest $role;continue
    }
    if (-not $AllowServerSecurity -or ((IsSensitiveRole $role) -and -not $AllowPrivilegedRoles)) {
      Add-Action '' 'Server role membership' ($role+' / '+$dest) 'ServerSecurity' 'Blocked' 'Requires -AllowServerSecurity and (for privileged roles) -AllowPrivilegedRoles.' '' '' $dest $role;continue
    }
    if (-not $tl.ContainsKey($dest) -or -not $targetRoles.ContainsKey($role)) {
      Add-Action '' 'Server role membership' ($role+' / '+$dest) 'ServerSecurity' 'Deferred' 'Target member login and/or server role missing; rerun after prerequisites.' '' '' $dest $role;continue
    }
    if(-not (Server-Identity-Safe $member $dest)) {Add-Action '' 'Server role membership' ($role+' / '+$dest) 'ServerSecurity' 'Blocked' 'Member login SID/type conflict.' '' '' $dest $role;continue}
    $sourceRolePermissions=@($source.Permissions|Where-Object {$_.Grantee -eq $role})
    $targetRolePermissions=@($target.Permissions|Where-Object {$_.Grantee -eq $role})
    $sourceRoleStates=@{};$targetRoleStates=@{}
    foreach($rp in $sourceRolePermissions){$q=Permission-Object $rp '' $true;$sourceRoleStates[$q.Key]=$q.State}
    foreach($rp in $targetRolePermissions){$q=Permission-Object $rp '' $true;$targetRoleStates[$q.Key]=$q.State}
    $privilegeDifference=$false
    if($sourceRoleStates.Count -ne $targetRoleStates.Count){$privilegeDifference=$true}
    foreach($pk in $sourceRoleStates.Keys){if(-not $targetRoleStates.ContainsKey($pk) -or $targetRoleStates[$pk] -ne $sourceRoleStates[$pk]){$privilegeDifference=$true}}
    $extraParents=@($target.Members|Where-Object {$_.MemberName -eq $role -and -not $sourceMemberSet.ContainsKey((Key (Val $_.RoleName) (Val $_.MemberName)))})
    if($extraParents.Count){Add-Action '' 'Server role membership' ($role+' / '+$dest) 'ServerSecurity' 'Blocked' 'Target server role inherits additional role memberships; privileged access differs.' '' '' $dest $role;continue}
    if($privilegeDifference){Add-Action '' 'Server role membership' ($role+' / '+$dest) 'ServerSecurity' 'Deferred' 'Server role explicit permissions differ. Reconcile role permissions before granting memberships.' '' '' $dest $role;continue}
    $sql='ALTER SERVER ROLE '+(Qi $role)+' ADD MEMBER '+(Qi $dest)+';'
    Add-Action '' 'Server role membership' ($role+' / '+$dest) 'ServerSecurity' 'Planned' 'Add missing source membership.' $sql '' $dest $role
  }
  $targetPerms=@{}
  foreach($r in $target.Permissions){$p=Permission-Object $r '' $true;$targetPerms[$p.Key]=$p}
  $srcPermKeys=@{};foreach($sr in $source.Permissions){$srcPermKeys[(Permission-Object $sr '' $true).Key]=$true}
  foreach($tr in $target.Permissions){$p=Permission-Object $tr '' $true;if(-not $srcPermKeys.ContainsKey($p.Key)){Add-Action '' 'Target-only server permission' $p.Key 'Review' 'Target only' 'Target has additional explicit server permission; no removal.'}}
  foreach($r in $source.Permissions) {
    $p=Permission-Object $r '' $true
    $prior=Lookup $targetPerms $p.Key
    if ($null -ne $prior -and $prior.State -eq $p.State) {
      if($p.Grantee -eq 'public' -or (Server-Identity-Safe $p.Grantee $p.Grantee)){Add-Action '' 'Server permission' $p.Key 'ServerSecurity' 'Already correct' 'Permission state and grantee identity match.'}
      else{Add-Action '' 'Server permission' $p.Key 'ServerSecurity' 'Blocked' 'Permission names match but target grantee identity/SID differs.'}
      continue
    }
    if ($null -ne $prior) {Add-Action '' 'Server permission' $p.Key 'ServerSecurity' 'Blocked' 'Conflicting existing permission state; no GRANT/DENY override.';continue}
    if((IsMachine $p.Grantee) -and -not $AllowMachineAccounts) {Add-Action '' 'Server permission' $p.Key 'ServerSecurity' 'Blocked' 'Machine account permission requires -AllowMachineAccounts.';continue}
    if ($p.Grantee -eq 'public') {Add-Action '' 'Server permission' $p.Key 'ServerSecurity' 'Manual review' 'PUBLIC permission difference; never copied automatically.';continue}
    if (-not $p.Supported) {Add-Action '' 'Server permission' $p.Key 'ServerSecurity' 'Manual review' 'Unsupported server securable class; report only.';continue}
    if (-not $AllowServerSecurity -or -not $AllowPrivilegedPermissions -or ($p.State -eq 'D' -and -not $AllowDenies)) {
      Add-Action '' 'Server permission' $p.Key 'ServerSecurity' 'Blocked' 'Requires -AllowServerSecurity, -AllowPrivilegedPermissions and DENY approval where relevant.';continue
    }
    if (-not $tl.ContainsKey($p.Grantee) -and -not $targetRoles.ContainsKey($p.Grantee)) {Add-Action '' 'Server permission' $p.Key 'ServerSecurity' 'Deferred' 'Grantee missing.';continue}
    if(-not (Server-Identity-Safe $p.Grantee $p.Grantee)) {Add-Action '' 'Server permission' $p.Key 'ServerSecurity' 'Blocked' 'Grantee SID/type conflict; explicit remap requires manual permission review.';continue}
    $sql=Permission-Sql $p
    if (-not $sql) {Add-Action '' 'Server permission' $p.Key 'ServerSecurity' 'Manual review' 'Permission state or type not supported for script.';continue}
    Add-Action '' 'Server permission' $p.Key 'ServerSecurity' 'Planned' 'Explicit server permission; grantor metadata not reproduced.' $sql
  }
}

function Principal-Safe([string]$name,$sourcePrincipals,$targetPrincipals,$targetLogins) {
  if($name -eq 'dbo') {return $true}
  $s=Lookup $sourcePrincipals $name;$t=Lookup $targetPrincipals $name
  if($null -eq $s -or $null -eq $t){return $false}
  if((Val $s.Type) -cne (Val $t.Type)){return $false}
  if((Val $s.Type) -eq 'R'){
    $owner=Val $s.OwnerName
    if($owner -ine (Val $t.OwnerName)){return $false}
    if($owner -ieq 'dbo'){return $true}
    if(-not $owner -or $owner -ieq $name){return $false}
    return (Principal-Safe $owner $sourcePrincipals $targetPrincipals $targetLogins)
  }
  if((Val $s.Type) -notin @('S','U','G')){return $false}
  $srcLogin=Val $s.LoginName
  if(-not $srcLogin){return $false}
  $dest=TargetLoginName $srcLogin
  $login=Lookup $targetLogins $dest
  if($null -eq $login){return $false}
  if((Hex $t.Sid) -ne (Hex $login.Sid)){return $false}
  if((Hex $s.Sid) -eq (Hex $login.Sid)){return $true}
  return ($AllowIdentityMapping -and $dest -ne $srcLogin -and (Val $s.Type) -in @('U','G'))
}

function Plan-Database([string]$db,$source,$target) {
  $sp=ByName $source.Principals;$tp=ByName $target.Principals
  $ts=ByName $target.Schemas;$tr=ByName @($target.Principals|Where-Object {$_.Type -eq 'R'})
  $srcSchema=ByName $source.Schemas
  $tl=ByName $script:TargetMeta.Logins
  $memberSet=@{};foreach($m in $target.Memberships){$memberSet[(Key (Val $m.RoleName) (Val $m.MemberName))]=$true}
  $objects=@{};$cols=@{};$types=@{}
  foreach($o in $target.Objects){
    $k=Key (Val $o.SchemaName) (Val $o.ObjectName);$objects[$k]=$true
    $c=Val $o.ColumnName;if($c){$cols[(Key $k $c)]=$true}
  }
  foreach($t in $target.Types){$types[(Key (Val $t.SchemaName) (Val $t.TypeName))]=$true}

  foreach ($p in $source.Principals) {
    $name=Val $p.Name;$type=Val $p.Type
    if ($type -eq 'R') {continue}
    if ($type -notin @('S','U','G')) {
      Add-Action $db 'Unsupported database user' $name 'Users' 'Manual review' ('Principal type '+$type+' requires application/contained-user or certificate-specific migration.');continue
    }
    $srcLogin=Val $p.LoginName
    if (-not $srcLogin) {Add-Action $db 'Source unmapped database user' $name 'Users' 'Blocked' 'No matching source server login SID; contained/orphaned users require separate handling.';continue}
    $destLogin=TargetLoginName $srcLogin
    $tLogin=Lookup $tl $destLogin
    if ($null -eq $tLogin) {Add-Action $db 'Database user' $name 'Users' 'Deferred' ('Target login '+$destLogin+' missing. Run LOGINS, or provision target farm identity.');continue}
    if ((Val $tLogin.Type) -cne $type) {Add-Action $db 'Database user' $name 'Users' 'Blocked' 'Target login type differs from source database user.';continue}
    if ((Hex $p.Sid) -ne (Hex $tLogin.Sid) -and -not ($srcLogin -ne $destLogin -and $AllowIdentityMapping)) {
      Add-Action $db 'Database user' $name 'Users' 'Blocked' ('Source user SID and target login SID differ for '+$destLogin+'. Review identity mapping.');continue
    }
    if ((IsMachine $srcLogin) -and -not $AllowMachineAccounts) {Add-Action $db 'Database user' $name 'Users' 'Blocked' 'Machine/local service account requires explicit -AllowMachineAccounts.';continue}
    $existing=Lookup $tp $name
    if ($null -eq $existing) {
      $collisions=@($target.Principals|Where-Object {(Hex $_.Sid) -eq (Hex $tLogin.Sid) -and (Hex $_.Sid)})
      if ($collisions.Count) {Add-Action $db 'Database user' $name 'Users' 'Blocked' ('SID already mapped to database user '+(Val $collisions[0].Name));continue}
      $sql='CREATE USER '+(Qi $name)+' FOR LOGIN '+(Qi $destLogin)+';'
      Add-Action $db 'Database user' $name 'Users' 'Planned' 'Create for existing target login. Default schema is reconciled in ROLES stage.' $sql '' $destLogin
    } else {
      if ((Val $existing.Type) -cne $type) {Add-Action $db 'Database user' $name 'Users' 'Blocked' 'Existing user type differs; no overwrite.';continue}
      if ((Hex $existing.Sid) -ne (Hex $tLogin.Sid)) {Add-Action $db 'Database user SID' $name 'Users' 'Blocked' 'Existing target database user SID conflicts; no automatic ALTER USER.';continue}
      Add-Action $db 'Database user' $name 'Users' 'Already correct' 'User maps to intended target login.' '' '' $destLogin
      $srcDefault=Val $p.DefaultSchema;$tgtDefault=Val $existing.DefaultSchema
      if ($srcDefault -and $srcDefault -ine $tgtDefault) {
        if (-not $ts.ContainsKey($srcDefault)) {Add-Action $db 'Default schema' $name 'DefaultSchemas' 'Deferred' ('Source schema '+$srcDefault+' not yet on target.');continue}
        if (-not $AllowDefaultSchemaChanges) {Add-Action $db 'Default schema' $name 'DefaultSchemas' 'Manual review' ('Source '+$srcDefault+', target '+$tgtDefault+'. Requires -AllowDefaultSchemaChanges.');continue}
        $sql='ALTER USER '+(Qi $name)+' WITH DEFAULT_SCHEMA = '+(Qi $srcDefault)+';'
        Add-Action $db 'Default schema' $name 'DefaultSchemas' 'Planned' 'Set source default schema after schema reconciliation.' $sql
      }
    }
  }
  foreach ($p in $target.Principals) {
    if ((Val $p.Type) -eq 'R') {continue}
    if (-not $sp.ContainsKey((Val $p.Name))) {Add-Action $db 'Target-only user' (Val $p.Name) 'Review' 'Target only' 'Do not remove target-specific access automatically.'}
  }
  foreach ($r in @($source.Principals|Where-Object {$_.Type -eq 'R'})) {
    $name=Val $r.Name
    if ([bool]$r.FixedRole) {continue}
    $existing=Lookup $tr $name
    if ($null -ne $existing) {
      if ((Val $r.OwnerName) -ine (Val $existing.OwnerName)) {Add-Action $db 'Role owner' $name 'CustomRoles' 'Manual review' ('Source owner '+(Val $r.OwnerName)+'; target '+(Val $existing.OwnerName))}
      else {Add-Action $db 'Custom role' $name 'CustomRoles' 'Already correct' 'Role exists with matching owner.'}
      continue
    }
    if($tp.ContainsKey($name)) {Add-Action $db 'Custom role' $name 'CustomRoles' 'Blocked' 'Target principal name exists but is not a database role; cannot create role.';continue}
    if($tp.ContainsKey($name)) {Add-Action $db 'Custom role' $name 'CustomRoles' 'Blocked' 'Target principal name exists but is not a database role; cannot create role.';continue}
    if (-not $AllowCustomRoles) {
      Add-Action $db 'Custom role' $name 'CustomRoles' 'Blocked' 'Missing role requires -AllowCustomRoles.';continue
    }
    $owner=Val $r.OwnerName
    if (-not $owner -or ($owner -ine 'dbo' -and -not $tp.ContainsKey($owner))) {
      Add-Action $db 'Custom role' $name 'CustomRoles' 'Deferred' ('Role owner '+$owner+' missing; create database user/role first.');continue
    }
    if($owner -ine 'dbo' -and -not (Principal-Safe $owner $sp $tp $tl)) {Add-Action $db 'Custom role' $name 'CustomRoles' 'Blocked' 'Role owner identity differs; manual review.';continue}
    $sql='CREATE ROLE '+(Qi $name)+' AUTHORIZATION '+(Qi $owner)+';'
    Add-Action $db 'Custom role' $name 'CustomRoles' 'Planned' 'Create missing user-defined role.' $sql
  }
  foreach($r in @($target.Principals|Where-Object {$_.Type -eq 'R' -and -not [bool]$_.FixedRole})) {
    if (-not $sp.ContainsKey((Val $r.Name))) {Add-Action $db 'Target-only custom role' (Val $r.Name) 'Review' 'Target only' 'Target-only role; never automatically removed.'}
  }
  foreach($schema in $source.Schemas){
    $name=Val $schema.Name
    if($name -in @('sys','INFORMATION_SCHEMA')) {continue}
    $existing=Lookup $ts $name
    if($null -ne $existing) {
      if ((Val $existing.OwnerName) -ine (Val $schema.OwnerName)) {Add-Action $db 'Schema owner' $name 'Schemas' 'Manual review' ('Source owner '+(Val $schema.OwnerName)+'; target '+(Val $existing.OwnerName))}
      else {Add-Action $db 'Schema' $name 'Schemas' 'Already correct' 'Schema and owner exist.'}
      continue
    }
    if (-not $AllowSchemas) {Add-Action $db 'Schema' $name 'Schemas' 'Blocked' 'Creating schemas requires -AllowSchemas and ownership approval.';continue}
    $owner=Val $schema.OwnerName
    if (-not $owner -or ($owner -ine 'dbo' -and -not $tp.ContainsKey($owner))) {Add-Action $db 'Schema' $name 'Schemas' 'Deferred' ('Owner '+$owner+' missing; run USERS or CUSTOMROLES then replan.');continue}
    if($owner -ine 'dbo' -and -not (Principal-Safe $owner $sp $tp $tl)) {Add-Action $db 'Schema' $name 'Schemas' 'Blocked' 'Schema owner identity differs; manual review.';continue}
    $sql='CREATE SCHEMA '+(Qi $name)+' AUTHORIZATION '+(Qi $owner)+';'
    Add-Action $db 'Schema' $name 'Schemas' 'Planned' 'Create required source schema with matching owner.' $sql
  }
  $targetPerms=@{}
  foreach($r in $target.Permissions){$p=Permission-Object $r $db;$targetPerms[$p.Key]=$p}
  foreach($r in $source.Permissions){
    $p=Permission-Object $r $db
    $srcGrantee=Lookup $sp $p.Grantee
    if($p.Grantee -ne 'public' -and ($null -eq $srcGrantee -or (Val $srcGrantee.Type) -notin @('S','U','G','R'))){
      Add-Action $db 'Database permission' $p.Key 'DatabasePermissions' 'Manual review' 'Unsupported grantee principal type or missing principal; permission not migrated.' '' '' $p.Grantee;continue
    }
    $existing=Lookup $targetPerms $p.Key
    if($null -ne $existing){
      if($existing.State -eq $p.State){
        $sr=Lookup $sp $p.Grantee; $trr=Lookup $tp $p.Grantee
        if($p.Grantee -eq 'public' -or (Principal-Safe $p.Grantee $sp $tp $tl)){
          Add-Action $db 'Database permission' $p.Key 'DatabasePermissions' 'Already correct' 'Permission state and grantee identity match.' '' '' $p.Grantee
        }elseif($null -ne $sr -and $null -ne $trr -and (Val $sr.Type) -eq 'R' -and (Val $trr.Type) -eq 'R') {
          Add-Action $db 'Database permission' $p.Key 'DatabasePermissions' 'Already correct' 'Explicit permission state matches for role; role owner mismatch is tracked separately and membership remains gated.' '' '' $p.Grantee
        }else{Add-Action $db 'Database permission' $p.Key 'DatabasePermissions' 'Blocked' 'Permission state matches but target grantee SID/type differs.' '' '' $p.Grantee}
      }
      else{Add-Action $db 'Database permission' $p.Key 'DatabasePermissions' 'Blocked' ('Conflicting explicit state source='+$p.State+' target='+$existing.State+'; never overwrite.') '' '' $p.Grantee}
      continue
    }
    if((IsMachine $p.Grantee) -and -not $AllowMachineAccounts){Add-Action $db 'Database permission' $p.Key 'DatabasePermissions' 'Blocked' 'Machine/local service permission requires -AllowMachineAccounts.' '' '' $p.Grantee;continue}
    if($p.Grantee -eq 'public'){Add-Action $db 'Database permission' $p.Key 'DatabasePermissions' 'Manual review' 'PUBLIC permission difference affects all database users; never copied automatically.' '' '' $p.Grantee;continue}
    if(-not $p.Supported){Add-Action $db 'Database permission' $p.Key 'DatabasePermissions' 'Manual review' ('Unsupported or missing securable mapping: '+$p.Part) '' '' $p.Grantee;continue}
    if(-not $tp.ContainsKey($p.Grantee)) {Add-Action $db 'Database permission' $p.Key 'DatabasePermissions' 'Deferred' ('Grantee '+$p.Grantee+' missing.') '' '' $p.Grantee;continue}
    if(-not (Principal-Safe $p.Grantee $sp $tp $tl)) {Add-Action $db 'Database permission' $p.Key 'DatabasePermissions' 'Blocked' 'Grantee identity SID/type/role ownership conflict; never grant to another identity.' '' '' $p.Grantee;continue}
    $securableOK=$true
    if($p.Part.StartsWith('OBJECT:')) {
      $schema=Val $r.SchemaName;$obj=Val $r.ObjectName;$col=Val $r.ColumnName
      $k=Key $schema $obj
      $securableOK=$objects.ContainsKey($k)
      if($securableOK -and $col){$securableOK=$cols.ContainsKey((Key $k $col))}
    } elseif($p.Part.StartsWith('SCHEMA:')) {$securableOK=$ts.ContainsKey((Val $r.SchemaName))}
    elseif($p.Part.StartsWith('TYPE:')) {$securableOK=$types.ContainsKey((Key (Val $r.SchemaName) (Val $r.ObjectName)))}
    elseif($p.Part.StartsWith('PRINCIPAL:')) {$securableOK=$tp.ContainsKey((Val $r.SecurablePrincipal))}
    if(-not $securableOK) {Add-Action $db 'Database permission' $p.Key 'DatabasePermissions' 'Deferred' 'Referenced schema/object/column/type/principal missing on target.' '' '' $p.Grantee;continue}
    $danger=($p.Permission -match '^(CONTROL|ALTER|IMPERSONATE|TAKE OWNERSHIP|UNSAFE ASSEMBLY|AUTHENTICATE|ALTER ANY )' -or $p.State -eq 'W')
    if(-not $AllowDatabasePermissions -or ($danger -and -not $AllowPrivilegedPermissions) -or ($p.State -eq 'D' -and -not $AllowDenies)) {
      Add-Action $db 'Database permission' $p.Key 'DatabasePermissions' 'Blocked' 'Requires -AllowDatabasePermissions; privileged permissions/grant options and DENY require separate approvals.' '' '' $p.Grantee;continue
    }
    $sql=Permission-Sql $p
    if(-not $sql){Add-Action $db 'Database permission' $p.Key 'DatabasePermissions' 'Manual review' 'Unsupported permission/state for automatic scripting.' '' '' $p.Grantee;continue}
    Add-Action $db 'Database permission' $p.Key 'DatabasePermissions' 'Planned' 'Recreate source explicit permission; original GRANTOR metadata is not preserved.' $sql '' $p.Grantee
  }
  $sourcePermissionKeys=@{}
  foreach($sr in $source.Permissions){$sourcePermissionKeys[(Permission-Object $sr $db).Key]=$true}
  foreach($r in $target.Permissions){
    $p=Permission-Object $r $db
    if(-not $sourcePermissionKeys.ContainsKey($p.Key)) {Add-Action $db 'Target-only database permission' $p.Key 'Review' 'Target only' 'No permission removed automatically.' '' '' $p.Grantee}
  }
  $srcMembersByRole=@{};foreach($m in $source.Memberships){$srcMembersByRole[(Key (Val $m.RoleName) (Val $m.MemberName))]=$true}
  foreach($m in $source.Memberships){
    $role=Val $m.RoleName;$member=Val $m.MemberName
    $k=Key $role $member
    if($memberSet.ContainsKey($k)){
      if((Principal-Safe $role $sp $tp $tl) -and (Principal-Safe $member $sp $tp $tl)){
        Add-Action $db 'Database role membership' ($role+' / '+$member) 'Memberships' 'Already correct' 'Membership and source/target identities match.' '' '' $member $role
      }else{Add-Action $db 'Database role membership' ($role+' / '+$member) 'Memberships' 'Blocked' 'Membership names match but source/target role owner or member SID/type differs.' '' '' $member $role}
      continue
    }
    if(-not $tr.ContainsKey($role) -or -not $tp.ContainsKey($member)) {
      Add-Action $db 'Database role membership' ($role+' / '+$member) 'Memberships' 'Deferred' 'Role or member does not exist yet. Run USERS and role-definition stages first.' '' '' $member $role;continue
    }
    if(-not (Principal-Safe $role $sp $tp $tl) -or -not (Principal-Safe $member $sp $tp $tl)) {
      Add-Action $db 'Database role membership' ($role+' / '+$member) 'Memberships' 'Blocked' 'Member or role SID/type/owner differs; never assign access to an unverified principal.' '' '' $member $role;continue
    }
    if((IsMachine $member) -and -not $AllowMachineAccounts) {
      Add-Action $db 'Database role membership' ($role+' / '+$member) 'Memberships' 'Blocked' 'Machine/local service account role assignment requires -AllowMachineAccounts.' '' '' $member $role;continue
    }
    if((IsSensitiveRole $role) -and -not $AllowPrivilegedRoles) {
      Add-Action $db 'Database role membership' ($role+' / '+$member) 'Memberships' 'Blocked' 'Privileged role requires -AllowPrivilegedRoles.' '' '' $member $role;continue
    }
    # Never grant membership of a role whose declared permissions failed to replicate.
    $incomplete=@($script:Actions | Where-Object {
      $_.Database -eq $db -and $_.Kind -in @('Database permission','Target-only database permission') -and $_.Principal -eq $role -and $_.Status -in @('Blocked','Deferred','Manual review','Failed','Target only')
    })
    if($incomplete.Count) {Add-Action $db 'Database role membership' ($role+' / '+$member) 'Memberships' 'Deferred' 'Role permission differences (including target-only permissions) unresolved; membership withheld.' '' '' $member $role;continue}
    $extraRoleParents=@($target.Memberships | Where-Object {$_.MemberName -eq $role -and -not $srcMembersByRole.ContainsKey((Key (Val $_.RoleName) (Val $_.MemberName)))})
    if($extraRoleParents.Count) {Add-Action $db 'Database role membership' ($role+' / '+$member) 'Memberships' 'Blocked' 'Target role inherits extra role memberships not present in source; privileges may differ.' '' '' $member $role;continue}
    $sql='ALTER ROLE '+(Qi $role)+' ADD MEMBER '+(Qi $member)+';'
    Add-Action $db 'Database role membership' ($role+' / '+$member) 'Memberships' 'Planned' 'Add missing source database role membership.' $sql '' $member $role
  }
  $srcMembers=@{};foreach($m in $source.Memberships){$srcMembers[(Key (Val $m.RoleName) (Val $m.MemberName))]=$true}
  foreach($m in $target.Memberships){
    if(-not $srcMembers.ContainsKey((Key (Val $m.RoleName) (Val $m.MemberName)))) {
      Add-Action $db 'Target-only role membership' ((Val $m.RoleName)+' / '+(Val $m.MemberName)) 'Review' 'Target only' 'Extra target membership; review; never remove.'
    }
  }
  foreach($schema in $target.Schemas){
    $name=Val $schema.Name
    if($name -notin @('sys','INFORMATION_SCHEMA') -and -not $srcSchema.ContainsKey($name)) {
      Add-Action $db 'Target-only schema' $name 'Review' 'Target only' 'Schema exists only on target; no changes.'
    }
  }
}

function Build-Plan([bool]$includeHashes=$false) {
  $script:Actions.Clear()
  $script:PlanNumber++
  # APPLY reads pinned source inventory and fresh target. PLAN captures source inventory.
  $script:SourceMeta=Server-Inventory $true $includeHashes
  $script:TargetMeta=Server-Inventory $false $includeHashes
  $script:RelevantLogins=@{}
  $roles=New-Object System.Collections.Generic.List[object]
  $users=New-Object System.Collections.Generic.List[object]
  $logins=New-Object System.Collections.Generic.List[object]
  foreach($l in $script:SourceMeta.Logins) {
    if((Val $l.Type) -in @('S','U','G')) {
      $dest=TargetLoginName (Val $l.Name)
      $target=Lookup (ByName $script:TargetMeta.Logins) $dest
      $logins.Add([pscustomobject]@{SourceLogin=(Val $l.Name);TargetLogin=$dest;Type=(Val $l.Type);SourceSid=(Hex $l.Sid);TargetSid=$(if($null -ne $target){Hex $target.Sid}else{''});TargetPresent=($null -ne $target);SourceDisabled=[bool]$l.Disabled;TargetDisabled=$(if($null -ne $target){[bool]$target.Disabled}else{$false})})|Out-Null
    }
  }
  foreach($db in $script:SelectedDbs){
    try {$s=Database-Inventory $db $true;$targetDb=TargetDatabase $db;$t=Database-Inventory $targetDb $false}
    catch {
      Add-Action $db 'Database inventory' $db 'Preflight' 'Failed' $_.Exception.Message
      Log ERROR ('Inventory failed for '+$db+': '+$_.Exception.Message)
      continue
    }
    $script:DestinationDatasets[$targetDb]=$t
    foreach($sp in $s.Principals) {
      if((Val $sp.LoginName)){$script:RelevantLogins[(Val $sp.LoginName)]=$true}
      if ((Val $sp.Type) -in @('S','U','G')) {
        $target=Lookup (ByName $t.Principals) (Val $sp.Name)
        $users.Add([pscustomobject]@{SourceDatabase=$db;Database=$targetDb;SourceUser=(Val $sp.Name);SourceLogin=(Val $sp.LoginName);TargetLogin=$(TargetLoginName (Val $sp.LoginName));SourceSid=(Hex $sp.Sid);TargetUserPresent=($null -ne $target);TargetSid=$(if($null -ne $target){Hex $target.Sid}else{''});SourceSchema=(Val $sp.DefaultSchema);TargetSchema=$(if($null -ne $target){Val $target.DefaultSchema}else{''})})|Out-Null
      }
    }
    foreach($r in @($s.Principals|Where-Object {$_.Type -eq 'R'})) {
      $name=Val $r.Name
      $tRole=Lookup (ByName @($t.Principals|Where-Object {$_.Type -eq 'R'})) $name
      $sourceMemberCount=@($s.Memberships|Where-Object {$_.RoleName -eq $name}).Count
      $targetMemberCount=@($t.Memberships|Where-Object {$_.RoleName -eq $name}).Count
      $sourceUserCount=@($s.Memberships|Where-Object {$_.RoleName -eq $name -and $_.MemberType -ne 'R'}).Count
      $targetUserCount=@($t.Memberships|Where-Object {$_.RoleName -eq $name -and $_.MemberType -ne 'R'}).Count
      $sourcePermCount=@($s.Permissions|Where-Object {$_.Grantee -eq $name}).Count
      $targetPermCount=@($t.Permissions|Where-Object {$_.Grantee -eq $name}).Count
      $roles.Add([pscustomobject]@{SourceDatabase=$db;Database=$targetDb;Role=$name;Fixed=[bool]$r.FixedRole;ApplicationManaged=$false;SourceOwner=(Val $r.OwnerName);TargetOwner=$(if($null -ne $tRole){Val $tRole.OwnerName}else{''});TargetExists=($null -ne $tRole);SourceMembers=$sourceMemberCount;TargetMembers=$targetMemberCount;SourceUsers=$sourceUserCount;TargetUsers=$targetUserCount;SourceNestedRoles=($sourceMemberCount-$sourceUserCount);TargetNestedRoles=($targetMemberCount-$targetUserCount);SourceExplicitPermissions=$sourcePermCount;TargetExplicitPermissions=$targetPermCount})|Out-Null
    }
    $sourceDbInfo=@($script:SourceMeta.Databases|Where-Object {$_.name -eq $db})[0]
    $targetDbInfo=@($script:TargetMeta.Databases|Where-Object {$_.name -eq $targetDb})[0]
    if((Hex $sourceDbInfo.owner_sid) -ne (Hex $targetDbInfo.owner_sid)){
      Add-Action $targetDb 'Database owner SID' $targetDb 'Review' 'Manual review' 'Database owner SID differs. No automatic database-ownership changes.'
    }
    Plan-Database $targetDb $s $t
  }
  $missingSourceInventory=@($script:SelectedDbs|Where-Object {-not $script:SnapshotDatasets.ContainsKey($_)})
  if($missingSourceInventory.Count){
    Add-Action '' 'Source inventory' ($missingSourceInventory -join ', ') 'Preflight' 'Failed' 'Complete source inventory is required before deriving the common template.'
    throw ('Incomplete source inventory; cannot derive common template. Missing: '+($missingSourceInventory -join ', '))
  }
  PostPlan-Log 'START: LoadSourceInventory'
  $sourceInventories=@($script:SelectedDbs|ForEach-Object {Database-FromDataset $script:SnapshotDatasets[$_]})
  PostPlan-Log ('END: LoadSourceInventory SourceCount='+$sourceInventories.Count)
  if($sourceInventories.Count -ne $script:SelectedDbs.Count){throw 'Complete source inventory required before deriving common template.'}
  PostPlan-Log 'START: CommonTemplate'
  $derived=Derive-CommonTemplate $sourceInventories
  $script:CommonTemplate=$derived.Data
  $script:TemplateEvidence=$derived.Evidence
  PostPlan-Log ('END: CommonTemplate EvidenceCount='+$script:TemplateEvidence.Count)
  foreach($destinationDb in $script:AdditionalDestinationDbs){
    try {
      $destinationInventory=Database-Inventory $destinationDb $false
      $script:DestinationDatasets[$destinationDb]=$destinationInventory
      if($Mode -eq 'Plan' -or $ApproveCommonTemplate){ApplyCommonTemplate $destinationDb $destinationInventory}
    }
    catch {Add-Action $destinationDb 'Destination database inventory' $destinationDb 'Preflight' 'Failed' $_.Exception.Message;Log ERROR ('Inventory failed for additional destination '+$destinationDb+': '+$_.Exception.Message)}
  }
  foreach($unclassifiedDb in $script:UnclassifiedDatabases){
    try {$script:DestinationDatasets[$unclassifiedDb]=Database-Inventory $unclassifiedDb $false}
    catch {Add-Action $unclassifiedDb 'Unclassified destination database' $unclassifiedDb 'Preflight' 'Manual review' $_.Exception.Message;Log WARN ('Inventory failed for unclassified destination '+$unclassifiedDb+': '+$_.Exception.Message)}
  }
  foreach($excludedDb in @($script:ExplicitlyExcludedDatabases|Where-Object {$script:DestinationDbs -contains $_})){
    if(-not $script:DestinationDatasets.ContainsKey($excludedDb)){
      try {$script:DestinationDatasets[$excludedDb]=Database-Inventory $excludedDb $false}
      catch {Add-Action $excludedDb 'Explicitly excluded database' $excludedDb 'Preflight' 'Review' 'Excluded from migration scope; inventory collection failed.'}
    }
  }
  if($Mode -eq 'Apply' -and $script:SnapshotManifest.RequireTemplateApproval -and -not $ApproveCommonTemplate){
    Add-Action '' 'Common security template' 'All additional destination databases' 'Preflight' 'Blocked' 'Derived common template requires explicit -ApproveCommonTemplate.'
  }
  Plan-ServerSecurity $includeHashes
  $prefix=('Plan{0:D2}' -f $script:PlanNumber)
  $exceptionCount=Save-Report $prefix
  $roles|Export-Csv -LiteralPath (Join-Path $sessionDir ($prefix+'_RoleCoverage.csv')) -NoTypeInformation -Encoding UTF8
  $roleAggregate=@($roles|Group-Object Role|ForEach-Object {
    $items=@($_.Group)
    [pscustomobject]@{
      Role=$_.Name;SourceDatabaseCount=$items.Count;TargetDatabaseCount=@($items|Where-Object {$_.TargetExists}).Count;
      SourceMemberships=($items|Measure-Object -Property SourceMembers -Sum).Sum;
      TargetMemberships=($items|Measure-Object -Property TargetMembers -Sum).Sum;
      SourceUsers=($items|Measure-Object -Property SourceUsers -Sum).Sum;
      TargetUsers=($items|Measure-Object -Property TargetUsers -Sum).Sum;
      SourceNestedRoles=($items|Measure-Object -Property SourceNestedRoles -Sum).Sum;
      TargetNestedRoles=($items|Measure-Object -Property TargetNestedRoles -Sum).Sum;
      SourceExplicitPermissions=($items|Measure-Object -Property SourceExplicitPermissions -Sum).Sum;
      TargetExplicitPermissions=($items|Measure-Object -Property TargetExplicitPermissions -Sum).Sum
    }
  })
  if($roleAggregate.Count){$roleAggregate|Export-Csv -LiteralPath (Join-Path $sessionDir ($prefix+'_RoleSummary.csv')) -NoTypeInformation -Encoding UTF8}
  $users|Export-Csv -LiteralPath (Join-Path $sessionDir ($prefix+'_UserMappings.csv')) -NoTypeInformation -Encoding UTF8
  $logins|Export-Csv -LiteralPath (Join-Path $sessionDir ($prefix+'_Logins.csv')) -NoTypeInformation -Encoding UTF8
  return $exceptionCount
}

function Confirm-Apply([string]$phase) {
  Write-Host ''
  Write-Host "APPLY phase: $phase | destination $($script:TargetMeta.Info.ServerName)" -ForegroundColor Yellow
  Write-Host ('Databases: '+($script:SelectedDbs | ForEach-Object {$_+' -> '+(TargetDatabase $_)} | Out-String))
  $answer=Read-Host 'Type the EXACT target instance name to authorize this phase'
  if ($answer -cne (Val $script:TargetMeta.Info.ServerName)) {
    Log WARN "Phase $phase declined (target confirmation mismatch). No phase changes made."
    return $false
  }
  return $true
}
function Execute-Phase([string]$phase,[int]$passes=1) {
  for($pass=1;$pass -le $passes;$pass++) {
    Verify-SourceUnchanged
    $hashes=($phase -eq 'Logins' -and $AllowSqlLogins)
    [void](Build-Plan $hashes)
    $fatal=@($script:Actions|Where-Object {$_.Kind -eq 'Database inventory' -and $_.Status -eq 'Failed'})
    if($fatal.Count){throw 'Incomplete database inventory. Fail closed: no changes in this phase.'}
    $toRun=@($script:Actions|Where-Object {$_.Stage -eq $phase -and $_.Status -eq 'Planned' -and $_.Sql})
    if(-not $toRun.Count){Log INFO "Phase $phase pass ${pass}: no eligible changes.";return}
    Log WARN "Phase $phase pass ${pass}: $($toRun.Count) eligible changes. Blocked/deferred items will NOT execute."
    $success=0
    foreach($op in $toRun){
      $db=if($op.Database){$op.Database}else{'master'}
      $event=[pscustomobject]@{
        Time=(Get-Date -Format o);Phase=$phase;Database=$db;Kind=$op.Kind;
        Name=$op.Name;Status='';Detail=''
      }
      try {
        Apply-Sql $db $op.Sql
        $event.Status='Executed';$event.Detail='SQL statement accepted; post-APPLY verification still required.'
        $success++
        Log APPLIED "[$db] $($op.Kind) / $($op.Name). Awaiting post-stage verification."
      } catch {
        $event.Status='Failed';$event.Detail=Scrub $_.Exception.Message
        Log ERROR "[$db] $($op.Kind) / $($op.Name): $($_.Exception.Message)"
      } finally {$script:Stages.Add($event)|Out-Null}
    }
    if(-not $success){return}
    # Replan before another dependency pass rather than assuming earlier DDL succeeded.
  }
}
function Execute-Roles {
  # New users first, then roles, then schemas. Afterwards defaults and permissions
  # can refer to principals and securables that now exist; memberships last.
  Execute-Phase 'CustomRoles' 5
  Execute-Phase 'Schemas' 4
  Execute-Phase 'DefaultSchemas'
  Execute-Phase 'DatabasePermissions'
  Execute-Phase 'Memberships'
}
function Execute-ServerSecurity {
  if(-not $AllowServerSecurity){Log WARN 'SERVERSECURITY requested but -AllowServerSecurity not supplied; no server privilege changes.';return}
  # The server stage can contain role definitions, membership and permissions.
  # Each pass regenerates the complete inventory so dependency changes are seen.
  Execute-Phase 'ServerSecurity' 3
}
function Get-ActionAccounting {
  $counts=[ordered]@{}
  foreach($status in @('Already correct','Blocked','Deferred','Manual review','Planned','Target only','Failed')){$counts[$status]=@($script:Actions|Where-Object {$_.Status -eq $status}).Count}
  $exceptions=$counts['Blocked']+$counts['Deferred']+$counts['Manual review']+$counts['Failed']
  $dependencyRows=@($script:Actions|Where-Object {$_.Status -in @('Blocked','Deferred','Manual review','Failed')})
  $rootCauses=@($dependencyRows|Group-Object Kind,Reason|ForEach-Object {
    $first=$_.Group[0]
    [pscustomobject]@{Kind=$first.Kind;Reason=$first.Reason;Count=$_.Count;Database=$first.Database;Example=$first.Name}
  }|Sort-Object Count -Descending)
  return [pscustomobject]@{
    AlreadyCorrect=$counts['Already correct'];Blocked=$counts['Blocked'];Deferred=$counts['Deferred'];ManualReview=$counts['Manual review'];Planned=$counts['Planned'];TargetOnly=$counts['Target only'];Failed=$counts['Failed'];Exceptions=$exceptions;RootCauses=$rootCauses
  }
}
function Write-ReadinessReport($accounting,[string]$planStatus,[string]$inventoryStatus,[string]$manifestStatus,[string]$applyStatus,[string]$reconciliationStatus) {
  $lines=New-Object System.Collections.Generic.List[string]
  $lines.Add('# Migration Readiness');$lines.Add('');$lines.Add('## Status')
  $lines.Add(('- PLAN execution: **{0}**' -f $planStatus));$lines.Add(('- Inventory completeness: **{0}**' -f $inventoryStatus));$lines.Add(('- Manifest integrity: **{0}**' -f $manifestStatus));$lines.Add(('- Migration action readiness: **{0}**' -f $(if($accounting.Exceptions -or $accounting.Planned){'NOT_READY'}else{'READY_FOR_REVIEW'})));$lines.Add(('- APPLY execution: **{0}**' -f $applyStatus));$lines.Add(('- Final migration reconciliation: **{0}**' -f $reconciliationStatus));$lines.Add('')
  $lines.Add('## Action totals');$lines.Add('| Category | Count |');$lines.Add('|---|---:|')
  foreach($name in @('AlreadyCorrect','Blocked','Deferred','ManualReview','Planned','TargetOnly','Failed','Exceptions')){$value=$accounting.PSObject.Properties[$name].Value;$lines.Add('| '+$name+' | '+[string]$value+' |')}
  $lines.Add('');$lines.Add('Planned actions are proposed operations, not exceptions. Target-only records are reconciliation items and are never removed automatically.');$lines.Add('');$lines.Add('## Root causes')
  foreach($root in $accounting.RootCauses){$lines.Add('- **'+[string]$root.Kind+'**: '+[string]$root.Count+' ('+[string]$root.Reason+') in '+[string]$root.Database+'; example `'+[string]$root.Example+'`.')}
  $lines.Add('');$lines.Add('## Required safeguards');$lines.Add('- Login/SID conflicts require authoritative identity evidence; same names are not treated as equivalent and no login or SID is overwritten.');$lines.Add('- Externally managed roles, identities, and databases require external provisioning or separate approval.');$lines.Add('- Common-template actions apply only to additional destinations after template evidence review; matching databases use their corresponding source inventory.');$lines.Add('- APPLY was not executed by this report generation path.')
  [IO.File]::WriteAllLines((Join-Path $sessionDir 'MIGRATION_READINESS.md'),$lines,(New-Object Text.UTF8Encoding($false)))
  $accounting|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $sessionDir 'Readiness.json') -Encoding UTF8
}
function Finalize-Session {
  if($Mode -eq 'Plan') {Log INFO 'PLAN completed; no DDL executed. Final verification is reserved for APPLY.'}
  else {Log INFO 'Post-stage verification: comparing pinned source against fresh target metadata.';Verify-SourceUnchanged; $outstanding=Build-Plan $false}
  $script:Stages | Export-Csv -LiteralPath (Join-Path $sessionDir 'Execution.csv') -NoTypeInformation -Encoding UTF8
  $failures=@($script:Stages|Where-Object {$_.Status -eq 'Failed'})
  $failCols='Time','Phase','Database','Kind','Name','Status','Detail'
  if($failures.Count){
    $failures | Export-Csv -LiteralPath (Join-Path $sessionDir 'ExecutionFailures.csv') -NoTypeInformation -Encoding UTF8
    $failures | ForEach-Object {('['+$_.Time+'] '+$_.Phase+' / '+$_.Database+' / '+$_.Name+': '+$_.Detail)} | Set-Content -LiteralPath (Join-Path $sessionDir 'ExecutionFailures.log') -Encoding UTF8
  } else {
    ('"'+($failCols -join '","')+'"') | Set-Content -LiteralPath (Join-Path $sessionDir 'ExecutionFailures.csv') -Encoding UTF8
    'No SQL execution failures recorded.' | Set-Content -LiteralPath (Join-Path $sessionDir 'ExecutionFailures.log') -Encoding UTF8
  }
  $accounting=Get-ActionAccounting
  $open=$accounting.Exceptions+$accounting.Planned
  $planStatus=if($Mode -eq 'Plan'){if($accounting.Failed){'PLAN_EXECUTION_FAILED'}else{'PLAN_COMPLETED_WITH_EXCEPTIONS'}}else{'PLAN_PREVIEW_COMPLETED'}
  $inventoryStatus=if($Mode -eq 'Plan' -and (Test-Path -LiteralPath (Join-Path $script:SnapshotFolder 'Completion.marker'))){'COMPLETE'}else{'NOT_VERIFIED'}
  $manifestStatus=if($Mode -eq 'Plan' -and (Test-Path -LiteralPath (Join-Path $script:SnapshotFolder 'Manifest.json'))){'INTEGRITY_CHECKED'}else{'NOT_VERIFIED'}
  $applyStatus=if($Mode -eq 'Plan'){'NOT_EXECUTED'}else{'EXECUTED'}
  $reconciliationStatus=if($Mode -eq 'Plan'){'NOT_PERFORMED'}else{if($open){'OUTSTANDING'}else{'COMPLETE_IN_SUPPORTED_SCOPE'}}
  Write-ReadinessReport $accounting $planStatus $inventoryStatus $manifestStatus $applyStatus $reconciliationStatus
  $result=[pscustomobject]@{
    Source=[string]$script:SourceMeta.Info.ServerName;Target=[string]$script:TargetMeta.Info.ServerName;
    Mode=$Mode;SelectedDatabases=$script:SelectedDbs.Count;
    InventoryPath=$script:SnapshotFolder;
    InventoryPinned=[bool]$script:PinnedInventory;
    Executed=@($script:Stages|Where-Object {$_.Status -eq 'Executed'}).Count;
    Failed=$failures.Count;Unresolved=$accounting.Exceptions;Planned=$accounting.Planned;TargetOnly=$accounting.TargetOnly;
    PlanExecutionStatus=$planStatus;InventoryCompleteness=$inventoryStatus;ManifestIntegrity=$manifestStatus;
    MigrationActionReadiness=$(if($accounting.Exceptions -or $accounting.Planned){'NOT_READY'}else{'READY_FOR_REVIEW'});ApplyExecutionStatus=$applyStatus;FinalMigrationReconciliation=$reconciliationStatus;
    Status=$(if($failures.Count){'EXECUTION_FAILURES'}elseif($Mode -eq 'Plan'){'PLAN_COMPLETED_WITH_EXCEPTIONS'}elseif($script:Stages.Count -eq 0 -and -not $accounting.Planned){'APPLY_NO_ELIGIBLE_ACTIONS'}elseif($open){'PARTIAL_REVIEW_REQUIRED'}else{'NO_DETECTED_SOURCE_GAPS_SCOPE_LIMITED'});
    Caveat='Explicit grants, role/security objects compared where supported; effective AD membership, app provisioning, unsupported securables and original grantor not guaranteed.'
  }
  $result|ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $sessionDir 'Summary.json') -Encoding UTF8
  Log INFO "FINAL STATUS=$($result.Status); executed=$($result.Executed); failed=$($result.Failed); unresolved=$($result.Unresolved); target-only=$($result.TargetOnly)"
  Log INFO ('Reports: '+$sessionDir)
  if ($failures.Count){return 2}
  if ($open -gt 0){return 2}
  return 0
}

$transcriptStarted=$false
try {
  if($script:PinnedInventory){Load-ApprovedInventory
    if($script:SnapshotManifest.RequireTemplateApproval -and -not $ApproveCommonTemplate){throw 'APPLY requires -ApproveCommonTemplate after review of the derived common security template.'}
    if($script:IdentityMapFromSnapshot){$IdentityMapCsv=$script:IdentityMapFromSnapshot}
    if($script:DatabaseMapFromSnapshot){$DatabaseMapCsv=$script:DatabaseMapFromSnapshot}
    if($script:SnapshotManifest.IdentityMapHash -and -not $AllowIdentityMapping){throw 'Approved PLAN contains identity remapping: -AllowIdentityMapping is required before APPLY.'}
    if($script:SnapshotManifest.IdentityMapHash -and (File-SHA256 $IdentityMapCsv) -ne $script:SnapshotManifest.IdentityMapHash){throw 'Approved identity mapping file changed since PLAN.'}
    if($script:SnapshotManifest.DatabaseMapHash -and (File-SHA256 $DatabaseMapCsv) -ne $script:SnapshotManifest.DatabaseMapHash){throw 'Approved database mapping file changed since PLAN.'}
  }
  Load-IdentityMap
  Load-DatabaseMap
  if($script:PinnedInventory){
    foreach($d in $script:SnapshotManifest.Databases){if((TargetDatabase $d.SourceDatabase) -ine $d.TargetDatabase){throw ('Target database map changed since PLAN: '+$d.SourceDatabase)}}
    Verify-SourceUnchanged
  }
  if($TrustServerCertificate){Log WARN 'TrustServerCertificate is ON: SQL transport is encrypted but certificate identity is not validated.'}
  Verify-Preflight
  if($Mode -eq 'Plan') {
    [void](Build-Plan $false)
    Save-InventoryManifest
    $script:SnapshotCapture=$false
  } else {
    if($Stage -eq 'Prompt') {
      Write-Host 'APPLY operations: LOGINS, USERS, ROLES (definitions/schemas/permissions/memberships), SERVERSECURITY, ALL.'
      $selection=(Read-Host 'Enter APPLY operation').Trim().ToUpperInvariant()
      if($selection -notin @('LOGINS','USERS','ROLES','SERVERSECURITY','ALL')) {throw 'Unknown operation; no changes made.'}
      switch($selection){'LOGINS'{$Stage='Logins'} 'USERS'{$Stage='Users'} 'ROLES'{$Stage='Roles'} 'SERVERSECURITY'{$Stage='ServerSecurity'} 'ALL'{$Stage='All'}}
    }
    # Always create a fresh preview before any changes, even when caller chooses APPLY.
    [void](Build-Plan $false)
    Log WARN 'Review the initial Plan01_Plan.csv and Plan01_Exceptions.csv in this session folder before confirmation.'
    Write-Host ('Report folder: '+$sessionDir)
    $pre=(Read-Host 'Have you reviewed and approved the plan? Type REVIEWED').Trim()
    if($pre -cne 'REVIEWED'){throw 'APPLY cancelled; review was not confirmed.'}
    switch($Stage){
      'Logins' {
        if(Confirm-Apply 'LOGINS'){Execute-Phase 'Logins'}
      }
      'Users' {
        if(Confirm-Apply 'USERS'){
          Execute-Phase 'Users'
          [void](Build-Plan $false)
          Write-Host 'USERS complete. New PLAN generated. Roles and later stages require a separate authorization.' -ForegroundColor Yellow
        }
      }
      'Roles' {if(Confirm-Apply 'ROLES'){Execute-Roles}}
      'ServerSecurity' {if(Confirm-Apply 'SERVERSECURITY'){Execute-ServerSecurity}}
      'All' {
        if(Confirm-Apply 'LOGINS'){Execute-Phase 'Logins'}
        if(Confirm-Apply 'USERS'){Execute-Phase 'Users'}
        [void](Build-Plan $false)
        Write-Host 'New plan after USERS generated. Roles include schemas, explicit grants, and privileged memberships.' -ForegroundColor Yellow
        $next=(Read-Host 'Execute ROLES phase now? [Y/N]').Trim()
        if($next -ieq 'Y' -and (Confirm-Apply 'ROLES')) {Execute-Roles}
        if((Read-Host 'Proceed to SERVERSECURITY? [Y/N]').Trim() -ieq 'Y' -and (Confirm-Apply 'SERVERSECURITY')) {Execute-ServerSecurity}
      }
    }
  }
  $rc=Finalize-Session
  Write-Host ''
  Write-Host ('Results folder: '+$sessionDir)
  if($rc -eq 2){Write-Warning 'PARTIAL: Outstanding exceptions or failed actions. Migration is not complete.'}
  exit $rc
} catch {
  Log ERROR ('FATAL: '+$_.Exception.Message)
  Log ERROR ('FATAL LOCATION: '+$_.InvocationInfo.PositionMessage)
  if($_.ScriptStackTrace){Log ERROR ('FATAL STACK: '+$_.ScriptStackTrace)}
  if($script:Stages.Count){$script:Stages|Export-Csv -LiteralPath (Join-Path $sessionDir 'Execution.csv') -NoTypeInformation -Encoding UTF8}
  Write-Host ('Results folder: '+$sessionDir) -ForegroundColor Yellow
  exit 1
}
