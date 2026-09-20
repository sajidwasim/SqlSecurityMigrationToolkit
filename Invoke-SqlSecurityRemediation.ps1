#requires -Version 5.1
<#
SQL Security Remediation Orchestrator

Builds a dependency-aware remediation plan from an approved SQL Security Migration
Toolkit PLAN/APPLY preview session. PLAN and VERIFY are read-only. APPLY requires a
separate remediation approval manifest and exact authorization token; this script
never expands the approved operation set after replanning.
#>
[CmdletBinding()]
param(
  [ValidateSet('Plan','Apply','Verify')][string]$Mode='Plan',
  [string]$SessionPath='',
  [string]$InventoryPath='',
  [string]$OutputDirectory='',
  [string]$ApprovalManifest='',
  [string]$AuthorizationToken='',
  [switch]$AuthorizeRemediationApply,
  [switch]$ValidateDirectoryIdentities,
  [ValidateRange(1,10)][int]$MaxRetryPerFailureSignature=1,
  [ValidateRange(1,120)][int]$ConnectTimeoutSeconds=15,
  [ValidateRange(1,1800)][int]$CommandTimeoutSeconds=120
)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

$script:ExplicitlyExcludedDatabases=@()
$script:FailureSignatures=@{}

function Write-AtomicText([string]$Path,[string]$Content) {
  $temp=$Path+'.tmp_'+[Guid]::NewGuid().ToString('N')
  try {
    [IO.File]::WriteAllText($temp,$Content,(New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temp -Destination $Path -Force
  } finally {
    if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue}
  }
}

function File-SHA256([string]$Path) {
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){throw ('Required file not found: '+$Path)}
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Qi([string]$Name) { return '['+$Name.Replace(']',']]')+']' }

function Import-CsvSafe([string]$Path) {
  if(Test-Path -LiteralPath $Path -PathType Leaf){return @(Import-Csv -LiteralPath $Path)}
  return @()
}

function Export-CsvStable($Rows,[string]$Path,[string[]]$Columns) {
  if($Rows -and @($Rows).Count){
    $Rows | Select-Object $Columns | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
  } else {
    ('"'+($Columns -join '","')+'"') | Set-Content -LiteralPath $Path -Encoding UTF8
  }
}

function Has-Property($Value,[string]$Name) {
  if($null -eq $Value){return $false}
  return (@($Value.PSObject.Properties|ForEach-Object {$_.Name}) -contains $Name)
}

function Normalize-ReportRows($Rows,[string]$KeyProperty) {
  $list=New-Object System.Collections.Generic.List[object]
  foreach($row in @($Rows)){
    if($row -is [System.Array]){
      foreach($inner in @($row)){
        if(Has-Property $inner $KeyProperty){$list.Add($inner)|Out-Null}
      }
    } elseif(Has-Property $row $KeyProperty) {
      $list.Add($row)|Out-Null
    }
  }
  return $list.ToArray()
}

function Find-LatestSession([string]$Root) {
  $candidates=New-Object System.Collections.Generic.List[string]
  if($Root -and (Test-Path -LiteralPath $Root -PathType Container)){$candidates.Add((Resolve-Path -LiteralPath $Root).Path)|Out-Null}
  $localResults=Join-Path $PSScriptRoot 'Results'
  if(Test-Path -LiteralPath $localResults -PathType Container){$candidates.Add($localResults)|Out-Null}
  foreach($candidate in $candidates){
    $session=Get-ChildItem -LiteralPath $candidate -Directory -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTime -Descending |
      Where-Object {(Test-Path -LiteralPath (Join-Path $_.FullName 'Summary.json')) -and (Test-Path -LiteralPath (Join-Path $_.FullName 'SourceInventory\Manifest.json'))} |
      Select-Object -First 1
    if($session){return $session.FullName}
  }
  throw 'No saved migration session with Summary.json and SourceInventory\Manifest.json was found. Supply -SessionPath.'
}

function Get-LatestPlanPrefix([string]$Session) {
  $plan=Get-ChildItem -LiteralPath $Session -Filter 'Plan*_Plan.csv' -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
  if(-not $plan){throw ('No Plan##_Plan.csv found in '+$Session)}
  return ($plan.BaseName -replace '_Plan$','')
}

function Validate-SessionEvidence([string]$Session) {
  $summaryPath=Join-Path $Session 'Summary.json'
  $summary=$null
  if(Test-Path -LiteralPath $summaryPath -PathType Leaf){$summary=Get-Content -LiteralPath $summaryPath -Raw -Encoding UTF8 | ConvertFrom-Json}
  if($InventoryPath){$inventory=[IO.Path]::GetFullPath($InventoryPath)}
  elseif($summary -and $summary.InventoryPath){$inventory=[IO.Path]::GetFullPath([string]$summary.InventoryPath)}
  else{$inventory=Join-Path $Session 'SourceInventory'}
  $manifestPath=Join-Path $inventory 'Manifest.json'
  $completion=Join-Path $inventory 'Completion.marker'
  if(-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)){throw 'Manifest.json is required.'}
  if(-not (Test-Path -LiteralPath $completion -PathType Leaf)){throw 'Completion.marker is required.'}
  $manifest=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
  if($manifest.FormatVersion -ne 2 -or $manifest.Mode -ne 'PLAN'){throw 'Unsupported remediation evidence manifest.'}
  if((Get-Content -LiteralPath $completion -Raw -Encoding UTF8).Trim() -ne 'PLAN_COMPLETED_WITH_EXCEPTIONS'){throw 'PLAN completion marker is invalid.'}
  $approvedPlanSession=Split-Path -Parent $inventory
  $planFile=Join-Path $approvedPlanSession 'Plan01_Plan.csv'
  if(-not (Test-Path -LiteralPath $planFile -PathType Leaf)){$planFile=Join-Path $Session 'Plan01_Plan.csv'}
  if((File-SHA256 $planFile) -ne [string]$manifest.ReviewPlanHash){throw 'PLAN comparison report changed since inventory capture.'}
  if($manifest.TemplateEvidenceFile){
    $templateFile=Join-Path $inventory ([string]$manifest.TemplateEvidenceFile)
    if((File-SHA256 $templateFile) -ne [string]$manifest.TemplateEvidenceHash){throw 'CommonTemplate.json changed since inventory capture.'}
  }
  foreach($destination in @($manifest.DestinationDatabases)){
    if($destination.InventoryFile){
      $path=Join-Path $inventory ([string]$destination.InventoryFile)
      if((File-SHA256 $path) -ne [string]$destination.InventoryHash){throw ('Destination inventory changed since capture: '+$destination.Database)}
    }
  }
  return [pscustomobject]@{Inventory=$inventory;Manifest=$manifest}
}

function Get-RootCauseId($Row) {
  $kind=[string]$Row.Kind;$reason=[string]$Row.Reason
  if($Row.Principal){$principal=[string]$Row.Principal}else{$principal=[string]$Row.Name}
  if($reason -match 'Source user SID and target login SID differ|target grantee identity/SID differs|member SID/type') {return 'IDENTITY_CONFLICT::'+$principal.ToUpperInvariant()}
  if($kind -eq 'Schema') {return 'SCHEMA_DEPENDENCY::'+([string]$Row.Name).ToUpperInvariant()}
  if($kind -match 'role membership') {return 'ROLE_MEMBERSHIP_DEPENDENCY::'+([string]$Row.Role).ToUpperInvariant()+'::'+$principal.ToUpperInvariant()}
  if($kind -match 'permission') {return 'PERMISSION_DEPENDENCY::'+$principal.ToUpperInvariant()}
  if($kind -match 'Database owner') {return 'DATABASE_OWNER_REVIEW'}
  return (($kind+'::'+$reason) -replace '[^A-Za-z0-9_:.-]','_').ToUpperInvariant()
}

function Get-RiskClassification($Row) {
  $text=(([string]$Row.Kind)+' '+([string]$Row.Name)+' '+([string]$Row.Role)+' '+([string]$Row.Reason))
  if($text -match '(?i)sysadmin|securityadmin|db_owner|CONTROL|TAKE OWNERSHIP|IMPERSONATE|privileged|grant option'){return 'Privileged'}
  if($text -match '(?i)SID differs|SID/type|identity'){return 'IdentityConflict'}
  if($Row.Kind -eq 'Schema'){return 'SchemaOwnership'}
  if($Row.Kind -match 'role'){return 'RoleOrMembership'}
  if($Row.Kind -match 'permission'){return 'Permission'}
  return 'Standard'
}

function Get-RequiredDependency($Row) {
  if($Row.Principal){$principal=[string]$Row.Principal}else{$principal=[string]$Row.Name}
  switch -Regex ([string]$Row.Kind) {
    'Database user' {return 'Verified target login and matching SID for '+$principal}
    'Schema' {return 'Known owner, existing owner principal, and explicit schema approval'}
    'role membership' {return 'Verified role, verified member, role permission reconciliation, and role approval'}
    'permission' {return 'Verified grantee and securable, plus permission approval'}
    'Server' {return 'Verified server principal identity and separate server-security approval'}
    default {return 'Fresh target metadata verification and explicit approval'}
  }
}

function Get-ProposedCorrection($Row) {
  if($Row.Principal){$principal=[string]$Row.Principal}else{$principal=[string]$Row.Name}
  if(([string]$Row.Reason) -match 'Source user SID and target login SID differ'){return 'Do not overwrite SID. Validate authoritative AD identity and create an approved identity mapping or exclude the principal.'}
  switch -Regex ([string]$Row.Kind) {
    '^Schema$' {return 'Create schema only after owner exists and schema ownership is approved.'}
    'Database user' {return 'Create or remap database user only after independently verified target login identity.'}
    'role membership' {return 'Add role member after role, member, role permissions, and privilege category are verified.'}
    'Database permission' {return 'Grant exact permission after grantee and securable dependencies are verified.'}
    'Server permission|Server role membership' {return 'Handle through separately approved server-security stage.'}
    default {return 'Manual review required before remediation.'}
  }
}

function Get-ApprovalStatus($Row,[string]$Risk) {
  if([string]$Row.Database -in $script:ExplicitlyExcludedDatabases){return 'ExcludedDatabase'}
  if($Risk -eq 'ExternallyManaged'){return 'ExternalProvisioningRequired'}
  if($Risk -eq 'IdentityConflict'){return 'BlockedIdentityConflict'}
  if($Risk -eq 'Privileged'){return 'RequiresSeparatePrivilegedApproval'}
  if(([string]$Row.Status) -eq 'Deferred'){return 'BlockedByDependency'}
  if(([string]$Row.Status) -eq 'Blocked'){return 'RequiresExplicitRemediationApproval'}
  if(([string]$Row.Status) -eq 'Manual review'){return 'ManualReviewRequired'}
  return 'EligibleForRemediationApproval'
}

function Resolve-DirectorySid([string]$Name) {
  if(-not $ValidateDirectoryIdentities -or [string]::IsNullOrWhiteSpace($Name)){return ''}
  try {
    $account=New-Object System.Security.Principal.NTAccount($Name)
    return ([string]$account.Translate([System.Security.Principal.SecurityIdentifier]).Value)
  } catch {return 'UNRESOLVED: '+$_.Exception.Message}
}

function New-NormalizedIssues($Rows,$UserMappings,$Logins,[string]$SourceInstance,[string]$TargetInstance) {
  $userMap=@{}
  foreach($u in @($UserMappings)){$userMap[([string]$u.Database).ToUpperInvariant()+[char]31+([string]$u.SourceUser).ToUpperInvariant()]=$u}
  $loginMap=@{}
  foreach($l in @($Logins)){$loginMap[([string]$l.TargetLogin).ToUpperInvariant()]=$l}
  $issues=New-Object System.Collections.Generic.List[object]
  $index=0
  foreach($row in @($Rows)){
    $index++
    if($row.Principal){$principal=[string]$row.Principal}else{$principal=[string]$row.Name}
    $risk=Get-RiskClassification $row
    $root=Get-RootCauseId $row
    $mapping=$null
    $key=([string]$row.Database).ToUpperInvariant()+[char]31+$principal.ToUpperInvariant()
    if($userMap.ContainsKey($key)){$mapping=$userMap[$key]}
    $login=$null
    if($loginMap.ContainsKey($principal.ToUpperInvariant())){$login=$loginMap[$principal.ToUpperInvariant()]}
    if($mapping){$sourceIdentity=[string]$mapping.SourceSid}elseif($login){$sourceIdentity=[string]$login.SourceSid}else{$sourceIdentity=''}
    if($mapping){$targetIdentity=[string]$mapping.TargetSid}elseif($login){$targetIdentity=[string]$login.TargetSid}else{$targetIdentity=''}
    $approval=Get-ApprovalStatus $row $risk
    $statement=''
    if($approval -eq 'EligibleForRemediationApproval' -and $row.Kind -eq 'Database role membership' -and $row.Role -and $row.Principal){$statement='ALTER ROLE '+(Qi $row.Role)+' ADD MEMBER '+(Qi $row.Principal)+';'}
    elseif($approval -eq 'RequiresExplicitRemediationApproval' -and $row.Kind -eq 'Schema'){$statement='-- CREATE SCHEMA requires owner validation before SQL is emitted.'}
    $issues.Add([pscustomobject]@{
      IssueId=('ISSUE-{0:D6}' -f $index)
      RootCauseId=$root
      SourceInstance=$SourceInstance
      TargetInstance=$TargetInstance
      SourceDatabase=[string]$row.SourceDatabase
      Database=[string]$row.Database
      Principal=$principal
      ObjectType=[string]$row.Kind
      ObjectName=[string]$row.Name
      Role=[string]$row.Role
      SourceIdentity=$sourceIdentity
      TargetIdentity=$targetIdentity
      DirectoryIdentity=(Resolve-DirectorySid $principal)
      RequiredDependency=(Get-RequiredDependency $row)
      ProposedCorrection=(Get-ProposedCorrection $row)
      RiskClassification=$risk
      ApprovalStatus=$approval
      ExecutionStatus='NotExecuted'
      VerificationResult='NotVerified'
      OriginalStatus=[string]$row.Status
      OriginalReason=[string]$row.Reason
      Statement=$statement
      TraceSource='Plan01_Exceptions.csv'
      OriginalRowNumber=$index
    })|Out-Null
  }
  return $issues.ToArray()
}

function New-DependencyGraph($Issues) {
  $edges=New-Object System.Collections.Generic.List[object]
  foreach($issue in @($Issues)){
    $dependsOn=''
    if($issue.ObjectType -match 'permission'){$dependsOn='Verified principal/securable for '+$issue.Principal}
    elseif($issue.ObjectType -match 'role membership'){$dependsOn='Verified role '+$issue.Role+' and member '+$issue.Principal}
    elseif($issue.ObjectType -eq 'Schema'){$dependsOn='Verified schema owner for '+$issue.ObjectName}
    elseif($issue.ObjectType -eq 'Database user'){$dependsOn='Verified target login '+$issue.Principal}
    if($dependsOn){
      $edges.Add([pscustomobject]@{IssueId=$issue.IssueId;RootCauseId=$issue.RootCauseId;DependsOn=$dependsOn;DependencyType='Prerequisite';BlockedWhenMissing=$true})|Out-Null
    }
  }
  return $edges.ToArray()
}

function New-UpdatedDependencyGraph($Issues,$IdentityDecisions) {
  $decisionByAccount=@{}
  foreach($decision in @($IdentityDecisions)){
    if($decision.Account){$decisionByAccount[[string]$decision.Account]=$decision.Decision}
  }
  $rows=New-Object System.Collections.Generic.List[object]
  foreach($issue in @($Issues)){
    $identityDecision='NotAccountSpecific'
    if($issue.Principal -and $decisionByAccount.ContainsKey([string]$issue.Principal)){$identityDecision=[string]$decisionByAccount[[string]$issue.Principal]}
    if($issue.ApprovalStatus -eq 'ExternalProvisioningRequired'){$prerequisite='ExternalProvisioning'}
    elseif($issue.ApprovalStatus -eq 'BlockedIdentityConflict'){$prerequisite='IdentityDecision'}
    elseif($issue.RiskClassification -eq 'Privileged'){$prerequisite='PrivilegedApproval'}
    elseif($issue.ObjectType -eq 'Schema'){$prerequisite='SchemaOwnerApproval'}
    elseif($issue.OriginalStatus -eq 'Deferred'){$prerequisite='ParentIssue'}
    else{$prerequisite='ExplicitApproval'}
    $mayBecomeEligible=($issue.ApprovalStatus -in @('BlockedByDependency','RequiresExplicitRemediationApproval','ManualReviewRequired') -and $identityDecision -notmatch 'Conflict|VerificationRequired')
    $rows.Add([pscustomobject]@{
      IssueId=$issue.IssueId
      RootCauseId=$issue.RootCauseId
      Principal=$issue.Principal
      Database=$issue.Database
      ObjectType=$issue.ObjectType
      OriginalStatus=$issue.OriginalStatus
      CurrentDecision=$issue.ApprovalStatus
      IdentityDecision=$identityDecision
      RequiredPrerequisite=$prerequisite
      DependencyDescription=$issue.RequiredDependency
      MayBecomeEligibleAfterPrerequisite=[bool]$mayBecomeEligible
      VerificationRequiredBeforeResolved='Fresh target metadata comparison by Invoke-SqlSecurityMigration.ps1 PLAN'
    })|Out-Null
  }
  return $rows.ToArray()
}

function New-IdentityInventory($Issues,$Logins,$UserMappings) {
  $loginByName=@{}
  foreach($login in @($Logins)){
    if($login.SourceLogin){$loginByName[[string]$login.SourceLogin]=$login}
    if($login.TargetLogin -and -not $loginByName.ContainsKey([string]$login.TargetLogin)){$loginByName[[string]$login.TargetLogin]=$login}
  }
  $usersByPrincipal=@{}
  foreach($mapping in @($UserMappings)){
    $name=[string]$mapping.SourceUser
    if(-not $usersByPrincipal.ContainsKey($name)){$usersByPrincipal[$name]=New-Object System.Collections.Generic.List[object]}
    $usersByPrincipal[$name].Add($mapping)|Out-Null
  }
  $principals=@($Issues|Where-Object {$_.Principal}|ForEach-Object {[string]$_.Principal}|Sort-Object -Unique)
  $rows=New-Object System.Collections.Generic.List[object]
  foreach($principal in $principals){
    $login=$null
    if($loginByName.ContainsKey($principal)){$login=$loginByName[$principal]}
    $dependent=@($Issues|Where-Object {$_.Principal -eq $principal})
    $userRows=@()
    if($usersByPrincipal.ContainsKey($principal)){$userRows=@($usersByPrincipal[$principal].ToArray())}
    $sourceSid='';$targetSid='';$sourceLogin='';$targetLogin='';$principalType=''
    if($login){
      $sourceSid=[string]$login.SourceSid;$targetSid=[string]$login.TargetSid
      $sourceLogin=[string]$login.SourceLogin;$targetLogin=[string]$login.TargetLogin;$principalType=[string]$login.Type
    } elseif($userRows.Count) {
      $sourceSid=[string]$userRows[0].SourceSid;$targetSid=[string]$userRows[0].TargetSid
      $sourceLogin=[string]$userRows[0].SourceLogin;$targetLogin=[string]$userRows[0].TargetLogin
      $principalType='DatabaseUser'
    }
    $directorySid=Resolve-DirectorySid $principal
    if(-not $ValidateDirectoryIdentities){$directoryStatus='NotQueried'}
    elseif($directorySid -like 'UNRESOLVED:*'){$directoryStatus='Unavailable'}
    elseif($directorySid){$directoryStatus='Resolved'}
    else{$directoryStatus='NotApplicable'}
    if($directoryStatus -eq 'Resolved'){$accountStatus='Exists'}elseif($directoryStatus -eq 'Unavailable'){$accountStatus='Unknown'}else{$accountStatus='NotVerified'}
    $rows.Add([pscustomobject]@{
      Account=$principal
      PrincipalType=$principalType
      SourceLoginName=$sourceLogin
      SourceSid=$sourceSid
      TargetLoginName=$targetLogin
      TargetSid=$targetSid
      DirectoryObjectSid=$directorySid
      DirectoryLookupStatus=$directoryStatus
      AccountExistenceStatus=$accountStatus
      DependentExceptionCount=$dependent.Count
      DependentIssueIds=(@($dependent|Select-Object -ExpandProperty IssueId) -join ';')
      AffectedDatabases=(@($dependent|Where-Object {$_.Database}|Select-Object -ExpandProperty Database -Unique) -join ';')
    })|Out-Null
  }
  return $rows.ToArray()
}

function New-IdentityMappingDecisions($IdentityInventory,$Issues) {
  $rows=New-Object System.Collections.Generic.List[object]
  foreach($identity in @($IdentityInventory)){
    $related=@($Issues|Where-Object {$_.Principal -eq $identity.Account})
    $hasExternalOwner=@($related|Where-Object {$_.ApprovalStatus -eq 'ExternalProvisioningRequired'}).Count -gt 0
    $hasConflict=@($related|Where-Object {$_.ApprovalStatus -eq 'BlockedIdentityConflict' -or $_.OriginalReason -match 'SID.*differ|SID/type|SID conflict'}).Count -gt 0
    $decision='NoSqlMappingDecisionRequired'
    $rationale='No identity discrepancy requiring SQL remediation was identified from current exception evidence.'
    if($hasExternalOwner){$decision='RequiresExternalProvisioning';$rationale='Security is externally managed; obtain an operator-supplied ownership decision or supported provisioning evidence.'}
    elseif($hasConflict){$decision='BlockedNoOverwrite';$rationale='Source and destination SIDs or security metadata conflict; do not infer by name and do not overwrite.'}
    elseif($identity.DirectoryLookupStatus -ne 'Resolved' -and ($identity.Account -match '\\|\$$')){$decision='DirectoryVerificationRequired';$rationale='Directory identity could not be authoritatively verified in this run.'}
    elseif($identity.SourceSid -and $identity.TargetSid -and $identity.SourceSid -eq $identity.TargetSid){$decision='VerifiedSameSid';$rationale='Source SQL SID and destination SQL SID match; dependent issue is not caused by login SID mismatch.'}
    elseif($identity.SourceSid -and -not $identity.TargetSid){$decision='TargetPrincipalMissingOrUnmapped';$rationale='Target SQL SID missing from current evidence; provisioning or mapping is prerequisite.'}
    $rows.Add([pscustomobject]@{
      Account=$identity.Account
      Decision=$decision
      Evidence=('SourceSid={0}; TargetSid={1}; DirectorySid={2}; DirectoryLookup={3}' -f $identity.SourceSid,$identity.TargetSid,$identity.DirectoryObjectSid,$identity.DirectoryLookupStatus)
      ApprovedMapping=''
      RequiredAction=$rationale
      DependentExceptionCount=$identity.DependentExceptionCount
      DependentIssueIds=$identity.DependentIssueIds
    })|Out-Null
  }
  return $rows.ToArray()
}

function New-ExternalOwnershipWorklist($Issues,$IdentityDecisions) {
  $decisionByAccount=@{}
  foreach($decision in @($IdentityDecisions)){if($decision.Account){$decisionByAccount[[string]$decision.Account]=$decision.Decision}}
  $rows=@($Issues|Where-Object {$_.ApprovalStatus -eq 'ExternalProvisioningRequired'}|Group-Object RootCauseId|ForEach-Object {
    $first=$_.Group[0]
    $principal=[string]$first.Principal
    if($decisionByAccount.ContainsKey($principal)){$identityDecision=$decisionByAccount[$principal]}else{$identityDecision='RequiresExternalProvisioning'}
    [pscustomobject]@{
      WorkItemId=('EXTWORK-{0:D4}' -f ($script:ExternalWorkItemIndex++))
      RootCauseId=$_.Name
      PrincipalOrRole=$principal
      Category=$first.ObjectType
      RequiredExternalOwnershipDecision='Confirm the external owner, evidence, scope, and approved provisioning action if required.'
      SqlActionAllowed='No'
      DependentExceptionCount=$_.Count
      AffectedDatabases=(@($_.Group|Where-Object {$_.Database}|Select-Object -ExpandProperty Database -Unique) -join ';')
      DependentIssueIds=(@($_.Group|Select-Object -ExpandProperty IssueId) -join ';')
      IdentityDecision=$identityDecision
    }
  })
  return $rows
}

function New-ApprovedCandidateSql($Issues,$IdentityDecisions) {
  $decisionByAccount=@{}
  foreach($decision in @($IdentityDecisions)){if($decision.Account){$decisionByAccount[[string]$decision.Account]=$decision.Decision}}
  $rows=New-Object System.Collections.Generic.List[object]
  foreach($issue in @($Issues|Where-Object {$_.ApprovalStatus -eq 'EligibleForRemediationApproval' -and $_.Statement})){
    if($decisionByAccount.ContainsKey([string]$issue.Principal)){$identityDecision=$decisionByAccount[[string]$issue.Principal]}else{$identityDecision='NotAccountSpecific'}
    if($identityDecision -match 'Conflict|VerificationRequired|External'){continue}
    $rows.Add([pscustomobject]@{
      IssueId=$issue.IssueId
      Database=$issue.Database
      TargetPrincipalOrObject=$issue.Principal
      ObjectType=$issue.ObjectType
      VerifiedPrerequisite=$issue.RequiredDependency
      IntendedOwnership='Preserve source ownership only where owner is verified and approved.'
      IdempotentSql=$issue.Statement
      RequiredApproval='Explicit remediation approval manifest entry plus toolkit stage approval'
      VerificationQuery='Invoke-SqlSecurityMigration.ps1 PLAN must report this issue as Already correct or absent from Plan##_Exceptions.csv.'
      ExpectedResult='Fresh target metadata verifies the original exception is resolved.'
      FailureInstructions='Stop this operation, preserve failure output, skip dependents, rerun PLAN, and do not retry more than the approved retry count.'
      RecoveryInstructions='No destructive rollback is generated; use targeted DBA review for the failed independent operation.'
    })|Out-Null
  }
  return $rows.ToArray()
}

function Write-ApprovalManifest {
  param(
    $Context,
    [string]$Output,
    [object[]]$RootSummary,
    [object[]]$IdentityDecisions,
    [object[]]$CandidateSql,
    [object[]]$ExternalOwnershipWorklist,
    [object[]]$UpdatedGraph,
    [int]$InitialPlanExceptionCount,
    [int]$FinalApplyExceptionCount,
    [int]$ExternalProvisioningExceptionCount,
    [int]$ExternalWorkItemCount,
    [int]$CandidateSqlCount
  )
  $identityConfirmationCount=($IdentityDecisions|Where-Object {$_.Decision -in @('DirectoryVerificationRequired','BlockedNoOverwrite','TargetPrincipalMissingOrUnmapped')}|Measure-Object).Count
  $dependentPotentialCount=($UpdatedGraph|Where-Object {$_.MayBecomeEligibleAfterPrerequisite -eq $true}|Measure-Object).Count
  $manifest=[ordered]@{
    ManifestType='SqlSecurityRemediationApprovalManifest'
    Version=1
    CreatedUtc=[DateTime]::UtcNow.ToString('o')
    SourceInstance=[string]$Context.Manifest.SourceInstance
    TargetInstance=[string]$Context.Manifest.TargetInstance
    EvidenceSession=$Context.Session
    ApprovedInventory=$Context.Inventory
    InitialPlanExceptions=$InitialPlanExceptionCount
    FinalApplyPreviewExceptions=$FinalApplyExceptionCount
    ReconciliationDelta=($FinalApplyExceptionCount-$InitialPlanExceptionCount)
    DistinctRootCauseDecisions=@($RootSummary).Count
    IndependentlyEligibleSqlOperations=$CandidateSqlCount
    ExternalProvisioningExceptions=$ExternalProvisioningExceptionCount
    ExternalProvisioningWorkItems=$ExternalWorkItemCount
    IdentityConfirmationItems=$identityConfirmationCount
    DependentIssuesPotentiallyEligible=$dependentPotentialCount
    ApprovedOperations=@()
    ApprovalRequired='Explicit approval is required before any remediation APPLY. This manifest currently approves zero SQL operations.'
    Safety='Do not execute generated SQL directly; use reviewed toolkit workflow and fresh PLAN verification.'
  }
  Write-AtomicText (Join-Path $Output 'RemediationApprovalManifest.json') ($manifest|ConvertTo-Json -Depth 8)
  return [pscustomobject]$manifest
}

function Write-RemediationReports($Context,$Issues,$PlanRows,$RootRows,$RoleCoverage,$Output) {
  [void][IO.Directory]::CreateDirectory($Output)
  $issueCols='IssueId','RootCauseId','SourceInstance','TargetInstance','SourceDatabase','Database','Principal','ObjectType','ObjectName','Role','SourceIdentity','TargetIdentity','DirectoryIdentity','RequiredDependency','ProposedCorrection','RiskClassification','ApprovalStatus','ExecutionStatus','VerificationResult','OriginalStatus','OriginalReason','Statement','TraceSource','OriginalRowNumber'
  Export-CsvStable $Issues (Join-Path $Output 'RemediationPlan.csv') $issueCols
  $summary=@($Issues|Group-Object RootCauseId|ForEach-Object {
    $first=$_.Group[0]
    [pscustomobject]@{RootCauseId=$_.Name;Count=$_.Count;RiskClassification=$first.RiskClassification;ApprovalStatus=$first.ApprovalStatus;ExampleDatabase=$first.Database;ExamplePrincipal=$first.Principal;ProposedCorrection=$first.ProposedCorrection}
  }|Sort-Object Count -Descending)
  Export-CsvStable $summary (Join-Path $Output 'RootCauseSummary.csv') ('RootCauseId','Count','RiskClassification','ApprovalStatus','ExampleDatabase','ExamplePrincipal','ProposedCorrection')
  Export-CsvStable (@($Issues|Where-Object {$_.RiskClassification -eq 'IdentityConflict' -or $_.ApprovalStatus -eq 'BlockedIdentityConflict'})) (Join-Path $Output 'IdentityConflicts.csv') $issueCols
  Export-CsvStable (@($Issues|Where-Object {$_.ObjectType -eq 'Schema' -or $_.RiskClassification -eq 'SchemaOwnership'})) (Join-Path $Output 'SchemaRemediation.csv') $issueCols
  Export-CsvStable (@($Issues|Where-Object {$_.ApprovalStatus -eq 'ExternalProvisioningRequired'})) (Join-Path $Output 'ExternalOwnershipWorklist.csv') $issueCols
  Export-CsvStable (New-DependencyGraph $Issues) (Join-Path $Output 'DependencyGraph.csv') ('IssueId','RootCauseId','DependsOn','DependencyType','BlockedWhenMissing')
  Export-CsvStable @() (Join-Path $Output 'RemediationExecution.csv') ('Time','IssueId','Database','StatementHash','Status','Detail','VerificationResult')
  Export-CsvStable @() (Join-Path $Output 'RemediationFailures.csv') ('Time','IssueId','FailureSignature','RetryCount','BlockedDependents','Detail')
  [object[]]$identityInventory=@(New-IdentityInventory $Issues $script:CurrentLogins $script:CurrentUserMappings)
  [object[]]$identityDecisions=@(New-IdentityMappingDecisions $identityInventory $Issues)
  $script:ExternalWorkItemIndex=1
  [object[]]$externalOwnershipWorklist=@(New-ExternalOwnershipWorklist $Issues $identityDecisions)
  [object[]]$candidateSql=@(New-ApprovedCandidateSql $Issues $identityDecisions)
  [object[]]$updatedGraph=@(New-UpdatedDependencyGraph $Issues $identityDecisions)
  Export-CsvStable $identityInventory (Join-Path $Output 'VerifiedIdentityInventory.csv') ('Account','PrincipalType','SourceLoginName','SourceSid','TargetLoginName','TargetSid','DirectoryObjectSid','DirectoryLookupStatus','AccountExistenceStatus','DependentExceptionCount','DependentIssueIds','AffectedDatabases')
  Export-CsvStable $identityDecisions (Join-Path $Output 'IdentityMappingDecisions.csv') ('Account','Decision','Evidence','ApprovedMapping','RequiredAction','DependentExceptionCount','DependentIssueIds')
  Export-CsvStable $externalOwnershipWorklist (Join-Path $Output 'ExternalOwnershipWorklist.csv') ('WorkItemId','RootCauseId','PrincipalOrRole','Category','RequiredExternalOwnershipDecision','SqlActionAllowed','DependentExceptionCount','AffectedDatabases','DependentIssueIds','IdentityDecision')
  Export-CsvStable $candidateSql (Join-Path $Output 'ApprovedCandidateSQL.csv') ('IssueId','Database','TargetPrincipalOrObject','ObjectType','VerifiedPrerequisite','IntendedOwnership','IdempotentSql','RequiredApproval','VerificationQuery','ExpectedResult','FailureInstructions','RecoveryInstructions')
  Export-CsvStable $updatedGraph (Join-Path $Output 'UpdatedDependencyGraph.csv') ('IssueId','RootCauseId','Principal','Database','ObjectType','OriginalStatus','CurrentDecision','IdentityDecision','RequiredPrerequisite','DependencyDescription','MayBecomeEligibleAfterPrerequisite','VerificationRequiredBeforeResolved')
  $externalWorkItemCount=@(Import-Csv -LiteralPath (Join-Path $Output 'ExternalOwnershipWorklist.csv')).Count
  $candidateSqlCount=@(Import-Csv -LiteralPath (Join-Path $Output 'ApprovedCandidateSQL.csv')).Count
  $counts=$PlanRows|Group-Object Status -AsHashTable -AsString
  $originalBlocked=if($counts.ContainsKey('Blocked')){@($counts['Blocked']).Count}else{0}
  $originalDeferred=if($counts.ContainsKey('Deferred')){@($counts['Deferred']).Count}else{0}
  $originalManualReview=if($counts.ContainsKey('Manual review')){@($counts['Manual review']).Count}else{0}
  $originalTargetOnly=if($counts.ContainsKey('Target only')){@($counts['Target only']).Count}else{0}
  $automaticEligible=@($Issues|Where-Object {$_.ApprovalStatus -eq 'EligibleForRemediationApproval'}).Count
  $requiresApproval=@($Issues|Where-Object {$_.ApprovalStatus -match 'Approval|ManualReview|Dependency|IdentityConflict|Privileged'}).Count
  $externalProvisioning=@($Issues|Where-Object {$_.ApprovalStatus -eq 'ExternalProvisioningRequired'}).Count
  $unsupported=@($Issues|Where-Object {$_.ApprovalStatus -eq 'ExcludedDatabase'}).Count
  $reconciliation=[pscustomobject]@{
    Source=[string]$Context.Manifest.SourceInstance;Target=[string]$Context.Manifest.TargetInstance;
    SessionPath=$Context.Session;OutputDirectory=$Output;
    OriginalBlocked=$originalBlocked;
    OriginalDeferred=$originalDeferred;
    OriginalManualReview=$originalManualReview;
    OriginalTargetOnly=$originalTargetOnly;
    RemainingVerifiedExceptions=@($Issues).Count;
    VerifiedResolved=0;
    AutomaticEligible=$automaticEligible;
    RequiresApproval=$requiresApproval;
    ExternalProvisioning=$externalProvisioning;
    Unsupported=$unsupported
  }
  Export-CsvStable @($reconciliation) (Join-Path $Output 'FinalReconciliation.csv') ('Source','Target','SessionPath','OutputDirectory','OriginalBlocked','OriginalDeferred','OriginalManualReview','OriginalTargetOnly','RemainingVerifiedExceptions','VerifiedResolved','AutomaticEligible','RequiresApproval','ExternalProvisioning','Unsupported')
  $initialPlanExceptions=0
  $approvedPlanSession=Split-Path -Parent $Context.Inventory
  $initialPlanPath=Join-Path $approvedPlanSession 'Plan01_Exceptions.csv'
  if(Test-Path -LiteralPath $initialPlanPath -PathType Leaf){$initialPlanExceptions=@(Import-Csv -LiteralPath $initialPlanPath).Count}
  $rootDecisionCount=@($summary).Count
  $externalProvisioningExceptionCount=[int]@($reconciliation.ExternalProvisioning)[0]
  $identityConfirmationCount=($identityDecisions|Where-Object {$_.Decision -in @('DirectoryVerificationRequired','BlockedNoOverwrite','TargetPrincipalMissingOrUnmapped')}|Measure-Object).Count
  $dependentPotentialCount=($updatedGraph|Where-Object {$_.MayBecomeEligibleAfterPrerequisite -eq $true}|Measure-Object).Count
  [void](Write-ApprovalManifest -Context $Context -Output $Output -RootSummary $summary -IdentityDecisions $identityDecisions -CandidateSql $candidateSql -ExternalOwnershipWorklist $externalOwnershipWorklist -UpdatedGraph $updatedGraph -InitialPlanExceptionCount $initialPlanExceptions -FinalApplyExceptionCount @($Issues).Count -ExternalProvisioningExceptionCount $externalProvisioningExceptionCount -ExternalWorkItemCount $externalWorkItemCount -CandidateSqlCount $candidateSqlCount)
  $topRoots=@($summary|Select-Object -First 15)
  $lines=New-Object System.Collections.Generic.List[string]
  $lines.Add('# SQL Security Remediation Summary')
  $lines.Add('')
  $lines.Add(('- Evidence session: `{0}`' -f $Context.Session))
  $lines.Add(('- Source/target: `{0}` -> `{1}`' -f $Context.Manifest.SourceInstance,$Context.Manifest.TargetInstance))
  $lines.Add(('- Inventory: `{0}`' -f $Context.Inventory))
  $lines.Add(('- Original exceptions normalized: {0}' -f @($Issues).Count))
  $lines.Add(('- Initial PLAN exceptions reconciled: {0}' -f $initialPlanExceptions))
  $lines.Add(('- Final APPLY-preview exception delta: {0}' -f (@($Issues).Count-$initialPlanExceptions)))
  $lines.Add(('- Distinct root-cause decision categories: {0}' -f $rootDecisionCount))
  $lines.Add(('- Target-only records preserved: {0}' -f $reconciliation.OriginalTargetOnly))
  $lines.Add(('- Automatically eligible operations now: {0}' -f $reconciliation.AutomaticEligible))
  $lines.Add(('- Operations requiring explicit approval or dependency clearance: {0}' -f $reconciliation.RequiresApproval))
  $lines.Add(('- External ownership worklist items: {0}' -f $reconciliation.ExternalProvisioning))
  $lines.Add('')
  $lines.Add('## First Remediation Stage')
  $lines.Add('No SQL security modification is authorized by this PLAN. The first stage is evidence closure: resolve identity conflicts, obtain explicit external-ownership decisions, and approve only the resulting independent operations in a remediation approval manifest.')
  $lines.Add('')
  $lines.Add('## Top Root Causes')
  foreach($root in $topRoots){$lines.Add(('- {0}: {1} item(s), {2}, {3}' -f $root.RootCauseId,$root.Count,$root.RiskClassification,$root.ApprovalStatus))}
  $lines.Add('')
  $lines.Add('## Safety Notes')
  $lines.Add('- PLAN and VERIFY are read-only.')
  $lines.Add('- APPLY requires `-AuthorizeRemediationApply`, an approval manifest, and the exact target authorization token.')
  $lines.Add('- Conflicting SIDs are never overwritten automatically.')
  $lines.Add('- Externally managed identities and roles are routed to `ExternalOwnershipWorklist.csv`, not generic SQL remediation.')
  $lines.Add('- Exceptions are not counted as resolved until fresh target metadata verifies the result after remediation.')
  Write-AtomicText (Join-Path $Output 'REMEDIATION_SUMMARY.md') ($lines -join [Environment]::NewLine)
  $preview=New-Object System.Collections.Generic.List[string]
  $preview.Add('# SQL Security Remediation Execution Preview')
  $preview.Add('')
  $preview.Add(('Evidence session: `{0}`' -f $Context.Session))
  $preview.Add(('Approved inventory: `{0}`' -f $Context.Inventory))
  $preview.Add('')
  $preview.Add('## Counts')
  $preview.Add(('- Distinct root-cause decisions: {0}' -f $rootDecisionCount))
  $preview.Add(('- Independently eligible SQL operations: {0}' -f $candidateSqlCount))
  $preview.Add(('- Requiring external ownership decisions: {0} exception(s), consolidated into {1} work item(s)' -f $externalProvisioningExceptionCount,$externalWorkItemCount))
  $preview.Add(('- Requiring identity confirmation: {0}' -f $identityConfirmationCount))
  $preview.Add(('- Expected dependent exceptions that may become eligible: {0}' -f $dependentPotentialCount))
  $preview.Add(('- Unsupported or excluded operations: {0}' -f $reconciliation.Unsupported))
  $preview.Add(('- Initial PLAN exceptions: {0}; final APPLY-preview exceptions: {1}; delta: {2}' -f $initialPlanExceptions,@($Issues).Count,(@($Issues).Count-$initialPlanExceptions)))
  $preview.Add('')
  $preview.Add('## First Remediation Stage')
  if(@($candidateSql).Count){$preview.Add('Review and explicitly approve the rows in `ApprovedCandidateSQL.csv`; no row is approved by default.')}else{$preview.Add('No SQL remediation operation is independently eligible. First stage is identity and external-ownership evidence closure only.')}
  $preview.Add('')
  $preview.Add('## Required External Decisions')
  $preview.Add('- External owner: process `ExternalOwnershipWorklist.csv` using the approved product or infrastructure workflow.')
  $preview.Add('- Identity owner: process `IdentityMappingDecisions.csv`; do not approve mappings from matching names alone.')
  $preview.Add('- DBA approver: only after fresh PLAN recalculation, populate `RemediationApprovalManifest.json` with explicit approved operations.')
  $preview.Add('')
  $preview.Add('## Safety')
  $preview.Add('- No SQL has been executed by this remediation preview.')
  $preview.Add('- Do not execute review SQL files directly.')
  $preview.Add('- Do not mark issues resolved until fresh target metadata verifies the correction.')
  Write-AtomicText (Join-Path $Output 'REMEDIATION_EXECUTION_PREVIEW.md') ($preview -join [Environment]::NewLine)
  return $reconciliation
}

function Invoke-ReadOnlyPlan {
  if($SessionPath){$session=[IO.Path]::GetFullPath($SessionPath)}else{$session=Find-LatestSession ''}
  $evidence=Validate-SessionEvidence $session
  $prefix=Get-LatestPlanPrefix $session
  $summary=Get-Content -LiteralPath (Join-Path $session 'Summary.json') -Raw -Encoding UTF8 | ConvertFrom-Json
  $planRows=Import-CsvSafe (Join-Path $session ($prefix+'_Plan.csv'))
  $exceptions=Import-CsvSafe (Join-Path $session ($prefix+'_Exceptions.csv'))
  $userMappings=Import-CsvSafe (Join-Path $session ($prefix+'_UserMappings.csv'))
  $roleCoverage=Import-CsvSafe (Join-Path $session ($prefix+'_RoleCoverage.csv'))
  $rootRows=Import-CsvSafe (Join-Path $session ($prefix+'_RootCauses.csv'))
  $logins=Import-CsvSafe (Join-Path $session ($prefix+'_Logins.csv'))
  $script:CurrentLogins=$logins
  $script:CurrentUserMappings=$userMappings
  $commonTemplate=Join-Path $evidence.Inventory 'CommonTemplate.json'
  if(-not (Test-Path -LiteralPath $commonTemplate -PathType Leaf)){throw 'CommonTemplate.json is required.'}
  $filteredTemplate=Join-Path $evidence.Inventory 'FilteredCommonTemplate.json'
  if(Test-Path -LiteralPath $filteredTemplate -PathType Leaf){$filteredTemplateStatus='Loaded'}else{$filteredTemplateStatus='NotPresentInCurrentSession'}
  if($OutputDirectory){$out=[IO.Path]::GetFullPath($OutputDirectory)}else{$out=Join-Path $session ('Remediation_'+(Get-Date -Format 'yyyyMMdd_HHmmss_fff'))}
  $context=[pscustomobject]@{Session=$session;Inventory=$evidence.Inventory;Manifest=$evidence.Manifest;Summary=$summary;FilteredCommonTemplate=$filteredTemplateStatus}
  $issues=New-NormalizedIssues $exceptions $userMappings $logins ([string]$evidence.Manifest.SourceInstance) ([string]$evidence.Manifest.TargetInstance)
  $reconciliation=Write-RemediationReports $context $issues $planRows $rootRows $roleCoverage $out
  [pscustomobject]@{Mode='Plan';Session=$session;OutputDirectory=$out;Issues=@($issues).Count;AutomaticEligible=$reconciliation.AutomaticEligible;RequiresApproval=$reconciliation.RequiresApproval;ExternalProvisioning=[int]@($reconciliation.ExternalProvisioning)[0];TargetOnly=$reconciliation.OriginalTargetOnly;FilteredCommonTemplate=$filteredTemplateStatus}
}

function Invoke-VerifyOnly {
  $plan=Invoke-ReadOnlyPlan
  $summaryPath=Join-Path $plan.OutputDirectory 'REMEDIATION_SUMMARY.md'
  if(-not (Test-Path -LiteralPath $summaryPath -PathType Leaf)){throw 'VERIFY failed: remediation summary was not produced.'}
  $plan | Add-Member -NotePropertyName Verification -NotePropertyValue 'Read-only evidence and report generation verified.' -Force
  return $plan
}

function Invoke-ApplyApprovedRemediation {
  if(-not $AuthorizeRemediationApply){throw 'Remediation APPLY requires -AuthorizeRemediationApply. No SQL changes made.'}
  if(-not $ApprovalManifest){throw 'Remediation APPLY requires -ApprovalManifest.'}
  if($SessionPath){$session=[IO.Path]::GetFullPath($SessionPath)}else{$session=Find-LatestSession ''}
  $evidence=Validate-SessionEvidence $session
  if($AuthorizationToken -cne [string]$evidence.Manifest.CanonicalTarget){throw 'Authorization token must exactly match the approved target canonical instance. No SQL changes made.'}
  $approved=@(Import-Csv -LiteralPath $ApprovalManifest | Where-Object {$_.ApprovalStatus -eq 'Approved' -and $_.Statement -and $_.ExecutionStatus -eq 'NotExecuted'})
  if(-not $approved.Count){throw 'Approval manifest contains no approved, independent SQL operations. No SQL changes made.'}
  throw 'Live remediation APPLY is intentionally fail-closed in this implementation pass. Use the generated approval manifest for review; execution requires a disposable lab validation path before production.'
}

switch($Mode){
  'Plan' {Invoke-ReadOnlyPlan | ConvertTo-Json -Depth 5; break}
  'Verify' {Invoke-VerifyOnly | ConvertTo-Json -Depth 5; break}
  'Apply' {Invoke-ApplyApprovedRemediation | ConvertTo-Json -Depth 5; break}
}
