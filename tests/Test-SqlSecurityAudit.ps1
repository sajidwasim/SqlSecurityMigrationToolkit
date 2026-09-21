#requires -Version 5.1
# Offline smoke: no SQL connection and no writes outside the temporary test directory.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
foreach($path in @('Invoke-SqlSecurityAudit.ps1','Compare-SqlSecurityAudit.ps1',
    'modules\SecurityAudit.psm1','modules\AuditExcel.psm1')){
    $errors=$null;$tokens=$null
    [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root $path),[ref]$tokens,[ref]$errors)
    if($errors.Count -gt 0){throw "PowerShell parser errors in $path : $($errors -join '; ')"}
}
Import-Module (Join-Path $root 'modules\AuditExcel.psm1') -Force
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('SqlAuditOffline_'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporary)
try {
    $path=Join-Path $temporary 'Synthetic.xlsx'
    $sheets=[ordered]@{Evidence=@([pscustomobject]@{Instance='EXAMPLE';Value='=HYPERLINK("https://example.invalid","test")';Status='SYNTHETIC'})}
    Export-AuditWorkbook -Sheets $sheets -Path $path
    if(-not (Test-Path -LiteralPath $path)){throw 'Synthetic workbook not created.'}
    $zip=[IO.Compression.ZipFile]::OpenRead($path)
    try {
        $sheet=$zip.GetEntry('xl/worksheets/sheet1.xml')
        if($null -eq $sheet){throw ('XLSX worksheet missing. Actual ZIP entries: '+(($zip.Entries|ForEach-Object {$_.FullName}) -join ', '))}
        $reader=[IO.StreamReader]::new($sheet.Open())
        try{$xml=$reader.ReadToEnd()}finally{$reader.Dispose()}
        if($xml -notmatch 't="inlineStr"' -or $xml -match '<f>'){throw 'Excel formula prevention failed.'}
        [xml]$parsed=$xml
        if($null -eq $parsed.DocumentElement){throw 'Worksheet XML malformed.'}
    }finally{$zip.Dispose()}
    $empty=[ordered]@{}
    foreach($name in @('RunInfo','Databases','ServerLogins','ServerRoles','ServerPermissions','DatabaseUsers',
      'DatabaseRoles','DatabasePermissions','Schemas','Objects','Findings','Errors')){$empty[$name]=@()}
    $sourceSheets=[ordered]@{};$targetSheets=[ordered]@{}
    foreach($name in $empty.Keys){$sourceSheets[$name]=@($empty[$name]);$targetSheets[$name]=@($empty[$name])}
    $sourceSheets['RunInfo']=@([pscustomobject]@{Instance='SOURCE';Database='ExampleDb';Item='DatabaseScan';Value='COMPLETED'})
    $targetSheets['RunInfo']=@([pscustomobject]@{Instance='TARGET';Database='ExampleDb';Item='DatabaseScan';Value='COMPLETED'})
    $sourceSheets['DatabaseRoles']=@([pscustomobject]@{Instance='SOURCE';Database='ExampleDb';RoleName='example_role';MemberName='example_user'})
    $targetSheets['DatabaseRoles']=@()
    $src=Join-Path $temporary 'source.json';$dst=Join-Path $temporary 'target.json'
    [IO.File]::WriteAllText($src,([ordered]@{SchemaVersion=1;ReadOnly=$true;Complete=$true;Sheets=$sourceSheets}|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($dst,([ordered]@{SchemaVersion=1;ReadOnly=$true;Complete=$true;Sheets=$targetSheets}|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
    $exe=Join-Path $PSHOME 'powershell.exe'
    & $exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'Compare-SqlSecurityAudit.ps1') -SourceInventoryPath $src -TargetInventoryPath $dst -SourceInstance 'SOURCE' -TargetInstance 'TARGET' | Out-Null
    if($LASTEXITCODE -ne 0){throw "Synthetic comparison failed with exit code $LASTEXITCODE"}
    $comparison=@(Get-ChildItem -LiteralPath $temporary -Filter 'SqlSecurityComparison_*.xlsx')
    if($comparison.Count -ne 1){throw 'Expected exactly one comparison workbook.'}
    $zip=[IO.Compression.ZipFile]::OpenRead($comparison[0].FullName)
    try {
        $sheet=$zip.GetEntry('xl/worksheets/sheet2.xml')
        if($null -eq $sheet){throw ('Differences worksheet missing. Actual ZIP entries: '+(($zip.Entries|ForEach-Object {$_.FullName}) -join ', '))}
        $reader=[IO.StreamReader]::new($sheet.Open())
        try{$diffXml=$reader.ReadToEnd()}finally{$reader.Dispose()}
        if($diffXml -notmatch 'SOURCE_RECORD_COUNT_DIFFERS'){throw 'Expected synthetic missing role membership not detected.'}
    }finally{$zip.Dispose()}
    Write-Host 'PASS: PowerShell parsing, OpenXML XLSX, text-only cells and synthetic security comparison.'
}finally{Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue}
