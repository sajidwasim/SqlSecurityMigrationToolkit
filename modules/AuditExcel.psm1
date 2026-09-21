#requires -Version 5.1
# Native OpenXML XLSX writer: every value is an inline string, never an Excel formula.
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function ConvertTo-AuditXml([object]$Value) {
    $text=if($null -eq $Value){''}else{[string]$Value}
    if($text.Length -gt 32767){$text=$text.Substring(0,32740)+' [TRUNCATED]'}
    $text=[regex]::Replace($text,'[\x00-\x08\x0B\x0C\x0E-\x1F]',' ')
    return [Security.SecurityElement]::Escape($text)
}
function Get-AuditColumn([int]$Index) {
    $text=''
    while($Index -gt 0){$Index--; $text=([string][char](65+($Index % 26)))+$text; $Index=[int][math]::Floor($Index/26)}
    return $text
}
function Write-AuditText([string]$Path,[string]$Text) {
    [IO.File]::WriteAllText($Path,$Text,[Text.UTF8Encoding]::new($false))
}
function Export-AuditWorkbook {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Sheets,
          [Parameter(Mandatory)][string]$Path)
    if($Sheets.Count -lt 1){throw 'At least one worksheet is required.'}
    if(Test-Path -LiteralPath $Path){throw 'Refusing to overwrite an existing evidence workbook.'}
    $root=Join-Path (Split-Path -Parent $Path) ('xlsx_build_'+[guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory((Join-Path $root '_rels'))
    [void][IO.Directory]::CreateDirectory((Join-Path $root 'xl\_rels'))
    [void][IO.Directory]::CreateDirectory((Join-Path $root 'xl\worksheets'))
    try {
        $types=[Text.StringBuilder]::new('<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>')
        $book=[Text.StringBuilder]::new('<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>')
        $rels=[Text.StringBuilder]::new('<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">')
        $number=0
        foreach($name in $Sheets.Keys){
            $number++
            if($name -notmatch '^[A-Za-z][A-Za-z0-9_]{0,30}$'){throw "Invalid worksheet name: $name"}
            $rows=@($Sheets[$name]); if($rows.Count -ge 1048576){throw "Excel row limit exceeded: $name"}
            $headers=[System.Collections.Generic.List[string]]::new()
            foreach($row in $rows){foreach($property in $row.PSObject.Properties){if(-not $headers.Contains($property.Name)){$headers.Add($property.Name)}}}
            if($headers.Count -eq 0){$headers.Add('Status')}
            if($headers.Count -gt 16384){throw "Excel column limit exceeded: $name"}
            $last=Get-AuditColumn $headers.Count
            [void]$types.Append("<Override PartName=`"/xl/worksheets/sheet$number.xml`" ContentType=`"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml`"/>")
            [void]$book.Append("<sheet name=`"$name`" sheetId=`"$number`" r:id=`"rId$number`"/>")
            [void]$rels.Append("<Relationship Id=`"rId$number`" Type=`"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet`" Target=`"worksheets/sheet$number.xml`"/>")
            $writer=[IO.StreamWriter]::new((Join-Path $root "xl\worksheets\sheet$number.xml"),$false,[Text.UTF8Encoding]::new($false))
            try {
                $writer.Write('<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">')
                $writer.Write("<dimension ref=`"A1:${last}$($rows.Count+1)`"/><sheetViews><sheetView workbookViewId=`"0`"><pane ySplit=`"1`" topLeftCell=`"A2`" activePane=`"bottomLeft`" state=`"frozen`"/></sheetView></sheetViews><sheetData><row r=`"1`">")
                for($i=0;$i -lt $headers.Count;$i++){$cell=(Get-AuditColumn ($i+1))+'1';$text=ConvertTo-AuditXml $headers[$i];$writer.Write("<c r=`"$cell`" t=`"inlineStr`"><is><t>$text</t></is></c>")}
                $writer.Write('</row>')
                for($r=0;$r -lt $rows.Count;$r++){
                    $line=$r+2;$writer.Write("<row r=`"$line`">")
                    for($i=0;$i -lt $headers.Count;$i++){
                        $prop=$rows[$r].PSObject.Properties[$headers[$i]]
                        $text=ConvertTo-AuditXml $(if($null -eq $prop){''}else{$prop.Value})
                        $cell=(Get-AuditColumn ($i+1))+$line
                        $writer.Write("<c r=`"$cell`" t=`"inlineStr`"><is><t xml:space=`"preserve`">$text</t></is></c>")
                    }
                    $writer.Write('</row>')
                }
                $writer.Write("</sheetData><autoFilter ref=`"A1:${last}$($rows.Count+1)`"/></worksheet>")
            }finally{$writer.Dispose()}
        }
        [void]$types.Append('</Types>');[void]$book.Append('</sheets></workbook>');[void]$rels.Append('</Relationships>')
        Write-AuditText (Join-Path $root '[Content_Types].xml') $types.ToString()
        Write-AuditText (Join-Path $root '_rels\.rels') '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
        Write-AuditText (Join-Path $root 'xl\workbook.xml') $book.ToString()
        Write-AuditText (Join-Path $root 'xl\_rels\workbook.xml.rels') $rels.ToString()
        # .NET Framework ZipFile.CreateFromDirectory preserves backslashes on Windows;
        # OpenXML part names MUST use forward slashes. Create canonical entries explicitly.
        $archive=[IO.Compression.ZipFile]::Open($Path,[IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach($file in Get-ChildItem -LiteralPath $root -File -Recurse){
                $entryName=$file.FullName.Substring($root.Length+1).Replace('\','/')
                $entry=$archive.CreateEntry($entryName,[IO.Compression.CompressionLevel]::Optimal)
                $input=[IO.File]::OpenRead($file.FullName)
                $output=$entry.Open()
                try{$input.CopyTo($output)}finally{$output.Dispose();$input.Dispose()}
            }
        }finally{$archive.Dispose()}
    }finally{if(Test-Path -LiteralPath $root){Remove-Item -LiteralPath $root -Recurse -Force}}
}
Export-ModuleMember -Function Export-AuditWorkbook
