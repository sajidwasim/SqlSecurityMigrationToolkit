#requires -Version 5.1
# SQL Server 2012+ metadata only. No dynamic SQL, security DDL, password hashes or stored credentials.
Set-StrictMode -Version Latest

$script:AuditQueries = [ordered]@{
    ServerInfo = @'
SELECT CONVERT(nvarchar(256),SERVERPROPERTY('ServerName')) AS CanonicalInstance,
       CONVERT(nvarchar(128),SERVERPROPERTY('ProductVersion')) AS ProductVersion,
       ORIGINAL_LOGIN() AS OriginalLogin, SUSER_SNAME() AS ExecutionLogin,
       IS_SRVROLEMEMBER('sysadmin') AS IsSysadmin;
'@
    Databases = @'
SELECT name AS DatabaseName, database_id AS DatabaseId, state_desc AS State,
       source_database_id AS SourceDatabaseId, is_read_only AS IsReadOnly
FROM sys.databases WHERE database_id > 4 ORDER BY name;
'@
    ServerLogins = @'
SELECT name AS PrincipalName, type_desc AS PrincipalType,
       CONVERT(varchar(170),sid,1) AS SidHex, is_disabled AS IsDisabled,
       default_database_name AS DefaultDatabase
FROM sys.server_principals WHERE principal_id > 1 ORDER BY name;
'@
    ServerRoles = @'
SELECT r.name AS RoleName, m.name AS MemberName
FROM sys.server_role_members AS x
JOIN sys.server_principals AS r ON r.principal_id=x.role_principal_id
JOIN sys.server_principals AS m ON m.principal_id=x.member_principal_id;
'@
    ServerPermissions = @'
SELECT g.name AS Grantee, p.state_desc AS PermissionState,
       p.permission_name AS PermissionName, p.class_desc AS PermissionClass,
       p.major_id AS MajorId, p.minor_id AS MinorId,
       CASE WHEN p.class=101 THEN s.name ELSE NULL END AS SecurableName
FROM sys.server_permissions AS p
JOIN sys.server_principals AS g ON g.principal_id=p.grantee_principal_id
LEFT JOIN sys.server_principals AS s ON p.class=101 AND s.principal_id=p.major_id;
'@
    DatabaseUsers = @'
SELECT name AS PrincipalName, type_desc AS PrincipalType,
       authentication_type_desc AS AuthenticationType,
       CONVERT(varchar(170),sid,1) AS SidHex,
       SUSER_SNAME(sid) AS ResolvedLogin, default_schema_name AS DefaultSchema
FROM sys.database_principals WHERE principal_id > 4 ORDER BY name;
'@
    DatabaseRoles = @'
SELECT r.name AS RoleName, m.name AS MemberName
FROM sys.database_role_members AS x
JOIN sys.database_principals AS r ON r.principal_id=x.role_principal_id
JOIN sys.database_principals AS m ON m.principal_id=x.member_principal_id;
'@
    DatabasePermissions = @'
SELECT g.name AS Grantee, p.state_desc AS PermissionState,
       p.permission_name AS PermissionName, p.class_desc AS PermissionClass,
       p.major_id AS MajorId, p.minor_id AS MinorId,
       CASE WHEN p.class=1 THEN OBJECT_SCHEMA_NAME(p.major_id)
            WHEN p.class=3 THEN SCHEMA_NAME(p.major_id) ELSE NULL END AS SecurableSchema,
       CASE WHEN p.class=1 THEN OBJECT_NAME(p.major_id) ELSE NULL END AS SecurableObject,
       CASE WHEN p.class=1 AND p.minor_id>0 THEN COL_NAME(p.major_id,p.minor_id) ELSE NULL END AS SecurableColumn
FROM sys.database_permissions AS p
JOIN sys.database_principals AS g ON g.principal_id=p.grantee_principal_id;
'@
    Schemas = @'
SELECT name AS SchemaName, USER_NAME(principal_id) AS OwnerName
FROM sys.schemas ORDER BY name;
'@
    Objects = @'
SELECT SCHEMA_NAME(schema_id) AS SchemaName, name AS ObjectName,
       type AS ObjectType, type_desc AS ObjectTypeDescription,
       USER_NAME(COALESCE(principal_id,SCHEMA_ID('dbo'))) AS ExplicitOrFallbackOwner
FROM sys.objects WHERE is_ms_shipped=0 ORDER BY schema_id,name;
'@
    ConnectionEncryption = @'
SELECT encrypt_option AS EncryptOption, auth_scheme AS AuthenticationScheme
FROM sys.dm_exec_connections WHERE session_id=@@SPID;
'@
}

function New-AuditSqlConnection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Instance,
          [string]$Database='master', [bool]$TrustCertificate=$false,
          [ValidateRange(1,120)][int]$ConnectTimeoutSeconds=15)
    $builder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
    $builder['Data Source']=$Instance
    $builder['Initial Catalog']=$Database
    $builder['Integrated Security']=$true
    $builder['Encrypt']=$true
    $builder['TrustServerCertificate']=$TrustCertificate
    $builder['Connect Timeout']=$ConnectTimeoutSeconds
    $builder['Pooling']=$false
    $builder['Application Name']='SQL Security Migration Toolkit - Read Only Audit'
    $connection = New-Object System.Data.SqlClient.SqlConnection($builder.ConnectionString)
    try { $connection.Open(); return $connection }
    catch { $connection.Dispose(); throw }
}

function Invoke-AuditMetadataQuery {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Data.SqlClient.SqlConnection]$Connection,
          [Parameter(Mandatory)][ValidateSet('ServerInfo','Databases','ServerLogins','ServerRoles',
              'ServerPermissions','DatabaseUsers','DatabaseRoles','DatabasePermissions',
              'Schemas','Objects','ConnectionEncryption')][string]$Query,
          [ValidateRange(1,1800)][int]$CommandTimeoutSeconds=120)
    $command=$Connection.CreateCommand()
    try {
        $command.CommandText=$script:AuditQueries[$Query]
        $command.CommandTimeout=$CommandTimeoutSeconds
        $table=New-Object System.Data.DataTable
        $adapter=New-Object System.Data.SqlClient.SqlDataAdapter($command)
        try { [void]$adapter.Fill($table) } finally { $adapter.Dispose() }
        return ,$table
    } finally { $command.Dispose() }
}

function Convert-AuditRows {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Data.DataTable]$Table,
          [Parameter(Mandatory)][string]$Instance,[string]$Database='master')
    foreach($row in $Table.Rows) {
        $record=[ordered]@{Instance=$Instance;Database=$Database}
        foreach($column in $Table.Columns) {
            $value=$row[$column.ColumnName]
            $record[$column.ColumnName]=if($value -is [DBNull]){$null}
                elseif($value -is [byte[]]){'0x'+[BitConverter]::ToString($value).Replace('-','')}
                else{$value}
        }
        [pscustomobject]$record
    }
}

Export-ModuleMember -Function New-AuditSqlConnection,Invoke-AuditMetadataQuery,Convert-AuditRows
