function Install-DbaAuditDDL {
    <#
    .SYNOPSIS
        Sets database owners with a desired login if databases do not match that owner.

    .DESCRIPTION
        This function will alter database ownership to match a specified login if their current owner does not match the target login. By default, the target login will be 'sa', but the function will allow the user to specify a different login for  ownership. The user can also apply this to all databases or only to a select list of databases (passed as either a comma separated list or a string array).

        Best Practice reference: http://weblogs.sqlteam.com/dang/archive/2008/01/13/Database-Owner-Troubles.aspx

    .PARAMETER SqlInstance
        The target SQL Server instance or instances.

    .PARAMETER SqlCredential
        Login to the target instance using alternative credentials. Accepts PowerShell credentials (Get-Credential).

        Windows Authentication, SQL Server Authentication, Active Directory - Password, and Active Directory - Integrated are all supported.

        For MFA support, please use Connect-DbaInstance.

    .PARAMETER Database
        Specifies the database(s) to process. Options for this list are auto-populated from the server. If unspecified, all databases will be processed.

    .PARAMETER ExcludeDatabase
        Specifies the database(s) to exclude from processing. Options for this list are auto-populated from the server.

    .PARAMETER InputObject
        Enables piping from Get-DbaDatabase

    .PARAMETER Hidden
	    Mark table as system object. 

    .NOTES
        Tags: Database, Audit, AuditDDL
        Author: Sozezzo

    .LINK
        https://...

    .EXAMPLE
        PS C:\> Install-DbaAuditDDL -SqlInstance localhost 

        Install AuditDDL on all databases except master, tempdb, model, msdb

    .EXAMPLE
        PS C:\> Set-DbaDbOwner -SqlInstance sqlserver -Database db1, db2

        Install AuditDDL on the db1 and db2 databases.


    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [parameter(ValueFromPipeline)]
        [DbaInstanceParameter[]]$SqlInstance,
        [PSCredential]$SqlCredential,
        [object[]]$Database,
        [object[]]$ExcludeDatabase = '*',
		[switch]$Hidden,
        [parameter(ValueFromPipeline)]
        [Microsoft.SqlServer.Management.Smo.Database[]]$InputObject
    )

    process {
"
Each database changes are logged on the table [dbo].[AuditDDL]

ex:
     select * from [dbo].[AuditDDL]

"
	if (Test-Bound Hidden)
	{
"
* Mark table as system object. *

"	
	}
        $sqlTableAuditDDL = "
IF OBJECT_ID('dbo.AuditDDL') IS NULL
BEGIN
CREATE TABLE [dbo].[AuditDDL](
	[AuditDDL_ID] [int] IDENTITY(1,1) NOT NULL,
	[Event_Type] [varchar](100) NULL,
	[Database_Name] [varchar](100) NULL,
	[SchemaName] [varchar](100) NULL,
	[ObjectName] [varchar](100) NULL,
	[ObjectType] [varchar](100) NULL,
	[EventDate] [datetime] NULL,
	[SystemUser] [varchar](100) NULL,
	[CurrentUser] [varchar](100) NULL,
	[HostName] [varchar](100) NULL,
	[OriginalUser] [varchar](100) NULL,
	[EventDataText] [varchar](max) NULL,
 CONSTRAINT [pk_AuditDDL] PRIMARY KEY CLUSTERED 
(
	[AuditDDL_ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 98) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY];
END
"

		$sqlTableAuditDDLHidden = "EXEC sp_ms_marksystemobject '[dbo].[AuditDDL]';" 

        $sqlTableAuditDDLTrigger = "
IF NOT EXISTS (SELECT 1 FROM sys.triggers WHERE Name = 'tr_AuditDDL_MonitorChange')
BEGIN
	DECLARE @SQL NVARCHAR(MAX) = '
--
-- Name: tr_AuditDDL_MonitorChange
-- Description: Generate audit traces.
--         url: http://schottsql.blogspot.com/2010/02/ddl-schema-change-auditing-on-sql.html
--
CREATE TRIGGER [tr_AuditDDL_MonitorChange] 
      ON DATABASE FOR DDL_DATABASE_LEVEL_EVENTS
AS

SET NOCOUNT ON
SET ANSI_PADDING ON
declare @EventType varchar(100)
declare @SchemaName varchar(100)
declare @DatabaseName varchar(100)
declare @ObjectName varchar(100)
declare @ObjectType varchar(100)
DECLARE @EventDataText VARCHAR(MAX)
BEGIN TRY

SELECT 
    @EventType    =EVENTDATA().value(''(/EVENT_INSTANCE/EventType)[1]'',''nvarchar(max)'')   ,
    @DatabaseName =EVENTDATA().value(''(/EVENT_INSTANCE/DatabaseName)[1]'',''nvarchar(max)''),
    @SchemaName   =EVENTDATA().value(''(/EVENT_INSTANCE/SchemaName)[1]'',''nvarchar(max)'')  ,
    @ObjectName   =EVENTDATA().value(''(/EVENT_INSTANCE/ObjectName)[1]'',''nvarchar(max)'')  ,
    @ObjectType   =EVENTDATA().value(''(/EVENT_INSTANCE/ObjectType)[1]'',''nvarchar(max)'')  ,
    @EventDataText=EVENTDATA().value(''(/EVENT_INSTANCE/TSQLCommand/CommandText)[1]'',''nvarchar(max)'')


--------------------
-- Add Exceptions --
-- ex.:

-- if ( @ObjectName = ''MyTable_DONT_be_watched'') return
-- if ( @EventType = ''UPDATE_STATISTICS'' ) return

--------------------


INSERT INTO AuditDDL
	(
	Event_Type,Database_Name,SchemaName,ObjectName ,
	ObjectType,EventDate    ,SystemUser,CurrentUser,
	HostName  ,OriginalUser ,EventDataText
	)
SELECT 
    @EventType,@DatabaseName,@SchemaName  ,@ObjectName ,
    @ObjectType  ,GETDATE()    ,SUSER_SNAME(),CURRENT_USER,
    HOST_NAME()  ,ORIGINAL_LOGIN(), @EventDataText

---- Clean-up
DELETE FROM AuditDDL WHERE AuditDDL_ID IN
(
    SELECT MIN(AuditDDL_ID) AS AuditDDL_ID
    FROM AuditDDL AS ToDelete
    WHERE EventDate < DateAdd(y,-1, GetDate())
    GROUP BY Database_Name, SchemaName, ObjectName, ObjectType
    HAVING(COUNT(*)>100)
)
END TRY
BEGIN CATCH
END CATCH
'
	EXEC (@SQL);
END
"

        if (-not $InputObject -and -not $SqlInstance) {
            Write-Message -Level Warning -Message "You must pipe in a database or specify a SqlInstance"
            return
        }

        if ($SqlInstance) {
            $InputObject += Get-DbaDatabase -SqlInstance $SqlInstance -SqlCredential $SqlCredential -Database $Database -ExcludeDatabase $ExcludeDatabase
        }

        foreach ($db in $InputObject) {
		
			
            # Exclude system databases
			if( $ExcludeDatabase -eq '*')
			{
				if ($db.IsSystemObject) {
					continue
				}
			}
			
            if (!$db.IsAccessible) {
                Write-Message -Level Warning -Message "Database $db is not accessible. Skipping."
                continue
            }

            $server   = $db.Parent
            $instance = $server.Name
            $dbName   = $db.name
			
            if ($PSCmdlet.ShouldProcess($instance, "Setting database AuditDDL for $dbName")) {
			
				"Setting AuditDDL at $instance on database [$dbName]"
                try {

                    if ($db.Status -notmatch 'Normal') {
                        Write-Message -Level Warning -Message "$dbName on $instance is in a  $($db.Status) state and can not be altered. It will be skipped."
                    }
                    #Database is updatable, not read-only
                    elseif ($db.IsUpdateable -eq $false) {
                        Write-Message -Level Warning -Message "$dbName on $instance is not in an updateable state and can not be altered. It will be skipped."
                    }
                    else 
                    {
					
					if ($SqlCredential)
						{
							Invoke-DbaQuery -SqlInstance $instance -Query $sqlTableAuditDDL        -Database $dbName -SqlCredential $SqlCredential
							Invoke-DbaQuery -SqlInstance $instance -Query $sqlTableAuditDDLTrigger -Database $dbName -SqlCredential $SqlCredential
							if (Test-Bound Hidden)
							{
							Invoke-DbaQuery -SqlInstance $instance -Database $dbName -Query $sqlTableAuditDDLHidden -SqlCredential $SqlCredential
							}

						} else
						{
						
							Invoke-DbaQuery -SqlInstance $instance -Database $dbName -Query $sqlTableAuditDDL        
							Invoke-DbaQuery -SqlInstance $instance -Database $dbName -Query $sqlTableAuditDDLTrigger
							
							if (Test-Bound Hidden)
							{
							Invoke-DbaQuery -SqlInstance $instance -Database $dbName -Query $sqlTableAuditDDLHidden
							}
						}
                    }
                } catch {
                    Write-Message -Level Warning -Message "Failure to install AuditDDL - database $dbName on $instance."
                }
            }
        }
		
		"--"
		
    }
}
