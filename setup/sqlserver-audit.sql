-- SQL Server 2016 audit configuration for rules 100400-100418.
-- Without these specifications the ERRORLOG carries logon events but no role,
-- permission or DDL activity, so about half the rules never fire.
-- Run as a principal with ALTER ANY SERVER AUDIT. Adjust the path and database.

USE [master];
GO

CREATE SERVER AUDIT [Wazuh_Security_Audit]
  TO FILE (
    FILEPATH           = 'C:\SQLAudit\',
    MAXSIZE            = 100 MB,
    MAX_ROLLOVER_FILES = 10,
    RESERVE_DISK_SPACE = OFF
  )
  WITH (ON_FAILURE = CONTINUE);
GO

ALTER SERVER AUDIT [Wazuh_Security_Audit] WITH (STATE = ON);
GO

CREATE SERVER AUDIT SPECIFICATION [Wazuh_Server_Spec]
  FOR SERVER AUDIT [Wazuh_Security_Audit]
    ADD (FAILED_LOGIN_GROUP),
    ADD (SUCCESSFUL_LOGIN_GROUP),
    ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP),
    ADD (SERVER_PERMISSION_CHANGE_GROUP),
    ADD (AUDIT_CHANGE_GROUP)
  WITH (STATE = ON);
GO

-- Repeat per monitored database.
USE [YourDatabaseName];
GO

CREATE DATABASE AUDIT SPECIFICATION [Wazuh_Database_Spec]
  FOR SERVER AUDIT [Wazuh_Security_Audit]
    ADD (DATABASE_OBJECT_CHANGE_GROUP),
    ADD (SCHEMA_OBJECT_CHANGE_GROUP),
    ADD (SCHEMA_OBJECT_ACCESS_GROUP),
    ADD (DATABASE_OBJECT_PERMISSION_CHANGE_GROUP),
    ADD (DATABASE_PRINCIPAL_CHANGE_GROUP)
  WITH (STATE = ON);
GO

-- Verify
SELECT name, is_state_enabled FROM sys.server_audits;
SELECT name, is_state_enabled FROM sys.server_audit_specifications;
SELECT * FROM sys.dm_server_audit_status;
GO

-- On a French-language instance the audit action groups are written to the log
-- in French, so rules 100406, 100407 and 100410 match both forms.
