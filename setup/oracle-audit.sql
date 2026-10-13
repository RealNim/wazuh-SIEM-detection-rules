-- Oracle 11g / 12c audit configuration for rules 100500-100518.
-- Audit must go to OS files, not SYS.AUD$, because the agent reads files.
-- With the default audit_trail the adump directory stays empty.
-- Run as SYSDBA. audit_trail is static, so the instance restarts.

ALTER SYSTEM SET audit_trail = 'OS' SCOPE = SPFILE;

SHUTDOWN IMMEDIATE;
STARTUP;

SHOW PARAMETER audit_file_dest;
SHOW PARAMETER audit_trail;

-- Statement-level auditing, which works on both 11g and 12c. On 12c and later
-- CREATE AUDIT POLICY is the supported mechanism and gives finer control.
AUDIT CREATE SESSION;
AUDIT CREATE SESSION BY SYS;
AUDIT GRANT ANY PRIVILEGE;
AUDIT GRANT ANY ROLE;
AUDIT ALTER ANY TABLE;
AUDIT DROP ANY TABLE;
AUDIT CREATE ANY TABLE;
AUDIT AUDIT SYSTEM;
AUDIT SYSTEM GRANT;

SELECT * FROM dba_stmt_audit_opts ORDER BY audit_option;

-- Listener logging and hardening, from the OS shell as the oracle user.
-- Feeds rules 100513 to 100516. admin_restrictions blocks runtime SET
-- commands against the listener, which is what 100516 detects attempts at.
--
--   lsnrctl set log_status on
--   lsnrctl set admin_restrictions on
--   lsnrctl reload
--
-- The agent user needs read access to the audit and diag trace directories.
