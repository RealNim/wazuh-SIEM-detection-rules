@echo off
rem Advanced audit policy for rules 100600-100619. Run elevated on the domain
rem controller. In a real domain this belongs in a GPO linked to the Domain
rem Controllers OU, since a local auditpol change is lost at the next policy
rem refresh. auditpol is used here so the lab is reproducible in one step.

rem Kerberos
auditpol /set /subcategory:"Kerberos Authentication Service"      /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations"   /success:enable /failure:enable

rem Logon and credential validation
auditpol /set /subcategory:"Credential Validation"                /success:enable /failure:enable
auditpol /set /subcategory:"Logon"                                /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout"                      /success:enable /failure:enable

rem Account and group management
auditpol /set /subcategory:"User Account Management"              /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management"            /success:enable /failure:enable

rem Directory service, for 4662 and 5136
auditpol /set /subcategory:"Directory Service Access"             /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes"            /success:enable /failure:enable

echo.
auditpol /get /category:"Account Logon","Logon/Logoff","Account Management","DS Access"

rem Remaining manual step for DCSync detection. Enabling Directory Service
rem Access is not enough: event 4662 is only written for an object carrying an
rem audit entry for the right being exercised, so rule 100609 needs a SACL on
rem the domain root. In AD Users and Computers with Advanced Features shown,
rem on the domain root object:
rem
rem   Properties -> Security -> Advanced -> Auditing -> Add
rem   Principal:  Everyone
rem   Type:       Success
rem   Applies to: This object only
rem   Permissions:
rem     Replicating Directory Changes
rem     Replicating Directory Changes All
rem     Replicating Directory Changes In Filtered Set
rem
rem Rule 100610 suppresses the resulting noise, since domain controllers
rem replicate with each other legitimately.
