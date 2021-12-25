# Import the AD module
Import-Module ActiveDirectory

# List all disabled AD users
Search-ADAccount -AccountDisabled | Select-Object Name, DistinguishedName

$distinguishedName = Read-Host -Prompt "Please Enter the Distinguished name found in attribute editor"

# Move all disabled AD users to disabled users OU
Search-ADAccount -AccountDisabled | Where {$_.DistinguishedName -notLike "OU=Disabled Users*"} | Move-ADObject -TargetPath "$distinguishedName"

# Disable all users in the disabled users OU 
Get-ADUser -Filter {Enabled -eq $True} -SearchBase "$distinguishedName" | Disable-ADAccount
