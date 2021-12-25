#Grab variables from user
$firstname = Read-Host -Prompt "Please enter the first name"
$lastname = Read-Host -Prompt "Please enter the last name" 
$password = Read-Host -Prompt "Please enter the secure password"
$organizationUnit = Read-Host -Prompt "Please enter the active directory ou"
$domain = Read-Host -Prompt "Please enter the active directory domain name"

#Create AD User
New-ADUser `
	-Name "$firstname $lastname" `
	-GivenName $firstname `
	-Surname $lastname `
	-UserPrincipalName "$firstname.$lastname"
	-AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
	-Path "OU=Domain Users,OU=$organizationUnit,DC=$domain,DC=com' `
	-ChangePasswordAtLogon 1
	-Enable $true
