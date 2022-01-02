# Importing AD Module
Import-Module ActiveDirectory

# Get all members of the roaming profile group 
Get-ADGroupMember 'Roaming Profile Users' | 
	# Loop through each user 
	ForEach-Object {
		# Do this for each member
		Set-ADUser -Identity $_.SamAccountName -ProfilePath ("\\IPDC01\Profile$\" + $_.SamAccountName)
	}
# Set as a scheduled task or run directly. 

