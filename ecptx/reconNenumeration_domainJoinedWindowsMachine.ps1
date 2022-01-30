# Run DNS query to get SRV records for DCs.
nslookup -querytype=SRV _LDAP._TCP.DC._MSDCS.{ domain_name }

# Use ADSI (PowerShell) to get domain results.
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers

# Use nltesst from Windows Resource Kit for domain DC identification.
nltest /server:{ ip_of_any_member } /dclist:{ domain_name }

# Use net view to enumerate domain. Returns list of member systems of domains and workgroups.
net view /domain
net view /domain:{ domain_name }

# Identify hostnames via DNS. 
nslookup { ip_of_any_member } #easily detectable. 

# for loop to perform nslookup 10.10.10.X commands against DNS server of domain. 
for /L %i in (1,1,255) do @nslookup 10.10.10.%i { server to resolve from } 2>nul | find "Name" && echo 10.10.10.%i

# Returns a remote machine MAC address, hostname, domain membership and codes that represent roles it performs.
nbtstat -A { remote_machine_ip }

# for loop to perform nbtstat for MAC address, hostname, domain membership and roles. 
for /L %i in (1,1,255) do @nbtscan -A 10.10.10.%i 2>nul && echo 10.10.10.%i

# Once we are inside the "Authenticated users" group we can continue enumerations user DumpSec, shareenum, enum.exe
DumpSec
shareenum.exe (SysInternals)
enum.exe

# Look for shares with insufficient secure permissions configured. 
net use e: \\{ ip }\ipc$ { password } /user:{ domain\username } 
net view \\{ ip } 

# Traditional user hunting
https://www.slideshare.net/harmj0y/i-hunt-sys-admins-20


