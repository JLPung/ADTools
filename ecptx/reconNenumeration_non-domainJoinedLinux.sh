#!/bin/bash

# Recon & enumerations through a non-domain joined Linux, without windows shell. 

# identify targets, start recon and enumeration by firing up nbtscan against the organization's IP ranges: 
# Option 1:
nbtscan -r $1

# Option 2:
# perform reverse DNS queries to identify hostname using nmap
nmap -sL $1 -oN ./reverseDNSqueries_hostnameScans.md

# Option 3: 
# use metatsploit smb version module to scan networks for windows systems. 
# >> use auxiliary/scanner/smb/smb_version 

# Investigate common SNMP misconfigurations: 
# metasploit's SNMP scanner to guess the community string. 
# >> use auxiliary/scanner/snmp/snmp_login

# use nmap to brute force guess community strings of SNMP. 
nmap -sU -p 161,162 --script snmp-brute $1 --script-args snmp-brute.communitiesdb=/usr/share/seclists/Discovery/SNMP/snmp.txt

# use onesixtyone to find community strings of SNMP
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt $1 	#change dictionary as needed. 

# Once found the community string, perform enumeration walk on the device. 
snmpcheck -c {community_strings} -t $1

# dig find windows global catalog record and authoritative DNS record to find Domain Controller addresses.
dig -t NS {domain_name}
dig _gc. {domain_name}

# recon on SMB & Null session
# with valid username
rpcclient -U {username} $1

# Null sessions
rpcclient -U "" $1

# with valid credentials, enumerate a range of accessible ip.
cat ips.txt | while read line 
do 
	echo $line && rpcclient -U "ELS\samatha%P@ssword123" -c "enumdomusers;quit" $line 
done 

# rpcclient get more information
rpcclient $> srvinfo

# rpcclient enumerate domain users
rpcclient $> enumdomusers

# rpcclient enumerate domain and built-in groups 
rpcclient $> enumalsgroups domain
rpcclient $> enumalsgroups builtin

# rpcclient identify SID
rpcclient $> lookupnames {username or groupname} 

# rpcclient get details for a user.
rpcclient $> queryuser 500 

# Enumerate share.
smbclient -U "{Domain\username%password}" -L $1

# RestrictAnonymous bypass technique
dumpusers - windows tool

