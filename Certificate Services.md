    

# Creating CA Server and Subordinate CA Server:

Pre-requiste: Joined Domain, not a standalone Server. Installation on Standalone Server will result in later part errors in joining domain. The CA will grey out the option to do that.

Results: Creating a RootCA Server, Creating a Subordinate CA Server, Creating a IIS web server for domain joined computers to enroll to get certificates. 

![[Pasted image 20220108132623.png]]
- Select Enterprise CA for Domain Root CA.

![[Pasted image 20220108132656.png]]
- Select RootCA if this is the first CA in the domain.
- Select Subordinate CA if there is a CA server in the domain. 

![[Pasted image 20220108132835.png]]
- We can change the Common Name for the CA or just leave it as default. Default will be the hostname. 

![[Pasted image 20220108132950.png]]
- Validity period default is 5 years. Change if needed to be longer or shorter. 
- Click on Configure to finish the installation. 

![[Pasted image 20220108133157.png]]
- After finished installing the CA, go back to roles and features to install the other modules. 

![[Pasted image 20220108133625.png]]
Go through the settings, leave default settings is fine. 

![[Pasted image 20220108133719.png]]
- Select Windows integrated authentication if asked. 

![[Pasted image 20220108133833.png]]
- Select the rootCA. 
- Click on Configure and wait for installation to complete. 






