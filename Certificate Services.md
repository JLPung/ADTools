    

# Creating CA Server and Subordinate CA Server:

Pre-requiste: Joined Domain, not a standalone Server. Installation on Standalone Server will result in later part errors in joining domain. The CA will grey out the option to do that.

Results: Creating a RootCA Server, Creating a Subordinate CA Server, Creating a IIS web server for domain joined computers to enroll to get certificates. 

![image](https://user-images.githubusercontent.com/59461655/148633165-649d42f5-ccf6-4ae3-a4eb-c8e588df7642.png)
- Select Enterprise CA for Domain Root CA.

![image](https://user-images.githubusercontent.com/59461655/148633187-74845417-8f8d-46b7-810b-0d54bb5c3fb0.png)
- Select RootCA if this is the first CA in the domain.
- Select Subordinate CA if there is a CA server in the domain. 

![image](https://user-images.githubusercontent.com/59461655/148633191-e06da95e-f514-4f5f-9e69-4a7aca6215d0.png)
- We can change the Common Name for the CA or just leave it as default. Default will be the hostname. 

![image](https://user-images.githubusercontent.com/59461655/148633197-1097df22-58f1-43b0-8d15-fbbfba87b73e.png)
- Validity period default is 5 years. Change if needed to be longer or shorter. 
- Click on Configure to finish the installation. 

![image](https://user-images.githubusercontent.com/59461655/148633202-680d5209-722f-4273-8e1a-7ce294cd1e01.png)
- After finished installing the CA, go back to roles and features to install the other modules. 

![image](https://user-images.githubusercontent.com/59461655/148633206-d4e0fe73-08be-4251-a4f5-5da6480e791c.png)
Go through the settings, leave default settings is fine. 

![image](https://user-images.githubusercontent.com/59461655/148633210-a75ada89-c3bf-460d-bcff-9fdd2b0942b3.png)
- Select Windows integrated authentication if asked. 

![image](https://user-images.githubusercontent.com/59461655/148633214-6ffc77c2-b5f0-4fdd-8f3e-010e9dcb41fb.png)
- Select the rootCA. 
- Click on Configure and wait for installation to complete. 






