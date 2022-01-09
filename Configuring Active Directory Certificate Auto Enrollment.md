# Pre-requiste
- The server should be configured to be a domain member. It is not advisable to do it in a domain controller. Segregation is better. 
- The Certificates should be created and checked. CA Cert and Subordinate CA Cert must be in ok condition. 

# Configuration 
- Go to Certificate Authority.

![image](https://user-images.githubusercontent.com/59461655/148681704-3389ddc1-e378-4e54-bb3a-863fce35e510.png)

- Click on the CA and go to properties.

![image](https://user-images.githubusercontent.com/59461655/148681732-28621271-b315-45a5-91e2-78e540730b87.png)

- Go to Policy Module and Select Properties.

![image](https://user-images.githubusercontent.com/59461655/148681749-85dfcadc-eda6-4015-9595-09ba0ce4e231.png)

- By Default should be set to the 2nd option. 

![image](https://user-images.githubusercontent.com/59461655/148681789-78ece13a-5725-44ba-8792-ac449f4d6f5c.png)

- Then go to the Certitficate Template, Left-Click and go to Manage.

![image](https://user-images.githubusercontent.com/59461655/148681846-e5e5a666-dda4-46f3-8a2b-c33cb37b528e.png)

- Select the certificate that we want people to automatically enroll. 

![image](https://user-images.githubusercontent.com/59461655/148681899-19f3c37e-f96c-423d-a104-4cedc0ebbe36.png)

- Right-Click and select Properties. 

![image](https://user-images.githubusercontent.com/59461655/148681917-4d86203b-cc71-4cd3-add4-22b312e10ce8.png)

- Select Security tab and check Enroll and Autoenroll

![image](https://user-images.githubusercontent.com/59461655/148681957-ac8eabd7-8cf1-4384-96b3-4ce14fe5f601.png)

# Configuring Group Policy (Important Step that I missed out.)
- Go to Group Policy Management under Tools. 

![image](https://user-images.githubusercontent.com/59461655/148682030-c38d45e9-61fa-4217-98a7-e47d1d61ae48.png)

- Create or configure an existing GPO to autoenroll the certificate.

![image](https://user-images.githubusercontent.com/59461655/148682068-6d4b91cc-8ed0-4653-8aa7-d4836db352cf.png)

- Right-Click and edit policy. Go to User Configuration > Policies > Security Settings > Public Key Policies > Certificate Services Client - Auto-Enrollment. 

![image](https://user-images.githubusercontent.com/59461655/148682135-480d00ed-1555-4585-b86b-83ac9012aa7d.png)

- Enable it and set configuration as below. 

![image](https://user-images.githubusercontent.com/59461655/148682170-b9e35f0e-f325-4b7b-b04c-2ee24ceab145.png)

- Link the GPO to an existing OU. 
- run gpupdate /force. 


