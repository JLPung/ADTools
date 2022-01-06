1. notepad C:\Windows\CAPolicy.inf
2. ![image](https://user-images.githubusercontent.com/59461655/148338282-b0f278e7-611a-4be2-bf44-b452e4264363.png)
3. Add the below to the opened file.
```bash
[Version]
Signature="$Windows NT$"
[PolicyStatementExtension]
Policies=InternalPolicy
[InternalPolicy]
OID= 1.2.3.4.1455.67.89.5
[Certsrv_Server]
RenewalKeyLength=4096
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=10
LoadDefaultTemplates=0
````
4. Get .crt and .crl RootCA certificates from C:\Windows\System32\CertSrv\CertEnroll.
5. Will need to create under RootCA CA services revoked certs folder if .crl files does not exist. 
6. Copy the 2 files to the 2nd CA server. 
7. Need to register the 2 files using Windows Powershell. 

Publish root CA certificates and CRL list in AD
8. certutil.exe -dsPublish -f "C:\filename.crt" RootCA
9. certutil.exe -dsPublish -f "C:\filename.crl" RootCA

Add Root CA certificates and CRL list into Local Certificate Store. 
10. certutil.exe -addstore -f root "C:\filename.crt"
11. certutil.exe -addstore -f root "C:\filename.crl"

- Configure ADCS for SubordinateCA. look at https://www.youtube.com/watch?v=wUnHAE2uM3o @08:10 timing.
- Save the generated SubCA on the machine. Check the filename should be a .req file. 
- Transfer the .req file to RootCA machine to request for a certificate. 
- Go to ADCS console. Right-click on CA server name and hover to all task, submit new request. 
- Go to pending request, refresh and find the submitted request, rightclick and select issue. 
- export the subca certificate file and import into SubCA Server. 

Configure Certificate Revocation and CA Certificate Validity Periods
12. certutil -setreg CA\CRLPeriodUnits 1
13. certutil -setreg CA\CRLPeriod "Weeks"
14. certutil -setreg CA\CRLDeltaPeriodUnits 1
15. certutil -setreg CA\CRLDeltaPeriod "Days"

Define CRL overlap settings: 
16. certutil -setreg CA\CRLOverlapPeriodUnits 12
17. certutil -setreg CA\CRLOverlapPeriod "Hours" 

