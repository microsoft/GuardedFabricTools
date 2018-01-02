 # Reporting Attestation Requests using the HgsAttestationReporting Module

This PowerShell module provides a single cmdlet for reporting on attestation requests handled by a Host Guardian Service instance by reading the event logs from the targeted instance, and interpolating the relevant events into a strongly typed output.  This is useful for auditing which hosts have attested to an HGS cluster, what mode they used, and the attestation status and substatus from that request.

## Working with the AttestationRequest output object

This PowerShell module defines an AttestationRequest class that contains the following properties:
  - Time 
  - - A DateTime instance of the start time of the attestation request
  - HostName 
  - - A string representing the name of the host as could be found by the script. If the attestation request was in AD mode, then the HostName will be the SAM Account Name of the host or the machine SID for a passed or failed attestation attempt, respectively. If in TPM mode, the HostName will either be the one found that corresponds to the EkPub in the events picked up, or 'UnauthorizedHost' if the host was unauthorized.
  - AttestationOperationMode 
  - - The string value of the `Microsoft.Windows.RemoteAttestation.Core.AttestationOperationMode` enumeration that corresponds to the type of attestation request.
  - AttestationStatus 
  - - The string value of the `Microsoft.Windows.RemoteAttestation.Core.AttestationStatus` enumeration that corresponds to the type of attestation request. This is typically a broader view of the overall outcome of the attestation request.
  - AttestationSubStatus 
  - - The string value of the `Microsoft.Windows.RemoteAttestation.Core.AttestationSubStatus` enumeration that corresponds to the type of attestation request. This is a more specific, if applicable, look at the outcome of the attestation request.
  - AuthorizedHostGroup
  - - A string representing the name of the authorized host group used to validate the membership of the host in AD mode. In TPM mode, this will default to the value "NotApplicable"
  - EndorsementKeyHash
  - - A string representing the hashed value of the Endorsement Key used to identify the attesting host in TPM mode. In AD mode, this will default to the value "NotApplicable"

## Invoking Get-HgsAttestationReport on the Local Machine

If the local machine is the HGS server one would like to report attestation requests from, a credential is not required. Note that the function will attempt to reach all nodes in the HGS cluster, and it is thus reccommended to use this command as such in a user context that has access to the event log of all HGS servers in a cluster.

## Targeting a Remote HGS Server instance


  You can target a remote HGS server by adding the following mandatory parameters:
  - ComputerName
  - - The FQDN of the targeted HGS Server.
  - Credential
  - - A `PSCredential` object representing the credential used to reach the HGS server.  This credential should have the proper permissions to the event log.

  You can also select the PowerShell session configuration to use in remote calls to collect HGS server setting information by specifying it using the `-EndpointName` parameter. Note that this endpoint can be a JEA endpoint, but the credentials used in `-Credential` should have access to the following cmdlets:
  - Get-HgsServer
  - Get-HgsAttestationHostGroup
  - Get-HgsAttestationTpmHost
  - Get-ClusterNode 

  The following example collects a report of attestation requests on the HGS instance `AttestationService.Contoso.Com` using the HGS provided JEA endpoint.
```powershell
PS> $Cred = Get-Credential
PS> Get-HgsAttestationReport -ComputerName AttestationService.Contoso.Com -Credential $Cred -Endpoint Microsoft.Windows.HGS
```


## Selecting Specific Attestation Modes  
  By default, the `Get-HgsAttestationReport` function will use the current operation mode of the local machine. However, using the `-AD` or `-TPM` switch parameters will override this capability to parse AD and TPM based attestation requests respectively.  

  ```powershell
  PS> Get-HgsAttestationReport -AD
  Time                   HostName                                         AttestationOperationMode AttestationStatus AttestationSubStatus
  ----                   --------                                         ------------------------ ----------------- --------------------
  10/24/2016 10:54:07 AM CONTOSO\SecureHostAD$                              AD                       Passed            NoInformation
  10/24/2016 10:39:52 AM S-1-5-21-3623811015-3361044348-30300820-1013       AD                       UnauthorizedHost  NoInformation
  10/24/2016 10:39:30 AM CONTOSO\SecureHostAD$                              AD                       Passed            NoInformation
  10/24/2016 10:39:29 AM CONTOSO\SecureHostAD$                              AD                       Passed            NoInformation
  ```

  Both switches can be used concurrently to look for all attestation requests, though it will only be able to configure properties such as the HostName if the settings are still present. 
  
## Selecting a StartTime and EndTime  
  By default, the `Get-HgsAttestationReport` cmdlet will attempt to parse events from as early as possible to the current time.  However, you can pass DateTime objects to the `-StartTime` and `-EndTime` parameters to specify the bounds of the timespan used to filter the relevant events. For example, the follwing invocation will display all attestation requests in the current attestation mode from fourteen days ago to seven days ago.
  ```powershell
  PS> Get-HgsAttestationReport -StartTime (Get-Date).AddDays(-14) -EndTime (Get-Date).AddDays(-7)
  ```
  
