 # Managing Private Key Permissions

This PowerShell module exposes new capabilities on X509Certificate2 objects that allow you to view and update the ACL of certificate private keys.  This is useful for managing the permissions of certificates consumed by the Host Guardian Service in environments lacking a GUI (Windows Server Core) or that demand full automation.  The same actions can be completed in a GUI via the certlm.msc and certmgr.msc MMC snap-ins.

_Warning: these commands do not work for all certificates.  In particular, certificates backed by non-standard Key Storage Providers (KSP)_ or Cryptographic Service Providers (CSP) may not work.  This includes certificates managed by certain hardware security modules.  Any certificates managed by the standard Microsoft Software Key Storage Provider or other providers that properly implement Microsoft's Crytographic API: Next Gen (CNG) standards will function as expected._



## Acquire Certificate Objects

Working with private key permissions requires access to the `X509Certificate2` object that wraps the private key.  This can be acquired multiple ways:

- **At Creation Time**  
  When generating a self-signed certificate, PowerShell will return the required `X509Certificate2` object:
  ```powershell
  PS> $certificate = New-SelfSignedCertificate -Subject "HgsEncryption"
  ```
  After calling this command, `$certificate` contains the required certificate reference.  Note that the certificate is actually stored in the local machine's certificate store and the reference can be reacquired using the next method.
  
  
- **From the Certificate Store**  
  Since all Host Guardian Service certificates are stored in the local machine's certificate store, they can be retrieved by navigating the corresponding PSDrive:
  ```powershell
  PS> cd cert:\LocalMachine\My
  PS> dir

    PSParentPath: Microsoft.PowerShell.Security\Certificate::LocalMachine\My

  Thumbprint                                Subject
  ----------                                -------
  F1EB5D4AA845C0C2C21E0870C890C1D4D67DB4E5  CN=Microsoft Remote Attestation Service
  BE367605E86D38F6DA4561BC9422F9D397AEA6F0  CN=HgsEncryption
  B80710A85C39BB5F728A2469F63793DDA36E4262  CN=HgsSigning
  ```
  Individual certificates can then be retrieved by using any of the `Get-Item` or `Get-ChildItem` cmdlets with whatever filtering criteria you desire.  Here is an example of retrieving a certificate by its subject:
  ```
  PS> $certificate = Get-Item * | ? { $_.Subject -eq "CN=Microsoft Remote Attestation Service" }
  ```

- **From a PFX/CER/P7B/DER**  
Exported certificate files in any of the following formats:
  - PFX (PKCS#12)
  - PEM (Base 64 X509 ASN.1)
  - DER (Binary X509 ASN.1)
  - P7B (PKCS#7)
   
  ...must first be imported into the local machine's certificate store.  This is handled for you at the time that the Host Guardian Service is initialized.  If you have already completed HGS initialization and provided a PFX as input to the cmdlet, then you must retrieve the certificate using the previous method.
  
  If you have not completed HGS initialization and are unable to package the certificate as a PFX file, then import the file using the Windows Explorer or via the [`Import-Certificate`](https://technet.microsoft.com/en-us/library/hh848630.aspx) cmdlet.  Then call `Initialize-HgsServer` using the certificate's thumbprint.  You may later retrieve the certificate object using the previous method.
  
  
  
## Managing Permissions
With a certificate object gathered using the steps detailed in the last section, you are now ready to access and update the associated private key's access control list (ACL).  Note that the required properties are not accessible until the `GuardedFabricTools` module has been imported:
```powershell
PS> Import-Module GuardedFabricTools
```

### Viewing Private Key Permissions
With the required module in place, the access control list for the private key of a given certificate can be accesssed as follows:
```powershell
PS> $certificate.Acl

Path Owner Access
---- ----- ------
           Everyone Allow  -803274241...
```

You can iterate all of the applied access rules by inspecting the `Access` property:
```powershell
PS> $certificate.Acl.Access

FileSystemRights  : -803274241
AccessControlType : Allow
IdentityReference : Everyone
IsInherited       : False
InheritanceFlags  : None
PropagationFlags  : None

FileSystemRights  : -803274241
AccessControlType : Allow
IdentityReference : CREATOR OWNER
IsInherited       : False
InheritanceFlags  : None
PropagationFlags  : None

FileSystemRights  : -803274241
AccessControlType : Allow
IdentityReference : NT AUTHORITY\SYSTEM
IsInherited       : False
InheritanceFlags  : None
PropagationFlags  : None

FileSystemRights  : -803274241
AccessControlType : Allow
IdentityReference : BUILTIN\Administrators
IsInherited       : False
InheritanceFlags  : None
PropagationFlags  : None
```
Take care to note that this command will return nothing (`$null`) if the certificate lacks a private key or another complication prevents the retrieval of the security descriptor.  This can happen to certificates with a private key if that key is managed by a Key Storage Provider (KSP) or Cryptographic Service Provider (CSP) that implements a non-standard access control mechanisms such as a hardware security module.

### Updating Private Key Permissions
You can add and remove new access rules using the methods available on the `System.Security.AccessControl.FileSecurity` class [documented here](https://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesecurity(v=vs.110).aspx).  Note that the `Acl` property returns a read-only copy of the security descriptor controlling access to the certificate's private key.  To update the access control list, you must make your modifications to this copy and then save the changes by assigning the updated security descriptor back to the `Acl` property.

In the following example, we use the `Add-AccessRule` cmdlet to append a new rule and save the updated Acl in a single line of PowerShell:
```powershell
PS> $certificate.Acl = $certificate.Acl | Add-AccessRule "Administrator" FullControl Allow
```
After running this command, all permissions will be granted to the local "Administrator" account.  Note that you may need elevated privileges to update the permissions of particular certificates.  Additionally, this command will fail for certificates that lack a private key.

To view all of the options exposed by `Add-AccessRule` view the documentation by running:
```powershell
PS> help Add-AccessRule
```
## Tutorial: Fixing Certificate Permissions Errors
**Scenario**: You manage a Host Guardian Service cluster and have noted requests are returning strange errors.  You call [HGS Diagnostics](https://blogs.technet.microsoft.com/datacentersecurity/2016/05/04/overview-of-host-guardian-service-hgs-diagnostics/) to attempt to diagnose the issue.  The following output is returned:
```powershell
PS> Get-HgsTrace -RunDiagnostics
Overall Result: Fail
    HGS-01: Fail
        Certificates: Fail
            Attestation Certificate Permissions: Fail
            >>> The user "IIS AppPool\AttestationAppPool" must have read permissions to the certificate with the
            >>> subject "CN=Microsoft Remote Attestation Service" and thumbprint
            >>> "66C7DBE7B9D256DF54F6A26DDFE1DE6FCD1CFB53".
```
It appears that the health signing certificate does not have the correct permissions associated with its private key.  We can use the thumbprint (`66C7DBE7B9D256DF54F6A26DDFE1DE6FCD1CFB53`) and username (`IIS AppPool\AttestationAppPool`) returned in the output to retrieve the broken certificate and then patch its permissions.

**Fix**: First, retrieve the required certificate:
```powershell
PS> $certificate = Get-Item Cert:\LocalMachine\My\66C7DBE7B9D256DF54F6A26DDFE1DE6FCD1CFB53
```
This fetches the certificate from the local machine's certificate store by its thumbprint.  At this point we use the `Add-AccessRule` cmdlet to append a rule that grants the `IIS AppPool\AttestationAppPool` user read access to the private key:
```powershell
PS> $certificate.Acl = $certificate.Acl | Add-AccessRule "IIS AppPool\AttestationAppPool" Read Allow
```
After running the above commands, we note that `Get-HgsTrace` no longer reports errors with our certificates and requests to the Host Guardian Service are functioning correctly.