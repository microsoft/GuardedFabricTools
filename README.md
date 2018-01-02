# Guarded Fabric Tools

A PowerShell module containing tools to make deploying shielded virtual machines and managing a guarded fabric easier.

Included tools:
- **New-ShieldedVM** helps you deploy a shielded VM from PowerShell using a template disk and shielding data file. This function is intended for use on a guarded host.
- **New-ShieldingDataAnswerFile** generates answer files (also called unattend files) that automate configuration of Windows or Linux in a shielded VM. These answer files are compliant with System Center Virtual Machine Manager and `New-ShieldedVM`. This function is intended for use on the machine where you are preparing a shielding data file.
- **Get-HgsAttestationReport** queries the event log on an HGS server for information about recent attestation attempts to help you understand which hosts have tried attesting and whether or not they passed. This function is intended for use on an HGS server. [Additional documentation](./AttestationReport/Usage.md)
- **Add-AccessRule** and its accompanying extensions to the X509Certificate2 class in PowerShell allow you to manage the access control list (ACL) on certificate private keys through PowerShell. This function is intended for use on an HGS server when granting the group managed service account access to use the HGS encryption and signing keys. [Additional documentation](./CertificateManagement/Usage.md)

Check out the [official documentation](https://aka.ms/ShieldedVMs) for more information about shielded virtual machines in Windows Server.

## Installing

To use the Guarded Fabric Tools in a production environment, download and install the digitally signed module from the PowerShell Gallery. See [Guarded Fabric Tools on the PowerShell Gallery](https://www.powershellgallery.com/packages/GuardedFabricTools/).

Run the following command in PowerShell to install the module.

```powershell
Install-Module -Name GuardedFabricTools
```

If the computer where you're installing the module does not have internet connectivity, use [Save-Module](https://docs.microsoft.com/en-us/powershell/module/PowershellGet/Save-Module) to download the files and copy them manually to `C:\Program Files\WindowsPowerShell\Modules` on the target machine.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
