# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function New-ShieldingDataAnswerFile {

    <#
    .SYNOPSIS
    Creates an OS specialization answer file for use with shielded virtual machines.
    
    .DESCRIPTION
    Shielded VMs require unattended OS installations due to the security features that prevent you from seeing the VM console while the VM is running.
    These unattended installations require answer files to configure the operating system.
    For example, the administrator password must be set on your VM before you can use it.

    This function creates simple answer files for use with Windows and Linux shielded VMs that are compatible with System Center Virtual Machine Manager.
    SCVMM is not required to deploy VMs using these answer files, however they are designed to be compatible with it.

    Any text included in the answer file is encrypted in the shielding data file and cannot be changed by a malicious user.
    Such information includes your administrator password and domain join credentials.
    There are several substitution strings available for fields that must change when the VM is deployed, such as its computer name and static IP configuration, if required.
    These substitution strings are printed at the end of the command execution and should be supplied to New-ShieldedVMSpecializationDataFile with the actual, intended values.

    All answer files will include a command to turn off the VM after provisioning completes.
    This is required for most virtualization fabric managers to know when a shielded VM guest OS has finished specializing.
    
    .PARAMETER Path
    Location to save the answer file (.xml extension).
    
    .PARAMETER AdminCredentials
    The desired username and password for a new user account (with administrator privileges) to be created on the VM.
    
    .PARAMETER RootPassword
    The password for the root user account.

    .PARAMETER RootSshKey
    SSH public key blob to associate with the root user account.
    Either the path to a public key file (.pub) or the raw public key data can be provided.
    
    .PARAMETER DomainName
    Name of the Active Directory domain to which the VM should join.
    
    .PARAMETER DomainJoinCredentials
    User credentials privileged to join the VM to the specified Active Directory domain.
    
    .PARAMETER ProductKeyRequired
    Indicates that the VM OS requires a product key during installation.
    The product key will be provided at deployment time by Virtual Machine Manager or your fabric specialization keyfile.
    By default, the answer file will not include a field for the product key and assumes you have evaluation or volume licensed media.
    
    .PARAMETER RDPCertificatePath
    Path to a PFX file containing a certificate and private key that should be used to secure inbound Remote Desktop connections.
    
    .PARAMETER RDPCertificatePassword
    Password for the Remote Desktop certificate file.
    
    .PARAMETER StaticIPPool
    Indicates the VM should use a static IP address provided by a System Center Virtual Machine Manager IP pool.
    'All' will provision a static IPv4 address, IPv6 address, primary DNS server, and gateway.
    'IPv4Address' only provisions a static IPv4 address, primary DNS server, and gateway.
    'IPv6Address' only provisions a static IPv6 address, primary DNS server, and gateway.
    'DnsServerOnly' sets the primary DNS server but uses DHCP for IPv4 and IPv6 addresses.
    
    Omit this parameter if your VM should use DHCP to obtain its IPv4, IPv6 and DNS server addresses.
    
    .PARAMETER ConfigurationScript
    Path to any configuration scripts that should run during installation.
    Only .ps1 and .bat scripts are supported.
    
    .PARAMETER Locale
    Configures Windows to use a specific locale for language and UI elements.
    Defaults to en-US.
    
    .PARAMETER Force
    Skips all safety checks when creating the answer file. This switch will allow the use of default administrator account and overwrite existing files.
    
    .EXAMPLE
    $admin = Get-Credential 'administrator' -Message 'Local administrator account credentials'
    New-ShieldingDataAnswerFile -Path .\unattend.xml -AdminCredentials $admin

    Create a basic Windows answer file and sets the built-in administrator account password

    .EXAMPLE
    $admin = Get-Credential -Message "Local administrator account credentials"
    $djcred = Get-Credential -Message "Domain join credentials"
    New-ShieldingDataAnswerFile -Path .\unattend.xml -AdminCredentials $admin -DomainName 'contoso.com' -DomainJoinCredentials $djcred -ConfigurationScript .\mycustomconfig.ps1

    Create a Windows answer file that joins the VM to a domain and runs a configuration script

    .EXAMPLE
    $password = Read-Host -Prompt "Root Password" -AsSecureString
    New-ShieldingDataAnswerFile -Path ./linuxanswer.xml -RootPassword $password -RootSshKey ~/.ssh/id_rsa.pub

    Create a Linux answer file and associate your public SSH key with the root user account.
    #>
    
    [CmdletBinding(DefaultParameterSetName='WindowsAnswerFile')]

    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $Path,

        [Parameter(ParameterSetName='WindowsAnswerFile', Mandatory=$true)]
        [pscredential]
        $AdminCredentials,

        [Parameter(ParameterSetName='LinuxAnswerFile', Mandatory=$true)]
        [securestring]
        $RootPassword,

        [Parameter(ParameterSetName='LinuxAnswerFile')]
        [string]
        $RootSshKey,

        [Parameter(ParameterSetName='WindowsAnswerFile')]
        [string]
        $DomainName,

        [Parameter(ParameterSetName='WindowsAnswerFile')]
        [pscredential]
        $DomainJoinCredentials,

        [Parameter(ParameterSetName='WindowsAnswerFile')]
        [switch]
        $ProductKeyRequired,

        [Parameter(ParameterSetName='WindowsAnswerFile')]
        [string]
        $RDPCertificatePath,

        [Parameter(ParameterSetName='WindowsAnswerFile')]
        [securestring]
        $RDPCertificatePassword,

        [ValidateSet('All', 'IPv4Address', 'IPv6Address', 'DnsServerOnly')]
        [string]
        $StaticIPPool,

        [Parameter(ParameterSetName='WindowsAnswerFile')]
        [string[]]
        $ConfigurationScript,

        [Parameter(ParameterSetName='WindowsAnswerFile')]
        [ValidateSet("ar-SA", "bg-BG", "zh-HK", "zh-CN", "zh-TW", "hr-HR", "cs-CZ", "da-DK", "nl-NL", "en-US", "en-GB", "et-EE", "fi-FI", "fr-FR", "de-DE", "el-GR", "he-IL", "hu-HU", "it-IT", "ja-JP", "ko-KR", "lv-LV", "lt-LT", "nb-NO", "pl-PL", "pt-BR", "pt-PT", "ro-RO", "ru-RU", "sr-Latn-CS", "sr-Latn-RS", "sk-SK", "sl-SI", "es-ES", "sv-SE", "th-TH", "tr-TR", "uk-UA")]
        [string]
        $Locale = 'en-US',

        [switch]
        $Force = $false
    )

    $Windows = $PSCmdlet.ParameterSetName -eq 'WindowsAnswerFile'

    ## Parameter Validation
    # Ensure path has an XML extension
    if ($Path -notlike '*.xml') {
        throw [System.ArgumentException] "Answer file path must have a .xml extension"
    }

    # Validate path location
    $ParentPath = Split-Path $Path -Parent
    if ($ParentPath) {
        $ParentPath = Resolve-Path $ParentPath -ErrorAction SilentlyContinue

        if (-not (Test-Path $ParentPath -PathType Container)) {
            throw [System.IO.DirectoryNotFoundException] ("Answer file path is invalid: directory could not be found.")
        }
    }
    else {
        $ParentPath = Get-Location -PSProvider FileSystem
    }

    $Path = Join-Path $ParentPath (Split-Path $Path -Leaf)

    # Parse credentials
    if ($Windows) {
        $AdminUsername = $AdminCredentials.UserName
        $AdminPassword = $AdminCredentials.GetNetworkCredential().Password
    }
    else {
        $AdminUsername = 'root'
        $tempAdminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList 'root', $RootPassword
        $AdminPassword = $tempAdminCredential.GetNetworkCredential().Password
        $tempAdminCredential = $null
    }

    # Validate username
    if ([string]::IsNullOrEmpty($AdminUsername)) {
        throw [System.ArgumentException] 'Administrator username cannot be empty'
    }
    elseif ($Windows -and $AdminUsername -eq 'Administrator') {
        if ($Force) {
            Write-Warning "The built-in 'Administrator' account will be enabled by this answer file."
        }
        else {
            throw [System.ArgumentException] "It is not recommended to enable the built-in 'Administrator' account in the VM. Select a different username or use -Force if you are sure you want to use this account."
        }
    }
    elseif ($AdminUsername -and $Windows -and $AdminUsername -match '["/\\\[\]:;\|=,\+\*\?<>]+') {
        throw [System.ArgumentException] 'Administrator username cannot contain any of the following characters: " / \ [ ] : ; | = , + * ? < >'
    }

    # Validate password
    if ([string]::IsNullOrEmpty($AdminPassword)) {
        throw [System.ArgumentException] 'Administrator password cannot be empty'
    }

    # Ensure domain credentials are provided if a domain name is provided
    if ($DomainName -and -not $DomainJoinCredentials) {
        throw [System.ArgumentNullException] "Domain join credentials are required when a domain name is specified."
    }

    # Ensure the RDP certificate exists
    if ($RDPCertificatePath -and -not (Test-Path $RDPCertificatePath -PathType Leaf)) {
        throw [System.IO.FileNotFoundException] ("Could not find the RDP certificate at '{0}'. Please provide a path to a valid PFX file." -f $RDPCertificatePath)
    }

    # Ensure the RDP certificate is a PFX file
    if ($RDPCertificatePath -and $RDPCertificatePath -notlike '*.pfx') {
        throw [System.ArgumentException] "The RDP certificate must be in the Personal Information Exchange (.pfx) file format, containing both the certificate and its private key."
    }

    # Ensure an RDP certificate password is provided if an RDP certificate path is provided
    if ($RDPCertificatePath -and -not $RDPCertificatePassword) {
        throw [System.ArgumentNullException] "The RDP certificate password is required when an RDP certificate path is specified."
    }

    # Check if the RDP certificate password is valid for the specified file
    if ($RDPCertificatePath) {
        try {
            $null = Get-PfxData -FilePath $RDPCertificatePath -Password $RDPCertificatePassword
        }
        catch {
            throw [System.ArgumentException] "The RDP certificate password is invalid for the specified RDP certificate file."
        }
    }

    # Prevent users from passing more than one value to StaticIPPool if 'All' is included
    if ($StaticIPPool -and $StaticIPPool.Count -gt 1 -and ($StaticIPPool -contains 'All' -or $StaticIPPool -contains 'DnsServerOnly')) {
        throw [System.ArgumentException] "The Static IP Pool configuration specified is invalid. Valid combinations are: empty, 'All', 'DnsServerOnly', 'IPv4Address', 'IPv6Address', or both 'IPv4Address' and 'IPv6Address'."
    }

    # Validate configuration script extension for Windows
    if ($ConfigurationScript) {
        foreach ($script in $ConfigurationScript) {
            if ($script -notlike '*.ps1' -and $script -notlike '*.bat') {
                throw [System.ArgumentException] ("The configuration script '{0}' is invalid. Only PowerShell (.ps1) and batch scripts (.bat) are supported.")
            }
        }
    }

    ## Load the sample answer file
    $ScriptModulePath = Split-Path $PSCommandPath -Parent -Resolve | Convert-Path

    if ($Windows) {
        $AnswerFilePath = Join-Path $ScriptModulePath 'WindowsUnattend.xml'
    }
    else {
        $AnswerFilePath = Join-Path $ScriptModulePath 'LinuxUnattend.xml'
    }

    if (-not (Test-Path $AnswerFilePath -PathType Leaf)) {
        throw [System.IO.FileNotFoundException] ("Unable to load the template unattend file from '{0}'." -f $AnswerFilePath)
    }

    [xml]$AnswerFile = Get-Content -Path $AnswerFilePath -ErrorAction Stop

    $FilesToIncludeInPDK = @()
    $FSKSubstitutionStrings = @(
        [pscustomobject] @{ Key = '@ComputerName@'; Purpose = 'Network name for the VM' }
    )
    $FSK_IPv4Sub = $FSK_IPv6Sub = $FSK_DNSSub = $true

    if ($Windows) {
        $nsmgr = New-Object System.Xml.XmlNamespaceManager $AnswerFile.NameTable
        $nsmgr.AddNamespace('ns', 'urn:schemas-microsoft-com:unattend')
        $nsmgr.AddNamespace('xsi', 'http://www.w3.org/2001/XMLSchema-instance')
        $nsmgr.AddNamespace('wcm', 'http://schemas.microsoft.com/WMIConfig/2002/State')

        # Configure the local administrator account
        if ($AdminUsername -eq 'Administrator') {
            $AdminAccount = $AnswerFile.SelectSingleNode("//ns:AdministratorPassword", $nsmgr)
            $AdminAccount.Value = $AdminPassword

            $LocalAccounts = $AnswerFile.SelectSingleNode("//ns:LocalAccounts", $nsmgr)
            $null = $LocalAccounts.ParentNode.RemoveChild($LocalAccounts)
        }
        else {
            $LocalAccount = $AnswerFile.SelectSingleNode("//ns:LocalAccount", $nsmgr)
            $LocalAccount.Name = $AdminUsername
            $LocalAccount.Password.Value = $AdminPassword

            $AdminAccount = $AnswerFile.SelectSingleNode("//ns:AdministratorPassword", $nsmgr)
            $null = $AdminAccount.ParentNode.RemoveChild($AdminAccount)
        }
        
        # Remove product key if not required
        if (-not $ProductKeyRequired) {
            $pk = $AnswerFile.SelectSingleNode("//ns:ProductKey", $nsmgr)
            $null = $pk.ParentNode.RemoveChild($pk)
        }
        else {
            $FSKSubstitutionStrings += [pscustomobject] @{ Key = '@ProductKey@'; Purpose = 'Windows product key for activation' }
        }

        # Replace domain join information
        if ($DomainName) {
            $djinfo = $AnswerFile.SelectSingleNode("//ns:component[contains(@name, 'Microsoft-Windows-UnattendedJoin')]/ns:Identification", $nsmgr)
            $djinfo.JoinDomain = $DomainName

            $usercreds = $DomainJoinCredentials.GetNetworkCredential()

            if ($usercreds.Domain) {
                $userdomain = $usercreds.Domain
            }
            else {
                $userdomain = $DomainName
            }

            $djinfo.Credentials.Domain = $userdomain
            $djinfo.Credentials.Username = $usercreds.UserName
            $djinfo.Credentials.Password = $usercreds.Password
        }
        else {
            $djinfo = $AnswerFile.SelectSingleNode("//ns:component[contains(@name, 'Microsoft-Windows-UnattendedJoin')]", $nsmgr)
            $null = $djinfo.ParentNode.RemoveChild($djinfo)
        }

        # Add RDP certificate installation steps
        if ($RDPCertificatePath) {
            $flatname = Convert-Path $RDPCertificatePath | Split-Path -Leaf
            $password = (New-Object System.Management.Automation.PSCredential -ArgumentList 'anyuser', $RDPCertificatePassword).GetNetworkCredential().Password
            $passwordbytes = [System.Text.Encoding]::Unicode.GetBytes($password)
            $base64password = [System.Convert]::ToBase64String($passwordbytes)

            $RDPConfigPath = Join-Path $ParentPath 'RDPCertificateConfig.ps1'
            if ((Test-Path $RDPConfigPath) -and -not $Force) {
                throw [System.IO.IOException] ("RDP configuration file already exists at '{0}'. Use -Force to overwrite." -f $RDPConfigPath)
            }
            else {
                $command = @'
$Password = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("{0}"))
$SecurePassword = ConvertTo-SecureString -AsPlainText -String $Password -Force
$Certificate = Import-PfxCertificate -FilePath "$env:SystemDrive\temp\{1}" -Password $SecurePassword -CertStoreLocation Cert:\LocalMachine\My
Get-CimInstance -Namespace root/CIMV2/TerminalServices -ClassName Win32_TSGeneralSetting | Set-CimInstance -Property @{{ SSLCertificateSHA1Hash = $Certificate.Thumbprint }}
Remove-Item "$env:SystemDrive\temp\{1}" -Force
Remove-Item "$env:SystemDrive\temp\RDPCertificateConfig.ps1" -Force
'@ -f $base64password, $flatname

                Set-Content -Path $RDPConfigPath -Value $command -Force

                $firstCommand = $AnswerFile.SelectSingleNode("//ns:RunSynchronousCommand", $nsmgr)

                $clone = $firstCommand.CloneNode($true)
                $clone.Description = "Configures the RDP certificate"
                $clone.Path = 'cmd.exe /c "echo powershell.exe -File %SYSTEMDRIVE%\temp\RDPCertificateConfig.ps1" >> %WINDIR%\Setup\Scripts\SetupComplete.cmd'

                $null = $firstCommand.ParentNode.InsertBefore($clone, $firstCommand)

                $FilesToIncludeInPDK += [pscustomobject] @{ LocalPath = $RDPCertificatePath; VMPath = "%SYSTEMDRIVE%\temp\$flatname" }
                $FilesToIncludeInPDK += [pscustomobject] @{ LocalPath = $RDPConfigPath; VMPath = "%SYSTEMDRIVE%\temp\RDPCertificateConfig.ps1" }
            }
        }

        # Remove unnecessary networking nodes
        if ($StaticIPPool -ne 'All' -and $StaticIPPool -ne 'IPv4Address') {
            $IPNode = $AnswerFile.SelectSingleNode("//ns:Ipv4Settings", $nsmgr)
            $null = $IPNode.ParentNode.RemoveChild($IPNode)

            $IPv4Address = $AnswerFile.SelectSingleNode("//ns:component[contains(@name, 'Microsoft-Windows-TCPIP')]//ns:IpAddress[. = '@IP4Addr-1@']", $nsmgr)
            $IPv6Address = $AnswerFile.SelectSingleNode("//ns:component[contains(@name, 'Microsoft-Windows-TCPIP')]//ns:IpAddress[. = '@IP6Addr-1@']", $nsmgr)

            $null = $IPv4Address.ParentNode.RemoveChild($IPv4Address)
            $IPv6Address.keyValue = '1'

            $FSK_IPv4Sub = $false
        }
        if ($StaticIPPool -ne 'All' -and $StaticIPPool -ne 'IPv6Address') {
            $IPNode = $AnswerFile.SelectSingleNode("//ns:Ipv6Settings", $nsmgr)
            $null = $IPNode.ParentNode.RemoveChild($IPNode)

            $IPv6Address = $AnswerFile.SelectSingleNode("//ns:component[contains(@name, 'Microsoft-Windows-TCPIP')]//ns:IpAddress[. = '@IP6Addr-1@']", $nsmgr)
            $null = $IPv6Address.ParentNode.RemoveChild($IPv6Address)

            $FSK_IPv6Sub = $false
        }
        if (-not $StaticIPPool) {
            $IPNode = $AnswerFile.SelectSingleNode("//ns:component[contains(@name, 'Microsoft-Windows-TCPIP')]", $nsmgr)
            $null = $IPNode.ParentNode.RemoveChild($IPNode)

            $DnsNode = $AnswerFile.SelectSingleNode("//ns:component[contains(@name, 'Microsoft-Windows-DNS-Client')]", $nsmgr)
            $null = $DnsNode.ParentNode.RemoveChild($DnsNode)

            $FSK_IPv4Sub = $FSK_IPv6Sub = $FSK_DNSSub = $false
        }

        # Add configuration scripts
        if ($ConfigurationScript) {
            $originalnode = $AnswerFile.SelectSingleNode("//ns:RunSynchronousCommand", $nsmgr)
            $parentnode = $originalnode.ParentNode
            $templatenode = $originalnode.CloneNode($true)
            $null = $templatenode.RemoveChild($newnode.ChildNodes.Where({ $_.Name -eq 'Description'}))

            foreach ($script in $ConfigurationScript) {
                $newnode = $templatenode.CloneNode($true)

                $flatname = Split-Path -Path $script -Leaf

                if ($script -like '*.bat') {
                    $newnode.Path = 'cmd.exe /c "echo cmd.exe /c "%SYSTEMDRIVE%\temp\{0}"" >> %WINDIR%\Setup\Scripts\SetupComplete.cmd' -f $flatname
                }
                else {
                    $newnode.Path = 'cmd.exe /c "echo powershell.exe -File "%SYSTEMDRIVE%\temp\{0}"" >> %WINDIR%\Setup\Scripts\SetupComplete.cmd' -f $flatname
                }

                $null = $parentnode.InsertBefore($newnode, $originalnode)

                $FilesToIncludeInPDK += [pscustomobject] @{ LocalPath = $script; VMPath = ("%SYSTEMDRIVE%\temp\{0}" -f $flatname) }
            }
        }

        # Add command to delete existing setupcomplete.cmd if it exists
        $firstCommand = $AnswerFile.SelectSingleNode("//ns:RunSynchronousCommand", $nsmgr)
        $synchronousCommandsNode = $firstCommand.ParentNode
        $setupCompleteNode = $firstCommand.CloneNode($true)

        $setupCompleteNode.Description = "Delete existing setupcomplete.cmd file"
        $setupCompleteNode.Path = 'cmd.exe /c "IF EXIST %WINDIR%\Setup\Scripts\setupcomplete.cmd ( del /F %WINDIR%\Setup\Scripts\setupcomplete.cmd )"'
        $null = $synchronousCommandsNode.InsertBefore($setupCompleteNode, $firstCommand)

        # Add command to create script folder if it does not exist
        $scriptNode = $firstCommand.CloneNode($true)
        $scriptNode.Description = "Creates the scripts directory if required"
        $scriptNode.Path = 'cmd.exe /c "IF NOT EXIST %WINDIR%\Setup\Scripts ( md %WINDIR%\Setup\Scripts )"'
        $null = $synchronousCommandsNode.InsertBefore($scriptNode, $setupCompleteNode)

        # Ensure synchronous commands are ordered correctly
        $current = 1
        foreach ($commandnode in $AnswerFile.SelectSingleNode("//ns:RunSynchronous", $nsmgr).ChildNodes) {
            $commandnode.Order = $current.ToString()
            $current += 1
        }

        # Update locale placeholders
        $AnswerFile.SelectSingleNode("//ns:InputLocale", $nsmgr).'#text' = $Locale
        $AnswerFile.SelectSingleNode("//ns:UserLocale", $nsmgr).'#text' = $Locale
        $AnswerFile.SelectSingleNode("//ns:SystemLocale", $nsmgr).'#text' = $Locale
        $AnswerFile.SelectSingleNode("//ns:UILanguage", $nsmgr).'#text' = $Locale
    } # End Windows Configuration

    # Start Linux Configuration
    else {
        $nsmgr = New-Object System.Xml.XmlNamespaceManager $AnswerFile.NameTable
        $nsmgr.AddNamespace('ns', 'http://www.microsoft.com/schema/linuxvmmst')
        $nsmgr.AddNamespace('xsi', 'http://www.w3.org/2001/XMLSchema-instance')
        $nsmgr.AddNamespace('xsd', 'http://www.w3.org/2001/XMLSchema')
        $nsmgr.AddNamespace('d4p1', 'http://www.microsoft.com/schema/linuxvmmst')

        # Configure the administrator account
        $User = $AnswerFile.SelectSingleNode("//ns:User", $nsmgr)
        $User.Password = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($AdminPassword))

        # Configure the SSH key
        if ($RootSshKey) {
            # Check if a file path was provided
            if ((Test-Path -Path $RootSshKey -PathType Leaf -ErrorAction Continue)) {
                $RootSshKey = Get-Content -Path $RootSshKey -ErrorAction Stop
            }

            $User.SSHKey = $RootSshKey
        }
        else {
            $SSHKey = $User.SelectSingleNode("//ns:SSHKey", $nsmgr)
            $null = $User.RemoveChild($SSHKey)
        }

        # Configure networking
        if ($StaticIPPool -ne 'All' -and $StaticIPPool -ne 'IPv4Address') {
            $IPv4Node = $AnswerFile.SelectSingleNode("//ns:IPV4Property", $nsmgr)
            $null = $IPV4Node.ParentNode.RemoveChild($IPv4Node)

            $FSK_IPv4Sub = $false
        }
        if ($StaticIPPool -ne 'All' -and $StaticIPPool -ne 'IPv6Address') {
            $IPv6Node = $AnswerFile.SelectSingleNode("//ns:IPV6Property", $nsmgr)
            $null = $IPV6Node.ParentNode.RemoveChild($IPv6Node)

            $FSK_IPv6Sub = $false
        }
        if (-not $StaticIPPool) {
            $NetNode = $AnswerFile.SelectSingleNode("//ns:VNetAdapters", $nsmgr)
            $null = $NetNode.ParentNode.RemoveChild($NetNode)

            $FSK_IPv4Sub = $FSK_IPv6Sub = $FSK_DNSSub = $false
        }
    } # End Linux Configuration

    ## Finish collecting FSK substitution string messages
    if ($FSK_DNSSub) {
        $FSKSubstitutionStrings += [pscustomobject] @{ Key = '@MACAddr-1@'; Purpose = 'MAC address for vNIC' }            
        $FSKSubstitutionStrings += [pscustomobject] @{ Key = '@DnsAddr-1-1@'; Purpose = 'Static DNS server address' }
    }
    if ($FSK_IPv4Sub -or $FSK_IPv6Sub) {
        $FSKSubstitutionStrings += [pscustomobject] @{ Key = '@NextHop-1-1@'; Purpose = 'Static gateway address (e.g. 192.168.0.1)' }
        $FSKSubstitutionStrings += [pscustomobject] @{ Key = '@Prefix-1-1@'; Purpose = 'Prefix length for the route (e.g. 24)'}
    }
    if ($FSK_IPv4Sub) {
        $FSKSubstitutionStrings += [pscustomobject] @{ Key = '@IP4Addr-1@'; Purpose = 'Static IPv4 Address with prefix (CIDR notation)' }
    }
    if ($FSK_IPv6Sub) {
        $FSKSubstitutionStrings += [pscustomobject] @{ Key = '@IP6Addr-1@'; Purpose = 'Static IPv6 Address (CIDR notation)' }
    }

    ## Write answer file to disk
    if ((Test-Path $Path) -and -not $Force) {
        throw [System.IO.IOException] ("Answer file already exists at '{0}'. Use -Force to overwrite." -f $Path)
    }

    try {
        $AnswerFile.Save($Path)
    }
    catch {
        $e = [System.IO.IOException] "Unable to create the answer file."
        $e.InnerException = $_
        throw $e
    }

    ## Write required files and substitution strings to the console
    Write-Output ("Shielding data answer file was created successfully and saved to '{0}'" -f $Path)

    if ($FilesToIncludeInPDK.Count -gt 0) {
        Write-Output ""
        Write-Output "When creating your Shielding Data File, be sure to include the following items in the 'Other Files' section."
        Format-Table -AutoSize -InputObject $FilesToIncludeInPDK
    }

    Write-Output "", "The following substitution strings are included in the answer file and should be supplied when creating your shielded VM fabric specialization keyfile for a VM instance."
    Format-Table -AutoSize -InputObject $FSKSubstitutionStrings
}