# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function GetPdk($Path) {
    $pdk = CimCmdlets\Invoke-CimMethod -ClassName  Msps_ProvisioningFileProcessor -Namespace root\msps -MethodName PopulateFromFile -Arguments @{ FilePath = $ShieldingDataFilePath } -Verbose:$false -ErrorAction SilentlyContinue
    
    if (-not $pdk) {
        throw "Could not read PDK file."
    }

    return $pdk.ProvisioningFile
}

function GetSecuritySettingDataString($vm) {
    try {
        $cimvm = CimCmdlets\Get-CimInstance  -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter "Name = '$($vm.VMId)'" -Verbose:$false -ErrorAction Stop
        $vsd = CimCmdlets\Get-CimAssociatedInstance -InputObject $cimvm -ResultClassName "Msvm_VirtualSystemSettingData" -Verbose:$false -ErrorAction Stop
        $ssd = CimCmdlets\Get-CimAssociatedInstance -InputObject $vsd -ResultClassName "Msvm_SecuritySettingData" -Verbose:$false -ErrorAction Stop
        $cimSerializer = [Microsoft.Management.Infrastructure.Serialization.CimSerializer]::Create()
        $ssdString = [System.Text.Encoding]::Unicode.GetString($cimSerializer.Serialize($ssd, [Microsoft.Management.Infrastructure.Serialization.InstanceSerializationOptions]::None))
    }
    catch {
        throw "Could not read security setting data string"
    }

    return $ssdString
}

function GetSecurityService($vm) {
    try {
        $cimvm = CimCmdlets\Get-CimInstance -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter "Name = '$($vm.VMId)'" -Verbose:$false -ErrorAction Stop
        $ss = CimCmdlets\Get-CimAssociatedInstance -InputObject $cimvm -ResultClassName "Msvm_SecurityService" -Verbose:$false -ErrorAction Stop
    }
    catch {
        throw "Could not get security service for VM"
    }

    return $ss
}

function SetSecurityPolicy($vm, $pdk) {
    try {
        $ss = GetSecurityService -vm $vm
        $ssdString = GetSecuritySettingDataString -vm $vm
        $null = CimCmdlets\Invoke-CimMethod -InputObject $ss -MethodName SetSecurityPolicy -Arguments @{ "SecuritySettingData" = $ssdString; "SecurityPolicy" = $pdk.PolicyData } -Verbose:$false -ErrorAction Stop
    }
    catch {
        throw "Could not apply security policy to VM"
    }
}

function IsPdkForExistingVM($pdk) {
    return (-not $pdk.VolumeIDFilters)
}

function New-ShieldedVM {
    
    <#
    .SYNOPSIS
    Creates a new shielded virtual machine.
    
    .DESCRIPTION
    Creates a new shielded virtual machine using a prepared template disk and shielding data file.
    The virtual machine will go through shielded VM provisioning, which re-encrypts the OS volume
    and may take several minutes to complete. Use the -Wait parameter to observe the progress.
    
    .PARAMETER Name
    Name of the new virtual machine.
    
    .PARAMETER TemplateDiskPath
    Location of the template disk that has been prepared for use with shielded virtual machines.
    
    .PARAMETER ShieldingDataFilePath
    Location of the shielding data file used to configure the shielded VM.
    
    .PARAMETER SwitchName
    Name of network switch to which the VM should be connected.
    If no switch name is provided, and there is only one switch configured in Hyper-V, the VM will be connected to that switch.
    
    .PARAMETER Linux
    Indicates that the VM will run a Linux-based operating system.
    
    .PARAMETER MemoryStartupBytes
    Amount of memory to allocate to the VM (defaults to 2GB).
    
    .PARAMETER CpuCount
    Number of virtual processors to allocate to the VM (defaults to 2).
    
    .PARAMETER VMPath
    Location to store the resulting VM.
    If omitted, the default VM path configured in Hyper-V will be used for VM storage.
    
    .PARAMETER SpecializationValues
    Key-value pairs to replace in the shielding data answer file.
    @ComputerName@ is automatically set using the value of the -Name parameter, but can be overridden if desired.
    
    .PARAMETER Wait
    Shows the progress of the provisioning job and waits to return control until the VM is provisioned.
    
    .EXAMPLE
    New-ShieldedVM -Name 'CorpDC01' -TemplateDiskPath '.\WS2016-Template.vhdx' -ShieldingDataFilePath '.\DC.pdk' -SwitchName 'corpnet'

    Creates a new Windows shielded VM called "CorpDC01" using the specified templtae disk and shielding data file.

    .EXAMPLE
    New-ShieldedVM -Name 'ExampleVM' -TemplateDiskPath '.\template.vhdx' -ShieldingDataFilePath '.\myvm.pdk' -SpecializationValues @{ '@ComputerName@' = 'myVM01' }
    
    Creates a new Windows shielded VM with a custom replacement for the @ComputerName@ property in the shielding data answer file.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string]
        $TemplateDiskPath,

        [Parameter(Mandatory=$true)]
        [string]
        $ShieldingDataFilePath,
        
        [string]
        $SwitchName,

        [switch]
        $Linux,

        [ValidateRange(1GB, 1TB)]
        [Int64]
        $MemoryStartupBytes = 2GB,

        [ValidateRange(1,240)]
        [int]
        $CpuCount = 2,

        [string]
        $VMPath,

        [System.Collections.IDictionary]
        $SpecializationValues,

        [switch]
        $Wait
    )

    ## Parameter validation
    # Check for invalid names (relating to file paths assumed later)
    if ($Name -match '"|<|>|\||\\|/|\*|\?') {
        throw [System.ArgumentException] "Name cannot contain the following characters: `", ?, *, |, \, /, <, >"
    }

    # Ensure template disk exists
    $TemplateDiskPath = Microsoft.PowerShell.Management\Resolve-Path $TemplateDiskPath -ErrorAction Stop | Microsoft.PowerShell.Management\Convert-Path
    if (-not (Microsoft.PowerShell.Management\Test-Path $TemplateDiskPath -PathType Leaf) -or $TemplateDiskPath -notlike "*.vhdx") {
        throw [System.IO.FileNotFoundException] "The template disk path is invalid."
    }

    # Ensure shielding data file exists
    $ShieldingDataFilePath = Microsoft.PowerShell.Management\Resolve-Path $ShieldingDataFilePath -ErrorAction Stop | Microsoft.PowerShell.Management\Convert-Path
    if (-not (Microsoft.PowerShell.Management\Test-Path $ShieldingDataFilePath -PathType Leaf) -or $ShieldingDataFilePath -notlike "*.pdk") {
        throw [System.IO.FileNotFoundException] "The shielding data file path is invalid."
    }

    # Ensure the switch name is valid
    if ($SwitchName -and -not (Hyper-V\Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
        throw [System.ArgumentException] ("A networking switch with the name '{0}' could not be found on the host." -f $SwitchName)
    }
    elseif (-not $SwitchName) {
        $switches = Hyper-V\Get-VMSwitch
        if ($switches.Count -eq 1)
        {
            Microsoft.PowerShell.Utility\Write-Verbose ("No switch name was provided. The VM will be connected to the '{0}' switch." -f $switches.Name)
            $SwitchName = $switches.Name
        }
        else {
            throw [System.ArgumentException] ("More than one VM switch was found. Re-run the command and specify one of the following switch names to the -SwitchName parameter: {0}" -f `
                [string]::Join(', ', $switches.Name))
        }
    }

    # Ensure the VM path is valid
    if ($VMPath) {
        $VMPath = Microsoft.PowerShell.Management\Resolve-Path $VMPath -ErrorAction Stop | Microsoft.PowerShell.Management\Convert-Path
        if (-not (Microsoft.PowerShell.Management\Test-Path $VMPath -PathType Container)) {
            throw [System.IO.DirectoryNotFoundException] "The VM path is not a valid directory."
        }

        $VhdDirectory = Microsoft.PowerShell.Management\Join-Path $VMPath "Virtual Hard Disks"
        if (-not (Microsoft.PowerShell.Management\Test-Path $VhdDirectory)) {
            Microsoft.PowerShell.Utility\Write-Verbose ("Creating directory for VHD at '{0}'" -f $VhdDirectory)
            $null = Microsoft.PowerShell.Management\New-Item $VhdDirectory -ItemType Directory
        }
    }
    else {
        $vmroot = (Hyper-V\Get-VMHost).VirtualMachinePath
        $VMPath = Microsoft.PowerShell.Management\Join-Path $vmroot $Name
        
        if ((Microsoft.PowerShell.Management\Test-Path $VMPath)) {
            foreach ($i in 1..999) {
                $samplePath = "{0}-{1:D3}" -f $Name, $i
                $VMPath = Microsoft.PowerShell.Management\Join-Path $vmroot $samplePath
                if (-not (Microsoft.PowerShell.Management\Test-Path $VMPath)) {
                    break
                }
            }
        }

        Microsoft.PowerShell.Utility\Write-Verbose ("Creating a VM directory at '{0}'" -f $VMPath)
        $null = Microsoft.PowerShell.Management\New-Item -Path $VMPath -ItemType Directory -ErrorAction Stop
        $VhdDirectory = Microsoft.PowerShell.Management\Join-Path $VMPath "Virtual Hard Disks"
        $null = Microsoft.PowerShell.Management\New-Item -Path $VhdDirectory -ItemType Directory -ErrorAction Stop
    }

    # Ensure specialization values are not null
    if ($SpecializationValues) {
        foreach ($key in $SpecializationValues.Keys) {
            if ($key -isnot [string] -or $key -notlike "@*@") {
                throw [System.ArgumentException] ("Specialization key '{0}' is invalid. All specialization keys must be in the form '@KeyName@'." -f $key)
            }

            $value = $SpecializationValues.$key
            if ($value -isnot [string] -or [string]::IsNullOrEmpty($value)) {
                throw [System.ArgumentException] ("The value for specialization key '{0}' is invalid. Values must be non-empty strings." -f $key)
            }
        }
    }

    ## Create the VM
    $VHDPath = Microsoft.PowerShell.Management\Join-Path $VhdDirectory "$Name-OS.vhdx"
    Microsoft.PowerShell.Utility\Write-Verbose ("Copying the template disk to '{0}'" -f $VHDPath)
    Microsoft.PowerShell.Management\Copy-Item -Path $TemplateDiskPath -Destination $VHDPath -ErrorAction Stop

    Microsoft.PowerShell.Utility\Write-Verbose "Creating the new VM"
    $vm = Hyper-V\New-VM -Name $Name -Generation 2 -Path $VMPath -VhdPath $VHDPath -SwitchName $SwitchName -MemoryStartupBytes $MemoryStartupBytes -ErrorAction Stop
    Hyper-V\Set-VMProcessor -VM $vm -Count $CpuCount

    if ($Linux) {
        Hyper-V\Set-VMFirmware -VM $vm -SecureBootTemplate OpenSourceShieldedVM -ErrorAction Stop
    }

    # Attach the key protector
    $kp = Get-KeyProtectorFromShieldingDataFile -ShieldingDataFilePath $ShieldingDataFilePath
    Hyper-V\Set-VMKeyProtector -VM $vm -KeyProtector $kp -ErrorAction Stop

    # Get the security data from the PDK file
    try {
        $pdk = CimCmdlets\Invoke-CimMethod -ClassName  Msps_ProvisioningFileProcessor -Namespace root\msps -MethodName PopulateFromFile -Arguments @{ FilePath = $ShieldingDataFilePath } -Verbose:$false -ErrorAction Stop
        $cimvm = CimCmdlets\Get-CimInstance  -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter "Name = '$($vm.VMId)'" -Verbose:$false -ErrorAction Stop
        $vsd = CimCmdlets\Get-CimAssociatedInstance -InputObject $cimvm -ResultClassName "Msvm_VirtualSystemSettingData" -Verbose:$false -ErrorAction Stop
        $ssd = CimCmdlets\Get-CimAssociatedInstance -InputObject $vsd -ResultClassName "Msvm_SecuritySettingData" -Verbose:$false -ErrorAction Stop
        $ss = CimCmdlets\Get-CimAssociatedInstance -InputObject $cimvm -ResultClassName "Msvm_SecurityService" -Verbose:$false -ErrorAction Stop
        $cimSerializer = [Microsoft.Management.Infrastructure.Serialization.CimSerializer]::Create()
        $ssdString = [System.Text.Encoding]::Unicode.GetString($cimSerializer.Serialize($ssd, [Microsoft.Management.Infrastructure.Serialization.InstanceSerializationOptions]::None))
    }
    catch {
        throw "A security policy could not be created from the shielding data file.`n`n$($_.Message)"
    }

    # Apply the VM security policy and enable the VM TPM
    Microsoft.PowerShell.Utility\Write-Verbose "Enabling VM TPM"
    $null = CimCmdlets\Invoke-CimMethod -InputObject $ss -MethodName SetSecurityPolicy -Arguments @{ "SecuritySettingData" = $ssdString; "SecurityPolicy" = $pdk.ProvisioningFile.PolicyData } -Verbose:$false -ErrorAction Stop
    Hyper-V\Enable-VMTPM -VM $vm -ErrorAction Stop

    # Create the fabric specialization keyfile
    Microsoft.PowerShell.Utility\Write-Verbose "Creating specialization data file"
    $fskPath = Microsoft.PowerShell.Management\Join-Path $VMPath "SpecializationData.fsk"
    $simpleComputerName = $Name -replace '[^\w-]', ''
    $fskParams = @{ '@ComputerName@' = $simpleComputerName }
    
    if ($SpecializationValues) {
        foreach ($key in $SpecializationValues.Keys) {
            $fskParams.$key = $SpecializationValues.$key
        }
    }

    ShieldedVMProvisioning\New-ShieldedVMSpecializationDataFile -ShieldedVMSpecializationDataFilePath $fskPath -SpecializationDataPairs $fskParams -ErrorAction Stop

    # Provision the VM
    Microsoft.PowerShell.Utility\Write-Verbose "Initiating shielded VM provisioning process"
    $provisioningJob = ShieldedVMProvisioning\Initialize-ShieldedVM -VM $vm -ShieldingDataFilePath $ShieldingDataFilePath -ShieldedVMSpecializationDataFilePath $fskPath -ErrorAction Stop

    if ($Wait) {
        do {
            $status = ShieldedVMProvisioning\Get-ShieldedVMProvisioningStatus -VM $vm
            Write-Progress -Activity ("Provisioning shielded VM '{0}'" -f $Name) -PercentComplete $status.PercentComplete -Status ("{0}% complete" -f $Status.PercentComplete)
            Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 1500
        }
        while ($status -and $status.Status -ne 'Error' -and $status.PercentComplete -lt 100)

        if ($status) {
            Microsoft.PowerShell.Utility\Write-Output $status.JobStatus

            if ($status.ErrorDescription) {
                Microsoft.PowerShell.Utility\Write-Error $status.ErrorDescription
            }
        }
        else {
            Microsoft.Powershell.Utility\Write-Output "Unable to check the status of the shielded VM provisioning process."
        }
    }
    else {
        return $provisioningJob
    }
}

function ConvertTo-ShieldedVM {
    <#
    .SYNOPSIS
    Converts an existing virtual machine to a shielded virtual machine.
    
    .DESCRIPTION
    Converts an existing virtual machine to a shielded virtual machine by applying a virtual TPM and security policy to the VM.
    The VM will not automatically be encrypted by this command, but encryption can be enabled inside the guest OS after the virtual TPM is available.
    See https://aka.ms/AA3trat for information about automating the encryption of existing VMs.
    
    .PARAMETER VM
    Specifies the virtual machine to convert to a shielded virtual machine.
    
    .PARAMETER VMName
    Specifies the name of the virtual machine to convert to a shielded virtual machine.

    .PARAMETER ShieldingDataFilePath
    Path to a shielding data file used to shield the VM.
    The security policy and key protector from the shielding data file are applied to the specified VM.
    Answer files and additional files included in the shielding data file are not copied into the VM.
    
    .EXAMPLE
    $vm = Get-VM "SQL01"
    ConvertTo-ShieldedVM -VM $vm -ShieldingDataFilePath 'D:\ShieldingData\existingvm.pdk'

    Converts the "SQL01" virtual machine to a shielded virtual machine using the specified shielding data file.

    .EXAMPLE
    ConvertTo-ShieldedVM -VMName "CORPDC01" -ShieldingDataFilePath 'D:\ShieldingData\existingvm.pdk'

    Converts the "CORPDC01" virtual machine to a shielded virtual machine using the specified shielding data file.
    #>

    [CmdletBinding(DefaultParameterSetName="ByName", SupportsShouldProcess=$true, ConfirmImpact="Medium")]
    param(
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="ByVM")]
        [ValidateNotNullOrEmpty()]
        [Microsoft.HyperV.PowerShell.VirtualMachine]
        $VM,

        [Parameter(Mandatory=$true, Position=0, ParameterSetName="ByName")]
        [ValidateNotNullOrEmpty()]
        [string]
        $VMName,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ShieldingDataFilePath
    )

    ## Parameter validation
    # Check VM name
    if ($PSCmdlet.ParameterSetName -eq "ByName") {
        $VM = Get-VM -Name $VMName -ErrorAction Stop
    }

    # Check if VM can be shielded
    if ($VM.Generation -ne 2) {
        throw "The specified virtual machine is a generation 1 VM. Only generation 2 VMs can be shielded."
    }

    $kp = Get-VMKeyProtector -VM $VM
    if ($kp.Length -gt 4) {
        throw "The specified virtual machine has already been configured with a key protector. To change the key protector, delete the VM configuration and create a new one. This will also delete the virtual TPM associated with this VM and could result in data loss if data encryption is not suspended first."
    }

    $firmware = Get-VMFirmware -VM $VM
    if ($firmware.SecureBoot -ne "On") {
        throw "Secure Boot must be enabled on the virtual machine before it can be shielded."
    }

    if ($vm.State -ne 'Off') {
        throw "The virtual machine must be turned off before it can be shielded."
    }

    $vmVersion = [System.Version] $vm.Version
    $minVersion = [System.Version] "8.0"
    if ($vmVersion -lt $minVersion) {
        $latestVersion = (Get-VMHostSupportedVersion -Default).Version.ToString()
        throw "The virtual machine configuration version is currently $($vm.Version) but must be upgraded before the virtual machine can be shielded. Run `"Update-VMVersion '$($vm.Name)'`" to upgrade the VM to version $latestVersion." 
    }

    # Ensure shielding data file exists
    $ShieldingDataFilePath = Microsoft.PowerShell.Management\Resolve-Path $ShieldingDataFilePath -ErrorAction Stop | Microsoft.PowerShell.Management\Convert-Path
    if (-not (Microsoft.PowerShell.Management\Test-Path $ShieldingDataFilePath -PathType Leaf) -or $ShieldingDataFilePath -notlike "*.pdk") {
        throw [System.IO.FileNotFoundException] "The shielding data file path is invalid."
    }

    # Try opening the shielding data file
    try {
        $pdk = GetPDK -Path $ShieldingDataFilePath
        
        if (-not $pdk -or -not $pdk.PolicyData) {
            throw "Could not parse the shielding data file."
        }
    }
    catch {
        throw "Could not open the shielding data file."
    }

    # Warn if differencing disks are in use
    $VHDs = Get-VMHardDiskDrive -VM $VM
    foreach ($vhd in $VHDs) {
        $vhdDetails = Get-VHD -Path $vhd.Path
        if ($vhdDetails.VhdType -eq "Differencing") {
            Write-Warning "The specified virtual machine uses one or more differencing disks. To ensure all data is protected when you encrypt data on this virtual machine, delete all checkpoints and merge any differencing disks before enabling full volume encryption. Existing backups, checkpoints, and parent VHDs will not be encrypted if the guest OS enables full volume encryption."
            break
        }
    }

    ## Convert the VM
    if ($PSCmdlet.ShouldProcess("Converting '$($VM.Name)' to a shielded virtual machine", "Are you sure you want to convert '$($VM.Name)' to a shielded virtual machine?", "Shield existing VM")) {
        # Upgrade the VM version if necessary
        if ($vmVersion -lt $minVersion) {
            Write-Verbose "Upgrading VM version"
            Update-VMVersion -VM $VM -Force
        }

        # Attach the key protector
        Write-Verbose "Setting key protector on VM"
        $kp = Get-KeyProtectorFromShieldingDataFile -ShieldingDataFilePath $ShieldingDataFilePath
        Set-VMKeyProtector -VM $vm -KeyProtector $kp -ErrorAction Stop

        # Set the security policy
        Write-Verbose "Applying security policy to the VM"
        SetSecurityPolicy -vm $VM -pdk $pdk

        # Enable the VM TPM
        Write-Verbose "Enabling the VM TPM"
        Enable-VMTPM -VM $VM -ErrorAction Stop

        Write-Output "The virtual TPM has been enabled on the VM. To encrypt the VM data, turn on the VM and enable full volume encryption (leveraging the TPM to protect the encryption key) using the instructions for your operating system."
    }
}