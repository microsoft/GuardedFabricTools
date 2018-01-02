# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Creation of an attestation report class to have meaningful data and formatting
class AttestationReport
{
    [DateTime] $Time
    [string] $HostName
    [string] $AttestationOperationMode
    [string] $AttestationStatus
    [string] $AttestationSubStatus
    [string] $AuthorizedHostGroup
    [string] $EndorsementKeyHash
}

#region Constants
$script:AttestationEventProviderName = "Microsoft-Windows-HostGuardianService-Attestation"

# The telling event that an attestation request passed.
$script:TcgLogValidationEventId = 1203

# AD based attestation status events
$script:AttestationAdStatusEvents = 
@{
    1519 = "Passed";
    1524 = "UnauthorizedHost"
}


$script:AttestationTpmSubStatusEvents = 
@{
        1500 = "NoInformation";
        1508 = "SecureBoot";
        1510 = "DebugMode";
        1513 = "CodeIntegrityPolicy";
        1523 = "NoInformation";
        1533 = "Iommu";
        1534 = "VirtualSecureMode";
        1535 = "PagefileEncryption";
        1536 = "BitLocker";
        1537 = "HypervisorEnforcedCodeIntegrityPolicy";
        1538 = "CodeIntegrityPolicy";
        1539 = "HibernationEnabled";
        1540 = "DumpsEnabled";
        1541 = "DumpEncryption";
        1542 = "DumpEncryptionKey"
}

$script:AttestationTpmStatusEvents =
@{
        1500 = "UnauthorizedHost";
        1508 = "InsecureHostConfiguration";
        1510 = "InsecureHostConfiguration";
        1513 = "InsecureHostConfiguration";
        1523 = "Passed";
        1533 = "InsecureHostConfiguration";
        1534 = "InsecureHostConfiguration";
        1535 = "InsecureHostConfiguration";
        1536 = "InsecureHostConfiguration";
        1537 = "InsecureHostConfiguration";
        1538 = "InsecureHostConfiguration";
        1539 = "InsecureHostConfiguration";
        1540 = "InsecureHostConfiguration";
        1541 = "InsecureHostConfiguration";
        1542 = "InsecureHostConfiguration";
}
#endregion

<#
.Synopsis
   Generates a report of attestation requests done by an HGS server
.DESCRIPTION
   The Get-HgsAttestationReport cmdlet obtains events from the HostGuardianService-Attestation event provider, and parses them to find the past attestation requests handled by this HGS Server.

   When running this cmdlet on or target in an HGS server that is a member of a cluster, it will attempt to find relevant events from all nodes.

   If -AD or -TPM is not passed through, it will report attestation requests of the current operation mode.
.EXAMPLE
   Get-HgsAttestationReport -AD -Tpm -StartTime (Get-Date).AddDays(-7)

   Generates a report of all AD and TPM based attestation requests handled by the targeted HGS server for the past seven days.
.EXAMPLE
   $cred = Get-Credential
   Get-HgsAttestationReport -ComputerName HgsServer.Contoso.Com -Credential $cred

   Generates a report of all attestation requests of the current operation mode handled by the targeted HGS server as far back as the event logs go.
#>
function Get-HgsAttestationReport
{
    [CmdletBinding(DefaultParameterSetName = 'LocalComputer')]
    param
    (
        # Specifies the earliest date to look for events
        [Parameter(Mandatory = $false)]
        [Alias("NotBefore")]
        [DateTime]
        $StartTime = [System.DateTime]::MinValue,
        # Specifies the latest date to look for events
        [Parameter(Mandatory = $false)]
        [Alias("NotAfter")]
        [DateTime] 
        $EndTime = [System.DateTime]::MaxValue,
        # Specifies if the parser should look for AD based attestation requests. If both -AD and -Tpm are not present, the search defaults to the target's current Attestation Operation Mode.
        [Alias("ParseADRequests")]
        [Parameter(Mandatory = $false)]
        [Switch]
        $AD,
        # Specifies if the parser should look for Tpm based attestation requests. If both -AD and -Tpm are not present, the search defaults to the target's current Attestation Operation Mode.
        [Parameter(Mandatory = $false)]
        [Alias("ParseTpmRequests")]
        [switch]
        $Tpm,
        # The name of the target computer.
        [Parameter(Mandatory = $true, ParameterSetName = "RemoteComputer")]
        [String]
        $ComputerName,
        # Credentials for invoking commands on the target computer
        [Parameter(Mandatory = $true, ParameterSetName = "RemoteComputer")]
        [PSCredential]
        $Credential,
        # PSSession Configuration Name for invoking commands
        [Parameter(Mandatory = $false)]
        [Alias("ConfigurationName")]
        [String]
        $EndpointName = "Microsoft.PowerShell"
    )
    
    if ($PSCmdlet.ParameterSetName -eq "LocalComputer")
    {
        try 
        {
            $HgsServerInfo = Get-HgsServer -ErrorAction Stop    
        }
        catch [Exception] 
        {
            Write-Error $_
            break
        }
    }

    else
    {
        try 
        {
            $HgsServerInfo = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ConfigurationName $EndpointName -ScriptBlock {Get-HgsServer} -ErrorAction Stop   
        }
        catch [Exception] 
        {
            Write-Error $_
            break
        }
    }

    # In the case of multiple nodes
    $HgsServerNodeNames = @()
    switch ($PSCmdlet.ParameterSetName)
    {
        "LocalComputer" { $HgsServerNodeNames += (Get-ClusterNode | Where-Object {$_.State -eq "Up"}).Name }
        "RemoteComputer" {$HgsServerNodeNames += (Invoke-Command -ComputerName $ComputerName -Credential $Credential -ConfigurationName $EndpointName -ScriptBlock {Get-ClusterNode}).Name}
    }

    if ($HgsServerNodeNames.Count -gt 1)
    {
        switch ($PSCmdlet.ParameterSetName)
        {
            "LocalComputer" { 
                Write-Warning ("This host is not the only member of the Host Guardian Service instance '{0}'. To collect all attestation requests handled by this instance, run this script targeting all of the machines of this instance: {1}" -f $HgsServerInfo.AttestationUrl[0].Host, ($HgsServerNodeNames -join "; "))
            }
            "RemoteComputer" 
            {
                # This will still give the netBIOS name even if the input computername is the netBIOS
                Write-Warning ("The host '{0}' is not the only member of the Host Guardian Service instance '{1}'. To collect all attestation requests handled by this instance, run this script targeting all of the machines of this instance: {2}" -f $ComputerName,$HgsServerInfo.AttestationUrl[0].Host, ($HgsServerNodeNames -join "; "))
            }
        }
    }

    if (!$Tpm -and !$AD)
    {
        # If we can get the current attestation operation mode, use that.
        if ($HgsServerInfo.AttestationOperationMode.Value -eq "Tpm" -or $HgsServerInfo.AttestationOperationMode -eq "Tpm")
        {
            $Tpm = $true
        }
        else 
        {
            $AD = $true    
        }
    }

    $EventIds = @()

    if ($AD)
    {
        $EventIds += $script:AttestationAdStatusEvents.Keys
    }

    if ($Tpm) 
    {
        $TpmEventIDs = $script:AttestationTpmStatusEvents.Keys + $script:TcgLogValidationEventId
        $EventIds += $TpmEventIds
    }

    $AttestationEvents = @()
    switch ($PSCmdlet.ParameterSetName)
    {
        "LocalComputer" {
                            $AttestationEvents += Get-WinEvent -ProviderName $script:AttestationEventProviderName -ErrorAction Stop| Where-Object {($EventIds -contains $_.Id) -and ($_.TimeCreated -gt $StartTime) -and ($_.TimeCreated -le $EndTime)} 
                        }
        "RemoteComputer" {
                            $AttestationEvents += Get-WinEvent -ProviderName $script:AttestationEventProviderName -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop| Where-Object {($EventIds -contains $_.Id) -and ($_.TimeCreated -gt $StartTime) -and ($_.TimeCreated -le $EndTime)} 
                        }
    }

    $AttestationRequests = @()

    if ($Tpm)
    {
        $TpmEvents = $AttestationEvents | Where-Object {$TpmEventIds -contains $_.Id}
        
        if ($PSCmdlet.ParameterSetName -eq "RemoteComputer")
        {
            $TpmBasedAttestationRequests = FindTpmRequests -Events $TpmEvents -ComputerName $ComputerName -Credential $Credential -ConfigurationName $EndpointName -UseRemote
        }
        else 
        {
            $TpmBasedAttestationRequests = FindTpmRequests -Events $TpmEvents    
        }

        $AttestationRequests += $TpmBasedAttestationRequests
    }

    if ($AD)
    {
        $AdEvents = $AttestationEvents | Where-Object {$script:AttestationAdStatusEvents.Keys -contains $_.Id}
        if ($PSCmdlet.ParameterSetName -eq "RemoteComputer")
        {
            $AdBasedAttestationRequests = FindADRequests -Events $AdEvents -ComputerName $ComputerName -Credential $Credential -ConfigurationName $EndpointName -UseRemote
        }
        else 
        {
            $AdBasedAttestationRequests = FindADRequests -Events $AdEvents    
        }

        $AttestationRequests += $AdBasedAttestationRequests
    }

    # Re-sort by time
    $AttestationRequests = $AttestationRequests | Sort-Object -Property Time -Descending
    
    Write-Output $AttestationRequests
}

<#
 Parse events into AD based attestation requests
#>
function FindADRequests
{
    param(
        [System.Array] 
        $Events, 
        [switch] 
        $UseRemote, 
        [string]
        $ComputerName, 
        [PSCredential]
        $Credential, 
        [String]
        $ConfigurationName
    )

    if ($UseRemote)
    {
        $AuthorizedADHostGroups = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ConfigurationName $ConfigurationName -ScriptBlock {Get-HgsAttestationHostGroup -WarningAction Ignore -ErrorAction Stop} -ErrorAction Stop
    }
    else 
    {
        $AuthorizedADHostGroups = Get-HgsAttestationHostGroup -WarningAction Ignore
    }
    
    $ADAttestationEventGroups = GroupEvents $Events

    $AdBasedAttestationRequests = @()
    foreach ($ActivityId in $ADAttestationEventGroups.Keys)
    {
        $AttestationRequest = [AttestationReport]::new()
        $AttestationRequest.AttestationOperationMode = "AD"
        $AttestationRequest.EndorsementKeyHash = "NotApplicable"
        $EventList = $ADAttestationEventGroups[$ActivityId] | Sort-Object TimeCreated

        # Use time of earliest event 
        $AttestationRequest.Time = ($EventList)[0].TimeCreated
        
        foreach ($event in $EventList)
        {
            if ($AttestationAdStatusEvents.ContainsKey($event.Id))
            {
                $AttestationRequest.AttestationStatus = $script:AttestationAdStatusEvents[$event.Id]
                if ($AttestationRequest.AttestationStatus -eq "Passed")
                {
                    $AttestationRequest.AttestationSubStatus = "NoInformation"
                    $AttestationRequest.HostName = $event.Properties.Value

                    # Check if it can't be cast into a SID. If it can, then its the HostGroup Identifier.  Otherwise, it should be used as the Host Name
                    # Known issue with this approach: if the SAM account name is somehow in the form of a SID, but this should not be possible.
                    foreach ($prop in $Event.Properties)
                    {
                        try
                        {
                            $sid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $prop.Value
                            $hostGroup = $AuthorizedADHostGroups | Where-Object {$_.Identifier -eq $sid.Value}
                            if ($hostGroup -ne $null) 
                            {
                                $AttestationRequest.AuthorizedHostGroup = $hostGroup.Name     
                            }
                            else 
                            {
                                $AttestationRequest.AuthorizedHostGroup = $sid.Value
                            }
                        }
                        catch
                        {
                            $AttestationRequest.HostName = $prop.Value
                        }
                    }
                }
                else
                {
                    # Otherwise, the only property associated with this event is the machine SID of the attesting client
                    $AttestationRequest.HostName = $event.Properties.Value
                    $AttestationRequest.AuthorizedHostGroup = "NotApplicable"
                }

                $AdBasedAttestationRequests += ,$AttestationRequest
            }
        }
    }

    return $AdBasedAttestationRequests
}

<#
 Parse events into TPM requests
#>
function FindTpmRequests
{
    param(
        [System.Array] $Events, 
        [switch] $UseRemote,
        [string] $ComputerName,
        [PSCredential] $Credential,
        [string] $ConfigurationName
        )

    if ($UseRemote)
    {
        # Only need to get settings from one node
        $AuthorizedTpmHosts = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ConfigurationName $ConfigurationName -ScriptBlock {Get-HgsAttestationTpmHost -WarningAction Ignore -ErrorAction Stop} -ErrorAction Stop
    }
    else 
    {
        $AuthorizedTpmHosts = Get-HgsAttestationTpmHost -WarningAction Ignore -ErrorAction Stop
    }

    $TpmAttestationEventGroups = GroupEvents $Events

    $TpmBasedAttestationRequests = @()

    # Iterate through attestation groups, generating an AttestationReport object
    foreach ($ActivityId in $TpmAttestationEventGroups.Keys)
    {
        $AttestationRequest = [AttestationReport]::new()
        $AttestationRequest.AttestationOperationMode = "Tpm"
        $AttestationRequest.AuthorizedHostGroup = "NotApplicable"
        $tpmEventList = $TpmAttestationEventGroups[$ActivityId] | Sort-Object TimeCreated
        # Get earliest event
        $AttestationRequest.Time = ($tpmEventList)[0].TimeCreated
        $HostNameFound = $false
        foreach ($event in $tpmEventList)
        {
            # Not all attestation failure events have the host EK attached to it.  Instead, use the ID from the event corresponding to starting the TCG log verification
            if ($event.Id -eq $script:TcgLogValidationEventId -and -not $HostNameFound)
            {
                $AttestationRequest.EndorsementKeyHash = $Event.Properties.Value
                $Hostname = ($AuthorizedTpmHosts | Where-Object {$_.Identifier -eq $event.Properties.value}).Name
                if ($Hostname)
                {
                    $AttestationRequest.HostName = $HostName
                }

                $HostNameFound = $true
            }

            if($AttestationTpmStatusEvents.ContainsKey($Event.Id))
            {
                $AttestationRequest.AttestationStatus = $AttestationTpmStatusEvents[$event.Id]

                # Account for multiple substatus reasons
                if ($AttestationRequest.AttestationSubStatus -ne $AttestationTpmSubStatusEvents[$event.Id])
                {
                    $AttestationRequest.AttestationSubStatus += $AttestationTpmSubStatusEvents[$event.Id]
                }

                if (-not $HostNameFound -and $AttestationRequest.AttestationStatus -eq "UnauthorizedHost")
                {
                    $AttestationRequest.HostName = 'UnauthorizedHost'
                    $AttestationRequest.EndorsementKeyHash = $Event.Properties.Value
                    $HostNameFound = $true
                }
            }
        }

        $TpmBasedAttestationRequests += ,$AttestationRequest
    }

    return $TpmBasedAttestationRequests
}


# Group an array of events into a dictionary based on their Activity ID's.
function GroupEvents([System.Array] $Events)
{
    $EventGroups = [ordered] @{}

    # Form groups based on the correlation Activity ID (on the HGS server, these all properly map to identical attestation requests)
    foreach ($event in $Events)
    {
        if ($EventGroups.Contains($event.ActivityId))
        {
            $EventGroups[$event.ActivityId] += ($event)
        }
        else
        {
            $EventGroups.Add($event.ActivityId, @($event))
        }
    }

    return $EventGroups
}