<#
.SYNOPSIS
    Creates an Always On VPN device tunnel connection

.PARAMETER xmlFilePath
    [MANDATORY] Path to the ProfileXML configuration file. If you just specify a filename, the script assumes the file is in the same directory as the script.

.PARAMETER DeviceTunnelVersion
    [MANDATORY] Version of the tunnel installation, used by CM for DetectionMethod (HKLM:\SOFTWARE\Advitum\AOVPNDeviceTunnelVersion)

.PARAMETER ProfileName
    Name of the VPN profile to be created (Default: DeviceTunnel)

.PARAMETER OldProfileName
    Name of the VPN profile to be deleted (Default: DeviceTunnel)

.PARAMETER EnableStatus
    Enables the UI-status for DeviceTunnel (Default: $false)

.PARAMETER EnhancedSecurity
    Enables enhanced security for the DeviceTunnel (Default: $false) (Settings made: -AuthenticationTransformConstants SHA256128 -CipherTransformConstants AES128 -DHGroup Group14 -EncryptionMethod AES128 -IntegrityCheckMethod SHA256 -PFSgroup PFS2048)

.EXAMPLE
    .\New-AovpnDeviceTunnel.ps1 -xmlFilePath "DeviceTunnel.xml" -DeviceTunnelVersion 3 -ProfileName "DeviceTunnel" -EnableStatus -EnhancedSecurity

.DESCRIPTION
    This script will create an Always On VPN device tunnel on supported Windows 10 devices

.LINK
    https://github.com/marcuswahlstam/AlwaysOnVPN/blob/main/Add-AlwaysOnVPNDeviceTunnel.ps1

.NOTES
    Creation Date:      April 13, 2021
    Last Updated:       April 13, 2021
    Note:               This is a modified version of a script that Jon Anderson has on his GitHub, which is based on the script Richard Hicks has on his GitHub
    Original Scripts:    https://github.com/richardhicks/aovpn/blob/master/New-AovpnDeviceConnection.ps1 and https://github.com/ConfigJon/AlwaysOnVPN/blob/master/New-AovpnDeviceTunnel.ps1
#>

[CmdletBinding()]

Param(
    [Parameter(Mandatory = $True, HelpMessage = 'Enter the path to the ProfileXML file.')]    
    [string]$xmlFilePath,
    [Parameter(Mandatory = $True, HelpMessage = 'Enter the DeviceTunnel version.')]    
    [int]$DeviceTunnelVersion,
    [Parameter(Mandatory = $False, HelpMessage = 'Enter a name for the VPN profile. (Default: DeviceTunnel)')]        
    [string]$ProfileName = 'DeviceTunnel',
    [Parameter(Mandatory = $False, HelpMessage = 'Enter a name for the old VPN profile to remove. (Default: DeviceTunnel)')]        
    [string]$OldProfileName = 'DeviceTunnel',
    [Parameter(Mandatory = $False, HelpMessage = 'Enable status in UI for DeviceTunnel, default is $false')]
    [switch]$EnableStatus = $False,
    [Parameter(Mandatory = $False, HelpMessage = 'Enable enhanced security for DeviceTunnel, default is $false')]
    [switch]$EnhancedSecurity = $False
)

#Variables ============================================================================================================
$RegKey = "SOFTWARE\Advitum"
$RegValue = "AOVPNDeviceTunnelVersion"
#$DeviceTunnelVersion = 3

#Functions ============================================================================================================
Function New-RegistryValue
{
    [CmdletBinding()]
    param(   
        [String][parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$RegKey,
        [String][parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Name,
        [String][parameter(Mandatory=$true)][ValidateSet('String','ExpandString','Binary','DWord','MultiString','Qword','Unknown')]$PropertyType,
        [String][parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Value
    )
        
    #Create the registry key if it does not exist
    if(!(Test-Path $RegKey))
    {
        try{New-Item -Path $RegKey -Force | Out-Null}
        catch{throw "Failed to create $RegKey"}
    }

    #Create the registry value
    try
    {
        New-ItemProperty -Path $RegKey -Name $Name -PropertyType $PropertyType -Value $Value -Force | Out-Null
    }
    catch
    {
        Write-LogEntry -Value "Failed to set $RegKey\$Name to $Value" -Severity 3
        throw "Failed to set $RegKey\$Name to $Value"
    }

    #Check if the registry value was successfully created
    $KeyCheck = Get-ItemProperty $RegKey
    if($KeyCheck.$Name -eq $Value)
    {
        Write-LogEntry -Value "Successfully set $RegKey\$Name to $Value" -Severity 1
    }
    else
    {
        Write-LogEntry -Value "Failed to set $RegKey\$Name to $Value" -Severity 3
        throw "Failed to set $RegKey\$Name to $Value"
    }
}

#Write data to a CMTrace compatible log file. (Credit to SCConfigMgr - https://www.scconfigmgr.com/)
Function Write-LogEntry
{
	param(
		[parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
		[ValidateNotNullOrEmpty()]
		[string]$Value,
		[parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("1", "2", "3")]
		[string]$Severity,
		[parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
		[ValidateNotNullOrEmpty()]
		[string]$FileName = "Install-AOVPN-Device.log"
	)
    #Determine log file location
    $LogFilePath = Join-Path -Path $LogsDirectory -ChildPath $FileName
		
    #Construct time stamp for log entry
    if(-not(Test-Path -Path 'variable:global:TimezoneBias'))
    {
        [string]$global:TimezoneBias = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
        if($TimezoneBias -match "^-")
        {
            $TimezoneBias = $TimezoneBias.Replace('-', '+')
        }
        else
        {
            $TimezoneBias = '-' + $TimezoneBias
        }
    }
    $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), $TimezoneBias)
		
    #Construct date for log entry
    $Date = (Get-Date -Format "MM-dd-yyyy")
		
    #Construct context for log entry
    $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
		
    #Construct final log entry
    $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""Install-AOVPN"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
		
    #Add value to log file
    try
    {
        Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
    }
    catch [System.Exception]
    {
        Write-Warning -Message "Unable to append log entry to $FileName file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
    }
}

#Main Program =========================================================================================================

#Set the log directory
$LogsDirectory = "$ENV:ProgramData\AOVPN"
if(!(Test-Path -PathType Container $LogsDirectory))
{
    New-Item -Path $LogsDirectory -ItemType "Directory" -Force | Out-Null
}

Write-LogEntry -Value "START - Always On VPN Device Tunnel Script" -Severity 1


#Script must be running in the context of the SYSTEM account to extract ProfileXML from a device tunnel connection. Validate user, exit if not running as SYSTEM
Write-LogEntry -Value "Detect if the script is being run in the SYSTEM context" -Severity 1
$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$CurrentUserName = $CurrentPrincipal.Identities.Name

if($CurrentUserName -ne 'NT AUTHORITY\SYSTEM')
{
    Write-LogEntry -Value "This script is not running in the SYSTEM context" -Severity 3
    Write-LogEntry -Value "Use the Sysinternals tool Psexec.exe with the -i and -s parameters to run this script in the context of the local SYSTEM account." -Severity 3
    throw "This script is not running in the SYSTEM context"
}

# Check if the specified configuration file exists
if ($xmlFilePath -notcontains "\")
{
    $xmlFilePath = Join-Path $PSScriptRoot $xmlFilePath
    if (-not (Test-Path $xmlFilePath))
    {
        #Can not find config file
        $ErrorMessage = "Unable to validate config file $xmlFilePath"
        Write-LogEntry -Value $ErrorMessage -Severity 3
        throw $ErrorMessage
    }
}
elseif ($xmlFilePath -contains "\") 
{
    if (-not (Test-Path $xmlFilePath))
    {
        #Can not find config file
        $ErrorMessage = "Unable to validate config file $xmlFilePath"
        Write-LogEntry -Value $ErrorMessage -Severity 3
        throw $ErrorMessage
    }
}
else 
{
    $ErrorMessage = "Unable to validate config file $xmlFilePath"
    Write-LogEntry -Value $ErrorMessage -Severity 3
    throw $ErrorMessage
}


#OMA URI information
$NodeCSPURI = './Vendor/MSFT/VPNv2'
$NamespaceName = 'root\cimv2\mdm\dmmap'
$ClassName = 'MDM_VPNv2_01'

#Check for existing connection and remove if found
Write-LogEntry -Value "Check for and remove old instances ($OldProfileName) of the device tunnel" -Severity 1
$Count = 0
while((Get-VpnConnection -Name $OldProfileName -AllUserConnection -ErrorAction SilentlyContinue) -and ($Count -lt 20))
{
    Write-LogEntry -Value "Existing device tunnel detected. Attempt to disconnect and remove ($($Count + 1)/20)" -Severity 1
    # Disconnect the tunnel
    rasdial.exe $OldProfileName /disconnect | Out-Null
    # Delete the tunnel
    Get-VpnConnection -Name $OldProfileName -AllUserConnection | Remove-VpnConnection -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $Count++
}

# Remove CIM Instance if above removal doesn't work
if(Get-VpnConnection -Name $OldProfileName -AllUserConnection -ErrorAction SilentlyContinue)
{
    Write-LogEntry -Value "Unable to remove existing outdated instance(s) of $OldProfileName gracefully, removing CIM Instance forcefully." -Severity 1
    Get-CimInstance -Namespace "$NamespaceName" -ClassName "$ClassName" | Remove-CimInstance
}

#Exit if the loop fails to delete the tunnel and the CIM Instance was not deleted
if(Get-VpnConnection -Name $OldProfileName -AllUserConnection -ErrorAction SilentlyContinue)
{
    $ErrorMessage = "Unable to remove existing outdated instance(s) of $OldProfileName"
    Write-LogEntry -Value $ErrorMessage -Severity 3
    throw $ErrorMessage
}

#Import the Profile XML
Write-LogEntry -Value "Import the device profile XML" -Severity 1
$ProfileXML = Get-Content $xmlFilePath

#Escape spaces in the profile name
$ProfileNameEscaped = $ProfileName -replace ' ', '%20'
$ProfileXML = $ProfileXML -replace '<', '&lt;'
$ProfileXML = $ProfileXML -replace '>', '&gt;'
$ProfileXML = $ProfileXML -replace '"', '&quot;'

#Create a new CimSession
$Session = New-CimSession

#Create the device tunnel
$Error.Clear()
try
{
    Write-LogEntry -Value "Construct a new CimInstance object" -Severity 1
    $NewInstance = New-Object Microsoft.Management.Infrastructure.CimInstance $ClassName, $NamespaceName
    $Property = [Microsoft.Management.Infrastructure.CimProperty]::Create('ParentID', "$nodeCSPURI", 'String', 'Key')
    $NewInstance.CimInstanceProperties.Add($Property)
    $Property = [Microsoft.Management.Infrastructure.CimProperty]::Create('InstanceID', "$ProfileNameEscaped", 'String', 'Key')
    $NewInstance.CimInstanceProperties.Add($Property)
    $Property = [Microsoft.Management.Infrastructure.CimProperty]::Create('ProfileXML', "$ProfileXML", 'String', 'Property')
    $NewInstance.CimInstanceProperties.Add($Property)
    Write-LogEntry -Value "Create the new device tunnel" -Severity 1
    $Session.CreateInstance($NamespaceName, $NewInstance)
    Write-LogEntry -Value "Always On VPN device tunnel ""$ProfileName"" created successfully." -Severity 1
}
catch [Exception]
{
    $ErrorMessage = "Unable to create $ProfileName profile: $_"
    Write-LogEntry -Value $ErrorMessage -Severity 3
    throw $ErrorMessage
}

#Configure enchanced IKEv2 security settings
if ($EnhancedSecurity)
{
    Set-VpnConnectionIPsecConfiguration -ConnectionName $ProfileName -AuthenticationTransformConstants SHA256128 -CipherTransformConstants AES128 -DHGroup Group14 -EncryptionMethod AES128 -IntegrityCheckMethod SHA256 -PFSgroup PFS2048 -Force
}

# Enable DeviceTunnel Status in UI
if ($EnableStatus)
{
    New-Item -Path ‘HKLM:\SOFTWARE\Microsoft\Flyout\VPN’ -Force
    New-ItemProperty -Path ‘HKLM:\Software\Microsoft\Flyout\VPN\’ -Name ‘ShowDeviceTunnelInUI’ -PropertyType DWORD -Value 1 -Force
}

#Create a registry key for detection
if(!($Error))
{
    Write-LogEntry -Value "Create the registry key to use for the detection method" -Severity 1
    #Create a registry key for detection
    New-RegistryValue -RegKey "HKLM:\$($RegKey)" -Name $RegValue -PropertyType DWord -Value $DeviceTunnelVersion
}
Write-LogEntry -Value "END - Always On VPN Device Tunnel Script" -Severity 1
