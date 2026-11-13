<#
.SYNOPSIS
    Read-only collection for the endpoint security coverage review: Intune managed devices (with the Defender antivirus state of
    Windows devices), the BitLocker recovery keys in Entra ID (ids and dates only, never the key), and, from files you export, the
    Defender for Endpoint device inventory and the local administrators reported by Detect-LocalAdmins.ps1.

.DESCRIPTION
    Writes to the output folder:
      intune.csv          deviceName, serialNumber, azureADDeviceId, operatingSystem, osVersion, complianceState, isEncrypted,
                          lastSyncDateTime, userPrincipalName, managedDeviceOwnerType, and for Windows devices
                          realTimeProtectionEnabled, signatureUpdateOverdue, tamperProtectionEnabled
      recovery-keys.csv   id, deviceId, volumeType, createdDateTime (no key values)
      defender.csv        from -DefenderCsv (the device inventory export of the Defender portal), with the columns renamed
      local-admins.csv    from -RemediationCsv (the device status export of the Detect-LocalAdmins remediation)

    Nothing is changed in Intune, Entra ID or Defender. Graph permissions (delegated): DeviceManagementManagedDevices.Read.All and
    BitlockerKey.ReadBasic.All; reading recovery key metadata also needs one of the Entra roles that the API lists, for example
    Security Reader or Global Reader. The antivirus state comes from the beta endpoint windowsProtectionState, one call per Windows
    device; use -SkipProtectionState on a large estate or when the beta endpoint is not allowed.

.EXAMPLE
    .\Collect-EndpointCoverage.ps1 -OutputFolder .\data -DefenderCsv .\downloads\defender-devices.csv `
        -RemediationCsv .\downloads\detect-localadmins.csv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $OutputFolder,
    [string] $DefenderCsv,
    [string] $RemediationCsv,
    [switch] $SkipProtectionState,
    [string] $TenantId
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null

function Get-Col($row, [string[]] $names) {
    foreach ($n in $names) {
        $p = $row.PSObject.Properties | Where-Object { $_.Name -ieq $n } | Select-Object -First 1
        if ($p) { return [string]$p.Value }
    }
    return ''
}

# ------------------------------------------------------------------ Microsoft Graph
foreach ($m in 'Microsoft.Graph.Authentication', 'Microsoft.Graph.DeviceManagement', 'Microsoft.Graph.Identity.SignIns') {
    if (-not (Get-Module -ListAvailable -Name $m)) { throw "Module $m is missing: Install-Module Microsoft.Graph -Scope CurrentUser" }
}
$connect = @{ Scopes = 'DeviceManagementManagedDevices.Read.All', 'BitlockerKey.ReadBasic.All'; NoWelcome = $true }
if ($TenantId) { $connect.TenantId = $TenantId }
Connect-MgGraph @connect

Write-Host 'Intune managed devices...'
$props = 'id,deviceName,serialNumber,azureADDeviceId,operatingSystem,osVersion,complianceState,isEncrypted,lastSyncDateTime,' +
         'userPrincipalName,managedDeviceOwnerType'
$devices = Get-MgDeviceManagementManagedDevice -All -Property $props
$i = 0
$rows = foreach ($d in $devices) {
    $i++
    $rtp = ''; $sig = ''; $tamper = ''
    if (-not $SkipProtectionState -and $d.OperatingSystem -eq 'Windows') {
        Write-Progress -Activity 'Antivirus state' -Status $d.DeviceName -PercentComplete (100 * $i / $devices.Count)
        try {
            $ps = Invoke-MgGraphRequest -Method GET -OutputType PSObject `
                -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($d.Id)/windowsProtectionState"
            $rtp = $ps.realTimeProtectionEnabled; $sig = $ps.signatureUpdateOverdue; $tamper = $ps.tamperProtectionEnabled
        } catch {
            Write-Warning "$($d.DeviceName): no protection state ($($_.Exception.Message))"
        }
    }
    [pscustomobject]@{
        deviceName                = $d.DeviceName
        serialNumber              = $d.SerialNumber
        azureADDeviceId           = $d.AzureAdDeviceId
        operatingSystem           = $d.OperatingSystem
        osVersion                 = $d.OsVersion
        complianceState           = $d.ComplianceState
        isEncrypted               = $d.IsEncrypted
        lastSyncDateTime          = if ($d.LastSyncDateTime) { $d.LastSyncDateTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' }
        userPrincipalName         = $d.UserPrincipalName
        managedDeviceOwnerType    = $d.ManagedDeviceOwnerType
        realTimeProtectionEnabled = $rtp
        signatureUpdateOverdue    = $sig
        tamperProtectionEnabled   = $tamper
    }
}
Write-Progress -Activity 'Antivirus state' -Completed
$rows | Export-Csv (Join-Path $OutputFolder 'intune.csv') -NoTypeInformation -Encoding UTF8
Write-Host "  $($rows.Count) devices"

Write-Host 'BitLocker recovery keys (metadata only)...'
$keys = Get-MgInformationProtectionBitlockerRecoveryKey -All | ForEach-Object {
    [pscustomobject]@{
        id              = $_.Id
        deviceId        = $_.DeviceId
        volumeType      = $_.VolumeType
        createdDateTime = if ($_.CreatedDateTime) { $_.CreatedDateTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' }
    }
}
$keys | Export-Csv (Join-Path $OutputFolder 'recovery-keys.csv') -NoTypeInformation -Encoding UTF8
Write-Host "  $(@($keys).Count) keys"

# ------------------------------------------------------------------ Defender for Endpoint (portal export)
if ($DefenderCsv) {
    Write-Host 'Defender for Endpoint device inventory...'
    $def = Import-Csv $DefenderCsv | ForEach-Object {
        [pscustomobject]@{
            computerDnsName  = Get-Col $_ 'Device Name', 'computerDnsName', 'Name'
            aadDeviceId      = Get-Col $_ 'Aad Device Id', 'aadDeviceId', 'Microsoft Entra Device ID', 'Entra device ID'
            osPlatform       = Get-Col $_ 'OS Platform', 'osPlatform'
            onboardingStatus = Get-Col $_ 'Onboarding Status', 'onboardingStatus'
            healthStatus     = Get-Col $_ 'Health Status', 'Sensor health state', 'healthStatus'
            lastSeen         = Get-Col $_ 'Last Seen', 'Last device update', 'lastSeen'
            exposureLevel    = Get-Col $_ 'Exposure Level', 'exposureLevel'
        }
    }
    $def | Export-Csv (Join-Path $OutputFolder 'defender.csv') -NoTypeInformation -Encoding UTF8
    Write-Host "  $(@($def).Count) devices"
} else {
    Write-Warning 'No -DefenderCsv: export the device inventory from the Defender portal (Assets > Devices > Export) and save it as defender.csv'
}

# ------------------------------------------------------------------ local administrators (remediation export)
if ($RemediationCsv) {
    Write-Host 'Local administrators...'
    $adm = foreach ($r in Import-Csv $RemediationCsv) {
        $dev = Get-Col $r 'Device name', 'DeviceName', 'Device'
        $out = Get-Col $r 'Pre-remediation detection output', 'Detection output', 'PreRemediationDetectionScriptOutput', 'Output'
        if (-not $dev -or -not $out -or -not $out.StartsWith('ADMINS:')) { continue }
        foreach ($m in $out.Substring(7).Split(';')) {
            if (-not $m.Trim()) { continue }
            $name, $kind = $m.Split('|', 2)
            [pscustomobject]@{ Device = $dev; Account = $name.Trim(); Type = "$kind".Trim() }
        }
    }
    $adm | Export-Csv (Join-Path $OutputFolder 'local-admins.csv') -NoTypeInformation -Encoding UTF8
    Write-Host "  $(@($adm).Count) memberships"
}

Disconnect-MgGraph | Out-Null
Write-Host "Done. Add inventory.csv (from the CMDB), epm-elevations.csv (Intune EPM elevation report) and exceptions.csv to $OutputFolder."
