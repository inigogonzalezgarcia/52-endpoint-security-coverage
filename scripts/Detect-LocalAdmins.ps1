<#
.SYNOPSIS
    Detection script for Intune Remediations: reports the members of the local Administrators group as one line of output, so the
    device status export of the remediation becomes local-admins.csv (Collect-EndpointCoverage.ps1 -RemediationCsv).

.DESCRIPTION
    Read-only: it changes nothing and has no remediation script. Run it as System, in 64-bit PowerShell, on a daily schedule.
    Output: ADMINS:<name>|<class>;<name>|<class>;...  Exit code 0 always, so the device shows "Without issues" and the output is kept.
    The group is found by its well-known SID (S-1-5-32-544), so it works on any display language. Get-LocalGroupMember fails on
    groups with orphaned members; then it falls back to the ADSI provider.
#>
$ErrorActionPreference = 'Stop'
try {
    $members = Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { "$($_.Name)|$($_.ObjectClass)" }
} catch {
    $group = [ADSI]"WinNT://$env:COMPUTERNAME/$((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]),group"
    $members = @($group.Invoke('Members')) | ForEach-Object {
        $path = $_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null)
        $class = $_.GetType().InvokeMember('Class', 'GetProperty', $null, $_, $null)
        "$(($path -replace '^WinNT://', '') -replace '/', '\')|$class"
    }
}
$line = 'ADMINS:' + ($members -join ';')
if ($line.Length -gt 2000) { $line = $line.Substring(0, 2000) }   # the console keeps the first 2,048 characters
Write-Output $line
exit 0
