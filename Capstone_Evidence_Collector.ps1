<#
.SYNOPSIS
    Capstone evidence collector. READ-ONLY: it changes nothing on the computer. It only reads
    what Windows already records and saves copies to your evidence folder, with SHA-256 hashes.

.DESCRIPTION
    -Phase Baseline   (Day 13, Block 1)  Snapshot of "normal": users, Administrators members,
                                         services, scheduled tasks, listening ports, processes,
                                         Defender status, last updates.
    -Phase Collect    (Day 13, after the shift)  The same snapshot again, a DIFF against the
                                         baseline, the security events of the last -Hours hours,
                                         Defender detections, and a copy of the firewall log.

    Every file is listed in manifest.csv with its SHA-256 hash ("hash it, name it, lock it, log it").

.EXAMPLE
    .\Capstone_Evidence_Collector.ps1 -Phase Baseline
    .\Capstone_Evidence_Collector.ps1 -Phase Collect -Hours 4

.NOTES
    Run in Windows PowerShell 5.1, as Administrator (the Security log and the firewall log need it).
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Baseline', 'Collect')]
    [string]$Phase,
    [string]$OutDir = (Join-Path $env:USERPROFILE 'Evidence\Capstone\Day13'),
    [ValidateRange(1, 24)]
    [int]$Hours = 8
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$prefix = if ($Phase -eq 'Baseline') { 'baseline' } else { 'after' }
$stamp  = Get-Date -Format 'yyyyMMdd-HHmm'

function Save-Csv($Data, [string]$Name) {
    $path = Join-Path $OutDir ("{0}_{1}.csv" -f $prefix, $Name)
    $Data | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Host ("  saved {0}" -f (Split-Path $path -Leaf))
}

Write-Host "Evidence Collector - phase $Phase - $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Cyan

# ------------------------------------------------------------------------------------------
# 1. THE SNAPSHOT (both phases)
# ------------------------------------------------------------------------------------------
Save-Csv (Get-LocalUser | Select-Object Name, Enabled, LastLogon, Description) 'users'

try {
    $admins = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop |
        Select-Object Name, ObjectClass, PrincipalSource
} catch {
    # Get-LocalGroupMember fails on some Azure AD-joined PCs; fall back to 'net localgroup'
    $lines  = @(net localgroup (Get-LocalGroup -SID 'S-1-5-32-544').Name)
    $admins = $lines[6..($lines.Count - 2)] | Where-Object { $_.Trim() } |
        ForEach-Object { [pscustomobject]@{ Name = $_.Trim(); ObjectClass = ''; PrincipalSource = '' } }
}
Save-Csv $admins 'admins'

Save-Csv (Get-CimInstance Win32_Service |
          Select-Object Name, DisplayName, State, StartMode, PathName) 'services'

Save-Csv (Get-ScheduledTask | Where-Object TaskPath -notlike '\Microsoft\*' |
          Select-Object TaskPath, TaskName, State,
            @{ n = 'Action'; e = { ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | ' } }) 'tasks'

Save-Csv (Get-NetTCPConnection -State Listen |
          Select-Object LocalAddress, LocalPort, OwningProcess,
            @{ n = 'Process'; e = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } } |
          Sort-Object LocalPort) 'listening'

Save-Csv (Get-Process | Select-Object ProcessName, Id, Path, StartTime | Sort-Object ProcessName) 'processes'

Save-Csv (Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled,
          AntivirusSignatureVersion, AntivirusSignatureLastUpdated, AMEngineVersion, AMProductVersion,
          QuickScanEndTime, FullScanEndTime) 'defender_status'

Save-Csv (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID, Description, InstalledOn) 'hotfix'

# ------------------------------------------------------------------------------------------
# 2. COLLECT ONLY: the diff, the events, the detections, the firewall log
# ------------------------------------------------------------------------------------------
if ($Phase -eq 'Collect') {
    $diffs = @()
    $keys  = @{ users = 'Name'; admins = 'Name'; services = 'Name'; tasks = 'TaskName'; listening = 'LocalPort' }
    foreach ($k in $keys.Keys) {
        $b = Join-Path $OutDir "baseline_$k.csv"
        $a = Join-Path $OutDir "after_$k.csv"
        if ((Test-Path $b) -and (Test-Path $a)) {
            $key    = $keys[$k]
            $before = @(Import-Csv $b | ForEach-Object { $_.$key })
            $after  = @(Import-Csv $a | ForEach-Object { $_.$key })
            foreach ($x in ($after | Sort-Object -Unique)) {
                if ($before -notcontains $x) { $diffs += [pscustomobject]@{ Area = $k; Item = $x; Change = 'NEW since baseline' } }
            }
            foreach ($x in ($before | Sort-Object -Unique)) {
                if ($after -notcontains $x) { $diffs += [pscustomobject]@{ Area = $k; Item = $x; Change = 'GONE since baseline' } }
            }
        } else {
            Write-Warning "No baseline for '$k'. Did you run -Phase Baseline first?"
        }
    }
    $diffPath = Join-Path $OutDir 'diff_baseline_vs_after.csv'
    $diffs | Export-Csv -Path $diffPath -NoTypeInformation -Encoding UTF8
    Write-Host "  saved diff_baseline_vs_after.csv ($($diffs.Count) changes)"

    $since   = (Get-Date).AddHours(-$Hours)
    $filters = @(
        @{ LogName = 'Security'; Id = 4625, 4720, 4722, 4725, 4726, 4732, 4733, 4698, 4699, 1102 },
        @{ LogName = 'System'; Id = 7045, 104 },
        @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; Id = 106, 140, 141 },
        @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1000, 1001, 1116, 1117, 1118, 1119, 2000, 5001 },
        @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1, 3, 11, 13 }
    )
    $events = foreach ($f in $filters) {
        $f.StartTime = $since
        Get-WinEvent -FilterHashtable $f -MaxEvents 3000 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, LogName, Id, ProviderName,
                @{ n = 'Summary'; e = { $m = ($_.Message -replace '\s+', ' '); $m.Substring(0, [Math]::Min(700, $m.Length)) } }
    }
    $events = $events | Sort-Object TimeCreated
    $evPath = Join-Path $OutDir 'events_timeline.csv'
    $events | Export-Csv -Path $evPath -NoTypeInformation -Encoding UTF8
    Write-Host "  saved events_timeline.csv ($(@($events).Count) events since $($since.ToString('HH:mm')))"

    $det = Get-MpThreatDetection -ErrorAction SilentlyContinue |
        Select-Object InitialDetectionTime, ThreatID, ActionSuccess, CurrentThreatExecutionStatusID,
            @{ n = 'Resources'; e = { $_.Resources -join '; ' } }, ProcessName, DomainUser
    $det | Export-Csv -Path (Join-Path $OutDir 'defender_detections.csv') -NoTypeInformation -Encoding UTF8
    Write-Host '  saved defender_detections.csv'

    $fw = Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\pfirewall.log'
    if (Test-Path $fw) {
        Copy-Item $fw (Join-Path $OutDir 'pfirewall_copy.log') -Force
        Write-Host '  saved pfirewall_copy.log'
    } else {
        Write-Warning 'No firewall log found. Was firewall logging switched on in set-up §1.4?'
    }
}

# ------------------------------------------------------------------------------------------
# 3. HASH IT, LOG IT
# ------------------------------------------------------------------------------------------
$manifest = Join-Path $OutDir 'manifest.csv'
Get-ChildItem $OutDir -File | Where-Object Name -ne 'manifest.csv' |
    ForEach-Object {
        [pscustomobject]@{
            File      = $_.Name
            Bytes     = $_.Length
            SHA256    = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
            Collected = $stamp
            By        = $env:USERNAME
            Host      = $env:COMPUTERNAME
        }
    } | Export-Csv -Path $manifest -NoTypeInformation -Encoding UTF8
Write-Host "  saved manifest.csv (SHA-256 of every file)" -ForegroundColor Green
Write-Host "Done. Evidence folder: $OutDir"
