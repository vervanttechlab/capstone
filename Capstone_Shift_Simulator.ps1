<#
.SYNOPSIS
    Capstone "Operation Night Watch" shift simulator. Generates SAFE, reversible test
    incidents on THIS computer so the trainee can practise detecting and handling them.

.DESCRIPTION
    Cyber Threat Monitoring Level I, capstone Day 13, Block 2.

    Six incidents happen at random times during the shift, in a random order:
      J1  Six failed logons for the test account 'ctm_test'           (Security 4625)
      J2  A new local account 'ctm_helpdesk' is created               (Security 4720)
      J3  'ctm_helpdesk' is added to the local Administrators group   (Security 4732)
      J4  A scheduled task '\CTM\UpdaterCheck' is created             (Security 4698, TaskScheduler 106)
      J5  The EICAR antivirus TEST file is written to Downloads       (Defender 1116 / 1117)
      J6  A program listens on TCP port 4444 (loopback only), 15 min  (Get-NetTCPConnection)

    Nothing here is malware. Nothing leaves this computer:
      - the EICAR file is the industry-standard harmless antivirus test string
      - the scheduled task only runs "cmd /c echo", once a day at 03:00
      - the listener is bound to 127.0.0.1, so no other machine can reach it
      - the accounts get long random passwords that nobody is shown

    Run with -Cleanup at the end of the day to remove every item it created.

.PARAMETER DurationMinutes
    Length of the shift. Default 75. Minimum 15.

.PARAMETER Cleanup
    Remove the test accounts, the task, the EICAR file (if still present) and the listener.

.EXAMPLE
    .\Capstone_Shift_Simulator.ps1                       # start a 75-minute shift
    .\Capstone_Shift_Simulator.ps1 -DurationMinutes 15   # trainer's quick test
    .\Capstone_Shift_Simulator.ps1 -Cleanup              # end of day

.NOTES
    Run in Windows PowerShell 5.1, as Administrator. Read the whole script before running it.
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateRange(15, 240)]
    [int]$DurationMinutes = 75,
    [switch]$Cleanup
)

$ErrorActionPreference = 'Stop'

$Root      = Join-Path $env:ProgramData 'CTM_Capstone'
$LogFile   = Join-Path $Root 'simulator.log'
$TestUser  = 'ctm_test'
$NewUser   = 'ctm_helpdesk'
$TaskPath  = '\CTM\'
$TaskName  = 'UpdaterCheck'
$EicarFile = Join-Path $env:USERPROFILE 'Downloads\invoice_0926.txt'
$AdminsSid = 'S-1-5-32-544'   # the local Administrators group, in any Windows language

New-Item -ItemType Directory -Force -Path $Root | Out-Null

function Write-SimLog([string]$Message) {
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -Path $LogFile -Value $line
}

function New-RandomPassword {
    # 24 random letters and digits plus a fixed symbol set, so it meets complexity rules
    $chars = [char[]]((48..57) + (65..90) + (97..122))
    (-join (1..24 | ForEach-Object { $chars | Get-Random })) + '#Aa1'
}

# ------------------------------------------------------------------------------------------
# CLEANUP
# ------------------------------------------------------------------------------------------
if ($Cleanup) {
    Write-Host 'Cleaning up capstone test items...' -ForegroundColor Cyan
    foreach ($u in $NewUser, $TestUser) {
        if (Get-LocalUser -Name $u -ErrorAction SilentlyContinue) {
            Remove-LocalUser -Name $u
            Write-Host "  removed account $u"
        }
    }
    if (Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Confirm:$false
        Write-Host "  removed task $TaskPath$TaskName"
    }
    if (Test-Path $EicarFile) {
        Remove-Item $EicarFile -Force -ErrorAction SilentlyContinue
        Write-Host "  removed $EicarFile"
    }
    Get-NetTCPConnection -LocalPort 4444 -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object {
            $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            if ($p -and $p.ProcessName -match '^powershell') {
                Stop-Process -Id $p.Id -Force
                Write-Host "  stopped listener on 4444 (PID $($p.Id))"
            }
        }
    Get-Job -Name 'CTM_J6' -ErrorAction SilentlyContinue | Remove-Job -Force
    Write-SimLog 'CLEANUP completed'
    Write-Host "Done. The trainer's log is kept at $LogFile" -ForegroundColor Green
    return
}

# ------------------------------------------------------------------------------------------
# THE SIX INCIDENTS
# ------------------------------------------------------------------------------------------
function Invoke-J1 {
    # Six wrong-password attempts for the test account. Each makes one 4625 in the Security log.
    $bad  = ConvertTo-SecureString 'Wrong-Password-2026' -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ("$env:COMPUTERNAME\$TestUser", $bad)
    for ($i = 1; $i -le 6; $i++) {
        try { Start-Process -FilePath 'cmd.exe' -ArgumentList '/c exit' -Credential $cred -WindowStyle Hidden }
        catch { }   # the failure IS the event we want
        Start-Sleep -Seconds 8
    }
    Write-SimLog 'J1 six failed logons for ctm_test (expect Security 4625 x6)'
}

function Invoke-J2 {
    $pw = ConvertTo-SecureString (New-RandomPassword) -AsPlainText -Force
    New-LocalUser -Name $NewUser -Password $pw -Description 'Helpdesk' -AccountNeverExpires | Out-Null
    Write-SimLog 'J2 local account ctm_helpdesk created (expect Security 4720)'
}

function Invoke-J3 {
    Add-LocalGroupMember -SID $AdminsSid -Member $NewUser
    Write-SimLog 'J3 ctm_helpdesk added to Administrators (expect Security 4732)'
}

function Invoke-J4 {
    $action  = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c echo CTM capstone test'
    $trigger = New-ScheduledTaskTrigger -Daily -At '03:00'
    Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Action $action -Trigger $trigger `
        -Description 'Checks for updates' | Out-Null
    Write-SimLog 'J4 scheduled task \CTM\UpdaterCheck created (expect Security 4698, TaskScheduler/Operational 106)'
}

function Invoke-J5 {
    # The EICAR test string, built from character codes so this script itself is not flagged.
    $codes = 88,53,79,33,80,37,64,65,80,91,52,92,80,90,88,53,52,40,80,94,41,55,67,67,41,55,125,36,69,73,67,65,82,45,83,84,65,78,68,65,82,68,45,65,78,84,73,86,73,82,85,83,45,84,69,83,84,45,70,73,76,69,33,36,72,43,72,42
    $eicar = -join ($codes | ForEach-Object { [char]$_ })
    try { [System.IO.File]::WriteAllText($EicarFile, $eicar) } catch { }   # Defender may block the write
    Write-SimLog "J5 EICAR test file written to $EicarFile (expect Defender 1116, then 1117)"
}

function Invoke-J6 {
    Start-Job -Name 'CTM_J6' -ScriptBlock {
        $listener = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback, 4444)
        $listener.Start()
        Start-Sleep -Seconds 900
        $listener.Stop()
    } | Out-Null
    Write-SimLog 'J6 listener on 127.0.0.1:4444 for 15 minutes (owning process: powershell.exe)'
}

# ------------------------------------------------------------------------------------------
# THE SHIFT
# ------------------------------------------------------------------------------------------
if (-not (Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue)) {
    $pw = ConvertTo-SecureString (New-RandomPassword) -AsPlainText -Force
    New-LocalUser -Name $TestUser -Password $pw -Description 'CTM capstone test account' -AccountNeverExpires | Out-Null
}

# Five random minutes between minute 3 and five minutes before the end, in random order.
# J3 always follows J2 by 3 to 6 minutes.
$slots  = 3..($DurationMinutes - 8) | Get-Random -Count 5 | Sort-Object
$order  = 'J1', 'J2', 'J4', 'J5', 'J6' | Get-Random -Count 5
$plan   = @()
for ($i = 0; $i -lt 5; $i++) { $plan += [pscustomobject]@{ Minute = $slots[$i]; Id = $order[$i] } }
$j2     = ($plan | Where-Object Id -eq 'J2').Minute
$plan  += [pscustomobject]@{ Minute = $j2 + (Get-Random -Minimum 3 -Maximum 7); Id = 'J3' }
$plan   = $plan | Sort-Object Minute

$start = Get-Date
$end   = $start.AddMinutes($DurationMinutes)
Write-SimLog ("SHIFT START  duration {0} min  plan: {1}" -f $DurationMinutes,
    (($plan | ForEach-Object { '{0}@+{1}m' -f $_.Id, $_.Minute }) -join ' '))

Clear-Host
Write-Host '=================================================================' -ForegroundColor Cyan
Write-Host '  OPERATION NIGHT WATCH  -  your shift has started'                -ForegroundColor Cyan
Write-Host '=================================================================' -ForegroundColor Cyan
Write-Host ("  Started: {0:HH:mm}     Ends: {1:HH:mm}" -f $start, $end)
Write-Host '  Minimise this window. Do NOT close it until the shift ends.'
Write-Host '  Watch your tools: Event Viewer, Windows Security, TCP connections.'
Write-Host '  Log every detection in D3 the moment you see it.'
Write-Host ''

foreach ($step in $plan) {
    $due  = $start.AddMinutes($step.Minute)
    $wait = ($due - (Get-Date)).TotalSeconds
    if ($wait -gt 0) { Start-Sleep -Seconds ([int]$wait) }
    try   { & "Invoke-$($step.Id)" }
    catch { Write-SimLog "$($step.Id) ERROR: $($_.Exception.Message)" }
}

$rest = ($end - (Get-Date)).TotalSeconds
if ($rest -gt 0) { Start-Sleep -Seconds ([int]$rest) }
Write-SimLog 'SHIFT END'
Write-Host ("  Shift ended at {0:HH:mm}. Now run the Evidence Collector: -Phase Collect" -f (Get-Date)) -ForegroundColor Green
Write-Host '  Leave the test items in place until your trainer says to run -Cleanup.'
