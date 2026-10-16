# SPDX-License-Identifier: GPL-3.0-or-later
# DNSpro installer for Windows 10/11. Double-click "Install DNSpro.bat" to run it.
#Requires -Version 5.1
param([switch]$Quiet)  # -Quiet: no prompts (used by automated tests)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Src = Join-Path $Here 'dnspro.py'
if (-not (Test-Path $Src)) { $Src = Join-Path (Split-Path -Parent $Here) 'dnspro.py' }
$App = Join-Path $env:ProgramFiles 'DNSpro'
$Data = Join-Path $env:ProgramData 'DNSpro'
$Version = '1.0.0'

function Say($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Done-Pause { if (-not $Quiet) { Read-Host "`nPress Enter to close" | Out-Null } }
function Fail($m) { Write-Host "`n!! $m" -ForegroundColor Red; Done-Pause; exit 1 }

# ---- run as administrator (shows the usual Windows prompt)
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$($MyInvocation.MyCommand.Path)`"")
  if ($Quiet) { $argList += '-Quiet' }
  Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
  exit
}

Write-Host "DNSpro $Version - free system-wide ad, tracker and malware blocking" -ForegroundColor Green
Get-ChildItem $Here -File | Unblock-File -ErrorAction SilentlyContinue

# ---- find a Python that only administrators can modify (it runs as SYSTEM)
function Find-Python {
  if ($env:DNSPRO_PYTHON) { return $env:DNSPRO_PYTHON }  # for automated tests
  $best = $null; $bestVer = $null
  foreach ($k in (Get-ChildItem 'HKLM:\SOFTWARE\Python\PythonCore' -ErrorAction SilentlyContinue)) {
    if ($k.PSChildName -notmatch '^3\.(\d+)$' -or [int]$Matches[1] -lt 9) { continue }
    $exe = (Get-ItemProperty (Join-Path $k.PSPath 'InstallPath') -ErrorAction SilentlyContinue).ExecutablePath
    if (-not $exe -or -not (Test-Path $exe)) { continue }
    if (-not $exe.StartsWith($env:ProgramFiles, [StringComparison]::OrdinalIgnoreCase)) { continue }
    $v = [version]$k.PSChildName
    if (-not $bestVer -or $v -gt $bestVer) { $best = $exe; $bestVer = $v }
  }
  return $best
}

Say 'Checking for Python'
$Py = Find-Python
if (-not $Py) {
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Fail "Python isn't installed. Get it from https://www.python.org/downloads/ - in the installer choose`n   'Customize installation' and tick 'Install Python for all users'. Then run this again."
  }
  Write-Host '    Installing Python 3.13 for all users (this takes a minute)...'
  winget install --id Python.Python.3.13 -e --scope machine --silent --disable-interactivity `
    --accept-package-agreements --accept-source-agreements | Out-Host
  $Py = Find-Python
  if (-not $Py) { Fail "Python couldn't be installed automatically. Install it from https://www.python.org/downloads/ ('Install for all users'), then run this again." }
}
Write-Host "    Using $Py"

# ---- stop an older copy (reinstall / upgrade)
if (Get-ScheduledTask -TaskName 'DNSpro' -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName 'DNSpro' -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 2
}
Get-CimInstance Win32_Process -Filter "Name LIKE 'python%'" -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -like '*DNSpro\dnspro.py*' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

# ---- port 53 must be free on localhost
$busy = Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue |
  Where-Object { $_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::') }
if ($busy) {
  $p = Get-Process -Id ($busy | Select-Object -First 1).OwningProcess -ErrorAction SilentlyContinue
  Fail "Another program ($($p.ProcessName)) is already using DNS port 53. Close or uninstall it, then try again."
}

Say "Installing DNSpro to $App"
New-Item -ItemType Directory -Force -Path $App, $Data | Out-Null
Copy-Item $Src (Join-Path $App 'dnspro.py') -Force
Copy-Item (Join-Path $Here 'uninstall.ps1') (Join-Path $App 'uninstall.ps1') -Force
# Settings and blocklists: only SYSTEM and administrators may change them; users may read.
icacls $Data /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
$Dns = Join-Path $App 'dnspro.py'

Write-Host '    Downloading blocklists (first time only)...'
& $Py $Dns update
if ($LASTEXITCODE -ne 0) { Fail "Couldn't download the blocklists. Check your internet connection and try again." }

Say 'Starting the background service'
$action = New-ScheduledTaskAction -Execute $Py -Argument "`"$Dns`" run" -WorkingDirectory $App
$triggers = @(
  (New-ScheduledTaskTrigger -AtStartup),
  # Watchdog: every 5 minutes, start it again if it isn't running.
  (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5))
)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
  -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'DNSpro' -Description 'DNSpro ad blocker (DNS server on 127.0.0.1)' `
  -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 'DNSpro'
$up = $false
foreach ($i in 1..40) { & $Py $Dns status *> $null; if ($LASTEXITCODE -eq 0) { $up = $true; break }; Start-Sleep -Milliseconds 500 }
if (-not $up) { Fail "The service didn't start. Details are in $Data\dnspro.log" }

# ---- taskbar icon + Ctrl+Alt+Shift+A / B hotkeys (optional, needs PySide6)
$StartMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
$Shell = New-Object -ComObject WScript.Shell
function New-Shortcut($path, $target, $arguments, $desc) {
  $s = $Shell.CreateShortcut($path); $s.TargetPath = $target; $s.Arguments = $arguments
  $s.WorkingDirectory = $App; $s.Description = $desc; $s.Save()
}
New-Item -ItemType Directory -Force -Path (Join-Path $StartMenu 'DNSpro') | Out-Null
Set-Content -Path (Join-Path $StartMenu 'DNSpro\DNSpro Dashboard.url') -Value "[InternetShortcut]`r`nURL=http://127.0.0.1:5336/"
New-Shortcut (Join-Path $StartMenu 'DNSpro\Uninstall DNSpro.lnk') 'powershell.exe' `
  "-NoProfile -ExecutionPolicy Bypass -File `"$App\uninstall.ps1`"" 'Remove DNSpro and restore normal DNS'

if ($env:DNSPRO_NO_TRAY) {
  Write-Host "`n    Skipping the taskbar icon (DNSPRO_NO_TRAY is set)."
} else {
  Say 'Adding the taskbar icon (downloads about 80 MB, one time)'
  $trayOk = $false
  try {
    & $Py -m venv (Join-Path $App 'venv')
    & (Join-Path $App 'venv\Scripts\python.exe') -m pip install --disable-pip-version-check -q PySide6-Essentials
    $trayOk = ($LASTEXITCODE -eq 0)
  } catch { $trayOk = $false }
  if ($trayOk) {
    $pyw = Join-Path $App 'venv\Scripts\pythonw.exe'
    $lnk = Join-Path $StartMenu 'StartUp\DNSpro.lnk'
    New-Shortcut $lnk $pyw "`"$Dns`" tray" 'DNSpro taskbar icon'
    New-Shortcut (Join-Path $StartMenu 'DNSpro\DNSpro.lnk') $pyw "`"$Dns`" tray" 'DNSpro taskbar icon'
    Start-Process explorer.exe -ArgumentList "`"$lnk`""  # starts it as you, not as administrator
    Write-Host '    Done. Look for the shield next to the clock (click ^ if it is hidden).'
  } else {
    Write-Host '    The taskbar icon could not be installed; blocking still works. Use the dashboard instead.' -ForegroundColor Yellow
  }
}

# ---- Settings > Apps entry
$reg = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DNSpro'
New-Item -Path $reg -Force | Out-Null
$props = @{
  DisplayName = 'DNSpro'; DisplayVersion = $Version; Publisher = 'DNSpro contributors'
  InstallLocation = $App; NoModify = 1; NoRepair = 1
  UninstallString = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$App\uninstall.ps1`""
  URLInfoAbout = 'http://127.0.0.1:5336/'
}
foreach ($k in $props.Keys) { New-ItemProperty -Path $reg -Name $k -Value $props[$k] -Force | Out-Null }

# ---- point every network adapter's DNS at DNSpro, remembering the old settings
Say 'Pointing Windows DNS at DNSpro'
$saved = Join-Path $Data 'original-dns.json'
$adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
if (-not (Test-Path $saved)) {
  $orig = foreach ($a in $adapters) {
    $g = $a.InterfaceGuid
    [pscustomobject]@{
      Index = $a.ifIndex; Name = $a.Name
      V4 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$g" -Name NameServer -ErrorAction SilentlyContinue).NameServer
      V6 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$g" -Name NameServer -ErrorAction SilentlyContinue).NameServer
    }
  }
  ConvertTo-Json @($orig) | Set-Content -Path $saved -Encoding UTF8
}
foreach ($a in $adapters) {
  try { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses @('127.0.0.1', '::1') }
  catch { Write-Host "    (skipped adapter '$($a.Name)')" }
}
Clear-DnsClientCache

function Restore-Dns {
  foreach ($o in (Get-Content $saved -Raw | ConvertFrom-Json)) {
    try {
      Set-DnsClientServerAddress -InterfaceIndex $o.Index -ResetServerAddresses
      $static = @(("$($o.V4) $($o.V6)" -split '[,\s]+') | Where-Object { $_ })
      if ($static.Count) { Set-DnsClientServerAddress -InterfaceIndex $o.Index -ServerAddresses $static }
    } catch { }
  }
  Clear-DnsClientCache
}

Say 'Checking that it works'
Start-Sleep -Seconds 2
& $Py $Dns selftest --wait 30
if ($LASTEXITCODE -ne 0) {
  Restore-Dns
  Remove-Item $saved -Force
  Fail 'The check failed, so the DNS change was undone (your internet works as before).'
}
Write-Host "`nDone! Ads, trackers and malware are now blocked on this whole PC." -ForegroundColor Green
Write-Host '  Dashboard:   http://127.0.0.1:5336  (also in the Start menu)'
Write-Host '  Turn on/off: Ctrl+Alt+Shift+A / Ctrl+Alt+Shift+B, or click the shield icon'
Write-Host "  Also turn OFF 'Use secure DNS' in your browser settings, or the browser skips DNSpro."
Write-Host '  To remove: Settings > Apps > DNSpro > Uninstall'
Done-Pause
