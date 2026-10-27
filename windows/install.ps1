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
$Version = '1.2.0'

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
# The release download includes its own Python (python\ next to this script), so nothing needs installing.
$Bundled = Join-Path $Here 'python\python.exe'
$UseBundle = (Test-Path $Bundled) -and -not $env:DNSPRO_PYTHON
if ($UseBundle) {
  $Py = $Bundled
} else {
  $Py = Find-Python
}
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
if ($UseBundle) { Write-Host '    Using the Python included with DNSpro' } else { Write-Host "    Using $Py" }

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
Remove-Item (Join-Path $App 'venv') -Recurse -Force -ErrorAction SilentlyContinue  # left over from 1.0.0
if ($UseBundle) {
  # Installed under Program Files so only administrators can modify it (it runs as SYSTEM).
  robocopy (Join-Path $Here 'python') (Join-Path $App 'python') /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
  if ($LASTEXITCODE -ge 8) { Fail "Couldn't copy DNSpro's files to $App." }
  $Py = Join-Path $App 'python\python.exe'
}
# Settings and blocklists: only SYSTEM and administrators may change them; users may read.
icacls $Data /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
$Dns = Join-Path $App 'dnspro.py'

Write-Host '    Downloading blocklists (first time only)...'
& $Py $Dns update
if ($LASTEXITCODE -ne 0) { Fail "Couldn't download the blocklists. Check your internet connection and try again." }

# The key that turns DNSpro off and shows what it logged: only SYSTEM, administrators and
# the account installing DNSpro may read it (not other accounts on this PC).
& $Py $Dns init-key
$KeyFile = Join-Path $Data 'api-key'
$Owner = (Get-CimInstance Win32_ComputerSystem).UserName  # the signed-in user, even when elevated as another admin
if (-not $Owner) { $Owner = "$env:USERDOMAIN\$env:USERNAME" }
icacls $KeyFile /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' "${Owner}:R" | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "Couldn't protect DNSpro's key file ($KeyFile)." }

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
Remove-Item (Join-Path $StartMenu 'DNSpro\DNSpro Dashboard.url') -Force -ErrorAction SilentlyContinue  # 1.0.x
# Opens the dashboard already logged in (the page can't be opened by just typing its address).
$PyNoConsole = Join-Path (Split-Path -Parent $Py) 'pythonw.exe'
if (-not (Test-Path $PyNoConsole)) { $PyNoConsole = $Py }
New-Shortcut (Join-Path $StartMenu 'DNSpro\DNSpro Dashboard.lnk') $PyNoConsole "`"$Dns`" dashboard" 'See what DNSpro has blocked'
New-Shortcut (Join-Path $StartMenu 'DNSpro\Uninstall DNSpro.lnk') 'powershell.exe' `
  "-NoProfile -ExecutionPolicy Bypass -File `"$App\uninstall.ps1`"" 'Remove DNSpro and restore normal DNS'

if ($env:DNSPRO_NO_TRAY) {
  Write-Host "`n    Skipping the taskbar icon (DNSPRO_NO_TRAY is set)."
} else {
  Say 'Adding the taskbar icon'
  $trayOk = $false
  if ($UseBundle) {
    $pyw = Join-Path $App 'python\pythonw.exe'
    $trayOk = $true
  } else {
    Write-Host '    Downloading the icon libraries (about 80 MB, one time)...'
    try {
      & $Py -m venv (Join-Path $App 'venv')
      & (Join-Path $App 'venv\Scripts\python.exe') -m pip install --disable-pip-version-check -q PySide6-Essentials
      $trayOk = ($LASTEXITCODE -eq 0)
    } catch { $trayOk = $false }
    $pyw = Join-Path $App 'venv\Scripts\pythonw.exe'
  }
  if ($trayOk) {
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
  URLInfoAbout = 'https://github.com/I-MnM-I/DNSpro'
}
foreach ($k in $props.Keys) { New-ItemProperty -Path $reg -Name $k -Value $props[$k] -Force | Out-Null }

# ---- point every network adapter's DNS at DNSpro, remembering the old settings
Say 'Pointing Windows DNS at DNSpro'
$saved = Join-Path $Data 'original-dns.json'
# -IncludeHidden: some PCs (and VMs) route DNS through adapters Windows hides from the normal list
$adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
  Where-Object { Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue })
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
  try {
    # IPv4 first on its own: adapters with IPv6 turned off reject the whole list if it contains ::1
    Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses @('127.0.0.1') -ErrorAction Stop
    try { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses @('127.0.0.1', '::1') -ErrorAction Stop } catch { }
    Write-Host "    $($a.Name): done"
  } catch { Write-Host "    $($a.Name): skipped ($($_.Exception.Message.Trim()))" }
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
  Write-Host "`n    Diagnostics (share these if you ask for help):"
  Get-DnsClientServerAddress | Where-Object ServerAddresses |
    Format-Table InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses -AutoSize | Out-Host
  Get-NetIPConfiguration | Format-Table InterfaceAlias, InterfaceIndex, IPv4DefaultGateway -AutoSize | Out-Host
  Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue | Format-Table Namespace, NameServers -AutoSize | Out-Host
  $probe = "diag$(Get-Random)" + '.probe.dnspro.example'
  try { "    direct to DNSpro: " + ((Resolve-DnsName $probe -Server 127.0.0.1 -DnsOnly -ErrorAction Stop).IPAddress -join ', ') } catch { "    direct to DNSpro: FAILED $($_.Exception.Message)" }
  try { "    via Windows:      " + ((Resolve-DnsName $probe -DnsOnly -ErrorAction Stop).IPAddress -join ', ') } catch { "    via Windows:      FAILED $($_.Exception.Message)" }
  "    via getaddrinfo:  " + (& $Py -c "import socket,sys`ntry: print(sorted({a[4][0] for a in socket.getaddrinfo(sys.argv[1], 443)}))`nexcept Exception as e: print('FAILED', e)" $probe)
  Restore-Dns
  Remove-Item $saved -Force
  Fail 'The check failed, so the DNS change was undone (your internet works as before).'
}
Write-Host "`nDone! Ads, trackers and malware are now blocked on this whole PC." -ForegroundColor Green
Write-Host '  Dashboard:   Start menu > DNSpro Dashboard, or click the shield icon'
Write-Host '  Turn on/off: Ctrl+Alt+Shift+A / Ctrl+Alt+Shift+B, or click the shield icon'
Write-Host "  If you turned ON 'Use secure DNS' in your browser, turn it off, or the browser skips DNSpro."
Write-Host '  To remove: Settings > Apps > DNSpro > Uninstall'
Done-Pause
