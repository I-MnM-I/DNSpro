# SPDX-License-Identifier: GPL-3.0-or-later
# Removes DNSpro and restores normal DNS. Your allow/block settings (config.json) are kept.
#Requires -Version 5.1
param([switch]$Quiet)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$App = Join-Path $env:ProgramFiles 'DNSpro'
$Data = Join-Path $env:ProgramData 'DNSpro'

function Say($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }

$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$self = $MyInvocation.MyCommand.Path
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $self.StartsWith($App, [StringComparison]::OrdinalIgnoreCase)) {
  # Elevate, and run from a temp copy so the install folder can be deleted.
  $tmp = Join-Path $env:TEMP 'dnspro-uninstall.ps1'
  Copy-Item $self $tmp -Force
  $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$tmp`"")
  if ($Quiet) { $argList += '-Quiet' }
  if ($me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    & powershell.exe @argList; exit $LASTEXITCODE
  }
  Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
  exit
}

Say 'Restoring normal DNS'
$saved = Join-Path $Data 'original-dns.json'
if (Test-Path $saved) {
  foreach ($o in (Get-Content $saved -Raw | ConvertFrom-Json)) {
    try {
      Set-DnsClientServerAddress -InterfaceIndex $o.Index -ResetServerAddresses -ErrorAction Stop
      $static = @(("$($o.V4) $($o.V6)" -split '[,\s]+') | Where-Object { $_ })
      if ($static.Count) { Set-DnsClientServerAddress -InterfaceIndex $o.Index -ServerAddresses $static }
    } catch { }
  }
  Remove-Item $saved -Force
}
# Any adapter still pointing at DNSpro (e.g. added later) goes back to automatic DNS.
Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
  Where-Object { $_.ServerAddresses -contains '127.0.0.1' -or $_.ServerAddresses -contains '::1' } |
  ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue }
Clear-DnsClientCache

Say 'Stopping DNSpro'
Stop-ScheduledTask -TaskName 'DNSpro' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'DNSpro' -Confirm:$false -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name LIKE 'python%'" -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -like '*DNSpro\dnspro.py*' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1

Say 'Removing files and shortcuts'
$StartMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
Remove-Item (Join-Path $StartMenu 'StartUp\DNSpro.lnk'), (Join-Path $StartMenu 'DNSpro') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DNSpro' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $App -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem $Data -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'config.json' } |
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`nDNSpro is removed and DNS is back to normal." -ForegroundColor Green
if (-not $Quiet) { Read-Host "`nPress Enter to close" | Out-Null }
