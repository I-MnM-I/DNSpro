#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Removes DNSpro and restores normal DNS. Your allow/block settings (config.json) are kept.
set -uo pipefail
APP="/Library/Application Support/DNSpro"
SAVED="$APP/original-dns.tsv"
say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

[ "$(id -u)" -ne 0 ] || { echo "Don't run this with sudo; it asks for your password when needed."; exit 1; }
sudo -v || exit 1

say "Restoring normal DNS"
if [ -f "$SAVED" ]; then
  while IFS=$'\t' read -r svc servers; do
    # shellcheck disable=SC2086
    sudo networksetup -setdnsservers "$svc" $servers
  done < "$SAVED"
fi
# Any network service still pointing at DNSpro goes back to automatic DNS.
networksetup -listallnetworkservices | tail -n +2 | sed 's/^\*//' | while IFS= read -r svc; do
  networksetup -getdnsservers "$svc" 2>/dev/null | grep -qx '127.0.0.1' && sudo networksetup -setdnsservers "$svc" Empty
done
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder 2>/dev/null

say "Stopping DNSpro"
launchctl bootout "gui/$(id -u)/org.dnspro.tray" 2>/dev/null
sudo launchctl bootout system/org.dnspro.server 2>/dev/null
sudo rm -f /Library/LaunchDaemons/org.dnspro.server.plist /Library/LaunchAgents/org.dnspro.tray.plist

say "Removing files"
if [ -d "$APP" ]; then
  sudo find "$APP" -mindepth 1 -maxdepth 1 ! -name config.json -exec rm -rf {} +
fi

printf '\n\033[32mDNSpro is removed and DNS is back to normal.\033[0m\n'
[ -n "${DNSPRO_QUIET:-}" ] || read -r -p $'\nPress Return to close' _
