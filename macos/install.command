#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# DNSpro installer for macOS 11+. Double-click "Install DNSpro.command" (right-click > Open the first time).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/dnspro.py"; [ -f "$SRC" ] || SRC="$HERE/../dnspro.py"
APP="/Library/Application Support/DNSpro"
PY=/usr/bin/python3
DAEMON=/Library/LaunchDaemons/org.dnspro.server.plist
AGENT=/Library/LaunchAgents/org.dnspro.tray.plist
SAVED="$APP/original-dns.tsv"

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
pause() { [ -n "${DNSPRO_QUIET:-}" ] || read -r -p $'\nPress Return to close' _; }
fail() { printf '\n\033[31m!! %s\033[0m\n' "$*"; pause; exit 1; }

echo "DNSpro 1.2.0 - free system-wide ad, tracker and malware blocking"
[ "$(uname)" = Darwin ] || fail "This installer is for macOS."
[ "$(id -u)" -ne 0 ] || fail "Don't run this with sudo; it asks for your password when needed."

say "Checking for Python"
if ! xcode-select -p >/dev/null 2>&1; then
  xcode-select --install 2>/dev/null || true
  fail "macOS is now installing Apple's Command Line Tools (they include Python).
   When that finishes, double-click this installer again."
fi
"$PY" -c 'import sys; sys.exit(sys.version_info < (3, 9))' || fail "Python 3.9 or newer is required."

echo "    DNSpro needs administrator access to change DNS settings."
sudo -v || fail "Administrator access is required."

say "Installing DNSpro to $APP"
sudo launchctl bootout system/org.dnspro.server 2>/dev/null || true
sudo mkdir -p "$APP"
sudo install -m 755 -o root -g wheel "$SRC" "$APP/dnspro.py"
for u in "$HERE/uninstall.command" "$HERE/Uninstall DNSpro.command"; do
  [ -f "$u" ] && sudo install -m 755 -o root -g wheel "$u" "$APP/Uninstall DNSpro.command" && break
done
if sudo lsof -nP -iUDP:53 2>/dev/null | grep -qE '(127\.0\.0\.1|\*|\[::1\]):53'; then
  fail "Another program is already using DNS port 53 (another ad blocker or VPN?). Remove it first."
fi
echo "    Downloading blocklists (first time only)..."
sudo "$PY" "$APP/dnspro.py" update || fail "Couldn't download the blocklists. Check your internet connection."

say "Starting the background service"
sudo tee "$DAEMON" >/dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>org.dnspro.server</string>
  <key>ProgramArguments</key><array>
    <string>$PY</string><string>$APP/dnspro.py</string><string>run</string>
  </array>
  <key>EnvironmentVariables</key><dict><key>PYTHONUNBUFFERED</key><string>1</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$APP/dnspro.log</string>
  <key>StandardErrorPath</key><string>$APP/dnspro.log</string>
</dict></plist>
EOF
sudo chown root:wheel "$DAEMON"; sudo chmod 644 "$DAEMON"
sudo launchctl bootstrap system "$DAEMON"
for _ in $(seq 40); do "$PY" "$APP/dnspro.py" status >/dev/null 2>&1 && break; sleep 0.5; done
"$PY" "$APP/dnspro.py" status >/dev/null 2>&1 || fail "The service didn't start. Details: $APP/dnspro.log"

if [ -n "${DNSPRO_NO_TRAY:-}" ]; then
  echo "    Skipping the menu bar icon (DNSPRO_NO_TRAY is set)."
else
  say "Adding the menu bar icon (downloads about 80 MB, one time)"
  if sudo "$PY" -m venv "$APP/venv" && sudo "$APP/venv/bin/python" -m pip install --disable-pip-version-check -q PySide6-Essentials; then
    sudo tee "$AGENT" >/dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>org.dnspro.tray</string>
  <key>ProgramArguments</key><array>
    <string>$APP/venv/bin/python</string><string>$APP/dnspro.py</string><string>tray</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
</dict></plist>
EOF
    sudo chown root:wheel "$AGENT"; sudo chmod 644 "$AGENT"
    launchctl bootout "gui/$(id -u)/org.dnspro.tray" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$AGENT" 2>/dev/null || true
    echo "    Done. Look for the shield in the menu bar."
  else
    echo "    The menu bar icon couldn't be installed; blocking still works. Use the dashboard instead."
  fi
fi

say "Pointing macOS DNS at DNSpro"
services=()
while IFS= read -r svc; do
  [[ -z "$svc" || "$svc" == \** ]] && continue   # '*' = disabled service
  services+=("$svc")
done < <(networksetup -listallnetworkservices | tail -n +2)
if [ ! -f "$SAVED" ]; then
  for svc in "${services[@]}"; do
    cur="$(networksetup -getdnsservers "$svc" | tr '\n' ' ')"
    [[ "$cur" == *"aren't any"* ]] && cur="Empty"
    printf '%s\t%s\n' "$svc" "$cur"
  done | sudo tee "$SAVED" >/dev/null
fi
for svc in "${services[@]}"; do sudo networksetup -setdnsservers "$svc" 127.0.0.1 ::1; done
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder 2>/dev/null || true

restore_dns() {
  while IFS=$'\t' read -r svc servers; do
    # shellcheck disable=SC2086
    sudo networksetup -setdnsservers "$svc" $servers
  done < "$SAVED"
  sudo rm -f "$SAVED"
  sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder 2>/dev/null || true
}

say "Checking that it works"
sleep 2
if "$PY" "$APP/dnspro.py" selftest --wait 30; then
  printf '\n\033[32mDone! Ads, trackers and malware are now blocked on this whole Mac.\033[0m\n'
  echo "  Dashboard:   menu bar shield > Open dashboard"
  echo "  Turn on/off: click the shield in the menu bar"
  echo "  Also turn OFF 'Secure DNS' in your browser, and iCloud Private Relay if you use it."
  echo "  To remove:   double-click 'Uninstall DNSpro.command' (a copy is in $APP)"
  pause
else
  restore_dns
  fail "The check failed, so the DNS change was undone (your internet works as before)."
fi
