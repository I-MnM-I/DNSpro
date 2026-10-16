#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# DNSpro installer for Linux (systemd-resolved based distros: Fedora, Ubuntu, Bazzite, Mint, Pop!_OS, ...)
# Undo everything with ./uninstall.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/dnspro.py"; [ -f "$SRC" ] || SRC="$HERE/../dnspro.py"
BIN="$HOME/.local/bin/dnspro"
UNIT_DIR="$HOME/.config/systemd/user"
PORT=5335

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
fail() { printf '\n\033[31m!! %s\033[0m\n' "$*"; exit 1; }

say "Checking this computer"
[ "$(id -u)" -ne 0 ] || fail "Run this as your normal user, not with sudo. It will ask for your password when needed."
command -v python3 >/dev/null || fail "Python 3 is missing. Install it with your package manager (e.g. 'sudo apt install python3')."
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || fail "Python 3.9 or newer is required."
systemctl --user show-environment >/dev/null 2>&1 || fail "systemd user services aren't available on this system."
systemctl is-active --quiet systemd-resolved || fail "This system doesn't use systemd-resolved, which DNSpro for Linux needs.
   (Fedora, Ubuntu, Bazzite, Mint and Pop!_OS use it by default.)"
grep -qE '^nameserver 127\.0\.0\.53' /etc/resolv.conf || fail "/etc/resolv.conf doesn't point at systemd-resolved (127.0.0.53).
   DNSpro would be bypassed, so nothing was changed."
if ! systemctl --user is-active --quiet dnspro.service && command -v ss >/dev/null &&
   ss -lntu | grep -qE "127\.0\.0\.1:(5335|5336)\b"; then
  fail "Ports 5335/5336 are already in use by another program (an older ad blocker?). Remove it first."
fi
echo "    Looks good."

say "Installing DNSpro to $BIN"
install -Dm755 "$SRC" "$BIN"
echo "    Downloading blocklists (first time only, takes a few seconds)..."
"$BIN" update

say "Starting the background service"
mkdir -p "$UNIT_DIR"
cat > "$UNIT_DIR/dnspro.service" <<EOF
[Unit]
Description=DNSpro ad blocker
After=network-online.target

[Service]
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/env python3 $BIN run
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable dnspro.service >/dev/null 2>&1
systemctl --user restart dnspro.service
loginctl enable-linger "$USER" 2>/dev/null || true   # start at boot, not just at login
for _ in $(seq 40); do "$BIN" status >/dev/null 2>&1 && break; sleep 0.5; done
"$BIN" status >/dev/null 2>&1 || fail "The service didn't start. See: journalctl --user -u dnspro"

say "Adding keyboard shortcuts: Meta+Alt+A = on, Meta+Alt+B = off"
if gdbus introspect --session --dest org.kde.kglobalaccel --object-path /kglobalaccel >/dev/null 2>&1; then
  KGA="gdbus call --session --dest org.kde.kglobalaccel --object-path /kglobalaccel --method org.kde.KGlobalAccel"
  kde_shortcut() {  # name, command, label, Qt key code
    install -Dm644 /dev/stdin "$HOME/.local/share/applications/$1.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=$3
Exec=$BIN $2
Icon=security-high
NoDisplay=true
StartupNotify=false
X-KDE-GlobalAccel-CommandShortcut=true
EOF
    local action="['$1.desktop','_launch','$3','$3']"
    # KDE can take a moment to notice the new .desktop file, so verify and retry.
    for _ in 1 2 3 4 5; do
      sleep 1
      $KGA.doRegister "$action" >/dev/null 2>&1
      # flags 6 = SetPresent + NoAutoloading (without SetPresent KDE stores the keys but ignores the key press)
      $KGA.setShortcutKeys "$action" "[([$4],)]" 6 >/dev/null 2>&1
      if $KGA.allComponents 2>/dev/null | grep -q "/component/${1//-/_}_desktop'"; then
        echo "    $3: set"; return
      fi
    done
    echo "    $3: couldn't set it. Add it in System Settings > Shortcuts > Add New > Command: $BIN $2"
  }
  kde_shortcut dnspro-on  on  "DNSpro On"  402653249  # Meta+Alt+A
  kde_shortcut dnspro-off off "DNSpro Off" 402653250  # Meta+Alt+B
elif gsettings list-keys org.gnome.settings-daemon.plugins.media-keys >/dev/null 2>&1; then
  BIN="$BIN" python3 - <<'EOF'
import ast, os, subprocess
schema = "org.gnome.settings-daemon.plugins.media-keys"
base = "/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/"
cur = subprocess.run(["gsettings", "get", schema, "custom-keybindings"], capture_output=True, text=True).stdout
paths = ast.literal_eval(cur.split(" ", 1)[1] if cur.startswith("@as") else cur)
for name, cmd, keys in (("dnspro-on", "on", "<Super><Alt>a"), ("dnspro-off", "off", "<Super><Alt>b")):
    path = f"{base}{name}/"
    if path not in paths:
        paths.append(path)
    item = f"{schema}.custom-keybinding:{path}"
    for k, v in (("name", f"DNSpro {cmd}"), ("command", f"{os.environ['BIN']} {cmd}"), ("binding", keys)):
        subprocess.run(["gsettings", "set", item, k, v], check=True)
subprocess.run(["gsettings", "set", schema, "custom-keybindings", str(paths)], check=True)
print("    Super+Alt+A / Super+Alt+B: set")
EOF
else
  echo "    Your desktop isn't KDE or GNOME. Add shortcuts yourself for: $BIN on   and   $BIN off"
fi

say "Adding the taskbar icon"
if python3 -c 'import PySide6.QtWidgets' 2>/dev/null; then
  install -Dm644 /dev/stdin "$HOME/.config/autostart/dnspro-tray.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=DNSpro
Comment=Shows whether ad blocking is on
Exec=$BIN tray
Icon=security-high
X-KDE-autostart-phase=2
EOF
  install -Dm644 "$HOME/.config/autostart/dnspro-tray.desktop" "$HOME/.local/share/applications/dnspro-tray.desktop"
  pkill -f "python3 .*/dnspro tray$" 2>/dev/null || true
  setsid -f "$BIN" tray >/dev/null 2>&1 < /dev/null
  echo "    Done (GNOME needs the 'AppIndicator' extension to show tray icons)."
else
  echo "    Skipped: PySide6 isn't installed. Install it to get the icon, then run this installer again:"
  echo "      Fedora: sudo dnf install python3-pyside6     Ubuntu/Mint: sudo apt install python3-pyside6.qtwidgets"
fi

say "Pointing system DNS at DNSpro (needs your password)"
sudo mkdir -p /etc/systemd/resolved.conf.d
sudo tee /etc/systemd/resolved.conf.d/dnspro.conf >/dev/null <<EOF
# Added by DNSpro. Remove this file (or run uninstall.sh) to undo.
[Resolve]
DNS=127.0.0.1:$PORT
Domains=~.
EOF
NM=0
if systemctl is-active --quiet NetworkManager; then
  NM=1
  # Stop NetworkManager from handing your router's DNS to resolved (which would bypass DNSpro)
  sudo mkdir -p /etc/NetworkManager/conf.d
  sudo tee /etc/NetworkManager/conf.d/dnspro.conf >/dev/null <<EOF
# Added by DNSpro. Remove this file (or run uninstall.sh) to undo.
[main]
dns=none
EOF
  sudo systemctl restart NetworkManager
fi
sudo systemctl restart systemd-resolved
sudo resolvectl flush-caches 2>/dev/null || true

say "Checking that it works"
sleep 2
if "$BIN" selftest --wait 30; then
  printf '\n\033[32mDone! Ads, trackers and malware are now blocked on this whole computer.\033[0m\n'
  echo "  Dashboard:  http://127.0.0.1:5336"
  echo "  Turn on/off: Meta+Alt+A / Meta+Alt+B, or click the shield icon"
  echo "  Also turn OFF 'Secure DNS' / 'DNS over HTTPS' in your browser settings, or the browser skips DNSpro."
else
  echo "!! The check failed, so the DNS change was undone (your internet works as before)."
  sudo rm -f /etc/systemd/resolved.conf.d/dnspro.conf /etc/NetworkManager/conf.d/dnspro.conf
  [ "$NM" = 1 ] && sudo systemctl restart NetworkManager
  sudo systemctl restart systemd-resolved
  exit 1
fi
