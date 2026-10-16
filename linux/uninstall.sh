#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Removes DNSpro and restores normal DNS. Your allow/block lists (~/.config/dnspro) are kept.
set -uo pipefail
say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

say "Restoring normal DNS (needs your password)"
sudo rm -f /etc/systemd/resolved.conf.d/dnspro.conf /etc/NetworkManager/conf.d/dnspro.conf
systemctl is-active --quiet NetworkManager && sudo systemctl restart NetworkManager
sudo systemctl restart systemd-resolved

say "Removing keyboard shortcuts"
for name in dnspro-on dnspro-off; do
  gdbus call --session --dest org.kde.kglobalaccel --object-path /kglobalaccel \
    --method org.kde.KGlobalAccel.unregister "$name.desktop" _launch >/dev/null 2>&1
  rm -f "$HOME/.local/share/applications/$name.desktop"
done
if gsettings list-keys org.gnome.settings-daemon.plugins.media-keys >/dev/null 2>&1; then
  python3 - <<'EOF'
import ast, subprocess
schema = "org.gnome.settings-daemon.plugins.media-keys"
base = "/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/"
cur = subprocess.run(["gsettings", "get", schema, "custom-keybindings"], capture_output=True, text=True).stdout
paths = ast.literal_eval(cur.split(" ", 1)[1] if cur.startswith("@as") else cur)
mine = [f"{base}dnspro-on/", f"{base}dnspro-off/"]
for p in mine:
    subprocess.run(["gsettings", "reset-recursively", f"{schema}.custom-keybinding:{p}"], capture_output=True)
subprocess.run(["gsettings", "set", schema, "custom-keybindings", str([p for p in paths if p not in mine])])
EOF
fi

say "Removing taskbar icon"
pkill -f "python3 .*/dnspro tray$" 2>/dev/null
rm -f "$HOME/.config/autostart/dnspro-tray.desktop" "$HOME/.local/share/applications/dnspro-tray.desktop"

say "Removing service and files"
systemctl --user disable --now dnspro.service 2>/dev/null
rm -f "$HOME/.config/systemd/user/dnspro.service"
systemctl --user daemon-reload
rm -f "$HOME/.local/bin/dnspro"
rm -rf "$HOME/.local/share/dnspro"

printf '\n\033[32mDNSpro is removed and DNS is back to normal.\033[0m\n'
