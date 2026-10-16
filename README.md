# DNSpro

**Free ad, tracker and malware blocking for your whole computer** (Windows, Mac and Linux).

DNSpro blocks ads and tracking everywhere, not just in one browser: in every browser, in apps, in games, in
Discord, Spotify, Windows and macOS themselves. It also blocks hundreds of thousands of known scam, phishing and
malware sites, so a bad link is far less likely to hurt you.

- Blocks about **800,000** ad, tracker and malware domains, updated automatically every day
- Makes browsing faster: fewer things to load, and repeat lookups are answered instantly
- One-click on/off from the taskbar / menu bar icon
- Live dashboard showing what's been blocked, with one-click "Allow" if a site breaks
- Private: everything runs on your own computer. No account, no tracking, no data collected
- Free and open source forever (GPL-3.0)

---

## Install

### Windows 10 / 11
1. Download **`DNSpro-…-windows.zip`** from the [Releases page](../../releases) and unzip it (right-click > *Extract All*).
2. Double-click **`Install DNSpro.bat`**. Click **Yes** when Windows asks for permission.
   - If you see *"Windows protected your PC"*, click **More info** > **Run anyway**. (This appears for any new
     program that isn't from a big company. You can read every line of DNSpro's code here.)
3. Wait for **"Done!"**. If Python isn't installed, the installer installs it for you.

### Mac (macOS 11 or newer)
1. Download **`DNSpro-…-macos.zip`** from the [Releases page](../../releases) and double-click it to unzip.
2. **Right-click** **`Install DNSpro.command`** > **Open** > **Open**. (A plain double-click is blocked the first time
   because the file isn't from the App Store.)
3. Enter your Mac password when asked, and wait for **"Done!"**.
   - If macOS offers to install "command line developer tools", click **Install**, then run the installer again.

### Linux
Works on distributions that use systemd-resolved: Fedora, Ubuntu, Bazzite, Linux Mint, Pop!_OS and others.
```bash
tar xzf DNSpro-*-linux.tar.gz && cd DNSpro-*-linux && ./install.sh
```

### One more step: browsers
Turn off your browser's own "secure DNS", or the browser goes around DNSpro:
- **Chrome / Edge / Brave:** Settings > Privacy and security > Security > *Use secure DNS* > **Off**
- **Firefox:** Settings > Privacy & Security > *DNS over HTTPS* > **Off**
- **Mac:** also turn off **iCloud Private Relay** if you use it

---

## Using it

| | Windows | Mac | Linux |
|---|---|---|---|
| **Status** | Shield icon by the clock (click **^** if hidden) | Shield icon in the menu bar | Shield icon in the taskbar |
| **Turn on** | `Ctrl+Alt+Shift+A` or click the icon | Click the icon > *Turn on* | `Meta+Alt+A` or click the icon |
| **Turn off** | `Ctrl+Alt+Shift+B` or click the icon | Click the icon > *Turn off* | `Meta+Alt+B` or click the icon |
| **Dashboard** | http://127.0.0.1:5336 or Start menu > DNSpro | http://127.0.0.1:5336 | http://127.0.0.1:5336 |
| **Uninstall** | Settings > Apps > DNSpro > Uninstall | Double-click *Uninstall DNSpro.command* | `./uninstall.sh` |

**Green shield** = blocking on. **Red** = off. **Yellow** = DNSpro isn't running.

**A website or app doesn't work?** Open the dashboard, find the site under *Recent queries*, and click **Allow**.
Or turn DNSpro off for a moment to check whether it's the cause.

**Internet stopped working completely?** Uninstall DNSpro. It puts your computer's DNS settings back exactly as
they were.

### What DNSpro can't block
DNS blocking can't remove ads that come from the same servers as the content, mainly **YouTube and Twitch video
ads** and ads inside Facebook/Instagram. For those, also install the free browser extension
[uBlock Origin](https://ublockorigin.com). The two together give you the best protection.

---

## How it works

DNSpro runs a tiny DNS server on your own computer (`127.0.0.1`). When any app looks up a name like
`ads.example.com`, DNSpro checks it against the blocklists. Ad, tracker and malware domains get the answer
`0.0.0.0` ("nowhere"), so they never load. Everything else is forwarded to
[Quad9](https://quad9.net) (a non-profit resolver that also blocks malicious sites), with Cloudflare as a backup.

Everything is one readable Python file, [`dnspro.py`](dnspro.py). The server uses only Python's standard library.
The optional tray icon uses PySide6 (Qt).

| | Windows | Mac | Linux |
|---|---|---|---|
| Runs as | Scheduled task (SYSTEM), auto-restarts | launchd daemon (root) | systemd user service |
| Program | `C:\Program Files\DNSpro` | `/Library/Application Support/DNSpro` | `~/.local/bin/dnspro` |
| Settings & lists | `C:\ProgramData\DNSpro` | `/Library/Application Support/DNSpro` | `~/.config/dnspro`, `~/.local/share/dnspro` |
| DNS change | Every adapter → `127.0.0.1` / `::1` (originals saved) | Every network service → `127.0.0.1` / `::1` (originals saved) | systemd-resolved → `127.0.0.1:5335` |

### Command line
```
dnspro status | on | off | toggle | update | check DOMAIN | allow DOMAIN | block DOMAIN | selftest
```
(Windows: `"C:\Program Files\DNSpro\dnspro.py"` via `py`. Mac: `/usr/bin/python3 "/Library/Application Support/DNSpro/dnspro.py"`.)

Settings live in `config.json`: upstream resolvers, blocklists (https only), update interval, and your own
allow/block lists.

### Security
DNSpro changes how your computer finds every website, so it's built defensively:
- **Only reachable from this computer.** The DNS server and dashboard listen on `127.0.0.1`/`::1` only.
- **Websites can't control it.** The dashboard API refuses requests from other sites (CSRF protection via a
  required custom header and an Origin check) and refuses requests not addressed to `localhost`
  (DNS-rebinding protection). That stops a malicious page from switching DNSpro off or reading your history.
- **No code injection in the dashboard.** All data is inserted as plain text, and a strict Content-Security-Policy
  plus frame blocking are applied.
- **Spoofed answers are rejected.** Each upstream query uses a fresh random port, and the reply must match the
  query's ID and question.
- **Files only admins can change.** On Windows and Mac the service runs with system rights, so its program,
  Python interpreter, settings and blocklists are stored where only administrators can modify them.
- **Safe install and uninstall.** The installer checks that DNS works before finishing, and undoes the change
  if it doesn't. The uninstaller restores your original DNS settings.

Found a security problem? Please open an issue (or a private security advisory) on GitHub.

### Development
```bash
python -m unittest discover -v tests   # unit + integration tests, no internet needed
python build.py                        # builds the three downloads into dist/
```
GitHub Actions runs the tests on Windows, macOS and Linux (Python 3.9 and 3.13), and does a full
install → check → uninstall on each OS. Pushing a tag like `v1.0.1` publishes a release automatically.

---

## Credits & license

Blocklists are downloaded directly from their maintainers (DNSpro doesn't redistribute them). Thank you to:
[HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists) ·
[OISD](https://oisd.nl) ·
[StevenBlack/hosts](https://github.com/StevenBlack/hosts).

DNSpro is free software: you can use, share and modify it under the terms of the
[GNU General Public License v3.0 or later](LICENSE). It comes with **no warranty**.
