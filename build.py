#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Builds the downloadable packages into dist/:  python build.py"""
import hashlib
import io
import re
import shutil
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
VERSION = re.search(r'^__version__ = "(.+)"', (ROOT / "dnspro.py").read_text(), re.M).group(1)
STAMP = (2026, 1, 1, 0, 0, 0)  # fixed timestamps -> reproducible zips

# (path inside package, source file, executable?, convert to Windows line endings?)
PACKAGES = {
    "linux": [
        ("dnspro.py", "dnspro.py", True, False),
        ("install.sh", "linux/install.sh", True, False),
        ("uninstall.sh", "linux/uninstall.sh", True, False),
        ("README.md", "README.md", False, False),
        ("LICENSE", "LICENSE", False, False),
    ],
    "windows": [
        ("Install DNSpro.bat", "windows/Install DNSpro.bat", False, True),
        ("Uninstall DNSpro.bat", "windows/Uninstall DNSpro.bat", False, True),
        ("install.ps1", "windows/install.ps1", False, True),
        ("uninstall.ps1", "windows/uninstall.ps1", False, True),
        ("dnspro.py", "dnspro.py", False, False),
        ("README.txt", "README.md", False, True),
        ("LICENSE.txt", "LICENSE", False, True),
    ],
    "macos": [
        ("Install DNSpro.command", "macos/install.command", True, False),
        ("Uninstall DNSpro.command", "macos/uninstall.command", True, False),
        ("dnspro.py", "dnspro.py", True, False),
        ("README.txt", "README.md", False, False),
        ("LICENSE.txt", "LICENSE", False, False),
    ],
}


def content(src, crlf):
    data = (ROOT / src).read_bytes().replace(b"\r\n", b"\n")
    return data.replace(b"\n", b"\r\n") if crlf else data


def build():
    shutil.rmtree(DIST, ignore_errors=True)
    DIST.mkdir()
    outputs = []
    for platform, files in PACKAGES.items():
        top = f"DNSpro-{VERSION}-{platform}"
        if platform == "linux":
            out = DIST / f"{top}.tar.gz"
            with tarfile.open(out, "w:gz") as tar:
                for name, src, exe, crlf in files:
                    data = content(src, crlf)
                    info = tarfile.TarInfo(f"{top}/{name}")
                    info.size, info.mode, info.mtime = len(data), 0o755 if exe else 0o644, 1767225600
                    tar.addfile(info, io.BytesIO(data))
        else:
            out = DIST / f"{top}.zip"
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
                for name, src, exe, crlf in files:
                    info = zipfile.ZipInfo(f"{top}/{name}", STAMP)
                    info.create_system = 3  # unix, so the permission bits below are honoured
                    info.external_attr = (0o100755 if exe else 0o100644) << 16
                    info.compress_type = zipfile.ZIP_DEFLATED
                    z.writestr(info, content(src, crlf))
        outputs.append(out)
        print(f"  {out.relative_to(ROOT)}  ({out.stat().st_size // 1024} KB)")

    sums = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in outputs)
    (DIST / "SHA256SUMS.txt").write_text(sums)
    (DIST / "RELEASE_NOTES.md").write_text(f"""## DNSpro {VERSION}

Free system-wide ad, tracker and malware blocking. Pick the download for your computer:

| Your computer | Download | Then |
|---|---|---|
| **Windows 10/11** | `DNSpro-{VERSION}-windows.zip` | Unzip, double-click **Install DNSpro.bat** |
| **Mac** (macOS 11+) | `DNSpro-{VERSION}-macos.zip` | Unzip, right-click **Install DNSpro.command** > Open |
| **Linux** | `DNSpro-{VERSION}-linux.tar.gz` | Extract, run `./install.sh` in a terminal |

See the README for details. `SHA256SUMS.txt` lets you verify the downloads.
""")
    print(f"Built DNSpro {VERSION} into dist/")


if __name__ == "__main__":
    build()
