#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Builds the downloadable packages into dist/:  python build.py"""
import hashlib
import io
import re
import shutil
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
VERSION = re.search(r'^__version__ = "(.+)"', (ROOT / "dnspro.py").read_text(), re.M).group(1)
STAMP = (2026, 1, 1, 0, 0, 0)  # fixed timestamps -> reproducible zips

# The Windows download bundles Python and the bits of Qt the tray icon needs, so nobody has to
# install Python. Pinned by version and SHA-256; bump both together.
CACHE = ROOT / "build-cache"
WINDOWS_DEPS = [
    ("https://www.python.org/ftp/python/3.13.16/python-3.13.16-embed-amd64.zip",
     "97dae5274cc54867065e8d5a3226e48c35017ed332a0fdb0e27d5b5821961297"),
    ("https://files.pythonhosted.org/packages/03/61/9a7e32a37b224f68506785bfb0f288d516098ec71681782d72b695a6c95d/"
     "pyside6_essentials-6.12.0-cp310-abi3-win_amd64.whl",
     "c9a95102aa23c1f86516a30d5a9be37552d324eee7e567eb7508973f1218cb42"),
    ("https://files.pythonhosted.org/packages/2a/b6/bee97e7a2edeab72aafabb46ee5adc939790a638d107860b4cad7a20e407/"
     "shiboken6-6.12.0-cp310-abi3-win_amd64.whl",
     "a1906cb8116869178c64b6bab52623bbc8b4ceed7b30bfc3c9aa0f6e67f6438e"),
]
# Only what the tray icon uses (QtCore/QtGui/QtWidgets + the Windows platform plugin): ~42 MB instead of ~220 MB.
QT_KEEP = re.compile(r"""^(
    PySide6/[^/]+\.(py|json|typed) | shiboken6/[^/]+\.(py|json|typed|dll)
  | PySide6/(Qt6Core|Qt6Gui|Qt6Widgets|pyside6\.abi3|msvcp140[^/]*|concrt140|vcruntime140[^/]*)\.dll
  | PySide6/Qt(Core|Gui|Widgets)\.pyd
  | PySide6/plugins/platforms/qwindows\.dll | PySide6/plugins/styles/qmodernwindowsstyle\.dll
)$""", re.X | re.I)


def fetch(url, sha256):
    CACHE.mkdir(exist_ok=True)
    path = CACHE / url.rsplit("/", 1)[1]
    if not path.exists():
        print(f"  downloading {path.name}")
        tmp = path.with_suffix(".part")
        with urllib.request.urlopen(url, timeout=120) as r, open(tmp, "wb") as f:
            shutil.copyfileobj(r, f)
        tmp.replace(path)
    if hashlib.sha256(path.read_bytes()).hexdigest() != sha256:
        path.unlink()
        raise SystemExit(f"Checksum mismatch for {url}; refusing to build.")
    return path


def windows_runtime():
    """Yields (path inside package, bytes) for the bundled Python + trimmed PySide6."""
    (embed, _), *wheels = [(fetch(u, h), u) for u, h in WINDOWS_DEPS]
    with zipfile.ZipFile(embed) as z:
        for name in z.namelist():
            data = z.read(name)
            if name.endswith("._pth"):
                # Let the bundled Python find the tray icon libraries and run `site`.
                data = data.replace(b"#import site", b"import site").rstrip() + b"\r\nLib\\site-packages\r\n"
            yield f"python/{name}", data
    for wheel, _ in wheels:
        with zipfile.ZipFile(wheel) as z:
            for name in z.namelist():
                if QT_KEEP.match(name):
                    yield f"python/Lib/site-packages/{name}", z.read(name)


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
                if platform == "windows":
                    for name, data in windows_runtime():
                        info = zipfile.ZipInfo(f"{top}/{name}", STAMP)
                        info.compress_type = zipfile.ZIP_DEFLATED
                        z.writestr(info, data)
        outputs.append(out)
        print(f"  {out.relative_to(ROOT)}  ({out.stat().st_size // 1024} KB)")

    sums = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in outputs)
    (DIST / "SHA256SUMS.txt").write_text(sums)
    changes = ""
    log = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"\n## {VERSION}\n" in log:
        changes = "### What's new\n" + log.split(f"\n## {VERSION}\n", 1)[1].split("\n## ", 1)[0].strip() + "\n\n"
    (DIST / "RELEASE_NOTES.md").write_text(f"""## DNSpro {VERSION}

Free system-wide ad, tracker and malware blocking. Pick the download for your computer:

| Your computer | How to install |
|---|---|
| **Windows 10/11** | Download `DNSpro-{VERSION}-windows.zip`, unzip it, double-click **Install DNSpro.bat** (Python is included) |
| **Mac** (macOS 11+) | Open Terminal and paste the one-line command from the README (no security warnings) |
| **Linux** | Download `DNSpro-{VERSION}-linux.tar.gz`, extract it, run `./install.sh` in a terminal |

{changes}### Check a download is genuine
Each file is signed by GitHub to prove it was built from this repository's code. With the
[GitHub CLI](https://cli.github.com): `gh attestation verify <file> -R I-MnM-I/DNSpro`.
`SHA256SUMS.txt` lists each file's checksum.
""")
    print(f"Built DNSpro {VERSION} into dist/")


if __name__ == "__main__":
    build()
