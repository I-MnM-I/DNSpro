#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# One-line DNSpro install for macOS. Paste this into Terminal:
#   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/I-MnM-I/DNSpro/main/macos/get-dnspro.sh)"
#
# Downloads the latest release from GitHub, checks it against the published SHA-256
# checksum, and runs the normal installer. Files fetched with curl aren't marked
# "downloaded from the internet", so macOS doesn't show the unidentified-developer block.
set -euo pipefail
REPO="I-MnM-I/DNSpro"

fail() { printf '\n\033[31m!! %s\033[0m\n' "$*"; exit 1; }
[ "$(uname)" = Darwin ] || fail "This installer is for macOS."

echo "Finding the latest DNSpro release..."
tag="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
  sed -n 's/.*"tag_name": *"\(v[^"]*\)".*/\1/p' | head -n 1)"
[ -n "$tag" ] || fail "Couldn't reach GitHub. Check your internet connection and try again."
name="DNSpro-${tag#v}-macos"
base="https://github.com/$REPO/releases/download/$tag"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "Downloading $name..."
curl -fsSL -o "$tmp/$name.zip" "$base/$name.zip" || fail "Download failed."
curl -fsSL -o "$tmp/SHA256SUMS.txt" "$base/SHA256SUMS.txt" || fail "Download failed."
( cd "$tmp" && grep " $name.zip\$" SHA256SUMS.txt | shasum -a 256 -c - >/dev/null ) ||
  fail "The download doesn't match its published checksum, so it wasn't installed."
echo "    Checksum OK."
unzip -q "$tmp/$name.zip" -d "$tmp"
bash "$tmp/$name/Install DNSpro.command"
