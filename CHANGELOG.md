# Changelog

## 1.2.0

Security update. Installing it over an older version keeps your allow/block lists.

- **Encrypted DNS.** Lookups DNSpro sends to the internet now go to Quad9 and Cloudflare over
  DNS-over-TLS, so your internet provider or public Wi-Fi can't see or change them. The
  dashboard and `dnspro status` show whether lookups are encrypted. If a network blocks
  encrypted DNS, DNSpro falls back to normal DNS instead of cutting off the internet.
- **Browsers can't quietly skip DNSpro.** Firefox is told not to switch on its own encrypted
  DNS, and Apple devices not to use iCloud Private Relay, both of which went around the
  blocker. (To use Private Relay anyway, allow `mask.icloud.com` and `mask-h2.icloud.com`
  in the dashboard.)
- **Only you can turn it off.** Turning DNSpro on/off, changing allow/block rules and
  seeing which sites were visited now need a private key that only the account that
  installed it (and administrators) can read. Websites, other accounts on the computer and
  sandboxed apps can't. The dashboard now opens from the shield icon (or
  `dnspro dashboard`) instead of by typing its address.
- **Blocklist updates are checked.** A list that would block important sites (Google,
  Microsoft, Apple, Windows Update, GitHub...) or that suddenly changes size wildly is
  rejected, and DNSpro keeps using the last good copy of that list. A list that fails to
  download also falls back to its last good copy instead of disappearing until tomorrow.
- **Verifiable downloads.** Every download now comes with a signed GitHub attestation
  proving it was built from this repository's code by GitHub, and the build tools are
  pinned to exact versions.

## 1.0.0

First release.
