# SPDX-License-Identifier: GPL-3.0-or-later
"""Security checks against a DNSpro that's really installed and running (CI runs this
after each installer):  python tests/e2e_security.py"""
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import dnspro  # noqa: E402

cfg = dnspro.load_config()
base = f"http://127.0.0.1:{cfg['dashboard_port']}"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def post_without_key(path):
    try:
        opener.open(urllib.request.Request(base + path, method="POST", headers={"X-DNSpro": "1"}))
        return 200
    except urllib.error.HTTPError as e:
        return e.code


assert post_without_key("/api/pause?minutes=0") == 403, "turned off without the key"
assert "recent" not in json.load(opener.open(base + "/api/stats")), "history visible without the key"
assert b"Open dashboard" in opener.open(base + "/").read(), "dashboard opened without logging in"

full = dnspro.api(cfg, "/api/stats")
assert "recent" in full, "the key didn't unlock the stats"
assert dnspro.set_blocking(cfg, False)[0] == "Ad blocking OFF"
assert dnspro.api(cfg, "/api/stats")["paused_seconds"] == -1
assert dnspro.set_blocking(cfg, True)[0] == "Ad blocking ON"

assert not dnspro.lookup("use-application-dns.net"), "Firefox's DoH canary should not resolve"
assert not dnspro.lookup("mask.icloud.com"), "iCloud Private Relay canary should not resolve"
dnspro.lookup("example.org")
via = dnspro.api(cfg, "/api/stats")["upstream"]
assert via == "encrypted", f"lookups to the internet are {via}"
print("Security checks passed: key required, history private, bypass canaries answered, DNS encrypted")
