#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# DNSpro - free system-wide ad, tracker and malware blocking.
# Copyright (C) 2026 DNSpro contributors
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version. It is distributed WITHOUT ANY WARRANTY. See LICENSE for details.
"""
DNSpro - system-wide ad, tracker and malware blocking for Linux, Windows and macOS.

Runs a small DNS server on this computer that answers ad/tracker/malware
domains with 0.0.0.0 and forwards everything else to a normal resolver.
Once the system's DNS points at it, every app is covered.

Commands:
  dnspro run               start the DNS server and dashboard (the installer does this)
  dnspro status            show whether blocking is on, plus stats
  dnspro on | off          turn blocking on / off
  dnspro toggle            flip blocking on/off
  dnspro tray              show a taskbar / menu bar icon (needs PySide6)
  dnspro update            download the latest blocklists now
  dnspro check DOMAIN      say whether DOMAIN is blocked and by which rule
  dnspro allow DOMAIN      never block DOMAIN (or its subdomains)
  dnspro block DOMAIN      always block DOMAIN (and its subdomains)
  dnspro selftest [--wait SECONDS]   check that this computer's DNS goes through DNSpro
  dnspro version

The server needs only the Python 3.9+ standard library.
"""
import asyncio
import ipaddress
import json
import os
import re
import socket
import struct
import sys
import time
import urllib.request
from collections import Counter, OrderedDict
from pathlib import Path
from urllib.parse import parse_qs, urlparse

__version__ = "1.0.0"

IS_WINDOWS = os.name == "nt"
IS_MAC = sys.platform == "darwin"
# On Windows and macOS DNSpro runs as a system service on port 53 (neither OS lets
# you point DNS at another port). On Linux it runs as a user service on 5335 and
# systemd-resolved forwards to it.
SYSTEM_SERVICE = IS_WINDOWS or IS_MAC

if os.environ.get("DNSPRO_HOME"):
    CONFIG_DIR = DATA_DIR = Path(os.environ["DNSPRO_HOME"])
elif IS_WINDOWS:
    CONFIG_DIR = DATA_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "DNSpro"
elif IS_MAC:
    CONFIG_DIR = DATA_DIR = Path("/Library/Application Support/DNSpro")
else:
    CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "dnspro"
    DATA_DIR = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share") / "dnspro"
CONFIG_FILE = CONFIG_DIR / "config.json"
BLOCKLIST_FILE = DATA_DIR / "blocklist.txt"

DEFAULT_CONFIG = {
    "listen": ["127.0.0.1", "::1"] if SYSTEM_SERVICE else ["127.0.0.1"],
    "dns_port": 53 if SYSTEM_SERVICE else 5335,
    "dashboard_port": 5336,
    # Quad9 (blocks known-malicious domains too) with Cloudflare as backup.
    "upstreams": ["9.9.9.9", "1.1.1.1"],
    "lists": {
        # Well-maintained lists with few false positives. Add or remove as you like (https only).
        "HaGeZi Pro": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
        "OISD Big": "https://big.oisd.nl/",
        "StevenBlack Unified": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "HaGeZi Threat Intelligence (medium)": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt",
    },
    "update_hours": 24,
    "allowlist": [],
    "blocklist": [],
    "cache_size": 10000,
}

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
# DNSpro always answers <anything>.probe.dnspro.example with 0.0.0.0 (even when paused), so
# selftest/tray can tell whether this computer's DNS really goes through DNSpro. A normal
# resolver answers "doesn't exist" (.example is reserved). Random names dodge DNS caches.
PROBE_SUFFIX = ".probe.dnspro.example"
NULL_HOSTS = {"0.0.0.0", "127.0.0.1", "::", "::1", "localhost", "localhost.localdomain",
              "local", "broadcasthost", "ip6-localhost", "ip6-loopback"}

NOT_ROUTED_HINT = "Run the DNSpro installer again (a VPN can also cause this)."
if IS_WINDOWS:
    START_HINT = "Restart your PC, or run the DNSpro installer again"
    SHORTCUT_ON, SHORTCUT_OFF = "Ctrl+Alt+Shift+A", "Ctrl+Alt+Shift+B"
elif IS_MAC:
    START_HINT = "Run: sudo launchctl kickstart -k system/org.dnspro.server"
    SHORTCUT_ON = SHORTCUT_OFF = None
else:
    START_HINT = "Run: systemctl --user start dnspro"
    SHORTCUT_ON, SHORTCUT_OFF = "Meta+Alt+A", "Meta+Alt+B"


# ---------------------------------------------------------------- config

def load_config():
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if CONFIG_FILE.exists():
        cfg.update(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
    else:
        try:
            save_config(cfg)
        except OSError:
            pass  # e.g. a normal user reading a system-wide install
    if isinstance(cfg["listen"], str):
        cfg["listen"] = [cfg["listen"]]
    return cfg


def save_config(cfg):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    tmp.replace(CONFIG_FILE)


def add_rule(cfg, domain, kind):
    """Put domain on the allowlist or blocklist (and off the other one), then save."""
    other = "blocklist" if kind == "allowlist" else "allowlist"
    cfg[other] = [x for x in cfg[other] if x != domain]
    if domain not in cfg[kind]:
        cfg[kind].append(domain)
    save_config(cfg)


def parse_upstream(s):
    """'9.9.9.9', '2620:fe::fe', '1.2.3.4:5300' or '[2620:fe::fe]:53' -> (host, port)."""
    if s.startswith("["):
        host, _, port = s[1:].partition("]:")
        return host.rstrip("]"), int(port or 53)
    if s.count(":") == 1:
        host, port = s.split(":")
        return host, int(port)
    return s, 53


# ---------------------------------------------------------------- blocklists

def parse_line(line):
    """Extract a domain from hosts, plain-domain, wildcard, or Adblock (||x^) syntax."""
    line = line.split("#", 1)[0].split("!", 1)[0].strip().lower()
    if not line or line.startswith(("[", "@@")):
        return None
    if line.startswith("||"):
        line = line[2:]
        if not line.endswith("^") or any(c in line for c in "/$*"):
            return None  # path/option rules are browser-only, not DNS
        line = line[:-1]
    parts = line.split()
    if len(parts) >= 2 and parts[0] in NULL_HOSTS:
        line = parts[1]
    elif len(parts) != 1:
        return None
    line = line.removeprefix("*.").removeprefix(".").rstrip(".")
    if line in NULL_HOSTS or not DOMAIN_RE.match(line):
        return None
    return line


def update_lists(cfg):
    """Download, merge and save the blocklists. Returns True on success."""
    domains = set()
    for name, url in cfg["lists"].items():
        if not url.lower().startswith("https://"):
            print(f"  ! {name}: skipped (only https:// lists are allowed)")
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": f"DNSpro/{__version__}"})
            with urllib.request.urlopen(req, timeout=60) as r:
                text = r.read().decode("utf-8", "replace")
        except Exception as e:
            print(f"  ! {name}: failed ({e})")
            continue
        found = {d for d in map(parse_line, text.splitlines()) if d}
        print(f"  {name}: {len(found):,} domains")
        domains |= found
    if not domains:
        print("No lists downloaded; keeping the old blocklist.")
        return False
    # Drop subdomains already covered by a parent (we block wildcard-style).
    pruned = {d for d in domains if not any(
        ".".join(d.split(".")[i:]) in domains for i in range(1, d.count(".")))}
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = BLOCKLIST_FILE.with_suffix(".tmp")
    tmp.write_text("\n".join(sorted(pruned)) + "\n", encoding="utf-8")
    tmp.replace(BLOCKLIST_FILE)
    print(f"Saved {len(pruned):,} rules ({len(domains):,} before de-duplication)", flush=True)
    return True


class Filter:
    def __init__(self, cfg):
        self.blocked = set()
        if BLOCKLIST_FILE.exists():
            self.blocked = set(BLOCKLIST_FILE.read_text(encoding="utf-8").split())
        self.blocked |= {d.lower() for d in cfg["blocklist"]}
        self.allowed = {d.lower() for d in cfg["allowlist"]}

    @staticmethod
    def suffixes(name):
        labels = name.split(".")
        return (".".join(labels[i:]) for i in range(len(labels)))

    def match(self, name):
        """Return the rule that blocks name, or None. Blocks all subdomains too."""
        name = name.lower().rstrip(".")
        if any(s in self.allowed for s in self.suffixes(name)):
            return None
        for s in self.suffixes(name):
            if s in self.blocked:
                return s
        return None


# ---------------------------------------------------------------- DNS wire format

def parse_question(msg):
    """Return (qname, qtype, end_offset) for the first question."""
    if len(msg) < 17 or struct.unpack("!H", msg[4:6])[0] < 1:
        raise ValueError("no question")
    labels, i = [], 12
    while True:
        n = msg[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0:
            raise ValueError("compressed qname")
        labels.append(msg[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    if i + 4 > len(msg):
        raise ValueError("truncated question")
    qtype, = struct.unpack("!H", msg[i:i + 2])
    return ".".join(labels).lower(), qtype, i + 4


def blocked_response(query, qtype, q_end):
    qid, flags = struct.unpack("!HH", query[:4])
    flags = 0x8000 | (flags & 0x7900) | 0x0080  # QR, keep opcode+RD, set RA, rcode 0
    answer = b""
    if qtype == 1:      # A -> 0.0.0.0
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes(4)
    elif qtype == 28:   # AAAA -> ::
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 300, 16) + bytes(16)
    header = struct.pack("!HHHHHH", qid, flags, 1, 1 if answer else 0, 0, 0)
    return header + query[12:q_end] + answer


def servfail(query, q_end):
    qid, flags = struct.unpack("!HH", query[:4])
    flags = 0x8000 | (flags & 0x7900) | 0x0080 | 2
    return struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0) + query[12:q_end]


def skip_name(msg, i):
    while True:
        n = msg[i]
        if n == 0:
            return i + 1
        if n & 0xC0:
            return i + 2
        i += 1 + n


def min_ttl(resp):
    """Smallest TTL among answer records (used for cache lifetime)."""
    try:
        qd, an = struct.unpack("!HH", resp[4:8])
        i = 12
        for _ in range(qd):
            i = skip_name(resp, i) + 4
        ttls = []
        for _ in range(an):
            i = skip_name(resp, i)
            _, _, ttl, rdlen = struct.unpack("!HHIH", resp[i:i + 10])
            ttls.append(ttl)
            i += 10 + rdlen
        return min(ttls) if ttls else 60
    except Exception:
        return 0


def matches_query(resp, query, q_end):
    """Reject spoofed/mismatched upstream answers: same ID and same question."""
    return (len(resp) >= q_end and resp[:2] == query[:2] and resp[2] & 0x80
            and resp[12:q_end].lower() == query[12:q_end].lower())


# ---------------------------------------------------------------- server

class Blocker:
    def __init__(self, cfg):
        self.cfg = cfg
        self.filter = Filter(cfg)
        self.cache = OrderedDict()
        self.paused_until = 0
        self.started = time.time()
        self.total = self.blocked = self.cached = 0
        self.top_blocked = Counter()
        self.top_allowed = Counter()
        self.recent = []
        self.upstreams = [parse_upstream(u) for u in cfg["upstreams"]]

    def log(self, name, status):
        self.recent.append((time.strftime("%H:%M:%S"), name, status))
        del self.recent[:-100]

    async def forward_udp(self, query, q_end):
        loop = asyncio.get_running_loop()
        for host, port in self.upstreams:
            # A fresh socket per query gives a random source port (anti-spoofing).
            sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                await loop.sock_connect(sock, (host, port))
                await loop.sock_sendall(sock, query)
                deadline = loop.time() + 2.5
                while True:
                    resp = await asyncio.wait_for(loop.sock_recv(sock, 65535), deadline - loop.time())
                    if matches_query(resp, query, q_end):
                        return resp
            except (OSError, asyncio.TimeoutError, ValueError):
                continue
            finally:
                sock.close()
        return None

    async def forward_tcp(self, query, q_end):
        for host, port in self.upstreams:
            w = None
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(host, port), 3)
                w.write(struct.pack("!H", len(query)) + query)
                await w.drain()
                n, = struct.unpack("!H", await asyncio.wait_for(r.readexactly(2), 5))
                resp = await asyncio.wait_for(r.readexactly(n), 5)
                if matches_query(resp, query, q_end):
                    return resp
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                continue
            finally:
                if w:
                    w.close()
        return None

    @property
    def active(self):
        return time.time() >= self.paused_until

    async def resolve(self, query, tcp=False):
        try:
            name, qtype, q_end = parse_question(query)
        except (ValueError, IndexError, struct.error):
            return None
        if name.endswith(PROBE_SUFFIX):
            return blocked_response(query, qtype, q_end)
        self.total += 1
        if self.active:
            rule = self.filter.match(name)
            if rule:
                self.blocked += 1
                self.top_blocked[name] += 1
                self.log(name, "blocked")
                return blocked_response(query, qtype, q_end)
        self.top_allowed[name] += 1

        key = query[2:4] + query[12:q_end].lower()  # flags + question
        hit = self.cache.get(key)
        if hit and hit[0] > time.time():
            self.cached += 1
            self.cache.move_to_end(key)
            self.log(name, "cached")
            return query[:2] + hit[1][2:]

        resp = await (self.forward_tcp(query, q_end) if tcp else self.forward_udp(query, q_end))
        if resp is None:
            self.log(name, "failed")
            return servfail(query, q_end)
        rcode = resp[3] & 0x0F
        truncated = resp[2] & 0x02
        ttl = min(min_ttl(resp), 3600)
        if rcode in (0, 3) and not truncated and ttl > 0:
            self.cache[key] = (time.time() + ttl, resp)
            if len(self.cache) > self.cfg["cache_size"]:
                self.cache.popitem(last=False)
        self.log(name, "allowed")
        return resp

    def set_rule(self, domain, kind):
        add_rule(self.cfg, domain, kind)
        self.filter = Filter(self.cfg)
        self.cache.clear()

    # ---- transports

    class UDP(asyncio.DatagramProtocol):
        def __init__(self, blocker):
            self.b = blocker

        def connection_made(self, transport):
            self.t = transport

        def datagram_received(self, data, addr):
            asyncio.ensure_future(self.reply(data, addr))

        def error_received(self, exc):
            pass

        async def reply(self, data, addr):
            resp = await self.b.resolve(data)
            if resp:
                self.t.sendto(resp, addr)

    async def handle_tcp(self, reader, writer):
        try:
            while True:
                n, = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), 10))
                resp = await self.resolve(await reader.readexactly(n), tcp=True)
                if not resp:
                    break
                writer.write(struct.pack("!H", len(resp)) + resp)
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    # ---- dashboard / local API

    def stats(self):
        # paused_seconds: 0 = on, >0 = paused for that long, -1 = off until turned on
        paused = -1 if self.paused_until == float("inf") else max(0, int(self.paused_until - time.time()))
        return {
            "version": __version__,
            "total": self.total, "blocked": self.blocked, "cached": self.cached,
            "percent": round(100 * self.blocked / self.total, 1) if self.total else 0,
            "rules": len(self.filter.blocked), "uptime": int(time.time() - self.started),
            "paused_seconds": paused,
            "top_blocked": self.top_blocked.most_common(15),
            "top_allowed": self.top_allowed.most_common(15),
            "recent": self.recent[::-1][:50],
        }

    def allowed_hosts(self):
        p = self.cfg["dashboard_port"]
        return {f"127.0.0.1:{p}", f"localhost:{p}", f"[::1]:{p}"}

    def route(self, method, path, query, headers):
        """Returns (status, content_type, body)."""
        hosts = self.allowed_hosts()
        # DNS-rebinding protection: only answer requests addressed to localhost.
        if headers.get("host", "").lower() not in hosts:
            return "403 Forbidden", "text/plain", b"Forbidden"
        if method == "POST":
            # CSRF protection: a web page can't add this header to a cross-site request
            # without a CORS preflight, which we never approve.
            origin = headers.get("origin")
            if headers.get("x-dnspro") != "1" or (origin and origin.lower() not in {f"http://{h}" for h in hosts}):
                return "403 Forbidden", "application/json", b'{"ok":false,"error":"forbidden"}'
        elif method != "GET":
            return "405 Method Not Allowed", "application/json", b'{"ok":false}'

        ok = (b'{"ok":true}', b'{"ok":false}')
        if method == "GET" and path == "/":
            return "200 OK", "text/html; charset=utf-8", DASHBOARD.encode()
        if method == "GET" and path == "/api/stats":
            return "200 OK", "application/json", json.dumps(self.stats()).encode()
        if method == "POST" and path == "/api/pause":
            try:
                minutes = int(query.get("minutes", 5))
            except ValueError:
                return "400 Bad Request", "application/json", ok[1]
            self.paused_until = time.time() + 60 * minutes if minutes > 0 else float("inf")
            return "200 OK", "application/json", ok[0]
        if method == "POST" and path == "/api/resume":
            self.paused_until = 0
            return "200 OK", "application/json", ok[0]
        if method == "POST" and path in ("/api/allow", "/api/block"):
            d = query.get("domain", "").lower().strip().rstrip(".")
            if not DOMAIN_RE.match(d):
                return "400 Bad Request", "application/json", ok[1]
            self.set_rule(d, "allowlist" if path == "/api/allow" else "blocklist")
            return "200 OK", "application/json", ok[0]
        return "404 Not Found", "application/json", b"{}"

    async def handle_http(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            lines = head.decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split(" ", 2)
            headers = {}
            for line in lines[1:]:
                k, sep, v = line.partition(":")
                if sep:
                    headers[k.strip().lower()] = v.strip()
            url = urlparse(target)
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            code, ctype, body = self.route(method, url.path, q, headers)
            writer.write(
                f"HTTP/1.1 {code}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
                "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
                "X-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\n"
                "Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; "
                "style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; form-action 'none'\r\n"
                "Connection: close\r\n\r\n".encode() + body)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    # ---- lifecycle

    async def auto_update(self):
        loop = asyncio.get_running_loop()
        every = max(1, self.cfg.get("update_hours", 24)) * 3600
        if BLOCKLIST_FILE.exists():
            age = time.time() - BLOCKLIST_FILE.stat().st_mtime
            await asyncio.sleep(max(0, every - age))
        while True:
            print("Updating blocklists...", flush=True)
            ok = await loop.run_in_executor(None, update_lists, self.cfg)
            if ok:
                self.filter = await loop.run_in_executor(None, Filter, self.cfg)
                self.cache.clear()
            await asyncio.sleep(every if ok else 600)  # retry in 10 minutes if offline

    async def start(self):
        loop = asyncio.get_running_loop()
        port = self.cfg["dns_port"]
        self.servers = []
        for host in self.cfg["listen"]:
            t, _ = await loop.create_datagram_endpoint(lambda: self.UDP(self), local_addr=(host, port))
            self.servers.append(t)
            self.servers.append(await asyncio.start_server(self.handle_tcp, host, port))
        self.servers.append(await asyncio.start_server(self.handle_http, "127.0.0.1", self.cfg["dashboard_port"]))
        print(f"DNSpro {__version__}: blocking {len(self.filter.blocked):,} domains. "
              f"DNS on {', '.join(self.cfg['listen'])} port {port}", flush=True)
        print(f"Dashboard: http://127.0.0.1:{self.cfg['dashboard_port']}", flush=True)

    async def serve(self):
        await self.start()
        self.updater = asyncio.ensure_future(self.auto_update())
        await asyncio.Event().wait()


DASHBOARD = r"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>DNSpro</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1b1f24;--mute:#6b7280;--line:#e5e7eb;--red:#d93838;--green:#1f9d55;--accent:#3b6fe0}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--card:#1a1e24;--fg:#e8eaed;--mute:#9aa1ab;--line:#2a2f37;--red:#f06a6a;--green:#4cc38a;--accent:#7aa2ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0 0 4px}
.sub{color:var(--mute);margin-bottom:20px}.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.num{font-size:26px;font-weight:650;font-variant-numeric:tabular-nums}.lbl{color:var(--mute);font-size:13px}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}
h2{font-size:14px;margin:0 0 8px;color:var(--mute);font-weight:600}
table{width:100%;border-collapse:collapse;font-size:13px}td{padding:4px 2px;border-top:1px solid var(--line);word-break:break-all}
td.n{text-align:right;color:var(--mute);width:40px;white-space:nowrap}button{font:inherit;font-size:12px;border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:6px;padding:3px 8px;cursor:pointer}
button:hover{border-color:var(--accent)}.blocked,.failed{color:var(--red)}.allowed,.cached{color:var(--green)}
.bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:16px}#state{font-weight:600}
</style></head><body><main>
<h1>DNSpro</h1><div class="sub">System-wide ad, tracker and malware blocking for this computer</div>
<div class="bar"><span id="state"></span>
<button data-post="/api/pause?minutes=5">Pause 5 min</button>
<button data-post="/api/pause?minutes=60">Pause 1 hour</button>
<button data-post="/api/pause?minutes=0">Turn off</button>
<button data-post="/api/resume">Turn on</button></div>
<div class="row">
<div class="card"><div class="num" id="total">0</div><div class="lbl">Queries</div></div>
<div class="card"><div class="num" id="blocked">0</div><div class="lbl">Blocked</div></div>
<div class="card"><div class="num" id="percent">0%</div><div class="lbl">Blocked share</div></div>
<div class="card"><div class="num" id="rules">0</div><div class="lbl">Rules</div></div></div>
<div class="cols">
<div class="card"><h2>Top blocked</h2><table id="tb"></table></div>
<div class="card"><h2>Top allowed</h2><table id="ta"></table></div>
<div class="card" style="grid-column:1/-1"><h2>Recent queries</h2><table id="rc"></table></div></div>
</main><script>
// Everything from the server is inserted with textContent, never as HTML.
const $=id=>document.getElementById(id);
async function post(u){await fetch(u,{method:'POST',headers:{'X-DNSpro':'1'}});load()}
document.addEventListener('click',e=>{const b=e.target.closest('button[data-post]');if(b)post(b.dataset.post)});
function cell(tr,text,cls){const td=document.createElement('td');td.textContent=text;if(cls)td.className=cls;tr.appendChild(td);return td}
function action(tr,domain,isBlocked){const td=cell(tr,'','n'),b=document.createElement('button');
 b.textContent=isBlocked?'Allow':'Block';b.dataset.post=(isBlocked?'/api/allow':'/api/block')+'?domain='+encodeURIComponent(domain);td.appendChild(b)}
function fill(table,rows,make){table.replaceChildren(...rows.map(r=>{const tr=document.createElement('tr');make(tr,r);return tr}))}
async function load(){const s=await (await fetch('/api/stats')).json();
 for(const k of['total','blocked','rules'])$(k).textContent=s[k].toLocaleString();
 $('percent').textContent=s.percent+'%';
 const st=$('state');st.className=s.paused_seconds?'blocked':'allowed';
 st.textContent=s.paused_seconds<0?'Off':s.paused_seconds?`Paused (${Math.ceil(s.paused_seconds/60)} min left)`:'Protection on';
 fill($('tb'),s.top_blocked,(tr,[d,n])=>{cell(tr,d);cell(tr,n,'n');action(tr,d,true)});
 fill($('ta'),s.top_allowed,(tr,[d,n])=>{cell(tr,d);cell(tr,n,'n');action(tr,d,false)});
 fill($('rc'),s.recent,(tr,[t,d,x])=>{cell(tr,t,'n');cell(tr,d);cell(tr,x,x).style.width='70px';action(tr,d,x=='blocked')})}
load();setInterval(load,2000);
</script></body></html>"""


# ---------------------------------------------------------------- client side

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never send local API calls via a proxy


def api(cfg, path, method="GET", timeout=3):
    req = urllib.request.Request(f"http://127.0.0.1:{cfg['dashboard_port']}{path}",
                                 method=method, headers={"X-DNSpro": "1"})
    with _opener.open(req, timeout=timeout) as r:
        return json.load(r)


def notify(title, body):
    print(f"{title}: {body}")
    import subprocess
    try:
        if IS_MAC:
            esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')
            subprocess.run(["osascript", "-e", f'display notification "{esc(body)}" with title "{esc(title)}"'],
                           timeout=5, capture_output=True)
        elif not IS_WINDOWS:
            subprocess.run(["notify-send", "-a", "DNSpro", "-i", "security-high", "-t", "2500", title, body],
                           timeout=5, capture_output=True)
    except Exception:
        pass


def set_blocking(cfg, turn_on=None):
    """Turn blocking on (True), off (False), or flip it (None). Returns (title, body)."""
    try:
        if turn_on is None:
            turn_on = api(cfg, "/api/stats")["paused_seconds"] != 0
        api(cfg, "/api/resume" if turn_on else "/api/pause?minutes=0", "POST")
    except OSError:
        return "DNSpro isn't running", START_HINT
    if turn_on:
        return "Ad blocking ON", "Ads, trackers and malware are blocked"
    hint = f"Press {SHORTCUT_ON} to turn it back on" if SHORTCUT_ON else "Use the menu bar icon to turn it back on"
    return "Ad blocking OFF", hint


def lookup(host):
    try:
        return {ai[4][0].split("%")[0] for ai in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)}
    except socket.gaierror:
        return set()


def is_null(addr):
    ip = ipaddress.ip_address(addr)
    return ip.is_unspecified or (ip.version == 6 and ip.ipv4_mapped is not None and ip.ipv4_mapped.is_unspecified)


def dns_uses_dnspro():
    """True if this computer's DNS lookups actually go through DNSpro."""
    import secrets
    addrs = lookup(secrets.token_hex(6) + PROBE_SUFFIX)
    return bool(addrs) and all(is_null(a) for a in addrs)


def selftest(wait=0):
    """Check the computer's real DNS path. Retries for up to `wait` seconds (networks can
    take a few seconds to come back after the installer changes DNS settings)."""
    import secrets
    deadline = time.time() + wait
    while True:
        routed = dns_uses_dnspro()
        normal = lookup("example.com")
        ok_normal = bool(normal) and not all(is_null(a) for a in normal)
        if (routed and ok_normal) or time.time() >= deadline:
            break
        time.sleep(2)
    ad = lookup(secrets.token_hex(6) + ".doubleclick.net")
    blocked = bool(ad) and all(is_null(a) for a in ad)
    print(f"  DNS goes through DNSpro: {'yes' if routed else 'NO'}")
    print(f"  normal sites work:       {'yes' if ok_normal else 'NO'}")
    print(f"  ads blocked:             {'yes' if blocked else 'no'}")
    return 0 if routed and ok_normal else 1


# ---------------------------------------------------------------- tray icon

def shield_icon(color, mark):
    from PySide6.QtCore import QPointF, Qt
    from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap
    pix = QPixmap(64, 64)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    path = QPainterPath()
    path.moveTo(32, 3)
    path.lineTo(57, 11)
    path.lineTo(57, 29)
    path.cubicTo(57, 46, 46, 56, 32, 61)
    path.cubicTo(18, 56, 7, 46, 7, 29)
    path.lineTo(7, 11)
    path.closeSubpath()
    p.fillPath(path, QColor(color))
    pen = QPen(QColor("white"), 6)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    if mark == "check":
        p.drawPolyline([QPointF(20, 32), QPointF(29, 41), QPointF(45, 23)])
    elif mark == "x":
        p.drawLine(22, 22, 42, 42)
        p.drawLine(42, 22, 22, 42)
    else:
        p.drawLine(32, 18, 32, 34)
        p.drawPoint(32, 45)
    p.end()
    return QIcon(pix)


def register_windows_hotkeys(app, callbacks):
    """Global Ctrl+Alt+Shift+A / B on Windows via RegisterHotKey."""
    import ctypes
    from ctypes import wintypes
    from PySide6.QtCore import QAbstractNativeEventFilter

    MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_NOREPEAT, WM_HOTKEY = 0x1, 0x2, 0x4, 0x4000, 0x0312

    class HotkeyFilter(QAbstractNativeEventFilter):
        def nativeEventFilter(self, event_type, message):
            if bytes(event_type) in (b"windows_generic_MSG", b"windows_dispatcher_MSG"):
                msg = wintypes.MSG.from_address(int(message))
                if msg.message == WM_HOTKEY and msg.wParam in callbacks:
                    callbacks[msg.wParam]()
                    return True, 0
            return False, 0

    f = HotkeyFilter()
    app.installNativeEventFilter(f)
    ok = all(ctypes.windll.user32.RegisterHotKey(None, hid, MOD_CONTROL | MOD_ALT | MOD_SHIFT | MOD_NOREPEAT, ord(key))
             for hid, key in ((1, "A"), (2, "B")))
    return f, ok


def tray(cfg):
    """Green shield = on, red = off, yellow = not running."""
    import webbrowser
    from PySide6.QtCore import QDir, QLockFile, QTimer
    from PySide6.QtGui import QAction
    from PySide6.QtWidgets import QApplication, QMenu, QSystemTrayIcon

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setApplicationName("DNSpro")
    app.setDesktopFileName("dnspro-tray")
    import getpass
    lock = QLockFile(QDir.tempPath() + f"/dnspro-tray-{getpass.getuser()}.lock")
    if not lock.tryLock(100):
        return  # already running
    icons = {"on": shield_icon("#1f9d55", "check"), "off": shield_icon("#d93838", "x"),
             "down": shield_icon("#d99a1e", "!")}
    icon = QSystemTrayIcon(icons["down"])
    menu = QMenu()
    status = QAction("Checking...")
    status.setEnabled(False)
    menu.addAction(status)
    menu.addSeparator()
    on_label, off_label = "Turn on", "Turn off"
    if SHORTCUT_ON:
        on_label, off_label = f"Turn on  ({SHORTCUT_ON})", f"Turn off  ({SHORTCUT_OFF})"
    act_on = menu.addAction(icons["on"], on_label)
    act_off = menu.addAction(icons["off"], off_label)
    menu.addSeparator()
    menu.addAction("Open dashboard").triggered.connect(
        lambda: webbrowser.open(f"http://127.0.0.1:{cfg['dashboard_port']}"))
    menu.addAction("Hide this icon").triggered.connect(app.quit)
    icon.setContextMenu(menu)
    state = {"value": "down", "routed": True}

    def check_route():  # in a thread: DNS lookups can block for a few seconds
        while True:
            state["routed"] = dns_uses_dnspro() if state["value"] != "down" else True
            time.sleep(30)

    import threading
    threading.Thread(target=check_route, daemon=True).start()

    def switch(turn_on):
        title, body = set_blocking(cfg, turn_on)
        refresh()
        if IS_WINDOWS or IS_MAC:
            icon.showMessage(title, body, icons["on" if turn_on else "off"], 2500)
        else:
            notify(title, body)

    act_on.triggered.connect(lambda: switch(True))
    act_off.triggered.connect(lambda: switch(False))
    if not IS_MAC:  # on macOS a click opens the menu instead
        icon.activated.connect(lambda reason: reason == QSystemTrayIcon.ActivationReason.Trigger
                               and state["value"] != "down" and switch(state["value"] == "off"))

    def refresh():
        try:
            d = api(cfg, "/api/stats", timeout=0.5)
            value = "on" if d["paused_seconds"] == 0 else "off"
            if d["paused_seconds"] > 0:
                text = f"Ad blocking paused ({-(-d['paused_seconds'] // 60)} min left)"
            else:
                text = "Ad blocking ON" if value == "on" else "Ad blocking OFF"
            detail = f"{d['blocked']:,} of {d['total']:,} requests blocked ({d['percent']}%)"
        except (OSError, ValueError, KeyError):
            value, text, detail = "down", "DNSpro isn't running", START_HINT
        state["value"] = value
        if value != "down" and not state["routed"]:
            text, detail = "Not protecting: DNS isn't going through DNSpro", NOT_ROUTED_HINT
            value = "down"
        icon.setIcon(icons[value])
        icon.setToolTip(f"DNSpro: {text}\n{detail}")
        status.setText(text)
        act_on.setEnabled(state["value"] == "off")
        act_off.setEnabled(state["value"] == "on")

    if IS_WINDOWS:
        hotkeys, ok = register_windows_hotkeys(app, {1: lambda: switch(True), 2: lambda: switch(False)})
        if not ok:
            print("Couldn't register Ctrl+Alt+Shift+A/B (another app may be using them).")

    timer = QTimer()
    timer.timeout.connect(refresh)
    timer.start(2000)
    refresh()
    icon.show()
    sys.exit(app.exec())


# ---------------------------------------------------------------- CLI

def use_log_file():
    """On Windows the service has no console; keep a small log next to the data."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    log = DATA_DIR / "dnspro.log"
    if log.exists() and log.stat().st_size > 1_000_000:
        log.replace(log.with_suffix(".log.old"))
    sys.stdout = sys.stderr = open(log, "a", buffering=1, encoding="utf-8")


def asyncio_run(coro):
    """asyncio.run, but on Windows use the selector loop: it handles UDP errors
    (ICMP "port unreachable" from a client that went away) without stalling."""
    if not IS_WINDOWS:
        return asyncio.run(coro)
    if sys.version_info >= (3, 12):
        return asyncio.run(coro, loop_factory=asyncio.SelectorEventLoop)
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    return asyncio.run(coro)


def run(cfg):
    if IS_WINDOWS and (sys.stdout is None or not sys.stdout.isatty()):
        use_log_file()
    blocker = Blocker(cfg)
    if not BLOCKLIST_FILE.exists():
        print("No blocklist yet; serving DNS now and downloading lists in the background.", flush=True)
    try:
        asyncio_run(blocker.serve())
    except OSError as e:
        print(f"Couldn't start: {e}. Is something else using port {cfg['dns_port']} or {cfg['dashboard_port']}?",
              flush=True)
        sys.exit(1)
    except KeyboardInterrupt:
        pass


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    arg = sys.argv[2].lower().strip().rstrip(".") if len(sys.argv) > 2 else None
    if cmd in ("version", "--version"):
        print(f"DNSpro {__version__}")
        return
    if cmd == "selftest":
        wait = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[2] == "--wait" else 0
        sys.exit(selftest(wait))
    cfg = load_config()
    if cmd == "update":
        print("Downloading blocklists...")
        sys.exit(0 if update_lists(cfg) else 1)
    elif cmd == "run":
        run(cfg)
    elif cmd == "tray":
        tray(cfg)
    elif cmd in ("on", "off", "toggle"):
        title, body = set_blocking(cfg, {"on": True, "off": False, "toggle": None}[cmd])
        notify(title, body)
    elif cmd == "status":
        try:
            d = api(cfg, "/api/stats")
        except OSError:
            print(f"DNSpro isn't running. {START_HINT}")
            sys.exit(1)
        state = "ON" if d["paused_seconds"] == 0 else "OFF" if d["paused_seconds"] < 0 else \
            f"PAUSED ({-(-d['paused_seconds'] // 60)} min left)"
        print(f"Ad blocking: {state}\n{d['blocked']:,} of {d['total']:,} requests blocked ({d['percent']}%), "
              f"{d['rules']:,} rules\nDashboard: http://127.0.0.1:{cfg['dashboard_port']}")
        if not dns_uses_dnspro():
            print(f"WARNING: DNSpro is running, but this computer's DNS isn't going through it, so nothing "
                  f"is being blocked. {NOT_ROUTED_HINT}")
    elif cmd == "check" and arg:
        rule = Filter(cfg).match(arg)
        print(f"BLOCKED by rule: {rule}" if rule else "allowed")
    elif cmd in ("allow", "block") and arg:
        if not DOMAIN_RE.match(arg):
            print(f"'{arg}' doesn't look like a domain name.")
            sys.exit(1)
        try:
            api(cfg, f"/api/{cmd}?domain={arg}", "POST")
        except OSError:
            try:
                add_rule(cfg, arg, "allowlist" if cmd == "allow" else "blocklist")
            except OSError as e:
                print(f"Couldn't save the change ({e}). Try again as administrator.")
                sys.exit(1)
        print(f"{arg} will {'never' if cmd == 'allow' else 'always'} be blocked.")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
