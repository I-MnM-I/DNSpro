# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for DNSpro. Run with:  python -m unittest discover -v tests"""
import asyncio
import json
import os
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path

HOME = tempfile.mkdtemp(prefix="dnspro-test-")
os.environ["DNSPRO_HOME"] = HOME
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import dnspro  # noqa: E402

FAKE_IP = bytes([93, 184, 215, 14])


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_query(name, qtype=1, qid=0x1234):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


def answer_ips(resp):
    """Pull A/AAAA addresses out of a response (enough for these tests)."""
    _, q_end = dnspro.parse_question(resp)[0], dnspro.parse_question(resp)[2]
    an = struct.unpack("!H", resp[6:8])[0]
    i, ips = q_end, []
    for _ in range(an):
        i = dnspro.skip_name(resp, i)
        rtype, _, _, rdlen = struct.unpack("!HHIH", resp[i:i + 10])
        rdata = resp[i + 10:i + 10 + rdlen]
        ips.append(socket.inet_ntop(socket.AF_INET if rtype == 1 else socket.AF_INET6, rdata))
        i += 10 + rdlen
    return ips


class FakeUpstream(asyncio.DatagramProtocol):
    """Answers every A query with 93.184.215.14."""

    def connection_made(self, t):
        self.t = t

    def datagram_received(self, data, addr):
        _, qtype, q_end = dnspro.parse_question(data)
        ans = b""
        if qtype == 1:
            ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 120, 4) + FAKE_IP
        hdr = struct.pack("!HHHHHH", struct.unpack("!H", data[:2])[0], 0x8180, 1, 1 if ans else 0, 0, 0)
        self.t.sendto(hdr + data[12:q_end] + ans, addr)


class TestParsing(unittest.TestCase):
    def test_parse_line_formats(self):
        cases = {
            "0.0.0.0 ads.example.com": "ads.example.com",
            "127.0.0.1 tracker.example.net # comment": "tracker.example.net",
            "||ads.example.org^": "ads.example.org",
            "*.wild.example.com": "wild.example.com",
            "plain.example.io": "plain.example.io",
            "||example.com/path^": None,       # browser-only rule
            "@@||allowed.example.com^": None,  # exception rule
            "0.0.0.0 localhost": None,
            "! adblock comment": None,
            "# hosts comment": None,
            "com": None,                       # never block a whole TLD
            "": None,
        }
        for line, want in cases.items():
            self.assertEqual(dnspro.parse_line(line), want, line)

    def test_filter_subdomains_and_allowlist(self):
        cfg = dict(dnspro.DEFAULT_CONFIG, blocklist=["ads.test", "evil.test"], allowlist=["ok.ads.test"])
        f = dnspro.Filter(cfg)
        self.assertEqual(f.match("ads.test"), "ads.test")
        self.assertEqual(f.match("x.y.ads.test."), "ads.test")
        self.assertIsNone(f.match("ok.ads.test"))
        self.assertIsNone(f.match("deep.ok.ads.test"))
        self.assertIsNone(f.match("notads.test"))

    def test_parse_upstream(self):
        self.assertEqual(dnspro.parse_upstream("9.9.9.9"), ("9.9.9.9", 53))
        self.assertEqual(dnspro.parse_upstream("1.2.3.4:5300"), ("1.2.3.4", 5300))
        self.assertEqual(dnspro.parse_upstream("2620:fe::fe"), ("2620:fe::fe", 53))
        self.assertEqual(dnspro.parse_upstream("[2620:fe::fe]:5353"), ("2620:fe::fe", 5353))

    def test_malformed_packets_rejected(self):
        for bad in (b"", b"\x00" * 12, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05abc"):
            with self.assertRaises((ValueError, IndexError, struct.error)):
                dnspro.parse_question(bad)

    def test_spoofed_answer_rejected(self):
        q = make_query("example.com")
        _, _, q_end = dnspro.parse_question(q)
        good = q[:2] + b"\x81\x80" + q[4:]
        self.assertTrue(dnspro.matches_query(good, q, q_end))
        self.assertFalse(dnspro.matches_query(b"\x99\x99" + good[2:], q, q_end))       # wrong ID
        self.assertFalse(dnspro.matches_query(good.replace(b"example", b"exbmple"), q, q_end))  # wrong name


class TestServer(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        loop = asyncio.get_running_loop()
        up_port = free_port()
        self.up, _ = await loop.create_datagram_endpoint(FakeUpstream, local_addr=("127.0.0.1", up_port))
        self.cfg = dict(dnspro.DEFAULT_CONFIG, listen=["127.0.0.1"], dns_port=free_port(),
                        dashboard_port=free_port(), upstreams=[f"127.0.0.1:{up_port}"],
                        blocklist=["doubleclick.net"], allowlist=[])
        self.blocker = dnspro.Blocker(self.cfg)
        await self.blocker.start()

    async def asyncTearDown(self):
        for s in self.blocker.servers:
            s.close()
        self.up.close()

    async def dns(self, name, qtype=1, tcp=False):
        loop = asyncio.get_running_loop()
        q = make_query(name, qtype)
        if tcp:
            r, w = await asyncio.open_connection("127.0.0.1", self.cfg["dns_port"])
            w.write(struct.pack("!H", len(q)) + q)
            n, = struct.unpack("!H", await r.readexactly(2))
            resp = await r.readexactly(n)
            w.close()
            return resp
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_connect(sock, ("127.0.0.1", self.cfg["dns_port"]))
            await loop.sock_sendall(sock, q)
            return await asyncio.wait_for(loop.sock_recv(sock, 4096), 3)
        finally:
            sock.close()

    async def http(self, method, path, headers=None):
        port = self.cfg["dashboard_port"]
        h = {"Host": f"127.0.0.1:{port}"}
        h.update(headers or {})
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write((f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items())
                 + "Content-Length: 0\r\n\r\n").encode())
        data = await r.read()
        w.close()
        head, _, body = data.partition(b"\r\n\r\n")
        return int(head.split()[1]), head.decode(), body

    async def test_blocks_ads_and_forwards_the_rest(self):
        self.assertEqual(answer_ips(await self.dns("doubleclick.net")), ["0.0.0.0"])
        self.assertEqual(answer_ips(await self.dns("ad.doubleclick.net", qtype=28)), ["::"])
        self.assertEqual(answer_ips(await self.dns("example.com")), ["93.184.215.14"])
        self.assertEqual(answer_ips(await self.dns("example.com", tcp=True)), ["93.184.215.14"])  # served from cache over TCP
        self.assertEqual(self.blocker.cached, 1)

    async def test_probe_answers_even_when_paused_or_allowlisted(self):
        self.blocker.paused_until = float("inf")
        self.cfg["allowlist"].append("dnspro.example")
        self.assertEqual(answer_ips(await self.dns("abc123" + dnspro.PROBE_SUFFIX)), ["0.0.0.0"])
        self.assertEqual(self.blocker.total, 0)  # probes don't count in the stats

    async def test_pause_and_resume_via_api(self):
        hdr = {"X-DNSpro": "1"}
        self.assertEqual((await self.http("POST", "/api/pause?minutes=0", hdr))[0], 200)
        self.assertEqual(answer_ips(await self.dns("doubleclick.net")), ["93.184.215.14"])
        _, _, body = await self.http("GET", "/api/stats")
        self.assertEqual(json.loads(body)["paused_seconds"], -1)
        self.assertEqual((await self.http("POST", "/api/resume", hdr))[0], 200)
        self.assertEqual(answer_ips(await self.dns("doubleclick.net")), ["0.0.0.0"])

    async def test_allow_and_block_via_api(self):
        hdr = {"X-DNSpro": "1"}
        await self.http("POST", "/api/allow?domain=doubleclick.net", hdr)
        self.assertEqual(answer_ips(await self.dns("doubleclick.net")), ["93.184.215.14"])
        await self.http("POST", "/api/block?domain=example.org", hdr)
        self.assertEqual(answer_ips(await self.dns("www.example.org")), ["0.0.0.0"])
        saved = json.loads(dnspro.CONFIG_FILE.read_text())
        self.assertIn("doubleclick.net", saved["allowlist"])
        self.assertIn("example.org", saved["blocklist"])
        bad = await self.http("POST", "/api/block?domain=not a domain", hdr)
        self.assertEqual(bad[0], 400)

    async def test_security_rejects_cross_site_requests(self):
        # CSRF: a website POSTing without the custom header (forms/no-cors fetch can't add it)
        self.assertEqual((await self.http("POST", "/api/pause?minutes=0"))[0], 403)
        # CSRF: header present but from a foreign origin
        evil = {"X-DNSpro": "1", "Origin": "https://evil.example"}
        self.assertEqual((await self.http("POST", "/api/pause?minutes=0", evil))[0], 403)
        self.assertTrue(self.blocker.active)
        # DNS rebinding: evil.example resolving to 127.0.0.1 sends Host: evil.example
        self.assertEqual((await self.http("GET", "/api/stats", {"Host": "evil.example:5336"}))[0], 403)
        # Same-origin dashboard request is fine
        port = self.cfg["dashboard_port"]
        ok = {"X-DNSpro": "1", "Origin": f"http://127.0.0.1:{port}"}
        self.assertEqual((await self.http("POST", "/api/resume", ok))[0], 200)

    async def test_dashboard_headers_and_no_html_injection(self):
        code, head, body = await self.http("GET", "/")
        self.assertEqual(code, 200)
        self.assertIn("frame-ancestors 'none'", head)
        self.assertIn("X-Frame-Options: DENY", head)
        self.assertNotIn(b"innerHTML", body)  # all server data goes in via textContent

    async def test_garbage_does_not_crash_server(self):
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"\xff" * 40, ("127.0.0.1", self.cfg["dns_port"]))
        sock.close()
        await asyncio.sleep(0.1)
        self.assertEqual(answer_ips(await self.dns("example.com")), ["93.184.215.14"])


if __name__ == "__main__":
    unittest.main()
