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


def fake_answer(data):
    """93.184.215.14 for A queries; 60 addresses for big.test (too big for plain UDP)."""
    name, qtype, q_end = dnspro.parse_question(data)
    count = 60 if name == "big.test" else 1 if qtype == 1 else 0
    ans = (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 120, 4) + FAKE_IP) * count
    hdr = struct.pack("!HHHHHH", struct.unpack("!H", data[:2])[0], 0x8180, 1, count, 0, 0)
    return hdr + data[12:q_end] + ans


class FakeUpstream(asyncio.DatagramProtocol):
    def connection_made(self, t):
        self.t = t

    def datagram_received(self, data, addr):
        self.t.sendto(fake_answer(data), addr)


class FakeStreamUpstream:
    """DNS over TCP that answers out of order ('slow.*' names wait) and hangs up after
    `close_after` answers, like real DNS-over-TLS servers closing idle connections."""

    def __init__(self, close_after=1000):
        self.close_after, self.connections, self.ids = close_after, 0, []

    async def handle(self, reader, writer):
        self.connections += 1
        answered = 0
        tasks = []

        async def answer(data):
            if dnspro.parse_question(data)[0].startswith("slow."):
                await asyncio.sleep(0.2)
            resp = fake_answer(data)
            writer.write(struct.pack("!H", len(resp)) + resp)

        try:
            while answered < self.close_after:
                n, = struct.unpack("!H", await reader.readexactly(2))
                data = await reader.readexactly(n)
                self.ids.append(data[:2])
                tasks.append(asyncio.ensure_future(answer(data)))
                answered += 1
            await asyncio.gather(*tasks)
        except Exception:
            pass
        writer.close()


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
        p = dnspro.parse_upstream
        self.assertEqual(p("9.9.9.9"), ("udp", "9.9.9.9", 53, None))
        self.assertEqual(p("1.2.3.4:5300"), ("udp", "1.2.3.4", 5300, None))
        self.assertEqual(p("2620:fe::fe"), ("udp", "2620:fe::fe", 53, None))
        self.assertEqual(p("[2620:fe::fe]:5353"), ("udp", "2620:fe::fe", 5353, None))
        self.assertEqual(p("tls://9.9.9.9#dns.quad9.net"), ("tls", "9.9.9.9", 853, "dns.quad9.net"))
        self.assertEqual(p("tls://[2620:fe::fe]#dns.quad9.net"), ("tls", "2620:fe::fe", 853, "dns.quad9.net"))
        self.assertEqual(p("tcp://127.0.0.1:5353"), ("tcp", "127.0.0.1", 5353, None))
        for bad in ("tls://9.9.9.9", "https://9.9.9.9", "9.9.9.9#name"):
            with self.assertRaises(ValueError, msg=bad):
                p(bad)

    def test_default_upstreams_are_encrypted_and_old_config_upgrades(self):
        self.assertTrue(all(u.startswith("tls://") for u in dnspro.DEFAULT_CONFIG["upstreams"]))
        dnspro.CONFIG_FILE.write_text(json.dumps({"upstreams": ["9.9.9.9", "1.1.1.1"]}))
        try:
            self.assertEqual(dnspro.load_config()["upstreams"], dnspro.DEFAULT_CONFIG["upstreams"])
        finally:
            dnspro.CONFIG_FILE.unlink()

    def test_udp_size_limit_and_truncation(self):
        q = make_query("example.com")
        _, _, q_end = dnspro.parse_question(q)
        self.assertEqual(dnspro.udp_limit(q, q_end), 512)
        edns = q[:10] + b"\x00\x01" + q[12:] + b"\x00\x00\x29\x04\xd0" + bytes(6)
        self.assertEqual(dnspro.udp_limit(edns, q_end), 1232)
        t = dnspro.truncate(fake_answer(q), q_end)
        self.assertTrue(t[2] & 0x02)
        self.assertEqual(len(t), q_end)

    def test_blocklist_sanity_checks(self):
        must = set(dnspro.MUST_WORK) | {"big.oisd.nl"}
        ok = {f"ad{i}.example.net" for i in range(100)}
        self.assertIsNone(dnspro.list_problem(ok, 120, must))
        self.assertIsNone(dnspro.list_problem(ok | {"ads.google.com"}, 0, must))  # a subdomain is fine
        self.assertIn("google.com", dnspro.list_problem(ok | {"google.com"}, 0, must))
        self.assertIn("www.google.com", dnspro.list_problem(ok | {"www.google.com"}, 0, must))
        self.assertIn("oisd", dnspro.list_problem(ok | {"oisd.nl"}, 0, must))
        self.assertIn("size", dnspro.list_problem(ok, 100_000, must))
        self.assertIn("empty", dnspro.list_problem(set(), 0, must))

    def test_update_keeps_last_good_copy_of_a_bad_list(self):
        cfg = dict(dnspro.DEFAULT_CONFIG, lists={"A": "https://a.test/list", "B": "https://b.test/list"})
        bodies = {"https://a.test/list": b"one.test\ntwo.test\n", "https://b.test/list": b"three.test\n"}

        class Resp:
            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

            def read(self, n=-1):
                return self.body

        def fake_urlopen(req, timeout=None):
            body = bodies[req.full_url]
            if body is None:
                raise OSError("offline")
            return Resp(body)

        real = dnspro.urllib.request.urlopen
        dnspro.urllib.request.urlopen = fake_urlopen
        try:
            self.assertTrue(dnspro.update_lists(cfg))
            bodies["https://a.test/list"] = b"one.test\ngoogle.com\n"   # tampered
            bodies["https://b.test/list"] = None                          # offline
            self.assertFalse(dnspro.update_lists(cfg))
            bodies["https://b.test/list"] = b"four.test\n"
            self.assertTrue(dnspro.update_lists(cfg))
        finally:
            dnspro.urllib.request.urlopen = real
        rules = set(dnspro.BLOCKLIST_FILE.read_text().split())
        self.assertEqual(rules, {"one.test", "two.test", "four.test"})  # A's last good copy + new B
        dnspro.BLOCKLIST_FILE.unlink()

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
        self.key = {"X-DNSpro": "1", "X-DNSpro-Key": self.blocker.key}
        await self.blocker.start()

    async def asyncTearDown(self):
        for s in self.blocker.servers:
            s.close()
        self.up.close()

    async def dns(self, name, qtype=1, tcp=False, query=None):
        loop = asyncio.get_running_loop()
        q = query or make_query(name, qtype)
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
        hdr = self.key
        self.assertEqual((await self.http("POST", "/api/pause?minutes=0", hdr))[0], 200)
        self.assertEqual(answer_ips(await self.dns("doubleclick.net")), ["93.184.215.14"])
        _, _, body = await self.http("GET", "/api/stats")
        self.assertEqual(json.loads(body)["paused_seconds"], -1)
        self.assertEqual((await self.http("POST", "/api/resume", hdr))[0], 200)
        self.assertEqual(answer_ips(await self.dns("doubleclick.net")), ["0.0.0.0"])

    async def test_allow_and_block_via_api(self):
        hdr = self.key
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
        ok = dict(self.key, Origin=f"http://127.0.0.1:{port}")
        self.assertEqual((await self.http("POST", "/api/resume", ok))[0], 200)

    async def test_switch_and_history_need_the_key(self):
        for path in ("/api/pause?minutes=0", "/api/allow?domain=doubleclick.net", "/api/login-code"):
            self.assertEqual((await self.http("POST", path, {"X-DNSpro": "1"}))[0], 403, path)
            wrong = {"X-DNSpro": "1", "X-DNSpro-Key": "0" * 64}
            self.assertEqual((await self.http("POST", path, wrong))[0], 403, path)
        self.assertTrue(self.blocker.active)
        await self.dns("doubleclick.net")
        public = json.loads((await self.http("GET", "/api/stats"))[2])
        self.assertEqual(public["blocked"], 1)
        self.assertNotIn("recent", public)  # which sites were visited stays private
        full = json.loads((await self.http("GET", "/api/stats", self.key))[2])
        self.assertEqual(full["recent"][0][1], "doubleclick.net")
        _, _, page = await self.http("GET", "/")
        self.assertIn(b"Open dashboard", page)
        self.assertNotIn(b"/api/stats", page)

    async def test_dashboard_login(self):
        code = json.loads((await self.http("POST", "/api/login-code", self.key))[2])["code"]
        status, head, _ = await self.http("GET", f"/login?code={code}")
        self.assertEqual(status, 303)
        cookie = head.split("Set-Cookie: ")[1].split(";")[0]
        self.assertIn("HttpOnly; SameSite=Strict", head)
        self.assertEqual((await self.http("GET", f"/login?code={code}"))[0], 403)  # one use only
        self.assertEqual((await self.http("GET", "/login?code=guess"))[0], 403)
        browser = {"Cookie": cookie}
        _, _, page = await self.http("GET", "/", browser)
        self.assertIn(b"/api/stats", page)
        self.assertIn("recent", json.loads((await self.http("GET", "/api/stats", browser))[2]))
        port = self.cfg["dashboard_port"]
        post = dict(browser, **{"X-DNSpro": "1", "Origin": f"http://127.0.0.1:{port}"})
        self.assertEqual((await self.http("POST", "/api/pause?minutes=5", post))[0], 200)
        self.assertFalse(self.blocker.active)
        # The cookie alone isn't enough from another site (CSRF)
        evil = dict(browser, **{"X-DNSpro": "1", "Origin": "https://evil.example"})
        self.assertEqual((await self.http("POST", "/api/resume", evil))[0], 403)

    async def test_browser_bypass_canaries(self):
        for name in ("use-application-dns.net", "mask.icloud.com", "mask-h2.icloud.com"):
            resp = await self.dns(name)
            self.assertEqual(resp[3] & 0x0F, 3, name)  # NXDOMAIN
        self.blocker.set_rule("mask.icloud.com", "allowlist")  # someone who wants Private Relay
        self.assertEqual(answer_ips(await self.dns("mask.icloud.com")), ["93.184.215.14"])

    async def test_big_answers_ask_udp_clients_to_use_tcp(self):
        resp = await self.dns("big.test")
        self.assertTrue(resp[2] & 0x02)  # truncated over plain UDP (no EDNS)
        self.assertEqual(len(answer_ips(await self.dns("big.test", tcp=True))), 60)

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


class TestEncryptedUpstream(unittest.IsolatedAsyncioTestCase):
    """The pipelined stream client, using plain TCP (tcp://) in place of TLS."""

    async def start(self, upstreams, **cfg):
        self.cfg = dict(dnspro.DEFAULT_CONFIG, listen=["127.0.0.1"], dns_port=free_port(),
                        dashboard_port=free_port(), upstreams=upstreams, blocklist=[], allowlist=[], **cfg)
        self.blocker = dnspro.Blocker(self.cfg)

    async def ask(self, name, qid=0x1234):
        return await self.blocker.resolve(make_query(name, qid=qid))

    async def test_many_queries_share_one_connection_out_of_order(self):
        fake = FakeStreamUpstream()
        port = free_port()
        server = await asyncio.start_server(fake.handle, "127.0.0.1", port)
        await self.start([f"tcp://127.0.0.1:{port}"])
        names = ["slow.a.test", "b.test", "slow.c.test", "d.test"]
        resps = await asyncio.gather(*(self.ask(n, qid=i) for i, n in enumerate(names)))
        for i, (n, r) in enumerate(zip(names, resps)):
            self.assertEqual(dnspro.parse_question(r)[0], n)
            self.assertEqual(struct.unpack("!H", r[:2])[0], i)  # client's own ID restored
        self.assertEqual(fake.connections, 1)
        self.assertNotIn(b"\x00\x00", fake.ids)  # IDs sent upstream are randomised
        server.close()

    async def test_reconnects_when_the_server_hangs_up(self):
        fake = FakeStreamUpstream(close_after=1)
        port = free_port()
        server = await asyncio.start_server(fake.handle, "127.0.0.1", port)
        await self.start([f"tcp://127.0.0.1:{port}"])
        for n in ("a.test", "b.test", "c.test"):
            self.assertEqual(answer_ips(await self.ask(n)), ["93.184.215.14"])
            await asyncio.sleep(0.05)
        self.assertEqual(fake.connections, 3)
        server.close()

    async def test_falls_back_when_encrypted_dns_is_unreachable(self):
        loop = asyncio.get_running_loop()
        up_port = free_port()
        up, _ = await loop.create_datagram_endpoint(FakeUpstream, local_addr=("127.0.0.1", up_port))
        await self.start([f"tls://127.0.0.1:{free_port()}#dns.test", f"127.0.0.1:{up_port}"])
        self.assertEqual(answer_ips(await self.ask("a.test")), ["93.184.215.14"])
        self.assertEqual(self.blocker.via, "unencrypted")
        self.assertGreater(self.blocker.streams[0].down_until, 0)  # skipped for a while
        up.close()

    @unittest.skipUnless(os.environ.get("DNSPRO_NETWORK_TESTS"), "set DNSPRO_NETWORK_TESTS=1 (needs internet)")
    async def test_real_dns_over_tls(self):
        await self.start(list(dnspro.DEFAULT_CONFIG["upstreams"]), unencrypted_fallback=False)
        for up in self.blocker.streams:
            r = await up.query(make_query("example.com"), dnspro.parse_question(make_query("example.com"))[2])
            self.assertIsNotNone(r, up.tls_name)
            self.assertTrue(answer_ips(r), up.tls_name)
            up.close()
        # A server that can't prove it is who we asked for is refused.
        await self.start(["tls://9.9.9.9#wrong-name.example"], unencrypted_fallback=False)
        self.assertEqual((await self.ask("example.com"))[3] & 0x0F, 2)  # SERVFAIL
        await asyncio.sleep(0.1)


class TestKey(unittest.TestCase):
    @unittest.skipIf(dnspro.IS_WINDOWS, "Windows uses the ACL set by the installer")
    def test_key_file_is_private(self):
        key = dnspro.ensure_key()
        self.assertEqual(len(key), 64)
        self.assertEqual(dnspro.ensure_key(), key)
        self.assertEqual(dnspro.KEY_FILE.stat().st_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
