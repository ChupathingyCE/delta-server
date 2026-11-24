# SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
# SPDX-License-Identifier: MIT
"""Federation (federation.py): the shared test vectors (delta-spec's
reference/federation_vectors.json is the same file), names, roots.json,
the signed list of networks, the networks a game trusts, malformed input,
and two nodes on 127.0.0.1 as two networks whose players' certificates
check against each other's published root keys, offline:
python3 -m unittest tests.test_federation"""

import hashlib
import http.client
import json
import os
import secrets
import tempfile
import threading
import time
import unittest
from pathlib import Path

import accounts
import config
import delta_node
import ed25519
import federation
import identity

VECTORS = json.loads((Path(__file__).resolve().parent / "testdata" / "federation_vectors.json").read_text())


def seed(text: str) -> bytes:
    return hashlib.sha256(text.encode()).digest()


HOME = "chupathingy.org"
HOME_ROOT = bytes.fromhex(VECTORS[HOME]["root_primary"])
LIST_KEY = seed(VECTORS["list"]["key_seed_text"])


def listed():
    return federation.check_list(VECTORS["list"]["document"].encode(), VECTORS["list"]["signature"].encode(),
                                 [(ed25519.public_key(LIST_KEY), 0)])


class Vectors(unittest.TestCase):
    def test_roots_json(self):
        for domain in (HOME, "example.org"):
            network = VECTORS[domain]
            roots = federation.parse_roots(network["roots_json"].encode(), domain)
            self.assertEqual([root["key"].hex() for root in roots["roots"]],
                             [network["root_primary"], network["root_recovery"]])
            self.assertEqual(ed25519.public_key(seed(network["root_primary_seed_text"])).hex(), network["root_primary"])
            again = federation.make_roots(domain, [(seed(network["root_primary_seed_text"]), "primary", 0),
                                                   (seed(network["root_recovery_seed_text"]), "recovery",
                                                    roots["roots"][1]["until"])], roots["revoked"])
            self.assertEqual(again.decode(), network["roots_json"])

    def test_list(self):
        self.assertEqual(VECTORS["list"]["key_public"], ed25519.public_key(LIST_KEY).hex())
        self.assertEqual(sorted(listed()["networks"]), ["chupathingy.org", "example.org"])
        self.assertEqual(federation.sign_list(LIST_KEY, VECTORS["list"]["document"].encode()),
                         VECTORS["list"]["signature"])
        document, signature = federation.split_signed(VECTORS["list"]["signed"].encode())
        self.assertEqual(document.decode(), VECTORS["list"]["document"])

    def test_example_certificates_made_again(self):
        network = VECTORS["example.org"]
        issuer = ed25519.public_key(seed(network["issuer_seed_text"]))
        certificate = federation.issuer_certificate(seed(network["root_primary_seed_text"]), issuer,
                                                    1790000000, 1797776000)
        self.assertEqual(certificate.hex(), network["issuer_certificate"])
        fields = identity.parse_device(bytes.fromhex(network["device_certificate"]))
        self.assertEqual(fields["public"].hex(), network["device_public"])
        self.assertEqual(fields["account"], seed(network["account_text"])[:16])

    def test_checks(self):
        networks = federation.Networks(HOME, [HOME_ROOT], listed())
        alone = federation.Networks(HOME, [HOME_ROOT])
        for check in VECTORS["checks"]:
            network = VECTORS[check["issuer"]]
            answer = federation.check_name(networks if check["networks"] == "home + list" else alone,
                                           bytes.fromhex(network["issuer_certificate"]),
                                           bytes.fromhex(network["device_certificate"]), VECTORS["now"])
            if "name" in check:
                self.assertEqual((answer["why"], answer["name"], answer["account"]), ("", check["name"],
                                                                                     check["account"]))
            else:
                self.assertEqual(answer["why"], check["refused"])

    def test_names(self):
        for text in VECTORS["names"]["valid"]:
            self.assertEqual(":".join(federation.parse_qualified(text, HOME)), text)
        for text in VECTORS["names"]["invalid"]:
            self.assertIsNone(federation.parse_qualified(text, HOME), text)
        typed = VECTORS["names"]["home_alone"]
        self.assertEqual(":".join(federation.parse_qualified(typed["typed"], HOME)), typed["reads_as"])
        for case in VECTORS["shown"]:
            self.assertEqual(federation.shown(case["name"], case["domain"], case["viewer_home"]), case["shows"])


class Domains(unittest.TestCase):
    def test_domains(self):
        for good in ("chupathingy.org", "example.org", "a.b.co", "x-1.example.museum"):
            self.assertTrue(federation.valid_domain(good), good)
        for bad in ("", "org", "localhost", "Example.org", "example.org.", ".example.org", "exa_mple.org",
                    "1.2.3.4", "example.123", "-a.org", "a-.org", "xn--e1afmkfd.org", "a." + "b" * 64 + ".org",
                    "a" * 250 + ".org", "ex ample.org", "example.org\n", "exämple.org", None, 5):
            self.assertFalse(federation.valid_domain(bad), bad)

    def test_ascii_only(self):
        for bad in ("exämple.org", "example.org\u200b", "ex\u200bample.org", "\uff45xample.org", "example.\u043erg",
                    "xn--exmple-cua.org", "a.xn--p1ai", "sub.xn--abc.example.org", "xn--80ak6aa92e.com"):
            self.assertFalse(federation.valid_domain(bad), bad)
            self.assertIsNone(federation.parse_qualified("milenko:" + bad, HOME), bad)
        # (Unicode that lowercases to ASCII, the Kelvin sign to k, is refused before lowercasing)
        self.assertIsNone(federation.parse_qualified("milen\u212ao:example.org", HOME))
        self.assertIsNone(federation.parse_qualified("milenko:\u212aexample.org", HOME))
        self.assertEqual(federation.parse_qualified("MILENKO:EXAMPLE.ORG", HOME), ("milenko", "example.org"))
        self.assertEqual(federation.parse_qualified("MILENKO:XN--EXMPLE-CUA.ORG", HOME), None)
        key = VECTORS["example.org"]["root_primary"]
        with self.assertRaises(federation.FederationError):
            federation.parse_local(f"\u212aexample.org {key}")
        with self.assertRaises(federation.FederationError):
            federation.parse_local(f"xn--exmple-cua.org {key}")
        with self.assertRaises(federation.FederationError):
            federation.parse_roots(roots_document(domain="xn--exmple-cua.org"))

    def test_qualified(self):
        self.assertEqual(federation.qualified("milenko", "example.org"), "milenko:example.org")
        with self.assertRaises(federation.FederationError):
            federation.qualified("Milenko", "example.org")
        self.assertIsNone(federation.parse_qualified("x" * 300, HOME))
        self.assertIsNone(federation.parse_qualified(None, HOME))
        self.assertIsNone(federation.parse_qualified("milenko:", HOME))
        self.assertIsNone(federation.parse_qualified(":example.org", HOME))


def roots_document(**change) -> bytes:
    document = json.loads(VECTORS["example.org"]["roots_json"])
    document.update(change)
    return json.dumps(document).encode()


class MalformedRoots(unittest.TestCase):
    def refused(self, data, domain="example.org"):
        with self.assertRaises(federation.FederationError):
            federation.parse_roots(data, domain)

    def test_refused(self):
        good = VECTORS["example.org"]["roots_json"].encode()
        federation.parse_roots(good, "example.org")
        self.refused(good, "chupathingy.org")                               # another domain's
        self.refused(good + b" " * federation.ROOTS_MOST)                   # too big
        self.refused(b"")
        self.refused(b"[]")
        self.refused(b"\xff\xfe")
        self.refused(good[:-10])
        self.refused(good + b"{}")                                         # trailing bytes
        self.refused(roots_document(open_network_roots=2))
        self.refused(roots_document(open_network_roots=True))
        self.refused(roots_document(open_network_roots=1.0))
        self.refused(roots_document(domain="EXAMPLE.org"))
        self.refused(roots_document(roots=[]))
        self.refused(roots_document(roots=json.loads(good)["roots"] * 3))  # 6 roots, and twice
        self.refused(roots_document(revoked="http://example.org/x"))
        self.refused(roots_document(revoked="https://example.org/" + "x" * 300))
        self.refused(b'{"open_network_roots": 1, "open_network_roots": 1}')
        self.refused(b'{"open_network_roots": NaN}')
        self.refused(b'{"a":' * 20 + b'1' + b'}' * 20)
        self.refused(b'[' * 100000 + b']' * 100000)

    def test_bad_roots(self):
        document = json.loads(VECTORS["example.org"]["roots_json"])
        root = document["roots"][0]
        for change in ({"key": root["key"].upper()}, {"key": "00" * 32}, {"key": "01" + "00" * 31},
                       {"proof": "00" * 64}, {"proof": root["proof"][:-2]}, {"until": 1}, {"until": -1},
                       {"until": 2 ** 32}, {"use": "Primary"}, {"use": 7}):
            changed = dict(root, **change)
            self.refused(roots_document(roots=[changed]))
        # (a proof made for another domain)
        other = json.loads(VECTORS[HOME]["roots_json"])["roots"]
        self.refused(roots_document(roots=other))

    def test_unknown_members_skipped(self):
        document = json.loads(VECTORS["example.org"]["roots_json"])
        document["later"] = {"anything": [1, 2]}
        document["roots"][0]["later"] = "x"
        self.assertEqual(len(federation.parse_roots(json.dumps(document).encode())["roots"]), 2)


class MalformedList(unittest.TestCase):
    key = seed("a test list key for malformed lists")

    def signed(self, document: bytes):
        return document, federation.sign_list(self.key, document).encode()

    def check(self, document, signature=None, epoch=0):
        if signature is None:
            document, signature = self.signed(document)
        return federation.check_list(document, signature, [(ed25519.public_key(self.key), epoch)])

    def refused(self, document, signature=None, epoch=0):
        with self.assertRaises(federation.FederationError):
            self.check(document, signature, epoch)

    def test_signature(self):
        document = VECTORS["list"]["document"].encode()
        self.check(document)
        self.refused(document, VECTORS["list"]["signature"].encode())       # another key's
        self.refused(document + b" ", self.signed(document)[1])
        self.refused(document, b"")
        self.refused(document, self.signed(document)[1].upper())
        self.refused(document, ed25519.sign(self.key, document).hex().encode())  # no label
        self.refused(b" " * (federation.LIST_MOST + 1))
        with self.assertRaises(federation.FederationError):
            federation.split_signed(b"00" * 10)

    def test_epochs(self):
        self.check(federation.make_list(0x00FFFFFF, {}))
        self.refused(federation.make_list(0x01000001, {}))
        self.check(federation.make_list(0x01000001, {}), epoch=1)

    def test_documents(self):
        key = ed25519.public_key(seed("x")).hex()
        other = ed25519.public_key(seed("y")).hex()

        def document(networks, serial=1, **extra):
            return json.dumps(dict({"open_networks": 1, "serial": serial, "networks": networks}, **extra)).encode()

        self.check(document({"example.org": {"roots": [{"key": key}]}}))
        for bad in (
                document({"example.org": {"roots": [{"key": key}]}}, serial=0),
                document({}, serial=0xFFFFFFFF),
                document({}, serial="1"),
                document({}, issued=-1),
                document([]),
                document({"localhost": {"roots": [{"key": key}]}}),
                document({"example.org": {"roots": []}}),
                document({"example.org": {"roots": [{"key": key}] * 2}}),
                document({"example.org": {"roots": [{"key": key}]}, "example.net": {"roots": [{"key": key}]}}),
                document({"example.org": {"roots": [{"key": key, "until": 1.5}]}}),
                document({"example.org": {"roots": [{"key": "00" * 32}]}}),
                document({f"n{n}.org": {"roots": [{"key": ed25519.public_key(seed(str(n))).hex()}]}
                          for n in range(65)}),
                b'{"open_networks": 1, "serial": 1, "networks": {"example.org": {"roots": [{"key": "%s"}]},'
                b' "example.org": {"roots": [{"key": "%s"}]}}}' % (key.encode(), other.encode()),
                b'{"open_networks": 2, "serial": 1, "networks": {}}',
                b'{"open_networks": 1, "serial": 1, "networks": {}} x'):
            self.refused(bad)


class Trusted(unittest.TestCase):
    def setUp(self):
        self.example = VECTORS["example.org"]
        self.issuer = bytes.fromhex(self.example["issuer_certificate"])
        self.device = bytes.fromhex(self.example["device_certificate"])
        self.now = VECTORS["now"]

    def name(self, networks):
        return federation.check_name(networks, self.issuer, self.device, self.now)

    def test_local_addition_and_removal(self):
        added = federation.Networks(HOME, [HOME_ROOT], add=[f"example.org {self.example['root_primary']}"])
        self.assertEqual(self.name(added)["name"], "milenko:example.org")
        self.assertEqual(added.local, {"example.org"})
        removed = federation.Networks(HOME, [HOME_ROOT], listed(), remove=["Example.org"])
        self.assertEqual(self.name(removed)["why"], "no network trusted")

    def test_home_never_changed(self):
        # (a list or a setting can't take the home network's name, or remove it)
        evil = federation.Networks(HOME, [HOME_ROOT], add=[f"chupathingy.org {self.example['root_primary']}"],
                                   remove=[HOME])
        self.assertEqual(self.name(evil)["why"], "no network trusted")
        home = VECTORS[HOME]
        self.assertEqual(federation.check_name(evil, bytes.fromhex(home["issuer_certificate"]),
                                               bytes.fromhex(home["device_certificate"]), self.now)["name"],
                         "milenko:chupathingy.org")

    def test_a_key_belongs_to_one_network(self):
        # (another network that names example.org's key is left out)
        networks = federation.Networks(HOME, [HOME_ROOT], listed(),
                                       add=[f"evil.example {self.example['root_primary']}"])
        self.assertNotIn("evil.example", networks.networks)
        self.assertEqual(self.name(networks)["name"], "milenko:example.org")
        # (nor can a local addition claim the home network's key)
        networks = federation.Networks(HOME, [HOME_ROOT], add=[f"evil.example {HOME_ROOT.hex()}"])
        self.assertNotIn("evil.example", networks.networks)

    def test_bad_local_additions(self):
        lines = []
        networks = federation.Networks(HOME, [HOME_ROOT], add=["example.org", "example.org zz", "nodomain " +
                                                               self.example["root_primary"], "x" * 5000],
                                       log=lines.append)
        self.assertEqual(list(networks.networks), [HOME])
        self.assertEqual(len(lines), 4)
        many = [f"n{n}.example {ed25519.public_key(seed(str(n))).hex()}" for n in range(40)]
        self.assertEqual(len(federation.Networks(HOME, [HOME_ROOT], add=many).networks), 1 + federation.LOCAL_MOST)

    def test_root_until(self):
        until = 1790100000
        networks = federation.Networks(HOME, [HOME_ROOT])
        networks.networks["example.org"] = [(bytes.fromhex(self.example["root_primary"]), until)]
        self.assertEqual(self.name(networks)["why"], "no network trusted")
        self.now = until
        self.assertEqual(self.name(networks)["why"], "")

    def test_certificate_checks_still_apply(self):
        networks = federation.Networks(HOME, [HOME_ROOT], listed())
        self.assertEqual(federation.check_name(networks, self.issuer, self.device, self.now + 30 * 86400)["why"],
                         "expired")
        broken = self.device[:-1] + bytes((self.device[-1] ^ 1,))
        self.assertEqual(federation.check_name(networks, self.issuer, broken, self.now)["why"],
                         "not signed by its issuer")
        device_id = identity.parse_device(self.device)["device_id"]
        self.assertEqual(federation.check_name(networks, self.issuer, self.device, self.now,
                                               {"example.org": {device_id}})["why"], "revoked")
        # (another network's revocation list is not this one's)
        self.assertEqual(federation.check_name(networks, self.issuer, self.device, self.now,
                                               {HOME: {device_id}})["why"], "")
        self.assertEqual(federation.check_name(networks, b"", self.device, self.now)["why"],
                         "not an issuer certificate")
        home = VECTORS[HOME]
        # (a device certificate of one network under another network's issuer)
        self.assertEqual(federation.check_name(networks, bytes.fromhex(home["issuer_certificate"]), self.device,
                                               self.now)["why"], "another issuer's")


class Tool(unittest.TestCase):
    """federation.py's commands, end to end in a scratch folder"""

    def test_commands(self):
        import contextlib
        import io
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root = Path(folder.name)

        def run(*argv):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                code = federation.main([str(a) for a in argv])
            return code, out.getvalue()

        code, out = run("root-keys", "--domain", "example.org", "--dir", root / "keys")
        self.assertEqual(code, 0, out)
        self.assertEqual(os.stat(root / "keys" / "example.org-root-primary.key").st_mode & 0o077, 0)
        self.assertEqual(run("root-keys", "--domain", "example.org", "--dir", root / "keys")[0], 2)  # never overwrites
        self.assertEqual(run("root-keys", "--domain", "localhost", "--dir", root / "x")[0], 2)
        roots = federation.parse_roots((root / "keys" / "roots.json").read_bytes(), "example.org")
        issuer = secrets.token_bytes(32)
        code, out = run("issuer-cert", "--root-key", root / "keys" / "example.org-root-primary.key",
                        "--issuer-public", ed25519.public_key(issuer).hex(), "--out", root / "issuer.cert")
        self.assertEqual(code, 0, out)
        fields = identity.parse_issuer(identity.read_hex_file(str(root / "issuer.cert")))
        self.assertEqual(identity.check_issuer(fields, [roots["roots"][0]["key"]], int(time.time())), "")
        code, out = run("list-keys", "--dir", root / "list")
        self.assertEqual(code, 0, out)
        lines = [line for line in out.splitlines() if line.startswith("list ")]
        public = lines[0].split()[3]
        self.assertNotEqual(public, lines[1].split()[3])
        self.assertEqual(run("list-keys", "--dir", root / "list")[0], 2)  # never overwrites
        self.assertEqual(run("list-make", "--serial", 3, "--roots", root / "keys" / "roots.json",
                             "--out", root / "networks.json")[0], 0)
        self.assertEqual(run("list-sign", "--key", root / "list" / "list-primary.key", root / "networks.json")[0], 0)
        code, out = run("list-verify", "--public-key", public, root / "networks.json")
        self.assertEqual((code, out.strip()), (0, "list serial 3: example.org"))
        self.assertEqual(run("list-verify", "--public-key", "00" * 32, root / "networks.json")[0], 2)
        (root / "bad.json").write_text('{"open_networks": 1}')
        self.assertEqual(run("list-sign", "--key", root / "list" / "list-primary.key", root / "bad.json")[0], 2)


class TwoNetworks(unittest.TestCase):
    """two nodes, each its own network with its own root keys, issuer and
    roots.json; a player enrolls on each, and each player's certificates
    check against the published roots and a signed list, with no call
    from one node to the other and none at check time"""

    def make_network(self, folder: Path, network: str, site: str):
        root = secrets.token_bytes(32)
        recovery = secrets.token_bytes(32)
        issuer = secrets.token_bytes(32)
        (folder / network).mkdir()
        roots_file = folder / network / "roots.json"
        roots_file.write_bytes(federation.make_roots(network, [(root, "primary", 0), (recovery, "recovery", 0)]))
        cert = folder / network / "issuer.cert"
        now = int(time.time())
        cert.write_text(federation.issuer_certificate(root, ed25519.public_key(issuer), now - 3600,
                                                      now + 90 * 86400).hex() + "\n")
        key = folder / network / "issuer.key"
        key.write_text(issuer.hex())
        os.chmod(key, 0o600)
        settings = config.load("", environ={})
        settings["node"].update(domain=site, data=str(folder / network / "data"), database=":memory:")
        settings["identity"].update(issuer_cert_file=str(cert), issuer_key_file=str(key))
        settings["federation"].update(network=network, roots_file=str(roots_file),
                                      networks_file=str(folder / "networks.json"))
        node = delta_node.Node(settings, log=lambda text: None)
        httpd = delta_node.make_server(node, "127.0.0.1", 0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(node.close)
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        return node, httpd.server_address[1], root

    def call(self, port, method, path, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        headers = {"User-Agent": "ChupathingyCE/0.9.2 (linux; x86_64)"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=data, headers=headers)
        answer = connection.getresponse()
        raw = answer.read()
        connection.close()
        return answer.status, raw

    def enroll(self, node, port, site, handle):
        player_key = secrets.token_hex(32)
        copy = accounts.player_id_of(player_key)
        self.assertEqual(node.accounts.create(copy, handle), "")
        device = secrets.token_bytes(32)
        status, raw = self.call(port, "GET", "/v1/identity/nonce")
        nonce = json.loads(raw)["nonce"]
        signature = ed25519.sign(device, identity.enroll_message(site, bytes.fromhex(nonce), bytes.fromhex(copy),
                                                                 ed25519.public_key(device))).hex()
        status, raw = self.call(port, "POST", "/v1/identity/legacy/enroll", {
            "key": player_key, "device_key": ed25519.public_key(device).hex(), "nonce": nonce,
            "signature": signature, "platform": "pc_linux", "build": "0.9.2-test"})
        self.assertEqual(status, 200, raw)
        answer = json.loads(raw)
        return bytes.fromhex(answer["issuer"]), bytes.fromhex(answer["certificate"])

    def test_two_networks(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        folder = Path(folder.name)
        home, home_port, home_root = self.make_network(folder, "chupathingy.org", "stats.chupathingy.org")
        other, other_port, _ = self.make_network(folder, "example.org", "example.org")
        self.assertEqual(json.loads(self.call(other_port, "GET", "/v1/node")[1])["network"], "example.org")
        self.assertEqual(self.call(home_port, "GET", "/v1/delta/networks")[0], 404)
        # (the list's maintainers take each network's roots.json from its address)
        roots = {}
        for port, network in ((home_port, "chupathingy.org"), (other_port, "example.org")):
            status, raw = self.call(port, "GET", federation.ROOTS_PATH)
            self.assertEqual(status, 200)
            roots[network] = federation.parse_roots(raw, network)
        list_key = secrets.token_bytes(32)
        document = federation.make_list(1, {domain: [(root["key"], root["until"]) for root in found["roots"]]
                                            for domain, found in roots.items()})
        (folder / "networks.json").write_bytes(document)
        (folder / "networks.json.sig").write_text(federation.sign_list(list_key, document) + "\n")
        # (players enroll, each on their own network, both as "milenko")
        cards = {"chupathingy.org": self.enroll(home, home_port, "stats.chupathingy.org", "milenko"),
                 "example.org": self.enroll(other, other_port, "example.org", "milenko")}
        # (a game fetches the list from its own network's site, then checks offline)
        status, served = self.call(home_port, "GET", "/v1/delta/networks")
        status_sig, served_sig = self.call(home_port, "GET", "/v1/delta/networks.sig")
        self.assertEqual((status, status_sig), (200, 200))
        home.close = lambda: None  # (no node is asked anything from here on)
        checked = federation.check_list(served, served_sig, [(ed25519.public_key(list_key), 0)])
        networks = federation.Networks("chupathingy.org", [ed25519.public_key(home_root)], checked)
        now = int(time.time())
        names = {network: federation.check_name(networks, issuer, device, now)
                 for network, (issuer, device) in cards.items()}
        self.assertEqual({network: (answer["why"], answer["name"]) for network, answer in names.items()},
                         {"chupathingy.org": ("", "milenko:chupathingy.org"),
                          "example.org": ("", "milenko:example.org")})
        self.assertNotEqual(names["chupathingy.org"]["device_id"], names["example.org"]["device_id"])
        self.assertEqual(federation.shown("Milenko", "example.org", "chupathingy.org"), "Milenko:example.org")
        self.assertEqual(federation.shown("Milenko", "chupathingy.org", "chupathingy.org"), "Milenko")
        # (the other network's game, with its own home and the same list)
        theirs = federation.Networks("example.org", [roots["example.org"]["roots"][0]["key"]], checked)
        self.assertEqual(federation.check_name(theirs, *cards["chupathingy.org"], now)["name"],
                         "milenko:chupathingy.org")
        # (without the list, the other network's player isn't verified)
        alone = federation.Networks("chupathingy.org", [ed25519.public_key(home_root)])
        self.assertEqual(federation.check_name(alone, *cards["example.org"], now)["why"], "no network trusted")

    def test_issuer_must_chain_to_roots_file(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        folder = Path(folder.name)
        node, _, _ = self.make_network(folder, "example.org", "example.org")
        settings = node.settings
        other = folder / "other.json"
        other.write_bytes(federation.make_roots("example.org", [(secrets.token_bytes(32), "primary", 0)]))
        settings["federation"]["roots_file"] = str(other)
        settings["identity"]["roots"] = [ed25519.public_key(secrets.token_bytes(32)).hex()]
        with self.assertRaises(config.ConfigError):
            delta_node.Node(settings, log=lambda text: None)
        settings["federation"]["network"] = "example.net"
        with self.assertRaises(config.ConfigError):
            delta_node.Node(settings, log=lambda text: None)


if __name__ == "__main__":
    unittest.main()


class Review(unittest.TestCase):
    """the security review's findings, each held by a test"""

    def test_no_trailing_line_feed(self):
        self.assertIsNone(federation.parse_qualified("milenko\n:example.org", HOME))
        self.assertEqual(federation.parse_qualified(" milenko:example.org ", HOME), ("milenko", "example.org"))
        with self.assertRaises(federation.FederationError):
            federation.qualified("milenko\n", "example.org")
        self.assertFalse(federation.valid_domain("example.org\n"))
        # (a device certificate whose handle ends in a line feed)
        body = identity.device_body(1, 0, 1790100000, 1790704800, bytes(8), bytes(8), bytes(16), bytes(32), 1,
                                    "milenko")
        raw = bytearray(body)
        raw[6] = 8
        raw += b"\n" + bytes(64)
        self.assertIsNone(identity.parse_device(bytes(raw)))
        with self.assertRaises(ValueError):
            identity.device_body(1, 0, 1790100000, 1790704800, bytes(8), bytes(8), bytes(16), bytes(32), 1,
                                 "milenko\n")
        with self.assertRaises(ValueError):
            identity.audience_bytes("example.org\n")
        self.assertIsNone(identity.HANDLE.match("milenko\n"))
        self.assertIsNone(identity.AUDIENCE.match("example.org\n"))
        self.assertIsNone(accounts.HANDLE.match("milenko\n"))

    def test_check_name_refuses_a_bad_handle_from_any_reader(self):
        """(a certificate reader that let a line feed through, as an older
        copy of identity.py did: the check refuses it rather than fail)"""
        example = VECTORS["example.org"]
        networks = federation.Networks(HOME, [HOME_ROOT], listed())
        real = identity.parse_device

        def loose(data):
            fields = real(data)
            if fields:
                fields["handle"] += "\n"
            return fields

        federation.identity.parse_device = loose
        try:
            answer = federation.check_name(networks, bytes.fromhex(example["issuer_certificate"]),
                                           bytes.fromhex(example["device_certificate"]), VECTORS["now"])
        finally:
            federation.identity.parse_device = real
        self.assertEqual((answer["why"], answer["name"]), ("not a handle", ""))

    def test_use_and_revoked_strict(self):
        for change in ({"use": 0}, {"use": ""}, {"use": []}, {"use": None}):
            document = json.loads(VECTORS["example.org"]["roots_json"])
            document["roots"][0].update(change)
            with self.assertRaises(federation.FederationError, msg=str(change)):
                federation.parse_roots(json.dumps(document).encode(), "example.org")
        for revoked in ([], "", 0, None, {}, False):
            with self.assertRaises(federation.FederationError, msg=repr(revoked)):
                federation.parse_roots(roots_document(revoked=revoked), "example.org")

    def test_config_domain(self):
        settings = config.load("", environ={})
        for bad in ("localhost", "xn--exmple-cua.org", "Example.org", "1.2.3.4"):
            settings["federation"]["network"] = bad
            with self.assertRaises(config.ConfigError, msg=bad):
                config.check(settings)
        settings["federation"]["network"] = ""
        config.check(settings)  # (no network, no roots: nothing published)
        settings["federation"]["roots_file"] = "roots.json"
        with self.assertRaises(config.ConfigError):  # (node.domain is localhost)
            config.check(settings)
        settings["node"]["domain"] = "example.org"
        config.check(settings)

    def test_issuer_lookups_remembered_and_two_networks_refused(self):
        example = VECTORS["example.org"]
        issuer = identity.parse_issuer(bytes.fromhex(example["issuer_certificate"]))
        networks = federation.Networks(HOME, [HOME_ROOT], listed())
        calls = []
        real = ed25519.verify

        def counted(*args):
            calls.append(1)
            return real(*args)

        federation.ed25519.verify = counted
        try:
            self.assertEqual(networks.network_of(issuer, VECTORS["now"]), "example.org")
            first = len(calls)
            for _ in range(5):
                self.assertEqual(networks.network_of(issuer, VECTORS["now"]), "example.org")
            self.assertEqual(len(calls), first)
        finally:
            federation.ed25519.verify = real
        # (the same issuer key, certified by the home network's root too: refused for both)
        home_seed = seed(VECTORS[HOME]["root_primary_seed_text"])
        again = identity.parse_issuer(federation.issuer_certificate(home_seed, issuer["public"], 1790000000,
                                                                   1797776000))
        self.assertIsNone(networks.network_of(again, VECTORS["now"]))
        self.assertIsNone(networks.network_of(issuer, VECTORS["now"]))
        self.assertIn(issuer["public"], networks.conflicts)

    def test_cli_check_default_home(self):
        import contextlib
        import io
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = Path(folder.name) / "networks.json"
        path.write_text(VECTORS["list"]["document"])
        Path(str(path) + ".sig").write_text(VECTORS["list"]["signature"] + "\n")
        example = VECTORS["example.org"]
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = federation.main(["check", "--list", str(path), "--list-key", VECTORS["list"]["key_public"],
                                    "--issuer", example["issuer_certificate"], "--device",
                                    example["device_certificate"], "--now", str(VECTORS["now"])])
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn("milenko:example.org", out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(federation.main(["check", "--home", "example.org", "--issuer", "00",
                                              "--device", "00"]), 2)

    def test_roots_settings_agree(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root = secrets.token_bytes(32)
        issuer = secrets.token_bytes(32)
        base = Path(folder.name)
        (base / "roots.json").write_bytes(federation.make_roots("example.org", [(root, "primary", 0)]))
        now = int(time.time())
        (base / "issuer.cert").write_text(federation.issuer_certificate(root, ed25519.public_key(issuer), now - 60,
                                                                        now + 86400).hex())
        (base / "issuer.key").write_text(issuer.hex())
        os.chmod(base / "issuer.key", 0o600)
        settings = config.load("", environ={})
        settings["node"].update(domain="example.org", data=str(base / "data"), database=":memory:")
        settings["identity"].update(issuer_cert_file=str(base / "issuer.cert"),
                                    issuer_key_file=str(base / "issuer.key"),
                                    roots=[ed25519.public_key(root).hex()])
        settings["federation"]["roots_file"] = str(base / "roots.json")
        delta_node.Node(settings, log=lambda text: None).close()
        settings["identity"]["roots"].append(ed25519.public_key(secrets.token_bytes(32)).hex())
        with self.assertRaises(config.ConfigError):
            delta_node.Node(settings, log=lambda text: None)


class RawBytes(unittest.TestCase):
    def test_list_served_byte_for_byte(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        base = Path(folder.name)
        raw = b'{"open_networks": 1, "x": "\xff\xfe"}\r\n'
        (base / "networks.json").write_bytes(raw)
        (base / "networks.json.sig").write_bytes(b"ab" * 64 + b"\n")
        settings = config.load("", environ={})
        settings["node"].update(data=str(base / "data"), database=":memory:")
        settings["federation"]["networks_file"] = str(base / "networks.json")
        node = delta_node.Node(settings, log=lambda text: None)
        httpd = delta_node.make_server(node, "127.0.0.1", 0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=10)
            connection.request("GET", "/v1/delta/networks")
            self.assertEqual(connection.getresponse().read(), raw)
            connection.close()
            self.assertEqual(node.info()["network"], "")  # (node.domain localhost is no network)
        finally:
            httpd.shutdown()
            httpd.server_close()
            node.close()
