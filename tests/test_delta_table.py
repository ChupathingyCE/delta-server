# SPDX-FileCopyrightText: 2026 The Chupathingy contributors
# SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests of the legacy table's pull from GitHub (delta_table.py): only a
newer serial signed with ChupathingyCE's key is ever served:
python3 -m unittest test_delta_table (needs the openssl command)"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import delta_table


def find_openssl():
    """OpenSSL 3 (Ed25519 signing): $OPENSSL, or the openssl command (not
    macOS's LibreSSL)"""
    for candidate in (os.environ.get("OPENSSL"), shutil.which("openssl"), "/opt/homebrew/opt/openssl@3/bin/openssl"):
        if candidate and os.path.exists(candidate):
            version = subprocess.run([candidate, "version"], capture_output=True, text=True).stdout
            if version.startswith("OpenSSL 3"):
                return candidate
    return None


OPENSSL = find_openssl()


def openssl(*arguments, data=None):
    return subprocess.run([OPENSSL, *arguments], input=data, capture_output=True, check=True).stdout


@unittest.skipUnless(OPENSSL, "needs OpenSSL 3 ($OPENSSL)")
class Pull(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        cls.keys = {}
        for name in ("ours", "other"):
            key = Path(cls.folder.name) / f"{name}.pem"
            openssl("genpkey", "-algorithm", "ed25519", "-out", str(key))
            public = openssl("pkey", "-in", str(key), "-pubout", "-outform", "DER")[-32:]
            cls.keys[name] = (key, public)

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def sign(self, document, who="ours"):
        path = Path(self.folder.name) / "document"
        path.write_bytes(document)
        return openssl("pkeyutl", "-sign", "-rawin", "-inkey", str(self.keys[who][0]), "-in", str(path)).hex().encode() + b"\n"

    def table(self, serial, **row):
        wires = {"chupa-20a": dict({"announce": 22, "minimum": 11, "maximum": 22}, **row)}
        return json.dumps({"delta_legacy": 1, "serial": serial, "issued": 1791331200, "wires": wires,
                           "disabled_capabilities": []}, indent=2).encode() + b"\n"

    def setUp(self):
        self.data = Path(tempfile.mkdtemp())
        self.remote = {}
        self.logs = []

        def fetch(url, limit):
            name = url.rsplit("/", 1)[-1]
            if name not in self.remote:
                raise OSError("404")
            data = self.remote[name]
            if len(data) > limit:
                raise delta_table.TableError("too large")
            return data

        self.puller = delta_table.Puller(self.data, "https://example.invalid/", keys={"ours": self.keys["ours"][1]},
                                         log=self.logs.append, fetch=fetch)

    def tearDown(self):
        shutil.rmtree(self.data)

    def publish(self, document, signature):
        self.remote = {"legacy.json": document, "legacy.json.sig": signature}

    def served(self):
        return (self.data / "delta_legacy.json").read_bytes(), (self.data / "delta_legacy.json.sig").read_bytes()

    def test_takes_a_signed_table_and_serves_it_as_it_is(self):
        document = self.table(2, follows="build-145")
        signature = self.sign(document)
        self.publish(document, signature)
        self.assertEqual(self.puller.pull(), "taken")
        self.assertEqual(self.served(), (document, signature))
        self.assertEqual(delta_table.summary(self.puller.served())[0]["follows"], "build-145")
        self.assertEqual(self.puller.pull(), "same")
        self.assertEqual(self.logs, ["legacy table: taken: serial 2", "legacy table: same"])

    def test_only_newer_serials(self):
        newer = self.table(3)
        self.publish(newer, self.sign(newer))
        self.puller.pull()
        older = self.table(2, maximum=40)
        self.publish(older, self.sign(older))
        self.assertEqual(self.puller.pull(), "same")
        self.assertEqual(self.served()[0], newer)

    def test_refuses_what_does_not_verify(self):
        document = self.table(2)
        cases = {
            "another key": (document, self.sign(document, "other")),
            "changed": (document.replace(b"22", b"23"), self.sign(document)),
            "no signature": (document, b"x" * 128 + b"\n"),
            "too large": (document + b" " * delta_table.DOCUMENT_SIZE, self.sign(document + b" " * delta_table.DOCUMENT_SIZE)),
            "not a table": (b"[]", self.sign(b"[]")),
            "serial 0": (self.table(0), self.sign(self.table(0))),
        }
        for name, (data, signature) in cases.items():
            self.publish(data, signature)
            self.assertNotEqual(self.puller.pull(), "taken", name)
            self.assertFalse((self.data / "delta_legacy.json").exists(), name)

    def test_unreachable_keeps_what_is_served(self):
        document = self.table(2)
        self.publish(document, self.sign(document))
        self.puller.pull()
        self.remote = {}
        self.assertTrue(self.puller.pull().startswith("not reached"))
        self.assertEqual(self.served()[0], document)

    def test_a_failed_write_is_noted_and_tried_again(self):
        document = self.table(2)
        self.publish(document, self.sign(document))
        # (a folder where the signature's temporary file goes: the write
        # fails as it would on a full disk, for root too)
        blocker = self.data / "delta_legacy.json.sig.new"
        blocker.mkdir()
        self.assertTrue(self.puller.pull().startswith("not written"))
        self.assertFalse((self.data / "delta_legacy.json").exists())
        blocker.rmdir()
        self.assertEqual(self.puller.pull(), "taken")
        self.assertEqual(self.served()[0], document)

    def test_the_thread_outlives_an_error(self):
        calls = []

        def pull():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("boom")
            raise SystemExit  # (ends the test's loop)

        self.puller.pull = pull
        self.puller.interval = 0
        with self.assertRaises(SystemExit):
            self.puller.run()
        self.assertEqual(len(calls), 2)
        self.assertIn("legacy table: failed: RuntimeError: boom", self.logs)

    def test_the_real_keys(self):
        self.assertEqual(sorted(delta_table.KEYS), ["primary", "recovery"])
        self.assertTrue(all(len(key) == 32 for key in delta_table.KEYS.values()))


if __name__ == "__main__":
    unittest.main()
