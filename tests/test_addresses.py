# SPDX-FileCopyrightText: 2026 The Chupathingy contributors
# SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
# SPDX-License-Identifier: MIT
"""Tests of how the site keeps and shows IP addresses (addresses.py): tags,
the audit log, the admin panel's listings, claims, Discord posts and
redact_addresses.py: python3 -m unittest test_addresses"""

import io
import os
import stat
import tempfile
import unittest

import addresses

# (public addresses, not documentation ranges: scrub leaves those, as they
# are no one's)
PLAYER = "8.8.4.4"
ADMIN = "1.1.1.1"
IPV6 = "2606:4700:4700::1111"


class Tags(unittest.TestCase):
    def test_stable_and_keyed(self):
        key = addresses.load_key(None)
        tag = addresses.tag(PLAYER, key)
        self.assertRegex(tag, r"\Aaddr#[0-9a-f]{8}\Z")
        self.assertEqual(addresses.tag(" " + PLAYER, key), tag)
        self.assertNotEqual(addresses.tag(ADMIN, key), tag)
        self.assertNotEqual(addresses.tag(PLAYER, addresses.load_key(None)), tag)
        # (a tag stays as it is; no address, no tag)
        self.assertEqual(addresses.tag(tag, key), tag)
        self.assertEqual(addresses.tag("", key), "")
        # (one IPv6 address however it is written)
        self.assertEqual(addresses.tag("2606:4700:4700:0:0:0:0:1111", key), addresses.tag(IPV6, key))

    def test_key_kept(self):
        with tempfile.TemporaryDirectory() as folder:
            key = addresses.load_key(folder)
            path = os.path.join(folder, addresses.KEY_FILE)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertEqual(addresses.load_key(folder), key)

    def test_scrub(self):
        self.assertEqual(addresses.scrub(f"joined from {PLAYER}:2302."), "joined from [address]:2302.")
        self.assertEqual(addresses.scrub(f"v6 {IPV6} here"), "v6 [address] here")
        for kept in ("192.168.1.4", "127.0.0.1", "10.0.0.2", "100.64.1.2", "fe80::1", "build 01.10.12.2276",
                     "at 12:30:45", "version 1.2.3", "1.2.3.4.5"):
            self.assertEqual(addresses.scrub(kept), kept)


if __name__ == "__main__":
    unittest.main()
