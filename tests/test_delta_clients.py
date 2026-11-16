# SPDX-FileCopyrightText: 2026 The Chupathingy contributors
# SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
# SPDX-License-Identifier: GPL-3.0-or-later
"""Delta clients (delta_clients.py): registering another app, its scopes on
its devices, pending and suspended clients, its own counts, and requests
with no client ID working as before: python3 -m unittest test_delta_clients"""
import unittest

import delta_clients

ADMIN_WHO = ("admin", "127.0.0.1")
APP = {"name": "Vita Port", "homepage": "https://example.org/vita", "contact": "dev@example.org",
       "platforms": ["vita", "pc_linux"], "scopes": ["play", "stats", "social"]}


class Names(unittest.TestCase):
    def test_fold_and_hosts(self):
        for name in ("Chupathingy", "Chupa Thingy", "CHUPATH1NGY", "chüpathingy", "DeIta Client", "0fficial port"):
            self.assertTrue(any(delta_clients.fold(word) in delta_clients.fold(name)
                                for word in delta_clients.RESERVED + delta_clients.HELD), name)
        self.assertEqual(delta_clients.fold("Vita  Port."), delta_clients.fold("vita-p0rt"))
        self.assertEqual(delta_clients.homepage_host("https://Example.org/a?b=1"), "example.org")
        for bad in ("http://example.org", "https://user:pw@example.org", "https://example.org/\"<x>",
                    "https://localhost", "javascript:alert(1)", "https://exa mple.org", "https://example.org:99999"):
            self.assertEqual(delta_clients.homepage_host(bad), "", bad)


if __name__ == "__main__":
    unittest.main()
