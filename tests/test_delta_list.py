# SPDX-FileCopyrightText: 2026 The Chupathingy contributors
# SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
# SPDX-License-Identifier: MIT
"""Tests of Delta List's host fields (delta_list.py): what a ChupathingyCE
host says of itself in its announcement, read compatibly (old clients send
none of it, malformed fields are left out), what /v1/games shows of each
game, its filters, the text and console lists' later fields, and a
carnage report's host: python3 -m unittest test_delta_list"""

import unittest

import delta_list

# a Linux machine's key (platform 3, key version 1, no flags, 128/128/128,
# 4 GB), a Steam Deck's, an original Xbox's, and a dedicated server's
LINUX_KEY = "0301008080800c00"
DECK_KEY = "0501008080800e00"
XBOX_KEY = "0601001010800600"
SERVER_KEY = "0301028080800c00"


def invite(number: int) -> str:
    return f"{number:064x}"


def old_form(number: int, **more) -> dict:
    """an announcement as builds before Delta List's fields send it"""
    return dict({"invite": invite(number), "name": "Walter", "map": "levels\\test\\bloodgulch\\bloodgulch",
                 "engine": "2", "players": "3", "maximum_players": "16", "open": "1", "version": "20",
                 "score_limit": "25", "teams": "0", "roster": "-1:Walter|-1:Guven|-1:Sarge"}, **more)


def new_form(number: int, **more) -> dict:
    """as ChupathingyCE 0.7.1b's hosts send it: the Delta fields before the roster"""
    form = old_form(number)
    roster = form.pop("roster")
    form.update({"delta": "1", "platform_key": LINUX_KEY, "arch": "x64", "build": "0.7.1b",
                 "capabilities": "00000003", "machines": "pc_linux:1,xbox:1,legacy:1"})
    form.update(more)
    form["roster"] = roster
    return form


class Parsing(unittest.TestCase):
    def test_an_old_client_says_nothing_more(self):
        self.assertEqual(delta_list.parse_announce(old_form(1)), {})

    def test_a_new_client(self):
        host = delta_list.parse_announce(new_form(1))
        self.assertEqual(host["delta"], 1)
        self.assertEqual(host["key"]["platform"], "pc_linux")
        self.assertEqual(host["key"]["version"], 1)
        self.assertFalse(host["key"]["dedicated"])
        self.assertEqual(host["key"]["memory_class"], 12)
        self.assertEqual((host["arch"], host["build"], host["capabilities"]), ("x64", "0.7.1b", 3))
        self.assertEqual(host["machines"], {"pc_linux": 1, "xbox": 1, "legacy": 1})

    def test_malformed_fields_are_left_out_one_by_one(self):
        host = delta_list.parse_announce(new_form(1, delta="x", platform_key="zz", arch="sparc", build="a b",
                                                  capabilities="123456789", machines="pc_linux:1,xbox"))
        self.assertEqual(host, {})
        host = delta_list.parse_announce(new_form(1, platform_key="03", machines="pc_linux:999"))
        self.assertNotIn("key", host)
        self.assertNotIn("machines", host)
        self.assertEqual(host["delta"], 1)

    def test_keys(self):
        self.assertTrue(delta_list.decode_key(SERVER_KEY)["dedicated"])
        self.assertTrue(delta_list.decode_key("0301018080800c00")["opted_in"])
        # (a later version's longer key: the bytes this list knows)
        self.assertEqual(delta_list.decode_key(DECK_KEY + "ffff")["platform"], "steam_deck")
        # (a platform added after this list: unknown, still a key)
        self.assertEqual(delta_list.decode_key("2a01008080800000")["platform"], "unknown")
        # (the game's registry, delta.h: 13 FreeBSD, 14 to 18 the ports' numbers of 2026-10-29)
        self.assertEqual([delta_list.decode_key(f"{n:02x}01001010108000")["platform"] for n in range(13, 19)],
                         ["pc_freebsd", "ps3", "ps4", "ps5", "n64", "pc_legacy"])
        # (19 the Steam Link, 20 iPhone and iPad, 21 the Apple TV, of 2026-11-04)
        self.assertEqual([delta_list.decode_key(f"{n:02x}01001010108000")["platform"] for n in range(19, 22)],
                         ["steamlink", "ios", "tvos"])
        self.assertEqual([delta_list.PLATFORM_LABELS[name] for name in ("steamlink", "ios", "tvos")],
                         ["Steam Link", "iPhone and iPad", "Apple TV"])
        self.assertEqual(delta_list.PLATFORM_LABELS["steam_deck"], "SteamOS")
        # (22 the Dreamcast, of 2026-11-14; 23 unassigned)
        self.assertEqual(delta_list.decode_key("1601001010108000")["platform"], "dreamcast")
        self.assertEqual(delta_list.PLATFORM_LABELS["dreamcast"], "Dreamcast")
        self.assertIn("dreamcast", delta_list.PLATFORM_GROUPS["console"])
        self.assertEqual(delta_list.decode_key("1701001010108000")["platform"], "unknown")
        for bad in ("", "0301", "0300008080800c00", "0301008080800c0", "g301008080800c00", "03" * 40):
            self.assertIsNone(delta_list.decode_key(bad), bad)

    def test_machines(self):
        self.assertEqual(delta_list.parse_machines("pc_windows:2, xbox:1,ps9:1"),
                         {"pc_windows": 2, "xbox": 1, "unknown": 1})
        self.assertEqual(delta_list.parse_machines("pc_linux:100,xbox:100"), {})
        self.assertEqual(delta_list.machines_text({"legacy": 1, "xbox": 1, "pc_linux": 2}), "pc_linux:2,xbox:1,legacy:1")

    def test_families(self):
        for name, family in (("levels\\test\\bloodgulch\\bloodgulch", "xbox"), ("timberland@ce", "ce"),
                             ("bloodgulch@PC", "pc"), ("bgplus_5@md", "md"), ("", "xbox"), ("x@zz", "pack"),
                             ("wizard@cex", "pack"), ("wizard@CEX", "pack"), ("x@de", "xbox"), ("x@toolongid", "xbox"),
                             ("@cex", "xbox"), ("x@c-x", "xbox")):
            self.assertEqual(delta_list.family(name), family, name)

    def test_map_pack_fields(self):
        host = delta_list.parse_announce({"map_title": "Gothra", "map_pack": "Halo CE+", "map_tag": "CE+"})
        self.assertEqual((host["map_title"], host["map_pack"], host["map_tag"]), ("Gothra", "Halo CE+", "CE+"))
        self.assertEqual(delta_list.parse_announce({"map_title": "G\u00f6thra", "map_tag": "TOOLONG"}), {})
        fields = delta_list.listing_fields({"map": "wizard@cex", "host_report": host}, "announced", "multiplayer")
        self.assertEqual((fields["family"], fields["map_title"], fields["map_tag"]), ("pack", "Gothra", "CE+"))
        # (only a pack's map has them)
        fields = delta_list.listing_fields({"map": "wizard", "host_report": host}, "announced", "multiplayer")
        self.assertEqual((fields["family"], fields["map_title"]), ("xbox", ""))


if __name__ == "__main__":
    unittest.main()
