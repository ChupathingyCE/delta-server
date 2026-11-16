# SPDX-FileCopyrightText: 2026 The Chupathingy contributors
# SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
# SPDX-License-Identifier: MIT
"""Tests of the blocked names (blocked_names.py): the matching, the names
that must stay allowed, the interface's answers, the game list, profiles and
the admin tools: python3 -m unittest test_blocked_names

The blocked examples are written in ROT13 (decoded by B), as the list is."""

import unittest

import blocked_names


def B(text: str) -> str:
    return blocked_names.rot13(text)


# names that must be blocked: the forms seen on the list, and look-alikes
BLOCKED = [B("avttre"), B("Avttn"), B("avvvvttn"), B("A1TT4"), B("a.v.t.t.n"), B("avvvvtttre"), B("avt"),
           B("Avttnf123"), B("N ERGNEQ"), B("uvgyre"), B("u1gy3e"), B("RivyEncvfg"), B("ArtebAnmv"),
           B("snttbg"), B("snt"), B("pbbaf"), "Nі" + B("tt") + "а"]
# names that must stay allowed: the scan's false positives (a Spanish
# nickname, words that contain a blocked one) and plain names
ALLOWED = ["kike01", "kike018", "Kikekike00", "KIKE", "therapist", "therapist01",
           "PC Spice", "spicky", "PEDOF", "Knight", "Nigeria", "Niigata", "snigger", "raccoon", "Tycoon", "grape",
           "Japan", "Nazir", "Heil", "Tardis", "Walter", "Guven", "[D] Chupathingy", "", "1234"]


class Matching(unittest.TestCase):
    def test_the_list_file_is_read(self):
        kinds = {kind for kind, _ in blocked_names.BUILT_IN}
        self.assertEqual(kinds, set(blocked_names.KINDS))

    def test_blocked(self):
        for name in BLOCKED:
            with self.subTest(name=B(name)):
                self.assertTrue(blocked_names.blocked(name))

    def test_allowed(self):
        for name in ALLOWED:
            with self.subTest(name=name):
                self.assertFalse(blocked_names.blocked(name), blocked_names.match(name))

    def test_an_allowed_word_does_not_hide_a_blocked_one(self):
        self.assertTrue(blocked_names.blocked("therapist" + B("encvfg")))

    def test_squeezed(self):
        self.assertEqual(blocked_names.squeeze("niiigggaaa"), "niga")

    def test_mask_shows_one_letter(self):
        self.assertEqual(blocked_names.mask("abcd"), "a***")

    def test_not_a_string(self):
        self.assertFalse(blocked_names.blocked(None))
        self.assertFalse(blocked_names.blocked(7))


class Scrub(unittest.TestCase):
    def test_names_in_an_answer(self):
        bad = B("uvgyre")
        report = {"id": 4, "name": bad, "map": "bloodgulch",
                  "players": [{"name": bad, "kills": 9, "player_id": "ab" * 16}, {"name": "Walter", "kills": 3}],
                  "names": [bad, "Walter"], "who": "name:" + bad, "leaders": [{"id": "name:" + bad, "name": "x"}],
                  "server_name": bad, "players_count": 2}
        shown = blocked_names.scrub(report)
        removed = blocked_names.REMOVED
        self.assertEqual(shown["name"], removed)
        self.assertEqual([p["name"] for p in shown["players"]], [removed, "Walter"])
        self.assertEqual(shown["players"][0]["kills"], 9)
        self.assertEqual(shown["names"], [removed, "Walter"])
        self.assertEqual(shown["who"], "name:" + removed)
        self.assertEqual(shown["leaders"][0]["id"], "name:" + removed)
        self.assertEqual(shown["server_name"], removed)
        self.assertEqual(shown["map"], "bloodgulch")
        # (the stored report is not changed)
        self.assertEqual(report["name"], bad)

    def test_other_fields_are_left(self):
        answer = {"weapon": B("uvgyre"), "id": "ab" * 16, "players": 4}
        self.assertEqual(blocked_names.scrub(answer), answer)


def invite(number: int) -> str:
    return f"{number:064x}"


if __name__ == "__main__":
    unittest.main()
