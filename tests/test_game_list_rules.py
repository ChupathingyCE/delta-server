"""Tests of which listed games the site shows (game_list_rules.py): only
games a current Chupathingy release can join, by the signed table's range,
with sample advertisements; /v1/games marks them "joinable", and the lists
the game's builds read keep every game: python3 -m unittest
test_game_list_rules

SPDX-FileCopyrightText: 2026 The Chupathingy contributors
SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: GPL-3.0-or-later
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

import game_list_rules as rules

# (the live table's rows, serial 12: chupa-44a joins 11 to 45)
TABLE = {"delta_legacy": 1, "serial": 12, "wires": {
    "chupa-38a": {"announce": 38, "minimum": 11, "maximum": 39},
    "chupa-43a": {"announce": 41, "minimum": 11, "maximum": 44},
    "chupa-44a": {"announce": 32, "minimum": 11, "maximum": 45}}}
RANGE = (11, 45)


class Rule(unittest.TestCase):
    """the rule, the same as the game's (port/linux/tests/game_list_rules_test.c)"""

    def test_broker_floor(self):
        self.assertEqual(rules.BROKER_MINIMUM_VERSION, 35)
        broker = lambda version, **more: dict({"source": "broker", "version": version}, **more)
        self.assertFalse(rules.broker_listed(broker(26)))
        self.assertFalse(rules.broker_listed(broker(34)))
        self.assertFalse(rules.broker_listed(broker(0)))
        self.assertFalse(rules.broker_listed(broker("junk")))
        self.assertFalse(rules.broker_listed(broker(0x8000 | 26)))
        self.assertTrue(rules.broker_listed(broker(35)))
        self.assertTrue(rules.broker_listed(broker(44)))
        # (only a broker's listing: an announced game, or a Delta host's, by its own rules)
        self.assertTrue(rules.broker_listed({"source": "announced", "version": 22}))
        self.assertTrue(rules.broker_listed(broker(32, protocol="delta")))

    def test_range_from_table(self):
        self.assertEqual(rules.table_range(TABLE), RANGE)
        self.assertIsNone(rules.table_range({}))
        self.assertIsNone(rules.table_range({"wires": {}}))
        self.assertIsNone(rules.table_range({"wires": {"x": {"minimum": "11", "maximum": 45}}}))
        self.assertIsNone(rules.table_range({"wires": {"x": {"minimum": True, "maximum": 45}}}))
        self.assertIsNone(rules.table_range({"wires": {"x": {"minimum": 50, "maximum": 45}}}))
        self.assertEqual(rules.table_range({"wires": {"x": {"minimum": 11, "maximum": 45}, "y": "junk"}}), RANGE)

    def test_legacy_versions_in_range(self):
        for version in (11, 22, 26, 32, 41, 42, 43, 44, 45):
            self.assertTrue(rules.joinable(version, False, RANGE), version)

    def test_legacy_versions_out_of_range(self):
        for version in (0, 10, 46, 60, None, "", "x"):
            self.assertFalse(rules.joinable(version, False, RANGE), version)

    def test_delta_hosts(self):
        # (their wire decides on joining, whatever number they announce)
        for version in (0, 32, 44, 46):
            self.assertTrue(rules.joinable(version, True, RANGE), version)

    def test_goat_h1_closed(self):
        for version in (0x8000 | 41, 0x8000 | 44, 0x8000, 0xFFFF):
            self.assertFalse(rules.joinable(version, False, RANGE), version)
            self.assertFalse(rules.joinable(version, True, RANGE), version)
            self.assertFalse(rules.joinable(version, False, None), version)

    def test_no_table_hides_only_closed(self):
        self.assertTrue(rules.joinable(46, False, None))
        self.assertTrue(rules.joinable(0, False, None))

    def test_listing(self):
        self.assertTrue(rules.game_joinable({"version": 46, "protocol": "delta"}, RANGE))
        self.assertFalse(rules.game_joinable({"version": 46, "protocol": "opence"}, RANGE))
        self.assertFalse(rules.game_joinable({"version": 46, "protocol": ""}, RANGE))
        self.assertTrue(rules.game_joinable({"version": 22, "protocol": ""}, RANGE))

    def test_versions_reads_the_served_table(self):
        with tempfile.TemporaryDirectory() as folder:
            versions = rules.Versions(folder)
            self.assertIsNone(versions.get())
            path = Path(folder) / rules.TABLE
            path.write_text(json.dumps(TABLE))
            self.assertEqual(versions.get(), RANGE)
            wider = json.loads(json.dumps(TABLE))
            wider["wires"]["chupa-46a"] = {"announce": 46, "minimum": 11, "maximum": 47}
            path.write_text(json.dumps(wider))
            os.utime(path, ns=(1, 1))
            self.assertEqual(versions.get(), (11, 47))
            path.write_text("not json")
            os.utime(path, ns=(2, 2))
            self.assertIsNone(versions.get())


if __name__ == "__main__":
    unittest.main()
