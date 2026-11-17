# SPDX-FileCopyrightText: 2026 The Chupathingy contributors
# SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
# SPDX-License-Identifier: MIT
"""Tests of friends (friends.py) and their requests (list_server.py):
python3 -m unittest test_friends"""

import sqlite3
import threading
import unittest

import friends
from test_clans import make_profiles

GAME_AGENT = "ChupathingyCE/0.9.0 (linux; x86_64)"


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


class Rules(unittest.TestCase):
    def setUp(self):
        self.database = sqlite3.connect(":memory:", check_same_thread=False)
        self.ids = make_profiles(self.database, ["church", "tucker", "caboose", "grif", "simmons", "sarge"])
        self.clock = Clock()
        self.friends = friends.Friends(self.database, threading.RLock(), self.clock)

    def befriend(self, one, two):
        self.assertEqual(self.friends.request(self.ids[one], two), "sent")
        self.friends.answer(self.ids[two], one, True)

    def handles(self, who):
        return [row[1] for row in self.friends.friend_rows(self.ids[who])]

    def test_request_accept_decline_remove(self):
        self.assertEqual(self.friends.request(self.ids["church"], "@Tucker"), "sent")
        self.assertEqual(self.friends.requests_of(self.ids["tucker"])["incoming"][0]["handle"], "church")
        self.assertEqual(self.friends.requests_of(self.ids["church"])["outgoing"][0]["handle"], "tucker")
        self.friends.answer(self.ids["tucker"], "church", True)
        self.assertEqual(self.handles("church"), ["tucker"])
        self.assertEqual(self.handles("tucker"), ["church"])
        self.assertEqual(self.friends.requests_of(self.ids["tucker"]), {"incoming": [], "outgoing": []})
        with self.assertRaises(friends.Refused):
            self.friends.request(self.ids["church"], "tucker")  # (friends already)
        self.friends.request(self.ids["church"], "caboose")
        self.friends.answer(self.ids["caboose"], "church", False)
        self.assertEqual(self.handles("caboose"), [])
        with self.assertRaises(friends.Refused):
            self.friends.answer(self.ids["caboose"], "church", True)  # (gone)
        self.friends.remove(self.ids["tucker"], "church")
        self.assertEqual(self.handles("church"), [])
        with self.assertRaises(friends.Refused):
            self.friends.request(self.ids["church"], "nobody")
        with self.assertRaises(friends.Refused):
            self.friends.request(self.ids["church"], "church")

    def test_a_request_both_ways_is_a_friendship(self):
        self.friends.request(self.ids["grif"], "simmons")
        self.assertEqual(self.friends.request(self.ids["simmons"], "grif"), "friends")
        self.assertEqual(self.handles("grif"), ["simmons"])

    def test_cancel_and_expiry(self):
        self.friends.request(self.ids["grif"], "sarge")
        self.friends.cancel(self.ids["grif"], "sarge")
        self.assertEqual(self.friends.requests_of(self.ids["sarge"])["incoming"], [])
        self.friends.request(self.ids["grif"], "sarge")
        self.clock.now += friends.REQUEST_LIFETIME + 1
        self.assertEqual(self.friends.requests_of(self.ids["sarge"])["incoming"], [])

    def test_block_is_silent(self):
        self.befriend("church", "tucker")
        self.friends.request(self.ids["tucker"], "caboose")
        self.friends.request(self.ids["caboose"], "tucker")  # (makes them friends)
        self.friends.request(self.ids["church"], "grif")
        self.friends.block(self.ids["church"], "tucker")
        self.assertEqual(self.handles("church"), [])
        self.assertTrue(self.friends.blocks(self.ids["church"], self.ids["tucker"]))
        self.assertEqual(self.friends.blocked_of(self.ids["church"]), ["tucker"])
        # (tucker's new request "goes": he sees it waiting, church never does)
        self.assertEqual(self.friends.request(self.ids["tucker"], "church"), "sent")
        self.assertEqual(self.friends.requests_of(self.ids["tucker"])["outgoing"][0]["handle"], "church")
        self.assertEqual(self.friends.requests_of(self.ids["church"])["incoming"], [])
        with self.assertRaises(friends.Refused):
            self.friends.answer(self.ids["church"], "tucker", True)
        # (a "nobody" rule refuses tucker as it would anyone)
        self.friends.cancel(self.ids["tucker"], "church")
        self.friends.set_privacy(self.ids["church"], requests="nobody")
        with self.assertRaises(friends.Refused):
            self.friends.request(self.ids["tucker"], "church")
        self.friends.set_privacy(self.ids["church"], requests="everyone")
        self.assertEqual(self.friends.request(self.ids["tucker"], "church"), "sent")
        # (church can't send one while he blocks; nor be made a friend by a silent one)
        with self.assertRaises(friends.Refused):
            self.friends.request(self.ids["church"], "tucker")
        # (unblocked: the silent request is gone, not delivered late)
        self.friends.unblock(self.ids["church"], "tucker")
        self.assertEqual(self.friends.requests_of(self.ids["church"])["incoming"], [])
        self.assertEqual(self.friends.request(self.ids["church"], "tucker"), "sent")

    def test_block_drops_invites_both_ways(self):
        self.befriend("church", "tucker")
        self.friends.invite(self.ids["church"], "tucker", "12" * 32)
        self.friends.invite(self.ids["tucker"], "church", "34" * 32)
        self.friends.block(self.ids["tucker"], "church")
        self.assertEqual(self.friends.invites_for(self.ids["church"]), [])
        self.assertEqual(self.friends.invites_for(self.ids["tucker"]), [])
        # (church's next invite is refused as any non-friend's: the block doesn't show)
        with self.assertRaises(friends.Refused) as refused:
            self.friends.invite(self.ids["church"], "tucker", "12" * 32)
        self.assertEqual(refused.exception.message, "You can invite friends only.")

    def test_clan_presence_privacy(self):
        """who sees a profile's status in its clan's roster: friends and clan
        by default, or friends only; anything else refused, the default not
        kept as a row"""
        self.assertEqual(self.friends.privacy_of(self.ids["sarge"])["clan_presence"], "friends_and_clan")
        self.assertEqual(self.friends.set_privacy(self.ids["sarge"], clan_presence="friends")["clan_presence"], "friends")
        self.assertEqual(self.friends.privacy_of(self.ids["sarge"])["clan_presence"], "friends")
        with self.assertRaises(friends.Refused):
            self.friends.set_privacy(self.ids["sarge"], clan_presence="everyone")
        self.friends.set_privacy(self.ids["sarge"], clan_presence="friends_and_clan")
        self.assertIsNone(self.friends.database.execute("SELECT 1 FROM social_privacy WHERE player_id = ?",
                                                        (self.ids["sarge"],)).fetchone())

    def test_page_presence_privacy(self):
        """who sees a profile's game on its page: friends by default, or
        everyone; anything else refused, the default not kept as a row"""
        self.assertEqual(self.friends.privacy_of(self.ids["sarge"])["page_presence"], "friends")
        self.assertEqual(self.friends.set_privacy(self.ids["sarge"], page_presence="everyone")["page_presence"], "everyone")
        self.assertEqual(self.friends.privacy_of(self.ids["sarge"])["page_presence"], "everyone")
        with self.assertRaises(friends.Refused):
            self.friends.set_privacy(self.ids["sarge"], page_presence="nobody")
        # (the other rules are left as they were)
        self.assertEqual(self.friends.privacy_of(self.ids["sarge"])["clan_presence"], "friends_and_clan")
        self.friends.set_privacy(self.ids["sarge"], page_presence="friends")
        self.assertIsNone(self.friends.database.execute("SELECT 1 FROM social_privacy WHERE player_id = ?",
                                                        (self.ids["sarge"],)).fetchone())

    def test_page_presence_on_an_older_table(self):
        """a social_privacy table from before page_presence gets the column,
        and its rows read as friends"""
        database = sqlite3.connect(":memory:", check_same_thread=False)
        ids = make_profiles(database, ["church"])
        database.execute("""CREATE TABLE social_privacy (
            player_id TEXT PRIMARY KEY, requests TEXT NOT NULL DEFAULT 'everyone',
            join_rule TEXT NOT NULL DEFAULT 'friends', appear_offline INTEGER NOT NULL DEFAULT 0,
            clan_presence TEXT NOT NULL DEFAULT 'friends_and_clan')""")
        database.execute("INSERT INTO social_privacy (player_id, requests) VALUES (?, 'nobody')", (ids["church"],))
        database.commit()
        older = friends.Friends(database, threading.RLock(), self.clock)
        privacy = older.privacy_of(ids["church"])
        self.assertEqual((privacy["requests"], privacy["page_presence"]), ("nobody", "friends"))

    def test_request_privacy(self):
        self.friends.set_privacy(self.ids["sarge"], requests="nobody")
        with self.assertRaises(friends.Refused) as refused:
            self.friends.request(self.ids["grif"], "sarge")
        self.assertEqual(refused.exception.status, 403)
        self.friends.set_privacy(self.ids["sarge"], requests="friends_of_friends")
        with self.assertRaises(friends.Refused):
            self.friends.request(self.ids["grif"], "sarge")
        self.befriend("sarge", "simmons")
        self.befriend("simmons", "grif")
        self.assertEqual(self.friends.request(self.ids["grif"], "sarge"), "sent")
        with self.assertRaises(friends.Refused):
            self.friends.set_privacy(self.ids["sarge"], requests="anyone at all")
        with self.assertRaises(friends.Refused):
            self.friends.set_privacy(self.ids["sarge"], join="whoever")
        self.assertEqual(self.friends.privacy_of(self.ids["church"]), friends.DEFAULT_PRIVACY)
        # (back to the defaults: no row kept)
        self.friends.set_privacy(self.ids["sarge"], requests="everyone")
        self.assertIsNone(self.database.execute("SELECT 1 FROM social_privacy").fetchone())

    def test_caps(self):
        for number in range(friends.OUTGOING_MOST):
            self.database.execute("INSERT INTO friend_requests (from_id, to_id, created) VALUES (?, ?, ?)",
                                  (self.ids["church"], f"e{number:031x}", int(self.clock.now)))
        with self.assertRaises(friends.Refused):
            self.friends.request(self.ids["church"], "tucker")
        for number in range(friends.FRIENDS_MOST):
            self.database.execute("INSERT INTO friends (a, b, since) VALUES (?, ?, 1)",
                                  friends.pair(self.ids["grif"], f"f{number:031x}"))
        self.friends.request(self.ids["simmons"], "grif")
        with self.assertRaises(friends.Refused) as refused:
            self.friends.answer(self.ids["grif"], "simmons", True)
        self.assertEqual(refused.exception.message, "Your friends list is full.")

    def test_requests_an_hour(self):
        handles = [f"p{number:02d}" for number in range(friends.REQUESTS_PER_HOUR + 1)]
        for number, handle in enumerate(handles):
            self.database.execute("INSERT INTO profiles (player_id, handle, display, bio, auth, backup, created, updated) "
                                  "VALUES (?, ?, ?, '', '', '{}', 1, 1)", (f"d{number:031x}", handle, handle))
        for handle in handles[:-1]:
            self.friends.request(self.ids["caboose"], handle)
        with self.assertRaises(friends.Refused) as refused:
            self.friends.request(self.ids["caboose"], handles[-1])
        self.assertEqual(refused.exception.status, 429)
        self.clock.now += 3601
        self.assertEqual(self.friends.request(self.ids["caboose"], handles[-1]), "sent")

    def test_invites(self):
        with self.assertRaises(friends.Refused):
            self.friends.invite(self.ids["church"], "tucker", "12" * 32)  # (friends only)
        self.befriend("church", "tucker")
        first = self.friends.invite(self.ids["church"], "tucker", "12" * 32)
        second = self.friends.invite(self.ids["church"], "tucker", "56" * 32)  # (replaces the first)
        self.assertNotEqual(first, second)
        self.assertEqual([i["invite"] for i in self.friends.invites_for(self.ids["tucker"])], ["56" * 32])
        self.assertTrue(self.friends.invited(self.ids["tucker"], self.ids["church"], "56" * 32))
        self.assertFalse(self.friends.invited(self.ids["tucker"], self.ids["church"], "12" * 32))
        self.clock.now += friends.INVITE_LIFETIME + 1
        self.assertEqual(self.friends.invites_for(self.ids["tucker"]), [])
        for _ in range(friends.INVITES_PER_MINUTE):
            self.friends.invite(self.ids["church"], "tucker", "12" * 32)
        with self.assertRaises(friends.Refused) as refused:
            self.friends.invite(self.ids["church"], "tucker", "12" * 32)
        self.assertEqual(refused.exception.status, 429)

    def test_online_and_appear_offline(self):
        self.friends.mark_online(self.ids["caboose"])
        self.assertTrue(self.friends.online(self.ids["caboose"]))
        self.clock.now += friends.ONLINE_LIFETIME + 1
        self.assertFalse(self.friends.online(self.ids["caboose"]))
        self.friends.mark_online(self.ids["caboose"])
        self.friends.set_privacy(self.ids["caboose"], appear_offline=True)
        self.assertFalse(self.friends.online(self.ids["caboose"]))
        self.friends.mark_online(self.ids["caboose"])
        self.assertFalse(self.friends.online(self.ids["caboose"]))

    def test_locked_profiles_are_left_out(self):
        self.befriend("church", "tucker")
        self.database.execute("UPDATE profiles SET locked = 1 WHERE handle = 'tucker'")
        self.assertEqual(self.handles("church"), [])
        with self.assertRaises(friends.Refused):
            self.friends.request(self.ids["grif"], "tucker")

    def test_forget(self):
        self.befriend("church", "tucker")
        self.friends.request(self.ids["church"], "grif")
        self.friends.block(self.ids["church"], "sarge")
        self.friends.set_privacy(self.ids["church"], join="anyone")
        self.friends.invite(self.ids["church"], "tucker", "12" * 32)
        self.friends.forget(self.ids["church"])
        for table, columns in (("friends", "a, b"), ("friend_requests", "from_id, to_id"), ("blocks", "player_id, blocked_id"),
                               ("social_privacy", "player_id, player_id")):
            for row in self.database.execute(f"SELECT {columns} FROM {table}").fetchall():
                self.assertNotIn(self.ids["church"], row, table)
        self.assertEqual(self.friends.invites_for(self.ids["tucker"]), [])


if __name__ == "__main__":
    unittest.main()


