# SPDX-FileCopyrightText: 2026 The Chupathingy contributors
# SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests of the clans (clans.py) and their requests (list_server.py):
python3 -m unittest test_clans"""

import json
import sqlite3
import threading
import unittest

import clans

GAME_AGENT = "ChupathingyCE/0.8.0 (linux; x86_64)"


def make_profiles(database, handles):
    database.execute("""CREATE TABLE IF NOT EXISTS profiles (
        player_id TEXT PRIMARY KEY, handle TEXT NOT NULL UNIQUE, display TEXT NOT NULL, bio TEXT NOT NULL,
        auth TEXT NOT NULL, backup TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL,
        locked INTEGER NOT NULL DEFAULT 0)""")
    ids = {}
    for number, handle in enumerate(handles):
        ids[handle] = f"{number + 1:032x}"
        database.execute("INSERT INTO profiles (player_id, handle, display, bio, auth, backup, created, updated) "
                         "VALUES (?, ?, ?, '', '', '{}', 1, 1)", (ids[handle], handle, handle.title()))
    database.commit()
    return ids


class Rules(unittest.TestCase):
    def setUp(self):
        self.database = sqlite3.connect(":memory:", check_same_thread=False)
        self.ids = make_profiles(self.database, ["walter", "jesse", "skyler", "hank", "saul"])
        self.hidden = set()
        self.clans = clans.Clans(self.database, threading.RLock(), lambda player_id: player_id in self.hidden)
        self.clan = self.clans.create(self.ids["walter"], "Heisenberg Crew", "HSB", "Say my name")

    def join(self, handle):
        self.clans.invite(self.ids["walter"], handle)
        self.clans.answer_invite(self.ids[handle], self.clan, True)

    def test_create_rules(self):
        refused = lambda *args: self.assertRaises(clans.Refused, self.clans.create, *args)
        refused(self.ids["jesse"], "heisenberg crew", "ABC")  # (the name taken, any case)
        refused(self.ids["jesse"], "Blue Sky", "hsb")  # (the tag taken)
        refused(self.ids["jesse"], "Blue Sky", "A")  # (too short a tag)
        refused(self.ids["jesse"], "Blue Sky", "ABCDEFGHI")  # (too long)
        refused(self.ids["jesse"], "Blue Sky", "A-B")
        refused(self.ids["jesse"], "x", "ABC")
        refused(self.ids["walter"], "Second", "TWO")  # (one clan each)
        self.assertTrue(self.clans.create(self.ids["jesse"], "Los Pollos Hermanos Distribution", "BLUESKY8"))

    def test_blocked_names(self):
        word = clans.blocked_names.rot13(sorted(w for k, w in clans.blocked_names.BUILT_IN if k == "whole")[0])
        word = clans.blocked_names.rot13(word)
        with self.assertRaises(clans.Refused):
            self.clans.create(self.ids["jesse"], word, "ABC")
        with self.assertRaises(clans.Refused):
            self.clans.create(self.ids["jesse"], "Fine Name", word[:8] if word[:8].isalnum() else "ABC", word)

    def test_an_invite_to_someone_who_blocks_the_inviter_is_silent(self):
        blocked = set()
        self.clans.blocks = lambda owner, other: (owner, other) in blocked
        blocked.add((self.ids["jesse"], self.ids["walter"]))
        # (taken as any invite: the inviter sees it waiting)
        self.clans.invite(self.ids["walter"], "jesse")
        self.assertEqual([i["handle"] for i in self.clans.invited(self.ids["walter"])], ["jesse"])
        # (the one who blocks never sees it, and can't take it)
        self.assertEqual(self.clans.mine(self.ids["jesse"])["invites"], [])
        with self.assertRaises(clans.Refused) as refused:
            self.clans.answer_invite(self.ids["jesse"], self.clan, True)
        self.assertEqual(refused.exception.status, 404)
        self.assertIsNone(self.clans.mine(self.ids["jesse"])["clan"])
        # (an officer's invite to them shows: only the inviter they block is silent)
        self.join("skyler")
        self.clans.set_rank(self.ids["walter"], "skyler", "officer")
        self.clans.invite(self.ids["skyler"], "jesse")
        self.assertEqual([i["by"] for i in self.clans.mine(self.ids["jesse"])["invites"]], ["skyler"])
        # (unblocked: walter's next invite shows as any other)
        blocked.clear()
        self.clans.invite(self.ids["walter"], "jesse")
        self.assertEqual([i["by"] for i in self.clans.mine(self.ids["jesse"])["invites"]], ["walter"])
        self.clans.answer_invite(self.ids["jesse"], self.clan, True)
        self.assertEqual(self.clans.mine(self.ids["jesse"])["clan"]["tag"], "HSB")

    def test_invites_and_ranks(self):
        self.join("jesse")
        self.join("skyler")
        mine = self.clans.mine(self.ids["jesse"])
        self.assertEqual(mine["clan"]["rank"], "member")
        self.assertEqual([m["handle"] for m in mine["clan"]["members"]], ["walter", "jesse", "skyler"])
        # (a member can't invite, kick or rank; an officer kicks members only)
        with self.assertRaises(clans.Refused):
            self.clans.invite(self.ids["jesse"], "hank")
        self.clans.set_rank(self.ids["walter"], "jesse", "officer")
        self.clans.invite(self.ids["jesse"], "hank")
        with self.assertRaises(clans.Refused):
            self.clans.kick(self.ids["jesse"], "walter")
        self.clans.kick(self.ids["jesse"], "skyler")
        self.assertIsNone(self.clans.mine(self.ids["skyler"])["clan"])
        # (an invite declined, or turned into a membership)
        self.assertEqual([i["tag"] for i in self.clans.mine(self.ids["hank"])["invites"]], ["HSB"])
        self.clans.answer_invite(self.ids["hank"], self.clan, False)
        self.assertEqual(self.clans.mine(self.ids["hank"])["invites"], [])
        with self.assertRaises(clans.Refused):
            self.clans.answer_invite(self.ids["hank"], self.clan, True)

    def test_leader_leaves_only_alone_or_after_handing_over(self):
        self.join("jesse")
        with self.assertRaises(clans.Refused):
            self.clans.leave(self.ids["walter"])
        self.clans.transfer(self.ids["walter"], "jesse")
        self.assertEqual(self.clans.mine(self.ids["walter"])["clan"]["rank"], "officer")
        self.assertFalse(self.clans.leave(self.ids["walter"]))
        self.assertTrue(self.clans.leave(self.ids["jesse"]))
        self.assertIsNone(self.clans.by_tag("hsb"))

    def test_rename_is_the_leaders(self):
        self.join("jesse")
        self.clans.set_rank(self.ids["walter"], "jesse", "officer")
        with self.assertRaises(clans.Refused):
            self.clans.edit(self.ids["jesse"], name="Pinkman Crew")
        self.clans.edit(self.ids["jesse"], motto="Yeah, science")
        self.clans.edit(self.ids["walter"], name="Pinkman Crew", tag="PNK")
        self.assertEqual(self.clans.view(self.clan)["tag"], "PNK")
        self.assertEqual(self.clans.view(self.clan)["motto"], "Yeah, science")

    def test_emblem(self):
        self.assertEqual(self.clans.view(self.clan)["emblem"], clans.DEFAULT_EMBLEM)
        emblem = {"fg": len(clans.EMBLEM_FOREGROUNDS) - 1, "bg": 3, "c1": 17, "c2": 0, "c3": 1}
        self.assertEqual(self.clans.set_emblem(self.ids["walter"], emblem), emblem)
        for bad in ({"fg": len(clans.EMBLEM_FOREGROUNDS)}, {"c1": 18}, {"bg": -1}, {"c2": True}, "x"):
            with self.assertRaises(clans.Refused):
                self.clans.set_emblem(self.ids["walter"], bad)
        pieces = clans.emblem_pieces()
        self.assertEqual(len(pieces["colors"]), 18)
        for piece in pieces["backgrounds"] + pieces["foregrounds"]:
            for part in piece["parts"]:
                for polygon in part["polygons"]:
                    self.assertGreaterEqual(len(polygon), 3)
                    self.assertTrue(all(0 <= v <= 100 for point in polygon for v in point), piece["name"])

    def test_privacy(self):
        self.join("jesse")
        self.hidden.add(self.ids["jesse"])
        view = self.clans.view(self.clan, self.ids["walter"])
        self.assertEqual(([m["handle"] for m in view["members"]], view["hidden"], view["count"]), (["walter"], 1, 2))
        # (their own line, for them)
        self.assertIn("jesse", [m["handle"] for m in self.clans.view(self.clan, self.ids["jesse"])["members"]])
        self.assertEqual(self.clans.tag_of(self.ids["walter"]), {"tag": "HSB", "name": "Heisenberg Crew"})
        self.clans.set_tag_shown(self.ids["walter"], False)
        self.assertIsNone(self.clans.tag_of(self.ids["walter"]))
        self.assertIsNone(self.clans.tag_of(self.ids["saul"]))
        text = json.dumps(self.clans.mine(self.ids["walter"]))
        for player_id in self.ids.values():
            self.assertNotIn(player_id, text)

    def test_public_tags(self):
        self.join("jesse")
        self.join("skyler")
        self.assertEqual(self.clans.public_tags(), {self.ids[h]: "HSB" for h in ("walter", "jesse", "skyler")})
        # (a tag turned off, a hidden service record, a locked profile: none shown)
        self.clans.set_tag_shown(self.ids["jesse"], False)
        self.hidden.add(self.ids["skyler"])
        self.database.execute("UPDATE profiles SET locked = 1 WHERE player_id = ?", (self.ids["walter"],))
        self.assertEqual(self.clans.public_tags(), {})

    def test_forget(self):
        self.join("jesse")
        self.join("skyler")
        self.clans.set_rank(self.ids["walter"], "skyler", "officer")
        self.clans.forget(self.ids["walter"])
        self.assertEqual(self.clans.mine(self.ids["skyler"])["clan"]["rank"], "leader")
        self.clans.forget(self.ids["skyler"])
        self.clans.forget(self.ids["jesse"])
        self.assertIsNone(self.clans.by_tag("HSB"))

    def test_full(self):
        database = self.database
        for number in range(clans.CLAN_MEMBERS - 1):
            database.execute("INSERT INTO clan_members (player_id, clan, rank, joined) VALUES (?, ?, 'member', ?)",
                             (f"f{number:031x}", self.clan, number))
        database.commit()
        with self.assertRaises(clans.Refused):
            self.clans.invite(self.ids["walter"], "jesse")


if __name__ == "__main__":
    unittest.main()
