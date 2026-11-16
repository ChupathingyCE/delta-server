# SPDX-FileCopyrightText: 2026 The Chupathingy contributors
# SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests of parties (party.py) and their requests (list_server.py):
python3 -m unittest test_party"""

import unittest

import party

GAME_AGENT = "ChupathingyCE/0.9.1 (linux; x86_64)"


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


def member(name, linked=True):
    return {"key": ("p:" if linked else "c:") + name, "player_id": name if linked else None, "name": name.title(),
            "platform": "pc_linux"}


class Rules(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.friendships = set()
        self.blocked = set()
        self.parties = party.Parties(lambda a, b: frozenset((a, b)) in self.friendships,
                                     lambda owner, other: (owner, other) in self.blocked, self.clock)
        self.sarge, self.grif, self.simmons, self.donut = (member(n) for n in ("sarge", "grif", "simmons", "donut"))
        self.lopez = member("lopez", linked=False)

    def befriend(self, one, two):
        self.friendships.add(frozenset((one["player_id"], two["player_id"])))

    def state(self, who):
        return self.parties.state_for(who)

    def names(self, who):
        return [m["name"] for m in self.state(who)["members"]]

    def test_create_invite_accept_leave(self):
        made = self.parties.create(self.sarge)
        self.assertEqual(self.names(self.sarge), ["Sarge"])
        self.assertTrue(self.state(self.sarge)["leader"])
        self.assertEqual(self.state(self.sarge)["link"], "halo://party/" + made["code"])
        with self.assertRaises(party.Refused):
            self.parties.create(self.sarge)  # (in one already)
        with self.assertRaises(party.Refused) as refused:
            self.parties.invite(self.sarge, "grif")  # (not friends)
        self.assertEqual(refused.exception.reason, "friends_only")
        self.befriend(self.sarge, self.grif)
        self.parties.invite(self.sarge, "grif")
        waiting = self.parties.invites_for("grif")
        self.assertEqual([(i["party"], i["from"], i["size"]) for i in waiting], [(made["id"], "sarge", 1)])
        self.parties.accept(self.grif, made["id"])
        self.assertEqual(self.names(self.grif), ["Sarge", "Grif"])
        self.assertFalse(self.state(self.grif)["leader"])
        self.assertEqual(self.parties.invites_for("grif"), [])
        self.parties.leave(self.grif)
        self.assertIsNone(self.state(self.grif))
        with self.assertRaises(party.Refused):
            self.parties.accept(self.grif, made["id"])  # (the invite was used)
        self.parties.leave(self.sarge)
        self.assertEqual(self.parties.parties, {})
        self.assertEqual(self.parties.by_code, {})

    def test_the_doorbell_rings_whom_a_change_is_news_to(self):
        rung = []
        self.parties.ring = lambda profile_ids, kind: rung.append((kind, sorted(profile_ids)))

        def rings():
            done = list(rung)
            rung.clear()
            return done

        made = self.parties.create(self.sarge)
        self.assertEqual(rings(), [])
        for other in (self.grif, self.simmons, self.donut):
            self.befriend(self.sarge, other)
        # (an invite: the friend invited; taking it: the others)
        self.parties.invite(self.sarge, "grif")
        self.assertEqual(rings(), [("party", ["grif"])])
        self.parties.accept(self.grif, made["id"])
        self.assertEqual(rings(), [("party", ["sarge"])])
        self.parties.join(self.simmons, made["code"])
        self.assertEqual(rings(), [("party", ["grif", "sarge"])])
        # (a member without a profile has no doorbell, and rings the others)
        self.parties.set_rule(self.sarge, "anyone")
        self.assertEqual(rings(), [("party", ["grif", "simmons"])])
        self.parties.set_rule(self.sarge, "anyone")
        self.assertEqual(rings(), [])
        self.parties.join(self.lopez, made["code"])
        self.assertEqual(rings(), [("party", ["grif", "sarge", "simmons"])])
        # (the leader's go: the members; the same game again rings nobody)
        self.parties.go(self.sarge, "ab" * 32)
        self.assertEqual(rings(), [("party", ["grif", "simmons"])])
        self.parties.go(self.sarge, "ab" * 32)
        self.assertEqual(rings(), [])
        self.parties.new_code(self.sarge)
        self.assertEqual(rings(), [("party", ["grif", "simmons"])])
        # (a kick: the one kicked too)
        simmons = [m["id"] for m in self.state(self.sarge)["members"] if m["player_id"] == "simmons"][0]
        self.parties.kick(self.sarge, simmons)
        self.assertEqual(rings(), [("party", ["grif", "simmons"])])
        grif = [m["id"] for m in self.state(self.sarge)["members"] if m["player_id"] == "grif"][0]
        self.parties.lead(self.sarge, grif)
        self.assertEqual(rings(), [("party", ["grif"])])
        # (leaving: those who stay; a decline and a refusal ring nobody)
        self.parties.leave(self.sarge)
        self.assertEqual(rings(), [("party", ["grif"])])
        self.befriend(self.grif, self.donut)
        self.parties.invite(self.grif, "donut")
        self.assertEqual(rings(), [("party", ["donut"])])
        self.parties.decline(self.donut, made["id"])
        with self.assertRaises(party.Refused):
            self.parties.invite(self.grif, "simmons")
        self.assertEqual(rings(), [])

    def test_decline_and_invites_expire(self):
        made = self.parties.create(self.sarge)
        self.befriend(self.sarge, self.grif)
        self.befriend(self.sarge, self.simmons)
        self.parties.invite(self.sarge, "grif")
        self.parties.invite(self.sarge, "simmons")
        self.parties.decline(self.grif, made["id"])
        self.assertEqual(self.parties.invites_for("grif"), [])
        self.clock.now += party.INVITE_LIFETIME + 1
        self.parties.touch(self.sarge)
        self.assertEqual(self.parties.invites_for("simmons"), [])

    def test_a_block_hides_as_not_friends(self):
        self.parties.create(self.sarge)
        self.befriend(self.sarge, self.grif)
        self.blocked.add(("grif", "sarge"))
        with self.assertRaises(party.Refused) as refused:
            self.parties.invite(self.sarge, "grif")
        self.assertEqual(refused.exception.reason, "friends_only")

    def test_codes_and_who_can_join(self):
        made = self.parties.create(self.sarge)
        code = made["code"]
        self.assertEqual(len(code), 6)
        self.assertTrue(all(c in party.CODE_LETTERS for c in code))
        # (friends, the default: a stranger and a copy with no profile are refused)
        with self.assertRaises(party.Refused) as refused:
            self.parties.join(self.grif, code)
        self.assertEqual(refused.exception.reason, "friends_only")
        with self.assertRaises(party.Refused):
            self.parties.join(self.lopez, code)
        self.befriend(self.sarge, self.grif)
        self.parties.join(self.grif, "halo://party/" + code.lower()[:3] + "-" + code.lower()[3:])
        self.assertEqual(self.names(self.sarge), ["Sarge", "Grif"])
        # (only the leader sets it)
        with self.assertRaises(party.Refused) as refused:
            self.parties.set_rule(self.grif, "anyone")
        self.assertEqual(refused.exception.reason, "not_leader")
        self.parties.set_rule(self.sarge, "anyone")
        self.parties.join(self.lopez, code)
        self.assertEqual(self.names(self.lopez), ["Sarge", "Grif", "Lopez"])
        self.assertEqual([m["player_id"] for m in self.state(self.lopez)["members"]], ["sarge", "grif", None])
        self.parties.set_rule(self.sarge, "invite")
        with self.assertRaises(party.Refused) as refused:
            self.parties.join(self.simmons, code)
        self.assertEqual(refused.exception.reason, "invite_only")
        # (an invite lets you in whatever the rule)
        self.befriend(self.grif, self.simmons)
        self.parties.invite(self.grif, "simmons")
        self.parties.join(self.simmons, code)
        self.assertIn("Simmons", self.names(self.sarge))
        with self.assertRaises(party.Refused) as refused:
            self.parties.join(self.donut, "ZZZZZZ")
        self.assertEqual(refused.exception.reason, "unknown")
        with self.assertRaises(party.Refused):
            self.parties.set_rule(self.sarge, "everyone")

    def test_wrong_codes_are_counted(self):
        for _ in range(party.WRONG_CODES_PER_HOUR):
            with self.assertRaises(party.Refused) as refused:
                self.parties.join(self.donut, "AAAAAA")
            self.assertEqual(refused.exception.reason, "unknown")
        with self.assertRaises(party.Refused) as refused:
            self.parties.join(self.donut, "AAAAAA")
        self.assertEqual(refused.exception.reason, "busy")

    def test_eight_at_most(self):
        made = self.parties.create(self.sarge)
        self.parties.set_rule(self.sarge, "anyone")
        for index in range(party.LARGEST - 1):
            self.parties.join(member("guest%d" % index, linked=False), made["code"])
        self.assertEqual(len(self.state(self.sarge)["members"]), party.LARGEST)
        with self.assertRaises(party.Refused) as refused:
            self.parties.join(self.grif, made["code"])
        self.assertEqual(refused.exception.reason, "full")
        self.befriend(self.sarge, self.grif)
        with self.assertRaises(party.Refused):
            self.parties.invite(self.sarge, "grif")

    def test_kick_lead_and_leader_leaving(self):
        made = self.parties.create(self.sarge)
        self.parties.set_rule(self.sarge, "anyone")
        for who in (self.grif, self.simmons, self.lopez):
            self.clock.now += 1
            self.parties.join(who, made["code"])
        ids = {m["name"]: m["id"] for m in self.state(self.sarge)["members"]}
        with self.assertRaises(party.Refused):
            self.parties.kick(self.grif, ids["Simmons"])  # (not the leader)
        self.parties.kick(self.sarge, ids["Lopez"])
        self.assertIsNone(self.state(self.lopez))
        with self.assertRaises(party.Refused) as refused:
            self.parties.join(self.lopez, made["code"])  # (kicked: invites only for a while)
        self.assertEqual(refused.exception.reason, "kicked")
        for _ in range(party.KICK_TIME // 100 + 1):
            self.clock.now += 100
            for who in (self.sarge, self.grif, self.simmons):
                self.parties.touch(who)
        self.parties.join(self.lopez, made["code"])
        self.parties.lead(self.sarge, ids["Simmons"])
        self.assertTrue(self.state(self.simmons)["leader"])
        self.assertEqual(self.state(self.sarge)["members"][0]["name"], "Simmons")
        with self.assertRaises(party.Refused):
            self.parties.set_rule(self.sarge, "invite")
        # (the leader leaves: the member who joined first leads)
        self.parties.leave(self.simmons)
        self.assertTrue(self.state(self.sarge)["leader"])

    def test_quiet_members_drop_out(self):
        made = self.parties.create(self.sarge)
        self.befriend(self.sarge, self.grif)
        self.parties.invite(self.sarge, "grif")
        self.parties.accept(self.grif, made["id"])
        self.clock.now += party.MEMBER_LIFETIME - 10
        self.parties.touch(self.grif)
        self.clock.now += 20
        # (the leader went quiet: Grif, invited, leads)
        self.assertEqual(self.names(self.grif), ["Grif"])
        self.assertTrue(self.state(self.grif)["leader"])
        self.clock.now += party.MEMBER_LIFETIME + 1
        self.assertIsNone(self.state(self.grif))
        self.assertEqual(self.parties.parties, {})

    def test_a_quiet_leader_never_hands_the_lead_to_the_code(self):
        made = self.parties.create(self.sarge)
        self.parties.set_rule(self.sarge, "anyone")
        self.parties.join(self.lopez, made["code"])
        self.clock.now += 1
        self.parties.join(self.grif, made["code"])
        self.clock.now += party.MEMBER_LIFETIME - 10
        self.parties.touch(self.lopez)
        self.parties.touch(self.grif)
        self.clock.now += 20
        # (Sarge went quiet; everyone left came in by the code: nobody leads)
        state = self.state(self.lopez)
        self.assertEqual(self.names(self.lopez), ["Lopez", "Grif"])
        self.assertFalse(state["has_leader"])
        self.assertFalse(any(m["leader"] for m in state["members"]))
        ids = {m["name"]: m["id"] for m in state["members"]}
        for refused_action in (lambda: self.parties.go(self.lopez, "ab" * 32),
                               lambda: self.parties.kick(self.lopez, ids["Grif"]),
                               lambda: self.parties.set_rule(self.lopez, "invite")):
            with self.assertRaises(party.Refused) as refused:
                refused_action()
            self.assertEqual(refused.exception.reason, "no_leader")
        # (nobody new comes in by the code while it has no leader)
        self.befriend(self.sarge, self.simmons)
        with self.assertRaises(party.Refused) as refused:
            self.parties.join(self.simmons, made["code"])
        self.assertEqual(refused.exception.reason, "no_leader")
        # (Sarge, back by the code, leads again)
        self.parties.join(self.sarge, made["code"])
        self.assertTrue(self.state(self.sarge)["leader"])
        self.assertTrue(self.state(self.lopez)["has_leader"])

    def test_a_leaderless_party_chooses(self):
        made = self.parties.create(self.sarge)
        self.parties.set_rule(self.sarge, "anyone")
        self.parties.join(self.lopez, made["code"])
        self.parties.join(self.grif, made["code"])
        self.parties.leave(self.sarge)
        ids = {m["name"]: m["id"] for m in self.state(self.lopez)["members"]}
        # (one vote is not every member's)
        self.parties.lead(self.lopez, ids["Lopez"])
        self.assertFalse(self.state(self.lopez)["has_leader"])
        self.parties.lead(self.grif, ids["Grif"])
        self.assertFalse(self.state(self.lopez)["has_leader"])
        self.parties.lead(self.grif, ids["Lopez"])
        self.assertTrue(self.state(self.lopez)["leader"])
        # (that leader, in by the code, leaves: nobody leads again; alone,
        # Grif's own vote is every member's)
        self.parties.leave(self.lopez)
        self.assertFalse(self.state(self.grif)["has_leader"])
        self.parties.lead(self.grif, ids["Grif"])
        self.assertTrue(self.state(self.grif)["leader"])

    def test_the_first_invited_member_leads_next(self):
        made = self.parties.create(self.sarge)
        self.parties.set_rule(self.sarge, "anyone")
        self.parties.join(self.lopez, made["code"])
        self.clock.now += 1
        self.befriend(self.sarge, self.grif)
        self.parties.invite(self.sarge, "grif")
        self.parties.accept(self.grif, made["id"])
        self.parties.leave(self.sarge)
        # (Lopez came in first, by the code; Grif, invited, leads)
        self.assertTrue(self.state(self.grif)["leader"])
        self.assertFalse(self.state(self.lopez)["leader"])

    def test_go_only_for_the_invited_and_friends(self):
        made = self.parties.create(self.sarge)
        self.parties.set_rule(self.sarge, "anyone")
        self.parties.join(self.lopez, made["code"])
        self.parties.join(self.donut, made["code"])
        self.befriend(self.sarge, self.grif)
        self.parties.join(self.grif, made["code"])
        self.parties.go(self.sarge, "ab" * 32)
        view = lambda invite, _: {"join": "halo://join/" + invite}
        # (strangers who came in by the code: told why, never the game)
        for stranger in (self.lopez, self.donut):
            go = self.parties.state_for(stranger, view)["go"]
            self.assertEqual(go["reason"], "invited")
            self.assertNotIn("join", go)
            self.assertNotIn("ab" * 32, repr(go))
        # (the leader's friend is given it)
        self.assertEqual(self.parties.state_for(self.grif, view)["go"]["join"], "halo://join/" + "ab" * 32)

    def test_new_code_and_a_kick_renew_the_code_and_tag(self):
        made = self.parties.create(self.sarge)
        self.parties.set_rule(self.sarge, "anyone")
        self.parties.join(self.lopez, made["code"])
        code, tag = made["code"], made["tag"]
        with self.assertRaises(party.Refused):
            self.parties.new_code(self.lopez)  # (not the leader)
        self.parties.new_code(self.sarge)
        self.assertNotEqual(made["code"], code)
        self.assertNotEqual(made["tag"], tag)
        with self.assertRaises(party.Refused) as refused:
            self.parties.join(self.grif, code)
        self.assertEqual(refused.exception.reason, "unknown")
        code, tag = made["code"], made["tag"]
        lopez = [m["id"] for m in self.state(self.sarge)["members"] if m["name"] == "Lopez"][0]
        self.parties.kick(self.sarge, lopez)
        self.assertNotEqual(made["code"], code)
        self.assertNotEqual(made["tag"], tag)
        self.assertEqual(self.state(self.sarge)["code"], made["code"])
        for _ in range(party.NEW_CODES_PER_HOUR - 1):
            self.parties.new_code(self.sarge)
        with self.assertRaises(party.Refused) as refused:
            self.parties.new_code(self.sarge)
        self.assertEqual(refused.exception.reason, "busy")

    def test_blocks_count_for_every_member(self):
        made = self.parties.create(self.sarge)
        self.parties.set_rule(self.sarge, "anyone")
        self.parties.join(self.grif, made["code"])
        # (Grif, a member but not the leader, blocks Simmons)
        self.blocked.add(("grif", "simmons"))
        with self.assertRaises(party.Refused) as refused:
            self.parties.join(self.simmons, made["code"])
        self.assertEqual(refused.exception.reason, "friends_only")
        self.befriend(self.sarge, self.simmons)
        self.parties.invite(self.sarge, "simmons")
        with self.assertRaises(party.Refused) as refused:
            self.parties.accept(self.simmons, made["id"])
        self.assertEqual(refused.exception.reason, "gone")
        # (and the other way: Donut blocks a member)
        self.blocked.add(("donut", "grif"))
        with self.assertRaises(party.Refused):
            self.parties.join(self.donut, made["code"])
        self.blocked.clear()
        self.parties.join(self.donut, made["code"])

    def test_counted_per_address(self):
        # (a fresh copy key each try: the address still counts them)
        for index in range(party.WRONG_CODES_PER_ADDRESS):
            who = dict(member("copy%d" % index, linked=False), address="198.51.100.7")
            with self.assertRaises(party.Refused) as refused:
                self.parties.join(who, "AAAAAA")
            self.assertEqual(refused.exception.reason, "unknown")
        who = dict(member("copy-last", linked=False), address="198.51.100.7")
        with self.assertRaises(party.Refused) as refused:
            self.parties.join(who, "AAAAAA")
        self.assertEqual(refused.exception.reason, "busy")
        # (no address is kept, only its hash)
        self.assertFalse(any("198.51.100.7" in key for key in self.parties.counts))
        for index in range(party.PARTIES_PER_ADDRESS):
            self.parties.create(dict(member("maker%d" % index, linked=False), address="203.0.113.9"))
        with self.assertRaises(party.Refused) as refused:
            self.parties.create(dict(member("maker-last", linked=False), address="203.0.113.9"))
        self.assertEqual(refused.exception.reason, "busy")
        # (and per member)
        for _ in range(party.PARTIES_PER_HOUR):
            self.parties.create(self.donut)
            self.parties.leave(self.donut)
        with self.assertRaises(party.Refused) as refused:
            self.parties.create(self.donut)
        self.assertEqual(refused.exception.reason, "busy")

    def test_names_lose_the_verified_mark(self):
        self.assertEqual(party.clean_name("@Milenko"), "Milenko")
        self.assertEqual(party.clean_name(" @ .@Tex"), "Tex")

    def test_go(self):
        made = self.parties.create(self.sarge)
        self.befriend(self.sarge, self.grif)
        self.parties.join(self.grif, made["code"])
        with self.assertRaises(party.Refused):
            self.parties.go(self.grif, "ab" * 32)
        first = self.parties.go(self.sarge, "ab" * 32)
        view = lambda invite, _: {"join": "halo://join/" + invite}
        go = self.parties.state_for(self.grif, view)["go"]
        self.assertEqual((go["serial"], go["join"]), (first, "halo://join/" + "ab" * 32))
        # (the leader's own answer has none)
        self.assertIsNone(self.parties.state_for(self.sarge, view)["go"])
        # (the same game again keeps its serial; a new one is a new go)
        self.assertEqual(self.parties.go(self.sarge, "ab" * 32), first)
        second = self.parties.go(self.sarge, "cd" * 32)
        self.assertGreater(second, first)
        self.clock.now += party.GO_LIFETIME + 1
        self.parties.touch(self.sarge)
        self.parties.touch(self.grif)
        self.assertIsNone(self.parties.state_for(self.grif, view)["go"])

    def test_forget(self):
        made = self.parties.create(self.sarge)
        self.befriend(self.sarge, self.grif)
        self.parties.invite(self.sarge, "grif")
        self.parties.forget("grif")
        self.assertEqual(self.parties.invites_for("grif"), [])
        self.parties.forget("sarge")
        self.assertNotIn(made["id"], self.parties.parties)

    def test_codes_cleaned(self):
        self.assertEqual(party.clean_code("abc-def"), "ABCDEF")
        self.assertEqual(party.clean_code("halo://party/ABCDEF/"), "ABCDEF")
        self.assertEqual(party.clean_code("ABCDE"), "")
        self.assertEqual(party.clean_code("ABC/DEF"), "")
        self.assertEqual(party.clean_name("Lo\x00pez\n" + "x" * 40), "Lopez" + "x" * 19)


if __name__ == "__main__":
    unittest.main()
