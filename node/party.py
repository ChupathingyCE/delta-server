"""Parties (list_server.py's /v1/party and /v1/social/state): a few players
who play together. The leader's game is where the party goes: when the
leader joins or hosts a game, their copy says so ("go"), and the members'
copies follow.

Kept in memory only, never in a database: a party is gone when its last
member leaves, or when no member's copy has asked for anything for
MEMBER_LIFETIME seconds. No address is kept or answered; members are named
by their Delta profile (handle and name) or, for a copy linked to no
profile, by the game name it sends.

    party   {"id", "code", "tag", "leader" (a member key), "members"
             {member key: {"id", "player_id" (None: no profile), "name",
             "platform", "joined", "seen"}}, "rule", "invites" {profile
             ID: (sent, from profile ID)}, "kicked" {member key: when},
             "go" {"serial", "invite", "time"} or None, "serial"}

A member key is "p:" and the profile ID for a copy linked to a profile,
else "c:" and the copy's ID (the player key's): one party at a time each.

- **Size:** LARGEST members (the leader too). A party of one is the leader
  waiting for the others.
- **Joining:** by an invite (a member's, to a friend of theirs, signed in;
  it lasts INVITE_LIFETIME seconds), or by the party's code (6 letters and
  digits, as halo://party/CODE). The party's "who can join" says who the
  code lets in: "anyone", "friends" (signed in, a friend of the leader's;
  the default) or "invite" (nobody: invites only). A player the leader
  kicked out can come back only by an invite for KICK_TIME seconds.
- **Blocks:** a player who blocks, or is blocked by, any member can't join
  (by code or invite); it shows as any other refusal, so a block never shows.
- **The leader** kicks members, passes the lead on, sets who can join, makes
  a new code and says where the party goes. A kick makes a new code and tag
  too. A leader who leaves or whose copy goes quiet passes the lead to the
  member who came in first by an invite (or who started the party); when
  every other member came in by the code, nobody leads until the leader
  comes back (by the code, whatever its "who can join") or the members
  choose: a leaderless party's "lead" is a vote, and the member every member
  votes for leads.
- **Go:** the leader's game's invite. Each member's answer has it for
  GO_LIFETIME seconds, as list_server.py checks it for them (the join link,
  or why they can't follow). Only members who came in by an invite (or
  started the party) and the leader's friends are given it: a stranger who
  joined an "anyone" party by its code is told they can't follow.
- **Tag:** 8 random bytes a party's members send their game's host (Delta
  Peer's party_teams, docs/delta.md) so that a host may keep them on one
  team. It names no one; a new party has a new one, and a kick or a new code
  makes a new one.
- **Counted:** wrong codes and new parties per member and, more loosely,
  per address (by a hash of it, in memory for an hour; the address itself
  is never kept).
- **The doorbell** (doorbell.py): ring(profile IDs, "party") for the
  profiles a change is news to, so their copies ask at once instead of on
  their next poll: an invite rings the friend invited; a member coming in,
  leaving or kicked out, a new leader, rule or code, and the leader's go
  ring the other members (and the one kicked). Only members with a
  profile have a doorbell; a decline and a quiet member dropping out ring
  nobody.

SPDX-FileCopyrightText: 2026 The Chupathingy contributors
SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: GPL-3.0-or-later
"""

import hashlib
import re
import secrets
import threading
import time

LARGEST = 8
MEMBER_LIFETIME = 300  # (the game asks every 15 s in the menus with a party, 60 s in a game)
INVITE_LIFETIME = 300
GO_LIFETIME = 120
KICK_TIME = 600
INVITES_PER_MINUTE = 10
WRONG_CODES_PER_HOUR = 20
WRONG_CODES_PER_ADDRESS = 60  # an hour (players share addresses)
PARTIES_PER_HOUR = 20  # made by one member
PARTIES_PER_ADDRESS = 100  # an hour
NEW_CODES_PER_HOUR = 10
MOST_PARTIES = 20000
NAME_SIZE = 24
JOIN_RULES = ("anyone", "friends", "invite")
DEFAULT_RULE = "friends"
# (no 0, O, 1, I or L: read aloud and typed on a pad)
CODE_LETTERS = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
CODE_SIZE = 6
CODE = re.compile(r"^[A-Z0-9]{6}$")
MEMBER_ID = re.compile(r"^[0-9a-f]{8}$")
PARTY_ID = re.compile(r"^[0-9a-f]{16}$")


class Refused(Exception):
    """what the rules don't allow: its HTTP status, words and reason"""

    def __init__(self, status: int, message: str, reason: str = ""):
        super().__init__(message)
        self.status = status
        self.message = message
        self.reason = reason


def clean_code(text) -> str:
    """a code as typed or linked ("abc-def", "halo://party/ABCDEF/") in its
    6 capitals, or "" if it can't be one"""
    text = str(text or "").strip()
    if text.lower().startswith("halo://party/"):
        text = text[len("halo://party/"):]
    text = text.strip("/").replace("-", "").replace(" ", "").upper()
    return text if CODE.match(text) else ""


def clean_name(text) -> str:
    """a game name as a member without a profile sends it: printable, cut
    at NAME_SIZE characters"""
    text = "".join(c for c in str(text or "") if c.isprintable()).strip()
    # (no "@" at its front: that's the mark of a verified handle)
    return text.lstrip("@ .")[:NAME_SIZE]


class Parties:
    """every party, in memory. are_friends(a, b) and blocks(owner, other)
    take profile IDs (friends.py's)"""

    def __init__(self, are_friends=lambda a, b: False, blocks=lambda a, b: False, clock=time.time):
        self.are_friends = are_friends
        self.blocks = blocks
        self.clock = clock
        self.lock = threading.Lock()
        self.parties = {}  # party ID -> party
        self.of_member = {}  # member key -> party ID
        self.by_code = {}  # code -> party ID
        self.counts = {}  # "invite:" or "code:" + member key -> [times]
        # the doorbell (list_server.py sets it): ring(profile IDs, kind),
        # called outside the lock
        self.ring = lambda profile_ids, kind: None

    # ---------- inside the lock

    def _count(self, key: str, window: int, most: int) -> bool:
        now = self.clock()
        times = [t for t in self.counts.get(key, ()) if now - t < window]
        if len(times) >= most:
            self.counts[key] = times
            return False
        times.append(now)
        self.counts[key] = times
        if len(self.counts) > 50000:
            for stale in [k for k, v in self.counts.items() if not v or now - v[-1] > 3600]:
                del self.counts[stale]
        return True

    def _count_address(self, kind: str, member: dict, most: int) -> bool:
        """counted per address (a hash of it) as well; True with none"""
        address = member.get("address")
        if not address:
            return True
        hashed = hashlib.sha256(("party:" + str(address)).encode()).hexdigest()[:16]
        return self._count(kind + "-address:" + hashed, 3600, most)

    def _new_code(self) -> str:
        while True:
            code = "".join(secrets.choice(CODE_LETTERS) for _ in range(CODE_SIZE))
            if code not in self.by_code:
                return code

    def _renew_code(self, party: dict):
        """a new code and tag (the old code lets nobody in)"""
        self.by_code.pop(party["code"], None)
        party["code"] = self._new_code()
        party["tag"] = secrets.token_hex(8)
        self.by_code[party["code"]] = party["id"]

    def _drop_member(self, party: dict, key: str):
        party["members"].pop(key, None)
        self.of_member.pop(key, None)
        if not party["members"]:
            self.parties.pop(party["id"], None)
            self.by_code.pop(party["code"], None)
            return
        party["votes"].pop(key, None)
        for voter in [v for v, chosen in party["votes"].items() if chosen == key]:
            del party["votes"][voter]
        if party["leader"] == key:
            # (the member who came in first by an invite: never one who came
            # in by the code alone, who may be a stranger; none, nobody leads)
            trusted = [k for k, m in party["members"].items() if m["via"] in ("create", "invite")]
            party["leader"] = min(trusted, key=lambda k: party["members"][k]["joined"]) if trusted else None
            party["away"] = None if trusted else key
            party["votes"] = {}
            party["go"] = None
        self._count_votes(party)
        party["serial"] += 1

    def _count_votes(self, party: dict):
        """a leaderless party: the member every member voted for leads"""
        if party["leader"] is not None or not party["votes"]:
            return
        chosen = set(party["votes"].values())
        if len(chosen) == 1 and set(party["votes"]) == set(party["members"]):
            party["leader"] = chosen.pop()
            party["away"] = None
            party["votes"] = {}

    def _expire(self):
        now = self.clock()
        for party in list(self.parties.values()):
            for key in [k for k, m in party["members"].items() if now - m["seen"] > MEMBER_LIFETIME]:
                self._drop_member(party, key)
            if party["id"] not in self.parties:
                continue
            for player_id in [p for p, (sent, _) in party["invites"].items() if now - sent > INVITE_LIFETIME]:
                del party["invites"][player_id]
            for key in [k for k, when in party["kicked"].items() if now - when > KICK_TIME]:
                del party["kicked"][key]
            if party["go"] and now - party["go"]["time"] > GO_LIFETIME:
                party["go"] = None

    @staticmethod
    def _profiles(party, but: str = "") -> list:
        """the profile IDs of a party's members (but one member key): who
        the doorbell rings"""
        if not party:
            return []
        return [m["player_id"] for key, m in party["members"].items() if m["player_id"] and key != but]

    def _rung(self, profile_ids):
        """the doorbell rung for these profiles (outside the lock)"""
        profile_ids = [p for p in dict.fromkeys(profile_ids) if p]
        if profile_ids:
            self.ring(profile_ids, "party")

    def _party_of(self, key: str) -> dict:
        party_id = self.of_member.get(key)
        return self.parties.get(party_id) if party_id else None

    def _member(self, member: dict, via: str) -> dict:
        now = self.clock()
        return {"id": secrets.token_hex(4), "player_id": member.get("player_id"),
                "name": clean_name(member.get("name")) or "Player", "platform": member.get("platform") or "unknown",
                "joined": now, "seen": now, "via": via}

    def _blocked(self, party: dict, player_id) -> bool:
        """whether a player blocks, or is blocked by, any member"""
        if not player_id:
            return False
        for entry in party["members"].values():
            other = entry["player_id"]
            if other and other != player_id and (self.blocks(other, player_id) or self.blocks(player_id, other)):
                return True
        return False

    def _follows(self, party: dict, key: str) -> bool:
        """whether a member is given the leader's game: in by an invite (or
        the party's starter), or the leader's friend"""
        entry = party["members"].get(key)
        if not entry or party["leader"] is None:
            return False
        if entry["via"] in ("create", "invite"):
            return True
        leader_id = party["members"][party["leader"]]["player_id"]
        return bool(entry["player_id"] and leader_id and self.are_friends(leader_id, entry["player_id"]))

    def _add(self, party: dict, member: dict, via: str):
        if len(party["members"]) >= LARGEST:
            raise Refused(409, "The party is full.", "full")
        entry = self._member(member, via)
        # (a member ID unique in its party)
        while any(m["id"] == entry["id"] for m in party["members"].values()):
            entry["id"] = secrets.token_hex(4)
        party["members"][member["key"]] = entry
        self.of_member[member["key"]] = party["id"]
        if member.get("player_id"):
            party["invites"].pop(member["player_id"], None)
        party["kicked"].pop(member["key"], None)
        # (the leader who went quiet, back: leads again)
        if party["leader"] is None and party.get("away") == member["key"]:
            party["leader"] = member["key"]
            party["away"] = None
            party["votes"] = {}
        party["serial"] += 1

    def _leader(self, member: dict) -> dict:
        party = self._party_of(member["key"])
        if not party:
            raise Refused(404, "You're not in a party.", "no_party")
        if party["leader"] is None:
            raise Refused(403, "The party has no leader right now.", "no_leader")
        if party["leader"] != member["key"]:
            raise Refused(403, "Only the party leader can do that.", "not_leader")
        return party

    def _by_member_id(self, party: dict, member_id: str) -> str:
        for key, entry in party["members"].items():
            if entry["id"] == member_id:
                return key
        raise Refused(404, "They're not in the party.", "no_member")

    # ---------- what a copy asks (member: {"key", "player_id" or None,
    # "name", "platform"}); each raises Refused

    def touch(self, member: dict):
        """a member's copy asked: still here (its name and platform kept up)"""
        with self.lock:
            self._expire()
            party = self._party_of(member["key"])
            if not party:
                return
            entry = party["members"][member["key"]]
            entry["seen"] = self.clock()
            name = clean_name(member.get("name"))
            platform = member.get("platform") or entry["platform"]
            if (name and name != entry["name"]) or platform != entry["platform"]:
                entry["name"] = name or entry["name"]
                entry["platform"] = platform
                party["serial"] += 1

    def create(self, member: dict) -> dict:
        with self.lock:
            self._expire()
            if self._party_of(member["key"]):
                raise Refused(409, "You're in a party already.", "in_party")
            if len(self.parties) >= MOST_PARTIES:
                raise Refused(503, "Parties are full right now. Try again later.", "busy")
            if not self._count("create:" + member["key"], 3600, PARTIES_PER_HOUR) or \
                    not self._count_address("create", member, PARTIES_PER_ADDRESS):
                raise Refused(429, "Too many new parties. Try again later.", "busy")
            party = {"id": secrets.token_hex(8), "code": self._new_code(), "tag": secrets.token_hex(8),
                     "leader": member["key"], "members": {}, "rule": DEFAULT_RULE, "invites": {}, "kicked": {},
                     "go": None, "serial": 0, "away": None, "votes": {}}
            self.parties[party["id"]] = party
            self.by_code[party["code"]] = party["id"]
            self._add(party, member, "create")
            return party

    def invite(self, member: dict, to_player_id: str):
        """a member's friend (both signed in; the caller has found them by
        handle) invited. Only to a friend who doesn't block you: refused as
        any other non-friend otherwise, so a block never shows"""
        with self.lock:
            self._expire()
            party = self._party_of(member["key"])
            if not party:
                raise Refused(404, "You're not in a party.", "no_party")
            if not member.get("player_id"):
                raise Refused(403, "Sign in to invite friends.", "signed_out")
            if to_player_id == member["player_id"]:
                raise Refused(400, "That's you.", "you")
            if not self.are_friends(member["player_id"], to_player_id) or self.blocks(to_player_id, member["player_id"]):
                raise Refused(403, "You can invite friends only.", "friends_only")
            if self.of_member.get("p:" + to_player_id) == party["id"]:
                raise Refused(409, "They're in the party already.", "member")
            if len(party["members"]) >= LARGEST:
                raise Refused(409, "The party is full.", "full")
            if not self._count("invite:" + member["key"], 60, INVITES_PER_MINUTE):
                raise Refused(429, "Too many invites. Try again in a minute.", "busy")
            party["invites"][to_player_id] = (self.clock(), member["player_id"])
        self._rung([to_player_id])

    def accept(self, member: dict, party_id: str) -> dict:
        """an invite taken: the party joined (any other one left)"""
        with self.lock:
            self._expire()
            party = self.parties.get(party_id)
            if not party or not member.get("player_id") or member["player_id"] not in party["invites"]:
                raise Refused(404, "That invite is gone.", "gone")
            if self.of_member.get(member["key"]) == party_id:
                return party
            if self._blocked(party, member["player_id"]):
                raise Refused(404, "That invite is gone.", "gone")
            if len(party["members"]) >= LARGEST:
                raise Refused(409, "The party is full.", "full")
            old = self._party_of(member["key"])
            if old:
                self._drop_member(old, member["key"])
            self._add(party, member, "invite")
            rung = self._profiles(old) + self._profiles(party, member["key"])
        self._rung(rung)
        return party

    def decline(self, member: dict, party_id: str):
        with self.lock:
            party = self.parties.get(party_id)
            if party and member.get("player_id"):
                party["invites"].pop(member["player_id"], None)

    def join(self, member: dict, code: str) -> dict:
        """the party of a code joined, as its "who can join" allows (an
        invite to it always does)"""
        code = clean_code(code)
        with self.lock:
            self._expire()
            party = self.parties.get(self.by_code.get(code, ""))
            if not party:
                # (per member, and per address: a copy's key is cheap to make)
                if not self._count("code:" + member["key"], 3600, WRONG_CODES_PER_HOUR) or \
                        not self._count_address("code", member, WRONG_CODES_PER_ADDRESS):
                    raise Refused(429, "Too many tries. Try again later.", "busy")
                raise Refused(404, "No party has that code.", "unknown")
            if self.of_member.get(member["key"]) == party["id"]:
                return party
            player_id = member.get("player_id")
            invited = bool(player_id) and player_id in party["invites"]
            returning = party["leader"] is None and party.get("away") == member["key"]
            if not invited and not returning:
                if party["leader"] is None:
                    raise Refused(403, "The party has no leader right now.", "no_leader")
                leader_id = party["members"][party["leader"]]["player_id"]
                if party["rule"] == "invite":
                    raise Refused(403, "This party takes invited players only.", "invite_only")
                if member["key"] in party["kicked"]:
                    raise Refused(403, "The leader took you out of this party.", "kicked")
                if party["rule"] == "friends" and not (player_id and leader_id and self.are_friends(leader_id, player_id)):
                    raise Refused(403, "Only the leader's friends can join this party.", "friends_only")
            if self._blocked(party, player_id):
                raise Refused(403, "Only the leader's friends can join this party.", "friends_only")
            if len(party["members"]) >= LARGEST:
                raise Refused(409, "The party is full.", "full")
            old = self._party_of(member["key"])
            if old:
                self._drop_member(old, member["key"])
            self._add(party, member, "invite" if invited else "code")
            rung = self._profiles(old) + self._profiles(party, member["key"])
        self._rung(rung)
        return party

    def leave(self, member: dict):
        with self.lock:
            party = self._party_of(member["key"])
            if party:
                self._drop_member(party, member["key"])
            rung = self._profiles(party)
        self._rung(rung)

    def kick(self, member: dict, member_id: str):
        with self.lock:
            self._expire()
            party = self._leader(member)
            key = self._by_member_id(party, str(member_id))
            if key == member["key"]:
                raise Refused(400, "That's you.", "you")
            kicked = party["members"][key]["player_id"]
            self._drop_member(party, key)
            party["kicked"][key] = self.clock()
            # (the code and tag they knew, gone)
            self._renew_code(party)
            rung = [kicked] + self._profiles(party, member["key"])
        self._rung(rung)

    def new_code(self, member: dict):
        """the leader's: a new code (and tag), the old one letting nobody in"""
        with self.lock:
            self._expire()
            party = self._leader(member)
            if not self._count("new_code:" + member["key"], 3600, NEW_CODES_PER_HOUR):
                raise Refused(429, "Too many new codes. Try again later.", "busy")
            self._renew_code(party)
            party["serial"] += 1
            rung = self._profiles(party, member["key"])
        self._rung(rung)

    def lead(self, member: dict, member_id: str):
        """the lead passed to another member; in a leaderless party, a vote
        for who leads (their own too)"""
        with self.lock:
            self._expire()
            party = self._party_of(member["key"])
            if party and party["leader"] is None:
                key = self._by_member_id(party, str(member_id))
                party["votes"][member["key"]] = key
                self._count_votes(party)
                party["serial"] += 1
                rung = self._profiles(party, member["key"])
            else:
                party = self._leader(member)
                key = self._by_member_id(party, str(member_id))
                rung = []
                if key != party["leader"]:
                    party["leader"] = key
                    party["go"] = None
                    party["serial"] += 1
                    rung = self._profiles(party, member["key"])
        self._rung(rung)

    def set_rule(self, member: dict, rule: str):
        if rule not in JOIN_RULES:
            raise Refused(400, "Who can join is anyone, friends or invited players.", "bad")
        with self.lock:
            self._expire()
            party = self._leader(member)
            rung = []
            if party["rule"] != rule:
                party["rule"] = rule
                party["serial"] += 1
                rung = self._profiles(party, member["key"])
        self._rung(rung)

    def go(self, member: dict, invite: str) -> int:
        """the leader's game (its invite, checked by the caller): its serial.
        The same game again keeps its serial (members who stayed aren't
        asked again), only its time renewed"""
        with self.lock:
            self._expire()
            party = self._leader(member)
            if party["go"] and party["go"]["invite"] == invite:
                party["go"]["time"] = self.clock()
                return party["go"]["serial"]
            serial = party["go"]["serial"] + 1 if party["go"] else party["serial"] + 1
            party["go"] = {"serial": serial, "invite": invite, "time": self.clock()}
            party["serial"] += 1
            rung = self._profiles(party, member["key"])
        self._rung(rung)
        return serial

    def forget(self, player_id: str):
        """a profile deleted: out of its party, its invites gone"""
        with self.lock:
            party = self._party_of("p:" + player_id)
            if party:
                self._drop_member(party, "p:" + player_id)
            for party in self.parties.values():
                party["invites"].pop(player_id, None)

    # ---------- answers

    def state_for(self, member: dict, go_view=None):
        """a member's view of their party, or None: {"id", "code", "link",
        "leader" (whether they lead), "who_can_join", "largest", "members"
        [{"id", "name", "handle" (the caller fills it), "platform", "leader",
        "you"}], "tag", "go"}. go_view(invite, party) makes the go's
        answer for the member (the leader's own has none)"""
        with self.lock:
            self._expire()
            party = self._party_of(member["key"])
            if not party:
                return None
            members = sorted(party["members"].items(), key=lambda item: (item[0] != party["leader"], item[1]["joined"]))
            answer = {"id": party["id"], "code": party["code"], "link": "halo://party/" + party["code"],
                      "leader": party["leader"] == member["key"], "who_can_join": party["rule"], "largest": LARGEST,
                      "members": [{"id": entry["id"], "player_id": entry["player_id"], "name": entry["name"],
                                   "platform": entry["platform"], "leader": key == party["leader"],
                                   "you": key == member["key"]} for key, entry in members],
                      "tag": party["tag"], "go": None, "has_leader": party["leader"] is not None}
            go = dict(party["go"]) if party["go"] else None
            follows = self._follows(party, member["key"])
        if go and not answer["leader"] and not follows:
            answer["go"] = {"serial": go["serial"], "time": int(go["time"]), "game": None, "reason": "invited",
                            "error": "Can't follow: only invited players and the leader's friends follow."}
        elif go and not answer["leader"] and go_view:
            answer["go"] = dict(go_view(go["invite"], answer), serial=go["serial"], time=int(go["time"]))
        return answer

    def invites_for(self, player_id: str) -> list:
        """the party invites waiting for a profile, newest first: [{"party",
        "from" (the inviter's profile ID), "size", "time", "expires"}]"""
        found = []
        with self.lock:
            self._expire()
            mine = self.of_member.get("p:" + player_id)
            for party in self.parties.values():
                if player_id in party["invites"] and party["id"] != mine:
                    sent, sender = party["invites"][player_id]
                    found.append({"party": party["id"], "from": sender, "size": len(party["members"]),
                                  "time": int(sent), "expires": int(sent + INVITE_LIFETIME)})
        return sorted(found, key=lambda i: -i["time"])
