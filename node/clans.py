"""Clans (list_server.py): groups of Delta profiles, with a name, a short
tag, a motto, an emblem and ranked members.

A clan (the clans table) has a name (CLAN_NAME_LENGTH at most), a tag
(TAG_PATTERN: letters and digits, unique, any case), a motto and an
emblem: a background shape in one color and a foreground shape in two,
from EMBLEM_BACKGROUNDS, EMBLEM_FOREGROUNDS and Halo's 18 armor colors
(EMBLEM_COLORS). The game draws the same pieces (the game's
port/linux/src/clan_emblem.c, made from this file's by its
tools/clan_emblem_table.py): a change to a piece here is a change there.

Members (clan_members) are profiles, one clan each, ranked leader (one),
officer or member:

    leader      everything: name, tag, motto, emblem, invites, ranks,
                kicking anyone, handing the clan to another member
    officer     motto, emblem, invites, kicking members
    member      leaving

A clan's leader leaves only when alone (the clan goes with them), or once
another member leads. Invites (clan_invites) are by handle, kept
INVITE_LIFETIME, and taken back when the player joins a clan.

Privacy: membership is the player's own choice (an invite they accepted).
An invite from someone the player blocks (blocks(owner, other), friends.py's)
is silent, as a friend request is: the inviter sees it waiting, the player
never sees it and can't take it.
A member who hides their service record is left out of the member lists
others see (counted as hidden); their tag shows only while "show_tag" is
on (clan_tag_hidden). Names, tags and mottos pass blocked_names; a locked
profile shows in no list. No address in any answer, and no player ID but
public_tags' (the IDs the pages already link service records by).

SPDX-FileCopyrightText: 2026 The Chupathingy contributors
SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: GPL-3.0-or-later
"""

import json
import math
import re
import time

import blocked_names

CLAN_NAME_LENGTH = 32
MOTTO_LENGTH = 64
TAG_PATTERN = re.compile(r"^[A-Za-z0-9]{2,8}$")
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 '.&_-]{1,31}$")
RANKS = ("leader", "officer", "member")
CLAN_MEMBERS = 50  # members in a clan, at most
CLAN_INVITES = 50  # a clan's invites waiting, at most
PLAYER_INVITES = 20  # invites a player may have waiting, at most
INVITE_LIFETIME = 30 * 86400

# Halo's armor colors, in the game's order (a profile's color index): name
# and the color the site and the game draw an emblem with
EMBLEM_COLORS = (
    ("White", "#e8e8e8"), ("Black", "#1c1c20"), ("Red", "#c42424"), ("Blue", "#2c50d2"), ("Gray", "#7c7c80"),
    ("Yellow", "#e6d020"), ("Green", "#2e9e36"), ("Pink", "#f07db4"), ("Purple", "#7e32b0"), ("Cyan", "#30d4e6"),
    ("Cobalt", "#3b5fa8"), ("Orange", "#ee7a22"), ("Teal", "#1e8c82"), ("Sage", "#6e8c5a"), ("Brown", "#6e4a28"),
    ("Tan", "#c8a878"), ("Maroon", "#781e32"), ("Salmon", "#f09c80"),
)


def _ring(cx, cy, r, sides, start=-90.0):
    return [(round(cx + r * math.cos(math.radians(start + 360.0 * i / sides)), 1),
             round(cy + r * math.sin(math.radians(start + 360.0 * i / sides)), 1)) for i in range(sides)]


def _star(cx, cy, outer, inner, points=5):
    out = []
    for i in range(points * 2):
        r = outer if i % 2 == 0 else inner
        angle = math.radians(-90.0 + 180.0 * i / points)
        out.append((round(cx + r * math.cos(angle), 1), round(cy + r * math.sin(angle), 1)))
    return out


# the pieces, on a 100 by 100 field: each a list of parts, a part (layer,
# [polygons]) filled even-odd (a polygon inside another makes a hole). A
# background's parts take the background color (layer 3); a foreground's,
# the primary (1) or secondary (2) color
EMBLEM_BACKGROUNDS = (
    ("Shield", [(3, [[(50, 4), (92, 16), (90, 52), (82, 72), (68, 86), (50, 96), (32, 86), (18, 72), (10, 52),
                     (8, 16)]])]),
    ("Circle", [(3, [_ring(50, 50, 46, 40)])]),
    ("Square", [(3, [[(8, 8), (92, 8), (92, 92), (8, 92)]])]),
    ("Diamond", [(3, [[(50, 3), (97, 50), (50, 97), (3, 50)]])]),
    ("Hexagon", [(3, [_ring(50, 50, 47, 6, 0)])]),
    ("Octagon", [(3, [_ring(50, 50, 47, 8, 22.5)])]),
    ("Triangle", [(3, [[(50, 5), (96, 90), (4, 90)]])]),
    ("Banner", [(3, [[(14, 4), (86, 4), (86, 96), (50, 78), (14, 96)]])]),
    ("Ring", [(3, [_ring(50, 50, 47, 40), _ring(50, 50, 37, 40)])]),
    ("None", []),
)
EMBLEM_FOREGROUNDS = (
    ("Chevrons", [(1, [[(22, 28), (50, 46), (78, 28), (78, 42), (50, 60), (22, 42)]]),
                  (2, [[(28, 56), (50, 70), (72, 56), (72, 66), (50, 80), (28, 66)]])]),
    ("Star", [(1, [_star(50, 50, 38, 16)]), (2, [_ring(50, 52, 8, 20)])]),
    ("Bolt", [(1, [[(58, 8), (28, 54), (46, 54), (38, 92), (72, 40), (54, 40), (64, 8)]])]),
    ("Cross", [(1, [[(40, 14), (60, 14), (60, 40), (86, 40), (86, 60), (60, 60), (60, 86), (40, 86), (40, 60),
                     (14, 60), (14, 40), (40, 40)]]),
               (2, [[(44, 44), (56, 44), (56, 56), (44, 56)]])]),
    ("Arrow", [(1, [[(50, 10), (82, 46), (62, 46), (62, 90), (38, 90), (38, 46), (18, 46)]])]),
    ("Target", [(1, [_ring(50, 50, 36, 36), _ring(50, 50, 26, 36)]), (2, [_ring(50, 50, 12, 24)])]),
    ("Crosshair", [(1, [_ring(50, 50, 34, 36), _ring(50, 50, 28, 36)]),
                   (2, [[(47, 8), (53, 8), (53, 36), (47, 36)], [(47, 64), (53, 64), (53, 92), (47, 92)],
                        [(8, 47), (36, 47), (36, 53), (8, 53)], [(64, 47), (92, 47), (92, 53), (64, 53)]])]),
    ("Wings", [(1, [[(46, 40), (6, 26), (14, 40), (8, 46), (18, 54), (14, 62), (46, 58)],
                    [(54, 40), (94, 26), (86, 40), (92, 46), (82, 54), (86, 62), (54, 58)]]),
               (2, [[(50, 34), (58, 48), (50, 66), (42, 48)]])]),
    ("Sword", [(1, [[(46, 10), (50, 4), (54, 10), (54, 66), (46, 66)]]),
               (2, [[(32, 66), (68, 66), (68, 72), (32, 72)], [(46, 72), (54, 72), (54, 88), (46, 88)],
                    _ring(50, 92, 5, 16)])]),
    ("Delta", [(1, [[(50, 12), (88, 82), (12, 82)], [(50, 34), (70, 72), (30, 72)]]),
               (2, [[(50, 46), (60, 66), (40, 66)]])]),
    ("Skull", [(1, [_ring(50, 42, 28, 32), [(34, 58), (66, 58), (64, 82), (36, 82)],
                    [(36, 36), (46, 36), (46, 48), (36, 48)], [(54, 36), (64, 36), (64, 48), (54, 48)]]),
               (2, [[(50, 52), (54, 60), (46, 60)], [(42, 70), (45, 70), (45, 80), (42, 80)],
                    [(48.5, 70), (51.5, 70), (51.5, 80), (48.5, 80)], [(55, 70), (58, 70), (58, 80), (55, 80)]])]),
    ("Bars", [(1, [[(18, 20), (82, 20), (82, 34), (18, 34)], [(18, 62), (82, 62), (82, 76), (18, 76)]]),
              (2, [[(18, 41), (82, 41), (82, 55), (18, 55)]])]),
)
DEFAULT_EMBLEM = {"fg": 0, "bg": 0, "c1": 10, "c2": 0, "c3": 1}


def clean_emblem(value) -> dict:
    """an emblem as the site keeps it, {"fg", "bg", "c1", "c2", "c3"}, from
    a request; ValueError if it is not one"""
    if not isinstance(value, dict):
        raise ValueError("emblem")
    out = {}
    for key, count in (("fg", len(EMBLEM_FOREGROUNDS)), ("bg", len(EMBLEM_BACKGROUNDS)), ("c1", len(EMBLEM_COLORS)),
                       ("c2", len(EMBLEM_COLORS)), ("c3", len(EMBLEM_COLORS))):
        item = value.get(key, DEFAULT_EMBLEM[key])
        if not isinstance(item, int) or isinstance(item, bool) or not 0 <= item < count:
            raise ValueError(key)
        out[key] = item
    return out


def emblem_pieces() -> dict:
    """the pieces and colors, as /v1/clans/emblem gives them to the pages"""
    def parts(piece):
        return [{"layer": layer, "polygons": [[list(point) for point in polygon] for polygon in polygons]}
                for layer, polygons in piece]
    return {"colors": [{"name": n, "hex": h} for n, h in EMBLEM_COLORS],
            "backgrounds": [{"name": n, "parts": parts(p)} for n, p in EMBLEM_BACKGROUNDS],
            "foregrounds": [{"name": n, "parts": parts(p)} for n, p in EMBLEM_FOREGROUNDS]}


class Refused(Exception):
    """a request the clan's rules don't allow: its HTTP status and words"""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def tag_key(tag: str) -> str:
    return tag.lower()


def name_key(name: str) -> str:
    return " ".join(name.lower().split())


class Clans:
    """the clans, their members and invites, in reports.db (the reports'
    database and lock); hidden(player_id) says whether a profile hides its
    service record"""

    def __init__(self, database, lock, hidden=lambda player_id: False, clock=time.time, blocks=lambda owner, other: False):
        self.database = database
        self.lock = lock
        self.hidden = hidden
        self.clock = clock
        # (called outside the lock: friends.py's takes the same one)
        self.blocks = blocks
        with self.lock:
            self.database.execute("""CREATE TABLE IF NOT EXISTS clans (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL, name_key TEXT NOT NULL UNIQUE, tag TEXT NOT NULL,
                tag_key TEXT NOT NULL UNIQUE, motto TEXT NOT NULL, emblem TEXT NOT NULL, created INTEGER NOT NULL)""")
            self.database.execute("""CREATE TABLE IF NOT EXISTS clan_members (
                player_id TEXT PRIMARY KEY, clan INTEGER NOT NULL, rank TEXT NOT NULL, joined INTEGER NOT NULL)""")
            self.database.execute("CREATE INDEX IF NOT EXISTS clan_members_clan ON clan_members (clan)")
            self.database.execute("""CREATE TABLE IF NOT EXISTS clan_invites (
                clan INTEGER NOT NULL, player_id TEXT NOT NULL, invited_by TEXT NOT NULL, created INTEGER NOT NULL,
                PRIMARY KEY (clan, player_id))""")
            self.database.execute("CREATE TABLE IF NOT EXISTS clan_tag_hidden (player_id TEXT PRIMARY KEY)")
            self.database.commit()

    # ---------- reading (under the lock)

    def _membership(self, player_id: str):
        """(clan ID, rank) of a profile, or None"""
        row = self.database.execute("SELECT clan, rank FROM clan_members WHERE player_id = ?", (player_id,)).fetchone()
        return (row[0], row[1]) if row else None

    def _clan_row(self, clan_id: int):
        return self.database.execute("SELECT id, name, tag, motto, emblem, created FROM clans WHERE id = ?",
                                     (clan_id,)).fetchone()

    def _profile_by_handle(self, handle: str):
        """(player ID, locked) of a handle's profile, or None"""
        row = self.database.execute("SELECT player_id, locked FROM profiles WHERE handle = ?",
                                    (str(handle).lower().lstrip("@"),)).fetchone()
        return (row[0], bool(row[1])) if row else None

    def _members(self, clan_id: int) -> list:
        """[(player ID, handle, display, rank, joined, locked)], leader, officers, members, by joining"""
        rows = self.database.execute(
            "SELECT m.player_id, p.handle, p.display, m.rank, m.joined, p.locked FROM clan_members m "
            "JOIN profiles p USING (player_id) WHERE m.clan = ? ORDER BY CASE m.rank WHEN 'leader' THEN 0 "
            "WHEN 'officer' THEN 1 ELSE 2 END, m.joined, p.handle", (clan_id,)).fetchall()
        return [(r[0], r[1], r[2], r[3], r[4], bool(r[5])) for r in rows]

    def _tag_shown(self, player_id: str) -> bool:
        return not self.database.execute("SELECT 1 FROM clan_tag_hidden WHERE player_id = ?", (player_id,)).fetchone()

    def _expire(self):
        self.database.execute("DELETE FROM clan_invites WHERE created < ?", (int(self.clock()) - INVITE_LIFETIME,))

    @staticmethod
    def _summary(row) -> dict:
        return {"id": row[0], "name": blocked_names.shown(row[1]), "tag": row[2],
                "motto": "" if blocked_names.blocked(row[3]) else row[3], "emblem": json.loads(row[4]),
                "created": row[5]}

    # ---------- the views

    def view(self, clan_id: int, viewer: str = "", limit: int = CLAN_MEMBERS):
        """a clan as a page shows it: its summary, and its members (handle,
        display, rank, joined; "you" the viewer's line), those who hide
        their service record or are locked left out but counted in
        "hidden" (the viewer always sees their own line); "count" all of
        them; at most limit members, "more" the rest. None for no clan"""
        with self.lock:
            row = self._clan_row(clan_id)
            if not row:
                return None
            members = self._members(clan_id)
        clan = self._summary(row)
        shown, hidden = [], 0
        for player_id, handle, display, rank, joined, locked in members:
            if player_id != viewer and (locked or self.hidden(player_id)):
                hidden += 1
                continue
            line = {"handle": handle, "display": display, "rank": rank, "joined": joined}
            if player_id == viewer:
                line["you"] = True
            shown.append(line)
        clan.update(count=len(members), hidden=hidden, members=shown[:limit], more=max(0, len(shown) - limit))
        return blocked_names.scrub(clan)

    def by_tag(self, tag: str):
        with self.lock:
            row = self.database.execute("SELECT id FROM clans WHERE tag_key = ?", (tag_key(str(tag)),)).fetchone()
        return row[0] if row else None

    def mine(self, player_id: str, limit: int = CLAN_MEMBERS) -> dict:
        """a profile's own clan matters: {"clan" (view, with "rank", or
        None), "invites" ([{"id", "name", "tag", "count", "emblem",
        "by" (the inviter's handle), "time"}]), "show_tag"}"""
        with self.lock:
            self._expire()
            membership = self._membership(player_id)
            invites = self.database.execute(
                "SELECT c.id, c.name, c.tag, c.emblem, i.created, p.handle, "
                "(SELECT COUNT(*) FROM clan_members m WHERE m.clan = c.id), i.invited_by FROM clan_invites i "
                "JOIN clans c ON c.id = i.clan LEFT JOIN profiles p ON p.player_id = i.invited_by "
                "WHERE i.player_id = ? ORDER BY i.created DESC", (player_id,)).fetchall()
            shown = self._tag_shown(player_id)
        # (an invite from someone this player blocks stays silent)
        invites = [r for r in invites if not self.blocks(player_id, r[7])]
        clan = None
        if membership:
            clan = self.view(membership[0], player_id, limit)
            if clan:
                clan["rank"] = membership[1]
        answer = {"clan": clan, "show_tag": shown,
                  "invites": [{"id": r[0], "name": blocked_names.shown(r[1]), "tag": r[2], "emblem": json.loads(r[3]),
                               "time": r[4], "by": r[5] or "", "count": r[6]} for r in invites]}
        return answer

    def tag_shown(self, player_id: str) -> bool:
        with self.lock:
            return self._tag_shown(player_id)

    def tag_of(self, player_id: str):
        """the clan a profile's card shows ({"tag", "name"}) while it shows
        its tag; else None"""
        with self.lock:
            membership = self._membership(player_id)
            if not membership or not self._tag_shown(player_id):
                return None
            row = self._clan_row(membership[0])
        return {"tag": row[2], "name": blocked_names.shown(row[1])} if row else None

    def public_tags(self) -> dict:
        """{player ID: tag} of every member whose tag the pages show next to
        their name (scoreboards, leaderboards, service records): those who
        show it ("show_tag"), as the member lists show them (not locked,
        not hiding their service record)"""
        with self.lock:
            rows = self.database.execute(
                "SELECT m.player_id, c.tag FROM clan_members m JOIN clans c ON c.id = m.clan "
                "JOIN profiles p ON p.player_id = m.player_id WHERE p.locked = 0 "
                "AND m.player_id NOT IN (SELECT player_id FROM clan_tag_hidden)").fetchall()
        return {player_id: tag for player_id, tag in rows if not self.hidden(player_id)}

    # ---------- changes (each raises Refused, else returns what changed)

    def _check_name(self, name: str, tag: str, skip: int = 0):
        if not NAME_PATTERN.match(name) or "  " in name:
            raise Refused(400, "Clan names are 2 to 32 letters, digits and spaces.")
        if not TAG_PATTERN.match(tag):
            raise Refused(400, "Tags are 2 to 8 letters and digits.")
        if blocked_names.blocked(name) or blocked_names.blocked(tag):
            raise Refused(400, "That name isn't allowed.")
        if self.database.execute("SELECT 1 FROM clans WHERE name_key = ? AND id != ?", (name_key(name), skip)).fetchone():
            raise Refused(409, "A clan has that name.")
        if self.database.execute("SELECT 1 FROM clans WHERE tag_key = ? AND id != ?", (tag_key(tag), skip)).fetchone():
            raise Refused(409, "A clan has that tag.")

    @staticmethod
    def _check_motto(motto: str):
        if len(motto) > MOTTO_LENGTH or blocked_names.blocked(motto):
            raise Refused(400, "That motto isn't allowed.")

    def _need(self, player_id: str, ranks=RANKS):
        membership = self._membership(player_id)
        if not membership:
            raise Refused(404, "You're not in a clan.")
        if membership[1] not in ranks:
            raise Refused(403, "Your rank can't do that.")
        return membership

    def create(self, player_id: str, name: str, tag: str, motto: str = "", emblem=None) -> int:
        emblem = clean_emblem(emblem if emblem is not None else DEFAULT_EMBLEM)
        now = int(self.clock())
        with self.lock:
            if self._membership(player_id):
                raise Refused(409, "Leave your clan first.")
            self._check_name(name, tag)
            self._check_motto(motto)
            cursor = self.database.execute(
                "INSERT INTO clans (name, name_key, tag, tag_key, motto, emblem, created) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (name, name_key(name), tag, tag_key(tag), motto, json.dumps(emblem, sort_keys=True), now))
            clan_id = cursor.lastrowid
            self.database.execute("INSERT INTO clan_members (player_id, clan, rank, joined) VALUES (?, ?, 'leader', ?)",
                                  (player_id, clan_id, now))
            self.database.execute("DELETE FROM clan_invites WHERE player_id = ?", (player_id,))
            self.database.commit()
        return clan_id

    def edit(self, player_id: str, name=None, tag=None, motto=None):
        with self.lock:
            clan_id, rank = self._need(player_id, ("leader", "officer"))
            row = self._clan_row(clan_id)
            if (name is not None and name != row[1]) or (tag is not None and tag != row[2]):
                if rank != "leader":
                    raise Refused(403, "Only the leader renames the clan.")
                name = row[1] if name is None else name
                tag = row[2] if tag is None else tag
                self._check_name(name, tag, clan_id)
                self.database.execute("UPDATE clans SET name = ?, name_key = ?, tag = ?, tag_key = ? WHERE id = ?",
                                      (name, name_key(name), tag, tag_key(tag), clan_id))
            if motto is not None:
                self._check_motto(motto)
                self.database.execute("UPDATE clans SET motto = ? WHERE id = ?", (motto, clan_id))
            self.database.commit()

    def set_emblem(self, player_id: str, emblem) -> dict:
        try:
            emblem = clean_emblem(emblem)
        except ValueError:
            raise Refused(400, "Bad emblem.")
        with self.lock:
            clan_id, _ = self._need(player_id, ("leader", "officer"))
            self.database.execute("UPDATE clans SET emblem = ? WHERE id = ?", (json.dumps(emblem, sort_keys=True), clan_id))
            self.database.commit()
        return emblem

    def invite(self, player_id: str, handle: str):
        now = int(self.clock())
        with self.lock:
            self._expire()
            clan_id, _ = self._need(player_id, ("leader", "officer"))
            found = self._profile_by_handle(handle)
            if not found or found[1]:
                raise Refused(404, "No profile has that handle.")
            if self._membership(found[0]):
                raise Refused(409, "They're in a clan already.")
            count = self.database.execute("SELECT COUNT(*) FROM clan_members WHERE clan = ?", (clan_id,)).fetchone()[0]
            waiting = self.database.execute("SELECT COUNT(*) FROM clan_invites WHERE clan = ?", (clan_id,)).fetchone()[0]
            if count + waiting >= CLAN_MEMBERS or waiting >= CLAN_INVITES:
                raise Refused(409, "The clan is full.")
            theirs = self.database.execute("SELECT COUNT(*) FROM clan_invites WHERE player_id = ?", (found[0],)).fetchone()[0]
            if theirs >= PLAYER_INVITES:
                raise Refused(409, "They have too many invites waiting.")
            self.database.execute("INSERT OR REPLACE INTO clan_invites (clan, player_id, invited_by, created) VALUES (?, ?, ?, ?)",
                                  (clan_id, found[0], player_id, now))
            self.database.commit()

    def cancel_invite(self, player_id: str, handle: str):
        with self.lock:
            clan_id, _ = self._need(player_id, ("leader", "officer"))
            found = self._profile_by_handle(handle)
            if found:
                self.database.execute("DELETE FROM clan_invites WHERE clan = ? AND player_id = ?", (clan_id, found[0]))
                self.database.commit()

    def invited(self, player_id: str) -> list:
        """the handles a member's clan has invited (its leader's and officers')"""
        with self.lock:
            self._expire()
            membership = self._membership(player_id)
            if not membership or membership[1] == "member":
                return []
            rows = self.database.execute(
                "SELECT p.handle, i.created FROM clan_invites i JOIN profiles p USING (player_id) WHERE i.clan = ? "
                "ORDER BY i.created DESC", (membership[0],)).fetchall()
        return [{"handle": r[0], "time": r[1]} for r in rows]

    def answer_invite(self, player_id: str, clan_id, accept: bool):
        now = int(self.clock())
        if isinstance(clan_id, int) and not isinstance(clan_id, bool):
            with self.lock:
                row = self.database.execute("SELECT invited_by FROM clan_invites WHERE clan = ? AND player_id = ?",
                                            (clan_id, player_id)).fetchone()
            # (a silent invite, from someone this player blocks: as gone)
            if row and self.blocks(player_id, row[0]):
                raise Refused(404, "That invite is gone.")
        with self.lock:
            self._expire()
            if not isinstance(clan_id, int) or isinstance(clan_id, bool) or not self.database.execute(
                    "SELECT 1 FROM clan_invites WHERE clan = ? AND player_id = ?", (clan_id, player_id)).fetchone():
                raise Refused(404, "That invite is gone.")
            if not accept:
                self.database.execute("DELETE FROM clan_invites WHERE clan = ? AND player_id = ?", (clan_id, player_id))
                self.database.commit()
                return
            if self._membership(player_id):
                raise Refused(409, "Leave your clan first.")
            if self.database.execute("SELECT COUNT(*) FROM clan_members WHERE clan = ?", (clan_id,)).fetchone()[0] >= CLAN_MEMBERS:
                raise Refused(409, "The clan is full.")
            self.database.execute("INSERT INTO clan_members (player_id, clan, rank, joined) VALUES (?, ?, 'member', ?)",
                                  (player_id, clan_id, now))
            self.database.execute("DELETE FROM clan_invites WHERE player_id = ?", (player_id,))
            self.database.commit()

    def leave(self, player_id: str) -> bool:
        """a member leaves; the leader only when alone, the clan going with
        them: True when it went"""
        with self.lock:
            clan_id, rank = self._need(player_id)
            others = self.database.execute("SELECT COUNT(*) FROM clan_members WHERE clan = ? AND player_id != ?",
                                           (clan_id, player_id)).fetchone()[0]
            if rank == "leader" and others:
                raise Refused(409, "Make another member leader first.")
            self.database.execute("DELETE FROM clan_members WHERE player_id = ?", (player_id,))
            if not others:
                self._remove(clan_id)
            self.database.commit()
        return not others

    def _remove(self, clan_id: int):
        self.database.execute("DELETE FROM clan_members WHERE clan = ?", (clan_id,))
        self.database.execute("DELETE FROM clan_invites WHERE clan = ?", (clan_id,))
        self.database.execute("DELETE FROM clans WHERE id = ?", (clan_id,))

    def _other(self, player_id: str, handle: str, ranks):
        """(clan ID, own rank, the other's player ID, their rank): a member of
        the same clan, by handle"""
        clan_id, rank = self._need(player_id, ranks)
        found = self._profile_by_handle(handle)
        other = self._membership(found[0]) if found else None
        if not other or other[0] != clan_id:
            raise Refused(404, "They're not in your clan.")
        if found[0] == player_id:
            raise Refused(400, "That's you.")
        return clan_id, rank, found[0], other[1]

    def kick(self, player_id: str, handle: str):
        with self.lock:
            _, rank, other, other_rank = self._other(player_id, handle, ("leader", "officer"))
            if other_rank == "leader" or (rank == "officer" and other_rank != "member"):
                raise Refused(403, "Your rank can't do that.")
            self.database.execute("DELETE FROM clan_members WHERE player_id = ?", (other,))
            self.database.commit()

    def set_rank(self, player_id: str, handle: str, rank: str):
        if rank not in ("officer", "member"):
            raise Refused(400, "Ranks are officer and member.")
        with self.lock:
            _, _, other, other_rank = self._other(player_id, handle, ("leader",))
            if other_rank == "leader":
                raise Refused(403, "Your rank can't do that.")
            self.database.execute("UPDATE clan_members SET rank = ? WHERE player_id = ?", (rank, other))
            self.database.commit()

    def transfer(self, player_id: str, handle: str):
        """the clan handed to another member, the leader an officer from then on"""
        with self.lock:
            _, _, other, _ = self._other(player_id, handle, ("leader",))
            self.database.execute("UPDATE clan_members SET rank = 'leader' WHERE player_id = ?", (other,))
            self.database.execute("UPDATE clan_members SET rank = 'officer' WHERE player_id = ?", (player_id,))
            self.database.commit()

    def set_tag_shown(self, player_id: str, shown: bool) -> bool:
        with self.lock:
            if shown:
                self.database.execute("DELETE FROM clan_tag_hidden WHERE player_id = ?", (player_id,))
            else:
                self.database.execute("INSERT OR IGNORE INTO clan_tag_hidden (player_id) VALUES (?)", (player_id,))
            self.database.commit()
        return shown

    def forget(self, player_id: str):
        """a profile deleted: out of its clan (the leadership going to the
        longest-serving officer, else member; the clan going if it was
        alone), its invites and choices gone"""
        with self.lock:
            membership = self._membership(player_id)
            self.database.execute("DELETE FROM clan_members WHERE player_id = ?", (player_id,))
            self.database.execute("DELETE FROM clan_invites WHERE player_id = ? OR invited_by = ?", (player_id, player_id))
            self.database.execute("DELETE FROM clan_tag_hidden WHERE player_id = ?", (player_id,))
            if membership:
                rest = self.database.execute(
                    "SELECT player_id FROM clan_members WHERE clan = ? ORDER BY CASE rank WHEN 'officer' THEN 0 ELSE 1 END, "
                    "joined LIMIT 1", (membership[0],)).fetchone()
                if not rest:
                    self._remove(membership[0])
                elif membership[1] == "leader":
                    self.database.execute("UPDATE clan_members SET rank = 'leader' WHERE player_id = ?", (rest[0],))
            self.database.commit()

    def remove_clan(self, clan_id: int) -> bool:
        """the admin's: a clan taken away (its members clanless)"""
        with self.lock:
            if not self._clan_row(clan_id):
                return False
            self._remove(clan_id)
            self.database.commit()
        return True

    def search(self, text: str = "", limit: int = 50) -> list:
        """clans by name or tag (all of them, biggest first, with no text)"""
        like = "%" + str(text).lower().replace("%", "").replace("_", "") + "%"
        with self.lock:
            rows = self.database.execute(
                "SELECT c.id, c.name, c.tag, c.motto, c.emblem, c.created, COUNT(m.player_id) AS n FROM clans c "
                "LEFT JOIN clan_members m ON m.clan = c.id WHERE c.name_key LIKE ? OR c.tag_key LIKE ? "
                "GROUP BY c.id ORDER BY n DESC, c.name_key LIMIT ?", (like, like, limit)).fetchall()
        return [dict(self._summary(r), count=r[6]) for r in rows]
