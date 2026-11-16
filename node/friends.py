"""Friends (list_server.py): Delta profiles who asked and said yes, the
requests between them, blocks, each profile's social privacy, and the
short-lived game invites between friends.

Friendship is mutual: one profile sends a request (by handle), the other
accepts or declines. A request to someone who already sent you one makes you
friends at once. Kept in reports.db (the reports' database and lock):

    friends          (a, b, since), a < b: one row a friendship
    friend_requests  (from_id, to_id, created, silent): waiting, gone after
                     REQUEST_LIFETIME; "silent" is a request sent to someone
                     who blocks its sender (kept so the sender sees it
                     waiting, never shown to the one it went to)
    blocks           (player_id, blocked_id, created)
    social_privacy   (player_id, requests, join_rule, appear_offline,
                     clan_presence): only for a profile that changed a
                     default

Privacy, a profile's own: who may send it requests (REQUEST_RULES, "everyone"
by default), who may join its game through the site (JOIN_RULES, "friends"
by default; "invite" is only those it invited), and "appear offline" (off by
default), which shows it offline to everyone, friends too. Who else sees
whether it's on and what it's playing (CLAN_PRESENCE_RULES): its friends
only, or its friends and its clan ("friends_and_clan", the default; DELTA's
clan roster, list_server.py's clan_presence). "Show when I'm playing" stays
the profiles' presence_hidden (list_server.py).

A block is silent: it ends any friendship, drops the requests both ways and
the invites both ways, and from then on the blocked profile's requests go
nowhere while it is told they went (refused only as anyone's would be, by
the privacy rule or a cap), and its invites are refused as any non-friend's
are. It sees the blocker offline, and can't join their game.

Caps: FRIENDS_MOST friends, OUTGOING_MOST requests waiting from a profile,
INCOMING_MOST waiting for one, REQUESTS_PER_HOUR requests sent an hour,
BLOCKS_MOST blocks. Game invites (memory only, never in the database) go
to friends, last INVITE_LIFETIME seconds, INVITES_PER_MINUTE a minute.

Who is online in menus (a copy asking for its friends' state, list_server's
/v1/social/state) is kept in memory only, ONLINE_LIFETIME seconds.

The doorbell (doorbell.py): each change calls ring(profile IDs, kind) for
the profiles whose state it changed, so their copies ask at once. A block
stays silent: it rings only the blocker's own copies, and a request to
someone who blocks its sender rings nobody.

Only Delta profiles are here: nothing of a player without one (an OpenCE
player, a copy never linked) is kept or shown. No address in any table or
answer; answers name profiles by handle, never by player ID.

SPDX-FileCopyrightText: 2026 The Chupathingy contributors
SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: GPL-3.0-or-later
"""

import secrets
import threading
import time
from collections import defaultdict

FRIENDS_MOST = 200
OUTGOING_MOST = 50
INCOMING_MOST = 200
REQUESTS_PER_HOUR = 20
REQUEST_LIFETIME = 30 * 86400
BLOCKS_MOST = 500
INVITE_LIFETIME = 300
INVITES_PER_MINUTE = 10
ONLINE_LIFETIME = 150  # (the game asks every 20 s in menus, 60 s in a game)
REQUEST_RULES = ("everyone", "friends_of_friends", "nobody")
JOIN_RULES = ("anyone", "friends", "invite")
CLAN_PRESENCE_RULES = ("friends", "friends_and_clan")
DEFAULT_PRIVACY = {"requests": "everyone", "join": "friends", "appear_offline": False,
                   "clan_presence": "friends_and_clan"}


class Refused(Exception):
    """a request the rules don't allow: its HTTP status and words"""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def pair(one: str, two: str) -> tuple:
    return (one, two) if one < two else (two, one)


class Friends:
    """the friends, requests, blocks and social privacy of profiles in
    reports.db (the profiles table's), plus the invites and online marks
    in memory"""

    def __init__(self, database, lock, clock=time.time):
        self.database = database
        self.lock = lock
        self.clock = clock
        self.memory = threading.Lock()
        self.invites = {}  # invite ID -> {"id", "from", "to", "invite", "created"}
        self.seen = {}  # profile ID -> when it last asked for its state
        self.sent = defaultdict(list)  # "request:" or "invite:" + profile ID -> [times]
        # the doorbell (list_server.py sets it): ring(profile IDs, kind)
        self.ring = lambda profile_ids, kind: None
        with self.lock:
            self.database.execute("""CREATE TABLE IF NOT EXISTS friends (
                a TEXT NOT NULL, b TEXT NOT NULL, since INTEGER NOT NULL, PRIMARY KEY (a, b))""")
            self.database.execute("CREATE INDEX IF NOT EXISTS friends_b ON friends (b)")
            self.database.execute("""CREATE TABLE IF NOT EXISTS friend_requests (
                from_id TEXT NOT NULL, to_id TEXT NOT NULL, created INTEGER NOT NULL, silent INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (from_id, to_id))""")
            self.database.execute("CREATE INDEX IF NOT EXISTS friend_requests_to ON friend_requests (to_id)")
            self.database.execute("""CREATE TABLE IF NOT EXISTS blocks (
                player_id TEXT NOT NULL, blocked_id TEXT NOT NULL, created INTEGER NOT NULL,
                PRIMARY KEY (player_id, blocked_id))""")
            self.database.execute("CREATE INDEX IF NOT EXISTS blocks_blocked ON blocks (blocked_id)")
            self.database.execute("""CREATE TABLE IF NOT EXISTS social_privacy (
                player_id TEXT PRIMARY KEY, requests TEXT NOT NULL DEFAULT 'everyone',
                join_rule TEXT NOT NULL DEFAULT 'friends', appear_offline INTEGER NOT NULL DEFAULT 0,
                clan_presence TEXT NOT NULL DEFAULT 'friends_and_clan')""")
            # (a table from before clan presence)
            columns = {row[1] for row in self.database.execute("PRAGMA table_info(social_privacy)")}
            if "clan_presence" not in columns:
                self.database.execute("ALTER TABLE social_privacy ADD COLUMN clan_presence TEXT NOT NULL "
                                      "DEFAULT 'friends_and_clan'")
            self.database.commit()

    # ---------- reading (under the lock)

    def _profile_by_handle(self, handle: str):
        """the player ID of a handle's profile (not locked), or None"""
        row = self.database.execute("SELECT player_id, locked FROM profiles WHERE handle = ?",
                                    (str(handle).strip().lower().lstrip("@"),)).fetchone()
        return row[0] if row and not row[1] else None

    def _other(self, player_id: str, handle: str) -> str:
        other = self._profile_by_handle(handle)
        if not other:
            raise Refused(404, "No profile has that handle.")
        if other == player_id:
            raise Refused(400, "That's you.")
        return other

    def _expire(self):
        self.database.execute("DELETE FROM friend_requests WHERE created < ?", (int(self.clock()) - REQUEST_LIFETIME,))

    def _are_friends(self, one: str, two: str) -> bool:
        return self.database.execute("SELECT 1 FROM friends WHERE a = ? AND b = ?", pair(one, two)).fetchone() is not None

    def _blocks(self, owner: str, other: str) -> bool:
        return self.database.execute("SELECT 1 FROM blocks WHERE player_id = ? AND blocked_id = ?",
                                     (owner, other)).fetchone() is not None

    def _count_friends(self, player_id: str) -> int:
        return self.database.execute("SELECT COUNT(*) FROM friends WHERE a = ? OR b = ?", (player_id, player_id)).fetchone()[0]

    def _friend_ids(self, player_id: str) -> set:
        rows = self.database.execute("SELECT a, b FROM friends WHERE a = ? OR b = ?", (player_id, player_id)).fetchall()
        return {b if a == player_id else a for a, b in rows}

    def _privacy(self, player_id: str) -> dict:
        row = self.database.execute("SELECT requests, join_rule, appear_offline, clan_presence FROM social_privacy "
                                    "WHERE player_id = ?", (player_id,)).fetchone()
        if not row:
            return dict(DEFAULT_PRIVACY)
        return {"requests": row[0], "join": row[1], "appear_offline": bool(row[2]),
                "clan_presence": row[3] if row[3] in CLAN_PRESENCE_RULES else DEFAULT_PRIVACY["clan_presence"]}

    def _befriend(self, one: str, two: str, now: int):
        for who in (one, two):
            if self._count_friends(who) >= FRIENDS_MOST:
                raise Refused(409, "Your friends list is full." if who == one else "Their friends list is full.")
        self.database.execute("INSERT OR IGNORE INTO friends (a, b, since) VALUES (?, ?, ?)", pair(one, two) + (now,))
        self.database.execute("DELETE FROM friend_requests WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)",
                              (one, two, two, one))

    # ---------- what the answers are made of

    def privacy_of(self, player_id: str) -> dict:
        """{"requests", "join", "appear_offline", "clan_presence"}"""
        with self.lock:
            return self._privacy(player_id)

    def are_friends(self, one: str, two: str) -> bool:
        with self.lock:
            return self._are_friends(one, two)

    def blocks(self, owner: str, other: str) -> bool:
        """whether owner blocks other"""
        with self.lock:
            return self._blocks(owner, other)

    def friend_ids(self, player_id: str) -> set:
        """the profile IDs of a profile's friends"""
        with self.lock:
            return self._friend_ids(player_id)

    def friend_rows(self, player_id: str) -> list:
        """[(player ID, handle, display, since)] of a profile's friends, by
        handle (a locked profile left out)"""
        with self.lock:
            rows = self.database.execute(
                "SELECT p.player_id, p.handle, p.display, f.since FROM friends f JOIN profiles p "
                "ON p.player_id = CASE WHEN f.a = ? THEN f.b ELSE f.a END "
                "WHERE (f.a = ? OR f.b = ?) AND p.locked = 0 ORDER BY p.handle", (player_id, player_id, player_id)).fetchall()
        return [tuple(r) for r in rows]

    def requests_of(self, player_id: str) -> dict:
        """{"incoming": [{"handle", "display", "time"}], "outgoing": [...]},
        newest first; a silent request (to someone who blocks you) is in
        its sender's outgoing only"""
        with self.lock:
            self._expire()
            incoming = self.database.execute(
                "SELECT p.handle, p.display, r.created FROM friend_requests r JOIN profiles p ON p.player_id = r.from_id "
                "WHERE r.to_id = ? AND r.silent = 0 AND p.locked = 0 ORDER BY r.created DESC", (player_id,)).fetchall()
            outgoing = self.database.execute(
                "SELECT p.handle, p.display, r.created FROM friend_requests r JOIN profiles p ON p.player_id = r.to_id "
                "WHERE r.from_id = ? AND p.locked = 0 ORDER BY r.created DESC", (player_id,)).fetchall()
        line = lambda r: {"handle": r[0], "display": r[1], "time": r[2]}
        return {"incoming": [line(r) for r in incoming], "outgoing": [line(r) for r in outgoing]}

    def incoming_count(self, player_id: str) -> int:
        """how many requests wait for a profile, as requests_of counts its
        "incoming" (the site's header shows it)"""
        with self.lock:
            return self.database.execute(
                "SELECT COUNT(*) FROM friend_requests r JOIN profiles p ON p.player_id = r.from_id "
                "WHERE r.to_id = ? AND r.silent = 0 AND p.locked = 0 AND r.created >= ?",
                (player_id, int(self.clock()) - REQUEST_LIFETIME)).fetchone()[0]

    def blocked_of(self, player_id: str) -> list:
        """the handles a profile blocks, newest first"""
        with self.lock:
            rows = self.database.execute(
                "SELECT p.handle FROM blocks b JOIN profiles p ON p.player_id = b.blocked_id WHERE b.player_id = ? "
                "ORDER BY b.created DESC", (player_id,)).fetchall()
        return [r[0] for r in rows]

    # ---------- changes (each raises Refused)

    def request(self, player_id: str, handle: str) -> str:
        """a friend request sent: "sent", or "friends" when they had sent
        one to you (both said yes). Sent silently (stored, never shown to
        them, never rung) when they block you"""
        result, rung = self._request(player_id, handle)
        if rung:
            self.ring(rung, "friends")
        return result

    def _request(self, player_id: str, handle: str) -> tuple:
        """request's work: (its answer, the profiles to ring)"""
        now = int(self.clock())
        with self.lock:
            self._expire()
            other = self._other(player_id, handle)
            if self._are_friends(player_id, other):
                raise Refused(409, "You're friends already.")
            if self._blocks(player_id, other):
                raise Refused(409, "Unblock them first.")
            blocked = self._blocks(other, player_id)
            if not blocked and self.database.execute(
                    "SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ? AND silent = 0", (other, player_id)).fetchone():
                self._befriend(player_id, other, now)
                self.database.commit()
                return "friends", [other, player_id]
            if self.database.execute("SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?",
                                     (player_id, other)).fetchone():
                return "sent", []
            # (the same refusals whether they block you or not: a block
            # never shows)
            rule = self._privacy(other)["requests"]
            if rule == "nobody" or (rule == "friends_of_friends" and
                                    not self._friend_ids(player_id) & self._friend_ids(other)):
                raise Refused(403, "They aren't taking friend requests.")
            if self.database.execute("SELECT COUNT(*) FROM friend_requests WHERE from_id = ?",
                                     (player_id,)).fetchone()[0] >= OUTGOING_MOST:
                raise Refused(409, "You have too many requests waiting.")
            if self._count_friends(player_id) >= FRIENDS_MOST:
                raise Refused(409, "Your friends list is full.")
            if self.database.execute("SELECT COUNT(*) FROM friend_requests WHERE to_id = ? AND silent = 0",
                                     (other,)).fetchone()[0] >= INCOMING_MOST:
                raise Refused(409, "They have too many requests waiting.")
            if not self._count("request:" + player_id, 3600, REQUESTS_PER_HOUR):
                raise Refused(429, "Too many friend requests. Try again in an hour.")
            self.database.execute("INSERT INTO friend_requests (from_id, to_id, created, silent) VALUES (?, ?, ?, ?)",
                                  (player_id, other, now, int(blocked)))
            self.database.commit()
        return "sent", [] if blocked else [other]

    def answer(self, player_id: str, handle: str, accept: bool):
        """a request from handle accepted (friends from now) or declined"""
        now = int(self.clock())
        with self.lock:
            self._expire()
            other = self._other(player_id, handle)
            if not self.database.execute("SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ? AND silent = 0",
                                         (other, player_id)).fetchone():
                raise Refused(404, "That request is gone.")
            if accept:
                self._befriend(player_id, other, now)
            else:
                self.database.execute("DELETE FROM friend_requests WHERE from_id = ? AND to_id = ?", (other, player_id))
            self.database.commit()
        # (a decline rings only the one who declined: their other copies)
        self.ring([other, player_id] if accept else [player_id], "friends")

    def cancel(self, player_id: str, handle: str):
        """one's own request taken back"""
        with self.lock:
            other = self._other(player_id, handle)
            self.database.execute("DELETE FROM friend_requests WHERE from_id = ? AND to_id = ?", (player_id, other))
            self.database.commit()

    def remove(self, player_id: str, handle: str):
        with self.lock:
            other = self._other(player_id, handle)
            if not self._are_friends(player_id, other):
                raise Refused(404, "You're not friends.")
            self.database.execute("DELETE FROM friends WHERE a = ? AND b = ?", pair(player_id, other))
            self.database.commit()
        self._drop_invites(player_id, other)
        self.ring([player_id, other], "friends")

    def block(self, player_id: str, handle: str):
        """silent: the friendship, the requests and the invites both ways gone"""
        now = int(self.clock())
        with self.lock:
            other = self._other(player_id, handle)
            if not self._blocks(player_id, other):
                if self.database.execute("SELECT COUNT(*) FROM blocks WHERE player_id = ?", (player_id,)).fetchone()[0] >= BLOCKS_MOST:
                    raise Refused(409, "You block too many players. Unblock some first.")
                self.database.execute("INSERT INTO blocks (player_id, blocked_id, created) VALUES (?, ?, ?)",
                                      (player_id, other, now))
            self.database.execute("DELETE FROM friends WHERE a = ? AND b = ?", pair(player_id, other))
            self.database.execute("DELETE FROM friend_requests WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)",
                                  (player_id, other, other, player_id))
            self.database.commit()
        self._drop_invites(player_id, other)
        # (silent: the blocker's own copies only)
        self.ring([player_id], "friends")

    def unblock(self, player_id: str, handle: str):
        """the block taken away (requests sent while it stood stay gone)"""
        with self.lock:
            other = self._other(player_id, handle)
            self.database.execute("DELETE FROM blocks WHERE player_id = ? AND blocked_id = ?", (player_id, other))
            self.database.execute("DELETE FROM friend_requests WHERE from_id = ? AND to_id = ? AND silent = 1", (other, player_id))
            self.database.commit()

    def set_privacy(self, player_id: str, requests=None, join=None, appear_offline=None, clan_presence=None) -> dict:
        """a profile's social privacy changed (None: left as it is)"""
        if requests is not None and requests not in REQUEST_RULES:
            raise Refused(400, "Friend requests are from everyone, friends of friends or nobody.")
        if join is not None and join not in JOIN_RULES:
            raise Refused(400, "Joining is for anyone, friends or those you invite.")
        if appear_offline is not None and not isinstance(appear_offline, bool):
            raise Refused(400, "Bad request.")
        if clan_presence is not None and clan_presence not in CLAN_PRESENCE_RULES:
            raise Refused(400, "Your status is for friends, or friends and clan.")
        with self.lock:
            current = self._privacy(player_id)
            new = {"requests": current["requests"] if requests is None else requests,
                   "join": current["join"] if join is None else join,
                   "appear_offline": current["appear_offline"] if appear_offline is None else appear_offline,
                   "clan_presence": current["clan_presence"] if clan_presence is None else clan_presence}
            if new == DEFAULT_PRIVACY:
                self.database.execute("DELETE FROM social_privacy WHERE player_id = ?", (player_id,))
            else:
                self.database.execute("INSERT OR REPLACE INTO social_privacy (player_id, requests, join_rule, appear_offline, "
                                      "clan_presence) VALUES (?, ?, ?, ?, ?)",
                                      (player_id, new["requests"], new["join"], int(new["appear_offline"]),
                                       new["clan_presence"]))
            self.database.commit()
        if new["appear_offline"]:
            with self.memory:
                self.seen.pop(player_id, None)
        if current["appear_offline"] and not new["appear_offline"]:
            # (back from appearing offline: its friends see it now. Going
            # offline rings nobody; its friends see it on their next poll)
            self.ring(list(self.friend_ids(player_id)), "presence")
        return new

    def forget(self, player_id: str):
        """a profile deleted: every row of it, and what memory holds"""
        with self.lock:
            self.database.execute("DELETE FROM friends WHERE a = ? OR b = ?", (player_id, player_id))
            self.database.execute("DELETE FROM friend_requests WHERE from_id = ? OR to_id = ?", (player_id, player_id))
            self.database.execute("DELETE FROM blocks WHERE player_id = ? OR blocked_id = ?", (player_id, player_id))
            self.database.execute("DELETE FROM social_privacy WHERE player_id = ?", (player_id,))
            self.database.commit()
        with self.memory:
            self.seen.pop(player_id, None)
            for key in [k for k, i in self.invites.items() if player_id in (i["from"], i["to"])]:
                del self.invites[key]
            self.sent.pop("request:" + player_id, None)
            self.sent.pop("invite:" + player_id, None)

    # ---------- memory only: rates, online marks, invites

    def _count(self, key: str, window: int, most: int) -> bool:
        """one more of key counted, if fewer than most in window seconds"""
        now = self.clock()
        with self.memory:
            times = [t for t in self.sent.get(key, ()) if now - t < window]
            if len(times) >= most:
                self.sent[key] = times
                return False
            times.append(now)
            self.sent[key] = times
            if len(self.sent) > 20000:
                for stale in [k for k, v in self.sent.items() if not v or now - v[-1] > 3600]:
                    del self.sent[stale]
        return True

    def mark_online(self, player_id: str):
        """a copy of the profile's asked for its state: online (in menus or a
        game) for ONLINE_LIFETIME, unless it appears offline"""
        if self.privacy_of(player_id)["appear_offline"]:
            return
        now = self.clock()
        with self.memory:
            before = self.seen.get(player_id)
            self.seen[player_id] = now
            if len(self.seen) > 50000:
                for stale in [p for p, t in self.seen.items() if now - t > ONLINE_LIFETIME]:
                    del self.seen[stale]
        if before is None or now - before > ONLINE_LIFETIME:
            # (came online: its friends see it now)
            self.ring(list(self.friend_ids(player_id)), "presence")

    def online(self, player_id: str) -> bool:
        with self.memory:
            when = self.seen.get(player_id)
            return when is not None and self.clock() - when <= ONLINE_LIFETIME

    def _drop_invites(self, one: str, two: str):
        with self.memory:
            for key in [k for k, i in self.invites.items() if {i["from"], i["to"]} == {one, two}]:
                del self.invites[key]

    def _expire_invites(self):
        now = self.clock()
        for key in [k for k, i in self.invites.items() if now - i["created"] > INVITE_LIFETIME]:
            del self.invites[key]

    def invite(self, player_id: str, handle: str, game_invite: str) -> str:
        """a friend invited to the game of game_invite (checked by the
        caller): the invite's ID. Friends only, and a block ends a
        friendship, so someone who blocks you is refused as anyone else
        who isn't your friend: the block never shows. One invite from you
        to them at a time"""
        with self.lock:
            other = self._other(player_id, handle)
            friends = self._are_friends(player_id, other) and not self._blocks(other, player_id)
        if not friends:
            raise Refused(403, "You can invite friends only.")
        if not self._count("invite:" + player_id, 60, INVITES_PER_MINUTE):
            raise Refused(429, "Too many invites. Try again in a minute.")
        invite_id = secrets.token_hex(8)
        with self.memory:
            self._expire_invites()
            for key in [k for k, i in self.invites.items() if i["from"] == player_id and i["to"] == other]:
                del self.invites[key]
            self.invites[invite_id] = {"id": invite_id, "from": player_id, "to": other, "invite": game_invite,
                                       "created": self.clock()}
        self.ring([other], "invite")
        return invite_id

    def invites_for(self, player_id: str) -> list:
        """the invites waiting for a profile, newest first: [{"id", "from"
        (profile ID), "invite", "created"}]"""
        with self.memory:
            self._expire_invites()
            found = [dict(i) for i in self.invites.values() if i["to"] == player_id]
        return sorted(found, key=lambda i: -i["created"])

    def invited(self, player_id: str, by: str, game_invite: str = "") -> bool:
        """whether by has invited player_id (to that game, if given), live"""
        return any(i["from"] == by and (not game_invite or i["invite"] == game_invite) for i in self.invites_for(player_id))
