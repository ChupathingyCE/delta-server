"""Delta profiles as a node keeps them: a handle per account, the copies of
the game linked to it, and who is in a game now.

Cut down from the Chupathingy site's Profiles (list_server.py): the
tables and their columns are the site's, so a node's database reads the
same, but there are no passwords, sessions, email or web sign-in here.
An account is made by the node's operator (delta_node.py profile-add)
until account sign-up is decided (README, Not done yet).

SPDX-FileCopyrightText: 2026 The Chupathingy contributors
SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: MIT
"""

import hashlib
import re
import time
from collections import defaultdict

from game_list import rate_key

PLAYER_KEY = re.compile(r"^[0-9a-f]{64}$")
PLAYER_ID = re.compile(r"^[0-9a-f]{32}$")
HANDLE = re.compile(r"^[a-z0-9_-]{3,20}$")
PRESENCE_LIFETIME = 180
PRESENCE_PER_ADDRESS = 600  # an hour
GAME_REQUESTS_PER_KEY = 6  # a minute
GAME_REQUESTS_PER_ADDRESS = 60  # an hour
SOCIAL_REQUESTS_PER_KEY = 6  # a minute
SOCIAL_ACTIONS_PER_KEY = 20  # a minute
SOCIAL_REQUESTS_PER_ADDRESS = 3000  # an hour


def player_id_of(key_hex: str) -> str:
    """a copy's player ID from its player key (the game's derivation)"""
    return hashlib.sha256(b"halo-ce-universal player id\n" + bytes.fromhex(key_hex)).hexdigest()[:32]


def cased_name(handle: str, wanted) -> str:
    """the shown name: the handle in the case asked for, else the handle"""
    wanted = str(wanted or "")
    return wanted if wanted.lower() == handle else handle


class Accounts:
    def __init__(self, database, lock, reserved=(), clock=time.time):
        self.database = database
        self.lock = lock
        self.clock = clock
        self.reserved = {name.lower() for name in reserved}
        self.presence = {}  # profile ID -> (invite, time): memory only
        self.counts = defaultdict(list)
        # (a profile shown in a game it wasn't in before: the doorbell rings
        # its friends; set by the runner)
        self.on_presence = None
        with self.lock:
            self.database.execute("""CREATE TABLE IF NOT EXISTS profiles (
                player_id TEXT PRIMARY KEY, handle TEXT NOT NULL UNIQUE, display TEXT NOT NULL, bio TEXT NOT NULL,
                auth TEXT NOT NULL, backup TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL,
                locked INTEGER NOT NULL DEFAULT 0, looks_like TEXT NOT NULL DEFAULT '')""")
            self.database.execute("""CREATE TABLE IF NOT EXISTS links (
                game_id TEXT PRIMARY KEY, player_id TEXT NOT NULL, created INTEGER NOT NULL,
                platform TEXT NOT NULL DEFAULT '')""")
            self.database.execute("CREATE TABLE IF NOT EXISTS presence_hidden (player_id TEXT PRIMARY KEY)")
            self.database.execute("CREATE INDEX IF NOT EXISTS links_player ON links (player_id)")
            self.database.commit()

    # ---------- profiles

    def create(self, player_id: str, handle: str, display: str = "") -> str:
        """a profile for a player ID: "" if made, else why not"""
        handle = handle.strip().lower()
        if not PLAYER_ID.match(player_id):
            return "bad player ID"
        if not HANDLE.match(handle):
            return "a handle is 3 to 20 of a-z, 0-9, _ and -"
        if handle in self.reserved:
            return "that name is reserved"
        now = int(self.clock())
        with self.lock:
            if self.database.execute("SELECT 1 FROM profiles WHERE player_id = ?", (player_id,)).fetchone():
                return "this player already has a profile"
            if self.database.execute("SELECT 1 FROM profiles WHERE handle = ?", (handle,)).fetchone():
                return "that profile name is taken"
            self.database.execute(
                "INSERT INTO profiles (player_id, handle, display, bio, auth, backup, created, updated) "
                "VALUES (?, ?, ?, '', '', '{}', ?, ?)", (player_id, handle, cased_name(handle, display), now, now))
            self.database.commit()
        return ""

    def get(self, player_id: str):
        with self.lock:
            row = self.database.execute("SELECT handle, display, created, locked FROM profiles WHERE player_id = ?",
                                        (player_id,)).fetchone()
        if not row:
            return None
        profile = {"handle": row[0], "display": cased_name(row[0], row[1]), "created": row[2]}
        if row[3]:
            profile["locked"] = True
        return profile

    def by_handle(self, handle: str):
        """(player_id, auth, locked) of a profile name (the site's shape)"""
        with self.lock:
            return self.database.execute("SELECT player_id, auth, locked FROM profiles WHERE handle = ?",
                                         (handle,)).fetchone()

    def profile_of_game(self, game_id: str):
        """the profile a copy counts for (the one it is linked to, else its
        own): (profile ID, locked), or None"""
        with self.lock:
            row = self.database.execute("SELECT player_id FROM links WHERE game_id = ?", (game_id,)).fetchone()
            player_id = row[0] if row else game_id
            known = self.database.execute("SELECT locked FROM profiles WHERE player_id = ?", (player_id,)).fetchone()
        return (player_id, bool(known[0])) if known else None

    def account_of(self, copy_id: str):
        """(account ID, handle, locked) for identity.py, or None"""
        found = self.profile_of_game(copy_id)
        if not found:
            return None
        profile = self.get(found[0])
        return found[0], profile["handle"] if profile else "", found[1]

    def copies_of(self, account: str) -> list:
        with self.lock:
            return [account] + [row[0] for row in self.database.execute(
                "SELECT game_id FROM links WHERE player_id = ?", (account,))]

    def link_copy(self, copy_id: str, account: str, foresee: bool = False):
        """a copy linked to a profile (a device signed in there by code):
        a string says why not"""
        with self.lock:
            if copy_id == account:
                return None
            if self.database.execute("SELECT 1 FROM profiles WHERE player_id = ?", (copy_id,)).fetchone():
                return "This copy has a profile of its own."
            if foresee:
                return None
            self.database.execute("INSERT OR REPLACE INTO links (game_id, player_id, created) VALUES (?, ?, ?)",
                                  (copy_id, account, int(self.clock())))
            self.database.commit()
        return None

    def unlink_copy(self, copy_id: str):
        with self.lock:
            row = self.database.execute("SELECT player_id FROM links WHERE game_id = ?", (copy_id,)).fetchone()
            self.database.execute("DELETE FROM links WHERE game_id = ?", (copy_id,))
            self.database.commit()
        return row[0] if row else None

    # ---------- presence (memory only)

    def presence_hidden(self, player_id: str) -> bool:
        with self.lock:
            return self.database.execute("SELECT 1 FROM presence_hidden WHERE player_id = ?",
                                         (player_id,)).fetchone() is not None

    def note_presence(self, game_id: str, invite: str, address: str) -> str:
        """a copy says it is in the game of that invite: "ok", "off" (no
        profile, or hidden), or "" past PRESENCE_PER_ADDRESS an hour"""
        now = self.clock()
        if not self._count("presence:" + rate_key(address), 3600, PRESENCE_PER_ADDRESS, now):
            return ""
        found = self.profile_of_game(game_id)
        if not found or found[1] or self.presence_hidden(found[0]):
            if found:
                with self.lock:
                    self.presence.pop(found[0], None)
            return "off"
        player_id = found[0]
        with self.lock:
            before = self.presence.get(player_id)
            self.presence[player_id] = (invite, now)
        if self.on_presence and (not before or before[0] != invite or now - before[1] > PRESENCE_LIFETIME):
            self.on_presence(player_id)
        return "ok"

    def presence_of(self, player_id: str):
        now = self.clock()
        with self.lock:
            entry = self.presence.get(player_id)
            if not entry:
                return None
            if now - entry[1] > PRESENCE_LIFETIME:
                del self.presence[player_id]
                return None
        if self.presence_hidden(player_id):
            return None
        return entry[0]

    def presence_online(self) -> int:
        now = self.clock()
        with self.lock:
            return sum(1 for entry in self.presence.values() if now - entry[1] <= PRESENCE_LIFETIME)

    # ---------- limits (memory only)

    def _count(self, key: str, window: int, most: int, now: float) -> bool:
        with self.lock:
            times = [t for t in self.counts.get(key, []) if now - t < window]
            if len(times) >= most:
                self.counts[key] = times
                return False
            times.append(now)
            self.counts[key] = times
            if len(self.counts) > 50000:
                self.counts.clear()
            return True

    def allow_social_request(self, game_id: str, address: str, action: bool = False) -> bool:
        now = self.clock()
        first = ("social action:" + game_id, 60, SOCIAL_ACTIONS_PER_KEY) if action else \
            ("social key:" + game_id, 60, SOCIAL_REQUESTS_PER_KEY)
        second = ("social address:" + rate_key(address), 3600, SOCIAL_REQUESTS_PER_ADDRESS)
        return self._count(*first, now) and self._count(*second, now)

    def allow_game_request(self, game_id: str, address: str) -> bool:
        now = self.clock()
        return (self._count("game key:" + game_id, 60, GAME_REQUESTS_PER_KEY, now) and
                self._count("game address:" + rate_key(address), 3600, GAME_REQUESTS_PER_ADDRESS, now))
