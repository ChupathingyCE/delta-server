"""Delta clients (chupathingyce's docs/delta-clients.md): other games and
tools that sign players in with Quick Connect on this site, each with a
client ID, the scopes it may ask for, and its own rate limits.

A fork's developer registers a client from a signed-in profile (name,
homepage, contact, its platforms, the scopes it wants). It starts pending:
its devices can sign in only to the developer's own profile, for testing.
Once an admin approves it, anyone can sign in with it. An admin can suspend
it, which revokes every device that came through it.

Its devices send their client ID with /v1/identity/device/start (and
/legacy/enroll). The approval shows "<name> (<homepage's host>) wants to"
and the scopes in plain words, and the device's certificate and tokens get
those scopes alone: the client's scopes, ANDed with what the device asked
for, ANDed with what a device would get anyway. "devices" (approving and
revoking other devices) is never a client's.

Chupathingy's own builds are the first-party client, FIRST_PARTY, which is
not in the table. A request with no client ID is first party too, so every
shipped build keeps working as it did.

A client ID is not a secret: anyone can read it out of a build. It lets an
honest fork be shown, limited and switched off as a group; it can't stop a
build that lies about what it is, any more than a modified Chupathingy can
be stopped. The player's own approval and per-device revoke stay the guard
for that.

SPDX-FileCopyrightText: 2026 The Chupathingy contributors
SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: GPL-3.0-or-later
"""

import re
import secrets
import time
import unicodedata
import urllib.parse

import identity

FIRST_PARTY = "chupathingy"
CLIENT_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,39}$")
STATUSES = ("pending", "approved", "suspended")

# scopes are identity.CAPABILITIES' bits; a client may ask for these
# ("devices" stays first party: approving and revoking never pass to a fork)
CLIENT_SCOPES = ("play", "stats", "profile", "social", "moderate")
CLIENT_MASK = sum(identity.CAPABILITIES[name] for name in CLIENT_SCOPES)
# (what a developer can ask for when registering; "moderate" only an admin
# gives, to an approved client)
REQUESTABLE_SCOPES = ("play", "stats", "profile", "social")
ADMIN_ONLY_SCOPES = ("moderate",)
# (what the approval says, in this order)
SCOPE_WORDS = {
    "play": "Show you as your profile in games",
    "stats": "Send your games to your stats",
    "profile": "See your profile, change its privacy settings, and see your devices",
    "social": "See your friends and clan, show them you're online, send invites, and list your games",
    "moderate": "Sign you in to moderate on servers where you have a role",
    "devices": "Approve and remove your other devices",
}

# limits: a new client's, and the most an admin may set
STARTS_PER_HOUR = 300
TOKENS_PER_HOUR = 3000
STARTS_MOST = 20000
TOKENS_MOST = 200000
CLIENTS_PER_OWNER = 3
NAME_MOST = 32
HOMEPAGE_MOST = 200
CONTACT_MOST = 120

# names a client can't take, or look like, compared folded (fold): these
# never (near ones too), and
RESERVED = ("chupathingy", "warthog", "official", "verified")
# these only with an admin's say-so (a name with one in it, "Deltarune
# Port", is held: the client registers, and an admin approves the name
# with it, which the audit log keeps)
HELD = ("chupa", "delta")
# (characters that read as letters, and runs of one letter made one)
LOOKALIKES = str.maketrans({"0": "o", "1": "l", "i": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
                            "9": "g", "6": "g", "$": "s", "@": "a", "|": "l", "!": "l"})
HOST = re.compile(r"^[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$")
UNSAFE = re.compile(r"[^!#-;=?-~]")
EMAIL = re.compile(r"^[^@\s\"'<>\\]{1,64}@[a-z0-9-]+(?:\.[a-z0-9-]+)+$")


def fold(name: str) -> str:
    """a name as it reads: compatibility forms, lowercase, look-alike
    characters as their letters, "rn" as "m" and "vv" as "w", only letters,
    each run of one letter as one"""
    text = unicodedata.normalize("NFKD", str(name or "")).casefold()
    text = "".join(c for c in text if not unicodedata.combining(c)).translate(LOOKALIKES)
    text = re.sub(r"[^a-z]", "", text).replace("rn", "m").replace("vv", "w")
    return re.sub(r"(.)\1+", r"\1", text)


def distance(a: str, b: str) -> int:
    """the edits (a letter added, dropped or changed) from a to b"""
    row = list(range(len(b) + 1))
    for i, x in enumerate(a, 1):
        previous, row[0] = row[0], i
        for j, y in enumerate(b, 1):
            previous, row[j] = row[j], min(row[j] + 1, row[j - 1] + 1, previous + (x != y))
    return row[-1]


def near(word: str, folded: str) -> bool:
    """whether a folded name has word in it, or something one edit from it
    (two for a long word)"""
    most = 2 if len(word) >= 8 else 1 if len(word) >= 7 else 0
    for size in range(max(1, len(word) - most), len(word) + most + 1):
        for start in range(0, max(1, len(folded) - size + 1)):
            if distance(word, folded[start:start + size]) <= most:
                return True
    return False


def scope_names(mask: int) -> list:
    return [name for name, bit in identity.CAPABILITIES.items() if mask & bit]


def lost(before: int, after: int, scope: str) -> bool:
    """whether a client's scopes went from having scope to not"""
    bit = identity.CAPABILITIES[scope]
    return bool(before & bit) and not after & bit


def scope_mask(names) -> int:
    mask = 0
    for name in names if isinstance(names, (list, tuple)) else ():
        mask |= identity.CAPABILITIES.get(str(name), 0)
    return mask


def homepage_host(homepage: str) -> str:
    """an https:// address's host (lowercase), or "" for anything else: no
    user or password in it, no spaces, quotes or angle brackets"""
    text = str(homepage or "")
    if UNSAFE.search(text) or not text.lower().startswith("https://"):
        return ""
    try:
        parts = urllib.parse.urlsplit(text)
        parts.port
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    if parts.username is not None or parts.password is not None or not HOST.match(host):
        return ""
    return host


class Refused(Exception):
    """(status, error)"""


class Clients:
    """the delta_clients table (in reports.db, beside the devices); its
    lock is the site's database lock, never held while calling out"""

    COLUMNS = ("client_id", "name", "folded", "homepage", "contact", "platforms", "scopes", "status", "owner",
               "created", "reviewed", "starts_per_hour", "tokens_per_hour", "name_held")

    def __init__(self, database, lock, platforms=(), clock=time.time):
        self.database = database
        self.lock = lock
        self.platforms = tuple(p for p in platforms if p != "unknown")
        self.clock = clock
        with self.lock:
            self.database.execute("""CREATE TABLE IF NOT EXISTS delta_clients (
                client_id TEXT PRIMARY KEY, name TEXT NOT NULL, folded TEXT NOT NULL, homepage TEXT NOT NULL,
                contact TEXT NOT NULL, platforms TEXT NOT NULL, scopes INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending', owner TEXT NOT NULL, created INTEGER NOT NULL,
                reviewed INTEGER NOT NULL DEFAULT 0, starts_per_hour INTEGER NOT NULL DEFAULT %d,
                tokens_per_hour INTEGER NOT NULL DEFAULT %d)""" % (STARTS_PER_HOUR, TOKENS_PER_HOUR))
            # (its name has HELD in it: approving it takes the admin's say-so)
            columns = [row[1] for row in self.database.execute("PRAGMA table_info(delta_clients)")]
            if "name_held" not in columns:
                self.database.execute("ALTER TABLE delta_clients ADD COLUMN name_held INTEGER NOT NULL DEFAULT 0")
            self.database.execute("CREATE INDEX IF NOT EXISTS delta_clients_owner ON delta_clients (owner)")
            self.database.commit()

    def _row(self, row) -> dict:
        client = dict(zip(self.COLUMNS, row))
        client["platforms"] = [p for p in client["platforms"].split(",") if p]
        return client

    def get(self, client_id: str):
        client_id = str(client_id or "").strip().lower()
        if not CLIENT_ID.match(client_id):
            return None
        with self.lock:
            row = self.database.execute("SELECT %s FROM delta_clients WHERE client_id = ?" % ", ".join(self.COLUMNS),
                                        (client_id,)).fetchone()
        return self._row(row) if row else None

    def all(self, status: str = "") -> list:
        with self.lock:
            rows = self.database.execute("SELECT %s FROM delta_clients %s ORDER BY created DESC" % (
                ", ".join(self.COLUMNS), "WHERE status = ?" if status else ""), (status,) if status else ()).fetchall()
        return [self._row(row) for row in rows]

    def of_owner(self, owner: str) -> list:
        with self.lock:
            rows = self.database.execute("SELECT %s FROM delta_clients WHERE owner = ? ORDER BY created" %
                                         ", ".join(self.COLUMNS), (owner,)).fetchall()
        return [self._row(row) for row in rows]

    # ---------- what a device's request is told

    def resolve(self, client_id):
        """(client, None) for a registered client that isn't suspended,
        (None, None) for the first party (no client ID, or FIRST_PARTY), or
        (None, (status, answer)) refused"""
        client_id = str(client_id or "").strip().lower()
        if not client_id or client_id == FIRST_PARTY:
            return None, None
        client = self.get(client_id)
        if not client:
            return None, (403, {"error": "This app isn't registered with this site.", "client": "unknown"})
        if client["status"] == "suspended":
            return None, (403, {"error": "This app was suspended on this site.", "client": "suspended"})
        return client, None

    def mask(self, client_id: str) -> int:
        """the capabilities a client's devices may use now: its scopes, or
        0 when it is suspended or gone"""
        client = self.get(client_id)
        if not client or client["status"] == "suspended":
            return 0
        return client["scopes"] & CLIENT_MASK

    @staticmethod
    def requested(client: dict, names) -> int:
        """the scopes a device of the client gets: what it asked for (all
        of the client's when it named none), within the client's"""
        asked = scope_mask(names) if isinstance(names, (list, tuple)) else client["scopes"]
        return asked & client["scopes"] & CLIENT_MASK

    @staticmethod
    def allows_account(client: dict, account: str) -> bool:
        """a pending client signs in to its developer's own profile only"""
        return client["status"] == "approved" or client["owner"] == account

    @staticmethod
    def shown(client: dict, mask: int) -> dict:
        """what the approval shows of a client and the scopes it asked for"""
        names = scope_names(mask)
        return {"id": client["client_id"], "name": client["name"], "homepage": client["homepage"],
                "host": homepage_host(client["homepage"]), "reviewed": client["status"] == "approved",
                "scopes": names, "scope_words": [SCOPE_WORDS[name] for name in names]}

    def public(self, client_id: str):
        """a device list's line for the client a device came through"""
        client = self.get(client_id)
        if not client:
            return {"id": client_id, "name": client_id, "homepage": "", "host": "", "status": "unknown"}
        return {"id": client["client_id"], "name": client["name"], "homepage": client["homepage"],
                "host": homepage_host(client["homepage"]), "status": client["status"]}

    def directory(self) -> list:
        """GET /v1/clients: the approved clients, for anyone (no contact,
        no owner)"""
        return [{"id": c["client_id"], "name": c["name"], "homepage": c["homepage"], "platforms": c["platforms"],
                 "scopes": scope_names(c["scopes"]), "since": c["reviewed"]} for c in self.all("approved")]

    # ---------- registering one

    @staticmethod
    def held_name(name: str) -> bool:
        """whether a name has HELD in it (its approval needs the admin's
        say-so)"""
        folded = fold(name)
        return any(fold(word) in folded for word in HELD)

    def check_name(self, name: str, except_id: str = "", owner: str = "") -> str:
        """why a name can't be taken, or "" (a held name can: held_name).
        It is checked against the approved apps and owner's own: a pending
        app holds no name from anyone else, so registering names nobody
        means to ship doesn't take them"""
        with self.lock:
            return self._name_refused(name, except_id, owner)

    def _name_refused(self, name: str, except_id: str, owner: str) -> str:
        """(under the lock) check_name"""
        folded = fold(name)
        if len(folded) < 3:
            return "Pick a name with at least three letters."
        if any(near(fold(word), folded) for word in RESERVED):
            return "That name is too close to Chupathingy's own. Pick your own name."
        others = [row[0] for row in self.database.execute(
            "SELECT folded FROM delta_clients WHERE client_id != ? AND (status = 'approved' OR owner = ?)",
            (except_id, owner))]
        if any(other == folded or (min(len(other), len(folded)) >= 5 and distance(other, folded) <= 1)
               for other in others):
            return "That name is taken, or looks like one that is."
        return ""

    def register(self, owner: str, body: dict) -> dict:
        """a new pending client for owner's profile: {"name", "homepage",
        "contact", "platforms": [...], "scopes": [...]}, or Refused"""
        name = re.sub(r"\s+", " ", str(body.get("name") or "")).strip()
        homepage = str(body.get("homepage") or "").strip()
        contact = str(body.get("contact") or "").strip()
        platforms = body.get("platforms")
        scopes = body.get("scopes")
        if not 3 <= len(name) <= NAME_MOST:
            raise Refused(400, f"A name is 3 to {NAME_MOST} characters.")
        if re.search(r"[^ -~]", name):
            raise Refused(400, "Use plain letters, digits, spaces and punctuation in a name.")
        if len(homepage) > HOMEPAGE_MOST or not homepage_host(homepage):
            raise Refused(400, "Your homepage is an https:// address.")
        contact_ok = len(contact) <= CONTACT_MOST and (EMAIL.match(contact.lower()) or homepage_host(contact))
        if not contact_ok:
            raise Refused(400, "A contact is an email address or an https:// address.")
        if not isinstance(platforms, list) or not platforms or len(platforms) > len(self.platforms) or \
                any(p not in self.platforms for p in platforms):
            raise Refused(400, "Pick the platforms your builds run on.")
        if isinstance(scopes, list) and any(s in ADMIN_ONLY_SCOPES for s in scopes):
            raise Refused(400, "Moderating is given by us, once your app is approved. Ask us if you need it.")
        if not isinstance(scopes, list) or any(s not in REQUESTABLE_SCOPES for s in scopes) or not scopes:
            raise Refused(400, "Pick the scopes from: " + ", ".join(REQUESTABLE_SCOPES) + ".")
        slug = re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", name.lower())).strip("-")[:24] or "app"
        if len(slug) < 3:
            slug = "app"
        # (the name, the count and the new row under one lock: two at once
        # can't both pass)
        with self.lock:
            refused = self._name_refused(name, "", owner)
            if refused:
                raise Refused(409, refused)
            count = self.database.execute("SELECT COUNT(*) FROM delta_clients WHERE owner = ?", (owner,)).fetchone()[0]
            if count >= CLIENTS_PER_OWNER:
                raise Refused(409, f"A profile can register {CLIENTS_PER_OWNER} apps. Ask us if you need more.")
            for _ in range(8):
                client_id = f"{slug}-{secrets.token_hex(3)}"
                added = self.database.execute(
                    "INSERT OR IGNORE INTO delta_clients (client_id, name, folded, homepage, contact, platforms, "
                    "scopes, status, owner, created, name_held) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)",
                    (client_id, name, fold(name), homepage, contact, ",".join(dict.fromkeys(platforms)),
                     scope_mask(scopes), owner, int(self.clock()), int(self.held_name(name)))).rowcount
                if added:
                    break
            else:
                raise Refused(503, "Try again in a moment.")
            self.database.commit()
        return self.get(client_id)

    # ---------- an admin's

    def set_status(self, client_id: str, status: str, allow_name: bool = False) -> dict:
        """a client approved or suspended; approving one whose name is held
        takes allow_name (the admin's say-so, logged by the caller)"""
        if status not in STATUSES:
            raise Refused(400, "Bad request.")
        client = self.get(client_id)
        if not client:
            raise Refused(404, "No such app.")
        if status == "approved" and client["name_held"] and not allow_name:
            raise Refused(409, "This name has Chupa or Delta in it. Approve the name too, if it's fine.")
        with self.lock:
            # (pending apps hold no names: the first approved keeps it, and
            # another with the same or a look-alike name is renamed first)
            if status == "approved" and client["status"] != "approved":
                refused = self._name_refused(client["name"], client["client_id"], "")
                if refused:
                    raise Refused(409, "An approved app has this name, or one like it. Rename this one first.")
            self.database.execute("UPDATE delta_clients SET status = ?, reviewed = ? WHERE client_id = ?",
                                  (status, int(self.clock()), client["client_id"]))
            self.database.commit()
        return self.get(client_id)

    def rename(self, client_id: str, name: str, allow_name: bool = False) -> dict:
        """(an admin's) a client's name changed: the name rules hold,
        against approved apps only, and a name with Chupa or Delta in it
        takes allow_name (the admin's say-so, logged by the caller)"""
        client = self.get(client_id)
        if not client:
            raise Refused(404, "No such app.")
        name = re.sub(r"\s+", " ", str(name or "")).strip()
        if not 3 <= len(name) <= NAME_MOST or re.search(r"[^ -~]", name):
            raise Refused(400, f"A name is 3 to {NAME_MOST} plain characters.")
        held = self.held_name(name)
        if held and not allow_name:
            raise Refused(409, "This name has Chupa or Delta in it. Allow the name too, if it's fine.")
        with self.lock:
            refused = self._name_refused(name, client["client_id"], "")
            if refused:
                raise Refused(409, refused)
            self.database.execute("UPDATE delta_clients SET name = ?, folded = ?, name_held = ? WHERE client_id = ?",
                                  (name, fold(name), int(held), client["client_id"]))
            self.database.commit()
        return self.get(client_id)

    def delete(self, client_id: str) -> dict:
        """(an admin's) a client gone from the table, its name free again;
        the caller revokes its devices first (identity.revoke_client).
        What it was"""
        client = self.get(client_id)
        if not client:
            raise Refused(404, "No such app.")
        with self.lock:
            self.database.execute("DELETE FROM delta_clients WHERE client_id = ?", (client["client_id"],))
            self.database.commit()
        return client

    def set_limits(self, client_id: str, body: dict) -> dict:
        """{"starts_per_hour"?, "tokens_per_hour"?, "scopes"?} (scopes only
        narrowed or widened within CLIENT_SCOPES, "moderate" only for an
        approved client; devices keep theirs until they sign in again, but
        never more than the client's: tokens are checked against it)"""
        client = self.get(client_id)
        if not client:
            raise Refused(404, "No such app.")
        starts = body.get("starts_per_hour", client["starts_per_hour"])
        tokens = body.get("tokens_per_hour", client["tokens_per_hour"])
        scopes = body.get("scopes")
        if not all(isinstance(n, int) and not isinstance(n, bool) for n in (starts, tokens)) or \
                not 1 <= starts <= STARTS_MOST or not 1 <= tokens <= TOKENS_MOST:
            raise Refused(400, "Limits are whole numbers, an hour's.")
        mask = client["scopes"]
        if scopes is not None:
            if not isinstance(scopes, list) or any(s not in CLIENT_SCOPES for s in scopes) or not scopes:
                raise Refused(400, "Pick the scopes from: " + ", ".join(CLIENT_SCOPES) + ".")
            if client["status"] != "approved" and any(s in ADMIN_ONLY_SCOPES for s in scopes):
                raise Refused(409, "Approve the app before giving it moderate.")
            mask = scope_mask(scopes)
        with self.lock:
            self.database.execute("UPDATE delta_clients SET starts_per_hour = ?, tokens_per_hour = ?, scopes = ? "
                                  "WHERE client_id = ?", (starts, tokens, mask, client["client_id"]))
            self.database.commit()
        return self.get(client_id)
