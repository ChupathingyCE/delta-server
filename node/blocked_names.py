"""Blocked names: names nobody may play or be shown under (slurs and hate).

Not the reserved names (list_server.py), which only their owner may take:
a blocked name is no one's. Where the site shows a player's in-game name
or a game's name (the pages' interface, the game list, carnage reports),
a blocked one is shown as REMOVED, its statistics kept as they are; a
listed game of a blocked name is not listed at all; a profile may not take
one as its profile name or display name.

The words: blocked_names.txt beside this file (built in; the dedicated
server ships the same list for sv_name_filter), and those the admin panel
adds (the blocked_names table: load_extra). Words are kept in ROT13, so
neither the list, the table nor the admin panel prints a slur; the panel
shows them masked (mask).

A name is compared as name_key makes it, and again with repeated letters
squeezed to one (squeeze): blocked if it is a "whole" word, or, once the
"allow" words (harmless words that contain a blocked one) are taken out,
if an "anywhere" word is in it.

SPDX-FileCopyrightText: 2026 The Chupathingy contributors
SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: GPL-3.0-or-later
"""

import codecs
import functools
import re
import threading
import unicodedata
from pathlib import Path

REMOVED = "[name removed]"
KINDS = ("anywhere", "whole", "allow")
LIST_FILE = Path(__file__).with_name("blocked_names.txt")

# letters other scripts draw like Latin ones, and digits and signs written for
# letters
LOOKALIKES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "к": "k", "м": "m", "н": "h", "т": "t", "в": "b", "α": "a", "ο": "o", "ρ": "p", "ι": "i", "κ": "k",
    "ν": "v", "τ": "t", "υ": "u", "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "@": "a", "$": "s", "!": "i", "|": "i"})


def name_key(name: str) -> str:
    """a name as the reserved and blocked names are compared: lower case,
    accents and separators gone, digits at its end dropped, look-alikes as
    the letters they look like, letters only"""
    text = unicodedata.normalize("NFKD", str(name or "").lower())
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = re.sub(r"[\s._\-]+", "", text)
    text = re.sub(r"[0-9]+$", "", text)
    return re.sub(r"[^a-z]", "", text.translate(LOOKALIKES))


def squeeze(key: str) -> str:
    """a key with each run of one letter made one ("aaa" -> "a")"""
    return re.sub(r"(.)\1+", r"\1", key)


def rot13(text: str) -> str:
    return codecs.encode(text, "rot13")


def mask(word: str) -> str:
    """a word as the admin panel shows it: its first letter and stars"""
    return word[:1] + "*" * max(len(word) - 1, 1)


def read_list(path: Path = LIST_FILE) -> list:
    """a list file's entries, [(kind, word)], words decoded (a missing file:
    none). Lines: "<kind> <word in ROT13>", # comments"""
    entries = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return entries
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) == 2 and parts[0] in KINDS:
            word = name_key(rot13(parts[1]))
            if word:
                entries.append((parts[0], word))
    return entries


BUILT_IN = read_list()
EXTRA = []  # [(kind, word)] added in the admin panel
_lock = threading.Lock()
_words = {}


def _rebuild():
    words = {kind: set() for kind in KINDS}
    for kind, word in BUILT_IN + EXTRA:
        words[kind].add(word)
    allow = sorted(words["allow"] | {squeeze(w) for w in words["allow"]}, key=len, reverse=True)
    global _words
    _words = {"anywhere": sorted(words["anywhere"]), "whole": words["whole"], "allow": allow}
    match.cache_clear()


def load_extra(database):
    """EXTRA read again from the blocked_names table"""
    rows = database.execute("SELECT kind, word FROM blocked_names").fetchall()
    with _lock:
        EXTRA[:] = [(kind, name_key(rot13(word))) for kind, word in rows if kind in KINDS]
        _rebuild()


def table(database):
    """the blocked_names table, added to a database (an older one too):
    words in ROT13, as name_key makes them"""
    database.execute("""CREATE TABLE IF NOT EXISTS blocked_names (
        kind TEXT NOT NULL, word TEXT NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (kind, word))""")


@functools.lru_cache(maxsize=65536)
def match(name: str):
    """the entry that blocks a name, (kind, word), or None"""
    key = name_key(name)
    if not key:
        return None
    words = _words
    variants = (key, squeeze(key))
    for word in variants:
        if word in words["whole"]:
            return ("whole", word)
    for variant in variants:
        for word in words["allow"]:
            variant = variant.replace(word, "|")
        for word in words["anywhere"]:
            if word in variant:
                return ("anywhere", word)
    return None


def blocked(name) -> bool:
    return isinstance(name, str) and match(name) is not None


def shown(name):
    """a name as the site shows it: REMOVED for a blocked one"""
    return REMOVED if blocked(name) else name


# the fields of the interface's answers that hold a player's in-game name or
# a game's or server's name (a string, or a list of them); "who" and an "id"
# may be "name:<name>", a player known only by name
NAME_FIELDS = frozenset({"name", "names", "display", "server_name", "played_as", "player", "players", "who",
                         "killer", "victim", "winner", "leader", "host", "holder", "by", "aliases"})


def _shown_field(value):
    if isinstance(value, str):
        if value.startswith("name:"):
            return "name:" + REMOVED if blocked(value[5:]) else value
        return shown(value)
    return value


def scrub(value):
    """an answer of the interface with every blocked name in it shown as
    REMOVED (a copy where anything changes; the rest as it was)"""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if key in NAME_FIELDS or key == "id":
                if isinstance(item, str):
                    item = _shown_field(item) if key != "id" or item.startswith("name:") else item
                elif isinstance(item, list) and key != "id":
                    item = [_shown_field(i) if isinstance(i, str) else scrub(i) for i in item]
                else:
                    item = scrub(item)
            else:
                item = scrub(item)
            out[key] = item
        return out
    if isinstance(value, list):
        return [scrub(item) for item in value]
    return value


def list_text() -> str:
    """the words, as the game's lists read them (/v1/blocked-names): the
    list file's lines, "<kind> <word in ROT13>", the admin panel's after"""
    lines = [f"{kind} {rot13(word)}" for kind, word in BUILT_IN + EXTRA]
    return "# Blocked names (ROT13): <kind> <word>\n" + "\n".join(lines) + "\n"


def entries() -> dict:
    """the words, as the admin panel lists them: masked, with their ROT13 (to
    remove an added one)"""
    def listed(pairs):
        return [{"kind": kind, "shown": mask(word), "entry": rot13(word)} for kind, word in sorted(pairs)]
    return {"built_in": listed(BUILT_IN), "extra": listed(EXTRA)}


_rebuild()
