"""Which listed games the site's game list shows: only games a current
Chupathingy release can join. The same rule as the game's lists (the game
repository's port/linux/src/game_list_rules.h); /v1/games marks each game
"joinable" by it, and the pages show only those (?all=1 on the page shows
every game, for tests). The lists the game's builds read (/v1/games.txt, the
console list) and the stats keep every game, as before.

A game is joinable when:

- its host speaks Delta ("protocol": "delta"): its game wire decides on
  joining, whatever number it announces for OpenCE's builds; or
- its network version is in the range the signed Delta table gives
  Chupathingy's releases (the lowest "minimum" to the highest "maximum" of
  its wires: delta_legacy.json in --data, delta_table.py).

A GOAT H1 host closed to other builds advertises its version with bit 15
set (CLOSED_VERSION): never joinable. Neither is a game of a number outside
the range, nor one that says none (0). With no table read yet, only the
closed games are left out.

A game heard only on OpenCE's brokers (source "broker", not a Delta host) is
listed at all only when its network version is BROKER_MINIMUM_VERSION or
newer (broker_listed): older builds' listings are left out of /v1/games,
games.txt, the console list, the counts and Donut's feed, though a game of
theirs is still joined by its invite. The game's lists leave out the same
(game_list_rules.h: GAME_LIST_BROKER_MINIMUM_VERSION).

SPDX-FileCopyrightText: 2026 The Chupathingy contributors
SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: MIT
"""

import json
import threading
from pathlib import Path

# the bit a GOAT H1 host sets in its advertised version while its game is
# closed to other builds (its network.allow_opence off)
CLOSED_VERSION = 0x8000

TABLE = "delta_legacy.json"

# the oldest network version a broker listing is listed under
BROKER_MINIMUM_VERSION = 35


def table_range(table):
    """the network versions Chupathingy's releases join, by a legacy table
    (its wires' lowest minimum and highest maximum): (minimum, maximum), or
    None for no usable table"""
    if not isinstance(table, dict) or not isinstance(table.get("wires"), dict):
        return None
    minimums, maximums = [], []
    for row in table["wires"].values():
        if not isinstance(row, dict):
            continue
        low, high = row.get("minimum"), row.get("maximum")
        if isinstance(low, int) and isinstance(high, int) and not isinstance(low, bool) \
                and not isinstance(high, bool) and 0 < low <= high:
            minimums.append(low)
            maximums.append(high)
    return (min(minimums), max(maximums)) if minimums else None


def joinable(version, delta: bool, versions) -> bool:
    """whether a game is one a current release can join: version, the
    number its host advertises; delta, its host speaks Delta; versions, the
    range (minimum, maximum), or None when not known"""
    try:
        version = int(version or 0)
    except (TypeError, ValueError):
        version = 0
    if version & CLOSED_VERSION:
        return False
    if delta:
        return True
    if versions is None:
        return True
    return version != 0 and versions[0] <= version <= versions[1]


def broker_listed(game: dict) -> bool:
    """whether a listing is listed at all: any but a broker's (not a Delta
    host's) under a version older than BROKER_MINIMUM_VERSION"""
    if game.get("source") != "broker" or game.get("protocol") == "delta":
        return True
    try:
        version = int(game.get("version") or 0)
    except (TypeError, ValueError):
        version = 0
    return version & ~CLOSED_VERSION >= BROKER_MINIMUM_VERSION


def game_joinable(game: dict, versions) -> bool:
    """joinable for a /v1/games listing"""
    return joinable(game.get("version"), game.get("protocol") == "delta", versions)


class Versions:
    """the range from the table served in the data folder (delta_table.py
    puts only a checked one there), read again when the file changes"""

    def __init__(self, data):
        self.path = Path(data) / TABLE
        self.lock = threading.Lock()
        self.stamp = None
        self.range = None

    def get(self):
        try:
            stat = self.path.stat()
            stamp = (stat.st_mtime_ns, stat.st_size)
        except OSError:
            return None
        with self.lock:
            if stamp != self.stamp:
                try:
                    self.range = table_range(json.loads(self.path.read_bytes()))
                except (OSError, ValueError):
                    self.range = None
                self.stamp = stamp
            return self.range
