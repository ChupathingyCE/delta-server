"""Delta List: the game list a node keeps (announce, withdraw, the JSON,
text and console lists).

Taken from the Chupathingy site's list server (list_server.py), cut to
what a node needs: hosts announce their games and repeat it while they
host; the list keeps them in memory only and never shows an address.

Not here yet (the site has them): the probe that checks a host can be
reached, games hosted from a profile, the OpenCE broker and master
listeners, server badges, playlists, the region lookup and the activity
counts. Each is a TODO in INVENTORY.md.

SPDX-FileCopyrightText: 2026 The Chupathingy contributors
SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: MIT
"""

import ipaddress
import re
import threading
import time
from urllib.parse import parse_qs

import blocked_names
import delta_list
import game_list_rules
import mcc_maps

EXPIRY = 75
MAXIMUM_GAMES = 512
MAXIMUM_GAMES_PER_ADDRESS = 4
REQUESTS_PER_MINUTE = 240
MAXIMUM_BODY = 2048
# (an announcement carries its roster: up to 128 names, URL-encoded)
MAXIMUM_ANNOUNCE_BODY = 32768
MAXIMUM_REPORT_PLAYERS = 128

INVITE = re.compile(r"^(?:[0-9a-f]{64}|[0-9a-f]{44})$")
FIELDS = {
    "name": 32,
    "map": 64,
}
# a game's roster, as its host announces it ("roster": "team:name|..."; team
# -1 without teams): at most this many players, each name this long (the
# game's 11 characters)
MAXIMUM_ROSTER = 128
ROSTER_NAME = 11

TEXT_FIELDS = ("invite", "name", "map", "engine", "players", "maximum_players", "open", "version", "age",
               "score_limit", "teams", "roster", "region", "platform", "hosting", "protocol", "machines", "gametype",
               "capabilities", "map_title", "map_pack", "map_tag", "playlist", "opence_server", "joins_locked",
               "badge", "badge_label", "badge_key")
TEXT_FIELDS_READ = 12
# the engine number a Bomb game announces (retail Halo has no 6: a browser
# that does not know it shows a Race game) and the text list's field count
# from which a client has asked for capabilities, so knows Bomb
ENGINE_BOMB = 6
TEXT_FIELDS_BOMB = TEXT_FIELDS.index("capabilities") + 1
# the console list (/v1/console/games; README): its format's version, at most
# this many games, each line at most this many bytes (its line break apart),
# made again at most this often
CONSOLE_FORMAT = 1
CONSOLE_GAMES = 64
# the maps a console can join a game on: the Xbox game's own multiplayer
# maps (a console has no Halo PC, HaloMD or custom maps)
CONSOLE_MAPS = frozenset(("beavercreek", "bloodgulch", "boardingaction", "carousel", "chillout", "damnation",
                          "hangemhigh", "longest", "prisoner", "putput", "ratrace", "sidewinder", "wizard"))
CONSOLE_LINE = 255
# the most players a console's game takes (every console build since
# 2026-10-21 takes 32: the Xbox's default, the Wii U and the 360); a game set
# for more is left out of the console list, since the console leaves it as
# soon as it joins. A build that takes another number asks with ?players=N
# (newer Xbox builds always ask: a stock one asks for 16).
CONSOLE_MAXIMUM_PLAYERS = 32
# the console builds' player counts (configure.py --console-players), asked with ?players=N
CONSOLE_PLAYER_BUILDS = frozenset((16, 24, 32, 64))
CONSOLE_CACHE = 5
CONSOLE_PATH = "/v1/console/games"
# the ping anchors' lines (list.anchors_file): "anchor<TAB>host<TAB>port<TAB>regions",
# host names only, never an address
ANCHOR_LINE = re.compile(r"anchor\t[A-Za-z0-9.-]{1,63}\t\d{1,5}\t[A-Z]{2}(?:-[A-Z]{2})?(?:,[A-Z]{2}(?:-[A-Z]{2})?)*")
PRIVATE_FIELDS = ("address", "host_address", "time", "listed", "reported", "expires_in", "host_report", "official")
ENGINE_NUMBERS = {"ctf": 1, "slayer": 2, "oddball": 3, "king": 4, "race": 5, "bomb": 6}
CAMPAIGN_MAPS = ("a10", "a30", "a50", "b30", "b40", "c10", "c20", "c40", "d20", "d40")


def rate_key(address: str) -> str:
    """an address as the limits count it: an IPv6 address by its /64 (a
    home or a server is given a whole /64), an IPv4 one as it is"""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return address
    if parsed.version == 6:
        if parsed.ipv4_mapped:
            return str(parsed.ipv4_mapped)
        return str(ipaddress.ip_network(f"{parsed}/64", strict=False))
    return str(parsed)


def host_address(value) -> str:
    """an address as the probe gives it, checked: "" if it is none"""
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""


def public(game: dict) -> dict:
    """a listing as the page and the interface show it: no address"""
    return {k: v for k, v in game.items() if k not in PRIVATE_FIELDS}


def clean_text(value: str, limit: int) -> str:
    """printable text only (no tabs or line breaks: the text list's
    separators), at most limit characters"""
    value = "".join(c for c in value if c.isprintable() and c not in "\t\r\n")
    return value.strip()[:limit]


def clean_roster(value: str) -> list:
    """a host's roster ("team:name|team:name", team -1 without teams) as
    [{"team", "name"}]; a malformed entry is left out"""
    roster = []
    for entry in value.split("|")[:MAXIMUM_ROSTER]:
        team, _, name = entry.partition(":")
        name = clean_text(name, ROSTER_NAME)
        try:
            team = clean_integer(team, -1, MAXIMUM_REPORT_PLAYERS - 1)
        except ValueError:
            continue
        if name:
            roster.append({"team": team, "name": name})
    return roster


def knows_bomb_agent(agent: str) -> bool:
    """whether a User-Agent is a Chupathingy client's (the game's browser
    sends "chupathingyce-browser"), which knows Bomb whatever fields it asks"""
    return agent.lower().startswith("chupathingyce")


def text_field(game: dict, name: str) -> str:
    """a listing's field as the text list gives it (no tab or line break in
    any: clean_text, delta_list.py)"""
    if name == "roster":
        return roster_text(game.get("roster", []))
    if name == "machines":
        return delta_list.machines_text(game.get("machines") or {})
    if name == "opence_server":
        return "opence_server" if game.get("opence_dedicated") is True else ""
    if name == "joins_locked":
        return "1" if game.get("joins_locked") else "0"
    return str(game.get(name, ""))


def roster_text(roster: list) -> str:
    """a roster as the text list's column: "team:name|team:name" """
    return "|".join(f"{player['team']}:{player['name'].replace('|', '')}" for player in roster)


def console_text(value, limit: int) -> str:
    """a field of the console list: printable ASCII only (any other
    character "?", tabs and line breaks left out), at most limit characters"""
    value = "".join(c if " " <= c <= "~" else "?" for c in str(value) if c not in "\t\r\n")
    return value.strip()[:limit]


def console_state(game: dict) -> str:
    """a listing's state as the console list gives it: open, full, closed,
    or playing (under way and not taking players, from listings that say).
    A game under way that takes players is open: the consoles join only
    open games, and a PC joins it in progress (OpenCE's public games say
    they are under way while they take players)"""
    if not game.get("open"):
        return "playing" if game.get("in_progress") else "closed"
    if 0 < game.get("maximum_players", 0) <= game.get("players", 0):
        return "full"
    return "open"


def console_map(name) -> str:
    """a map as the console list gives it: the scenario's short name
    (levels\\test\\bloodgulch\\bloodgulch as bloodgulch), with a Halo PC or
    HaloMD map's @ce or @md kept"""
    name = str(name or "").strip().replace("/", "\\")
    name, at, suffix = name.partition("@")
    name = name.rstrip("\\").rsplit("\\", 1)[-1].strip()
    return name + (at + suffix.lower() if at else "") if name else ""


def console_gametype(game: dict, engine: int, engines: dict) -> str:
    """a listing's gametype as the console list gives it: its own name, or
    the engine's where it has none, or none the console can show (only "?",
    a name in characters outside ASCII); "co-op" for a co-op game"""
    if game_mode(game.get("map")) == "coop":
        return "co-op"
    gametype = console_text(game.get("gametype") or "", 24)
    if not gametype.replace("?", "").strip():
        return engines.get(engine, "")
    return gametype


def console_list(games: list, maximum_players: int = CONSOLE_MAXIMUM_PLAYERS, packs: bool = False,
                 coop: bool = False) -> str:
    """the console list (README, The console list): a header line
    "warthog-list <format> <count>", a line a game, tab separated (invite name
    map engine gametype players maximum_players version region state), and
    "end"; ASCII, no address, CONSOLE_GAMES lines of CONSOLE_LINE bytes at
    most; the map's short name (console_map), a gametype the console can show
    (console_gametype); only games on the Xbox's own multiplayer maps
    (CONSOLE_MAPS), none co-op; with coop (a console that joins co-op games
    asks ?coop=1), the co-op games on the Xbox's own campaign levels too;
    and with packs (a console that plays Xbox map packs asks ?packs=1), the
    games on a pack's maps (wizard@cex), each with its map's name and its
    pack's tag in fields 14 and 15"""
    engines = {number: name for name, number in ENGINE_NUMBERS.items()}
    lines = []
    for game in games:
        if len(lines) >= CONSOLE_GAMES:
            break
        invite = str(game.get("invite", ""))
        map_name = console_text(console_map(game.get("map")), FIELDS["map"])
        if not map_name or not INVITE.match(invite):
            continue
        engine = game.get("engine", 0) if isinstance(game.get("engine"), int) else 0
        if mcc_maps.is_mcc(game.get("map")):
            continue  # (an MCC map: no console plays one, whatever its level's name)
        if engine == ENGINE_BOMB:
            continue  # (the console build has no Bomb: it would show a Race game it cannot join)
        # (only games a console can join: on the Xbox's own multiplayer maps,
        # not co-op unless asked for, then only on the Xbox's own campaign
        # levels (a10, not a Halo PC copy's a10@ce); a stock 64 MB Xbox reads
        # the list into what memory it has left, so rows it could never join
        # are not sent)
        pack_map = packs and bool(delta_list.pack_id(map_name))
        if game_mode(game.get("map")) == "coop":
            if not coop or map_name.lower() not in CAMPAIGN_MAPS:
                continue
        elif map_name.lower() not in CONSOLE_MAPS and not pack_map:
            continue
        if int(game.get("maximum_players", 0) or 0) > maximum_players:
            continue
        fields = (invite, console_text(game.get("name", ""), FIELDS["name"]) or "Halo",
                  map_name, str(engine),
                  console_gametype(game, engine, engines),
                  str(int(game.get("players", 0))), str(int(game.get("maximum_players", 0))),
                  str(int(game.get("version", 0))), console_text(game.get("region", ""), 16), console_state(game))
        line = "\t".join(fields)
        # (format 1's later fields, which a version 1 reader passes over:
        # the host's platform, hosting and protocol; left off a line they
        # would make too long)
        extra = [console_text(value, 16) for value in delta_list.console_fields(game)]
        # (a pack's map's name and tag, for a console that asked for packs;
        # its line kept whole or left out, never sent without them)
        # (then an OpenCE dedicated server's label, field 16, after the
        # pack's two, kept empty for another map)
        extra = extra[:3] + ([console_text(game.get("map_title", ""), 32), console_text(game.get("map_tag", ""), 4)]
                             if pack_map else ["", ""]) + extra[5:6]
        while extra and not extra[-1]:
            extra.pop()
        extended = "\t".join(fields + tuple(extra))
        if len(extended) <= CONSOLE_LINE:
            lines.append(extended)
        elif len(line) <= CONSOLE_LINE and not pack_map:
            lines.append(line)
    return "".join(f"{line}\n" for line in [f"warthog-list {CONSOLE_FORMAT} {len(lines)}"] + lines + ["end"])


def console_packs(query: str) -> bool:
    """whether the asking console plays Xbox map packs (?packs=1: a Warthog
    build with map packs); an older build's list has none of their games"""
    return parse_qs(query).get("packs", [""])[0] == "1"


def console_coop(query: str) -> bool:
    """whether the asking console joins co-op games (?coop=1: a Warthog
    build with the list's Co-op filter); an older build's list has none"""
    return parse_qs(query).get("coop", [""])[0] == "1"


def console_players(query: str) -> int:
    """the players the asking console's build takes (?players=N: 16 for a
    stock Xbox build, 32 for a test build), else CONSOLE_MAXIMUM_PLAYERS (32:
    an older build that does not say)"""
    try:
        players = int(parse_qs(query).get("players", [""])[0])
    except ValueError:
        return CONSOLE_MAXIMUM_PLAYERS
    return players if players in CONSOLE_PLAYER_BUILDS else CONSOLE_MAXIMUM_PLAYERS




def game_mode(map_name) -> str:
    """a game's mode by its map: "coop" on a campaign level (a10, or
    levels\\a10\\a10, any case, from any source: an announcement, an OpenCE
    public game's listing, the probe; a Halo PC copy's a10@ce too), else
    "multiplayer"."""
    mcc = mcc_maps.parse(map_name)
    if mcc:
        return "coop" if mcc["level"] in CAMPAIGN_MAPS else "multiplayer"
    name = str(map_name or "").strip().lower().replace("/", "\\").partition("@")[0]
    name = name.rstrip("\\").rsplit("\\", 1)[-1].strip()
    if name.endswith(".map"):
        name = name[:-4]
    return "coop" if name in CAMPAIGN_MAPS else "multiplayer"



def clean_integer(value: str, low: int, high: int) -> int:
    number = int(value)
    if not low <= number <= high:
        raise ValueError(value)
    return number



def invite_locked(invite: str, locked_slots) -> bool:
    """whether an invite is of a host whose broker listing has a password:
    its first 32 hex digits are the listing's slot (lobby.py)"""
    return len(invite) == 64 and invite[:32].lower() in locked_slots


def publicly_listed(game: dict) -> bool:
    """whether a listed game is shown outside (the pages, the game's lists,
    the counts, Donut's feed): not one of a blocked name (blocked_names.py),
    nor an older build's broker listing (game_list_rules.broker_listed)"""
    return not blocked_names.blocked(game.get("name")) and game_list_rules.broker_listed(game)


def parse_announce(form: dict) -> dict:
    """an announcement's form fields, checked (list_server.py's POST
    /v1/announce): ValueError for a bad one"""
    fields = {
        "invite": form.get("invite", "").lower(),
        "name": clean_text(form.get("name", ""), FIELDS["name"]) or "Halo",
        "map": clean_text(form.get("map", ""), FIELDS["map"]),
        "engine": clean_integer(form.get("engine", "0"), 0, 15),
        # (newer builds' variant name: "Grifball" for engine 6)
        "gametype": clean_text(form.get("gametype", ""), 24),
        "players": clean_integer(form.get("players", "0"), 0, 255),
        "maximum_players": clean_integer(form.get("maximum_players", "0"), 0, 255),
        "open": clean_integer(form.get("open", "0"), 0, 1),
        "version": clean_integer(form.get("version", "0"), 0, 65535),
        "score_limit": clean_integer(form.get("score_limit", "0"), 0, 32767),
        "teams": clean_integer(form.get("teams", "0"), 0, 1),
        "roster": clean_roster(form.get("roster", "")),
        # (newer dedicated servers: locked=1 while sv_lock keeps new players out)
        "joins_locked": form.get("locked", "0") == "1",
        # (newer builds': each optional, a malformed one left out)
        "host_report": delta_list.parse_announce(form),
    }
    if not INVITE.match(fields["invite"]):
        raise ValueError("bad invite")
    if not fields["map"]:
        raise ValueError("bad map")
    return fields


class GameList:
    """the announced games, in memory only (list_server.py's GameList
    without the probe, hosted games or the OpenCE listeners).

    TODO(federation): a node may also show other nodes' lists; see
    delta-spec's federation.md. Nothing is fetched from another node yet."""

    def __init__(self, games_per_address: int = MAXIMUM_GAMES_PER_ADDRESS, region=lambda address: "",
                 clock=time.monotonic):
        self.lock = threading.Lock()
        self.games = {}  # invite -> record
        self.requests = {}  # address -> [times]
        self.games_per_address = games_per_address
        self.region = region
        self.clock = clock
        # (OpenCE broker slots whose listing has a password: none here yet,
        # kept so the social answers read the same as the site's)
        self.locked_slots = set()

    def allow(self, address: str) -> bool:
        address = rate_key(address)
        now = self.clock()
        with self.lock:
            times = [t for t in self.requests.get(address, []) if now - t < 60]
            if len(times) >= REQUESTS_PER_MINUTE:
                self.requests[address] = times
                return False
            times.append(now)
            self.requests[address] = times
            return True

    def expire(self):
        now = self.clock()
        with self.lock:
            for invite in [i for i, g in self.games.items() if now - g["time"] > EXPIRY]:
                del self.games[invite]
            for address in [a for a, t in self.requests.items() if not t or now - t[-1] > 60]:
                del self.requests[address]

    def announce(self, address: str, fields: dict) -> str:
        """a game's announcement: "" if taken, else why not"""
        invite = fields["invite"]
        now = self.clock()
        record = {
            "invite": invite,
            "name": fields["name"],
            "map": fields["map"],
            "engine": fields["engine"],
            "gametype": fields.get("gametype", ""),
            "players": fields["players"],
            "maximum_players": fields["maximum_players"],
            "open": fields["open"],
            "version": fields["version"],
            "score_limit": fields["score_limit"],
            "teams": fields["teams"],
            "roster": fields.get("roster", []),
            "joins_locked": bool(fields.get("joins_locked")),
            "host_report": fields.get("host_report", {}),
            "official": False,
            "region": self.region(address),
            "address": address,
            "host_address": address,
            "time": now,
            "listed": now,
        }
        with self.lock:
            existing = self.games.get(invite)
            if existing and existing["address"] != address:
                return "the invite is listed from another address"
            if existing:
                record["listed"] = existing.get("listed", record["listed"])
                record["verified"] = existing.get("verified", False)
                self.games[invite] = record
                return ""
            if sum(1 for g in self.games.values() if rate_key(g["address"]) == rate_key(address)) >= \
                    self.games_per_address:
                return "too many games from this address"
            if len(self.games) >= MAXIMUM_GAMES:
                return "the list is full"
            # (TODO: the site probes a new game and marks it verified once
            # reached; a node without a probe lists it unverified)
            record["verified"] = False
            self.games[invite] = record
            return ""

    def withdraw(self, address: str, invite: str):
        with self.lock:
            game = self.games.get(invite)
            if game and game["address"] == address:
                del self.games[invite]

    def snapshot(self) -> list:
        """the list as the interface shows it, no address"""
        now = self.clock()
        with self.lock:
            games = sorted(self.games.values(),
                           key=lambda g: (game_mode(g["map"]) == "coop", -g["players"], g["name"].lower()))
            return [dict(public(g), age=int(now - g["time"]), region=g.get("region", ""), mode=game_mode(g["map"]),
                         verified=bool(g.get("verified")), counted=True, source="announced",
                         **delta_list.listing_fields(g, "announced", game_mode(g["map"])))
                    for g in games]

    def public_snapshot(self) -> list:
        """snapshot without the games of a blocked name, a blocked player
        name in a roster shown as blocked_names.REMOVED"""
        with self.lock:
            locked_slots = set(self.locked_slots)
        games = []
        for game in self.snapshot():
            if not publicly_listed(game):
                continue
            game = blocked_names.scrub(game)
            game["locked"] = invite_locked(game["invite"], locked_slots)
            if game["locked"]:
                game["invite"] = ""
            games.append(game)
        return games


class ConsoleCache:
    """the console list made at most each CONSOLE_CACHE seconds"""

    def __init__(self):
        self.lock = threading.Lock()
        self.made = {}

    def get(self, games: GameList, maximum_players: int = CONSOLE_MAXIMUM_PLAYERS, packs: bool = False,
            coop: bool = False) -> str:
        now = time.monotonic()
        with self.lock:
            made = self.made.get((maximum_players, packs, coop))
            if made is None or now - made[0] >= CONSOLE_CACHE:
                made = (now, console_list(games.public_snapshot(), maximum_players, packs, coop))
                self.made[(maximum_players, packs, coop)] = made
            return made[1]
