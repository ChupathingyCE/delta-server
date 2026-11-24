"""Delta List's extras: what a ChupathingyCE host says of itself when it
announces its game, and what the list shows of every game from it (the
game's docs/delta.md, Delta List; list_server.py).

A host's announcement (POST /v1/announce) may carry, beside the fields every
build sends, these optional form fields (ChupathingyCE 0.7.1b and later; an
older build sends none of them, and a list from before them ignores them):

    delta         the Delta major it hosts with (1), or 0: hosted without
                  Delta Peer (network.protocol = "opence", or its port taken)
    platform_key  the host machine's Delta platform key, 16 hexadecimal
                  digits (8 bytes: platform, key version, flags, host_players,
                  join_players, join_players_opt_in, memory_class, reserved);
                  a longer key (a later version) is read for these 8
    arch          the build's architecture: x64, x86, arm64 or arm
    build         its version ("0.7.1b")
    capabilities  the Delta capabilities it offers, 8 hexadecimal digits
    machines      its game's machines by platform, as Delta Peer knows them
                  ("pc_linux:2,xbox:1,legacy:1"): counts only, no player.
                  legacy: a machine without Delta (OpenCE's); unknown: a
                  Delta machine that does not share its platform. A
                  dedicated server leaves itself out (it has no players)
    map_title     an Xbox map pack's map's name ("Gothra"), map_pack its
    map_pack      pack's name ("Halo CE+") and map_tag the pack's short tag
    map_tag       ("CE+"), for a map of a pack (<file>@<pack>): printable
                  ASCII, at most 47, 47 and 4 characters (since map packs); an
                  MCC map's own name ("Blood Gulch" for mcc_maps\<item>\20)
                  with map_tag "MCC" (since 0.9.1a)
    workshop_id   an MCC map's Steam Workshop item id (decimal digits), from
                  the settings' Workshop tail, when its package folder
                  isn't the id itself; workshop_title the tail's title
                  (printable ASCII, at most 47, none blocked_names.py blocks):
                  what the site shows on that game alone until Steam's
                  title is known (mcc_maps.py)
    badge_cert, badge_time, badge_signature
                  a dedicated server's badge certificate (hex) and its proof
                  of holding the certificate's key: Unix seconds, and that
                  key's signature (server_badges.py; list_server.py checks
                  them, never parse_announce)

Each is checked on its own; one that is malformed is left out, never the
announcement. From them, and from where a listing came from, each game in
/v1/games gets:

    platform  the host's platform (PLATFORMS), "" if it did not say
    hosting   "official" (one of our dedicated servers: --official-hosts),
              "dedicated" (anyone's dedicated server), "player" (a player's
              copy of the game), "" not known
    protocol  "delta", "opence" (an OpenCE host, or one hosting without
              Delta: the legacy protocol alone), "" not known
    family    the map's: "xbox", "ce" (Halo PC Custom Edition, <file>@ce),
              "pc" (Halo PC retail, <file>@pc), "md" (HaloMD, <file>@md),
              "pack" (an Xbox map pack's, <file>@<pack>: Halo CE+'s
              wizard@cex), "mcc" (an MCC map, mcc_maps\<package>\<level>)
    map_title, map_pack, map_tag   a pack map's names, as its host says
              them; an MCC map's name (its host's map_title, else its
              workshop_title) tagged "MCC"; else "" 
    workshop_id, workshop_title   an MCC map's Steam Workshop item (its
              package folder's digits, or its host's workshop_id) and the
              title its host says, else "" 
    origin    "chupathingyce" (announced by a ChupathingyCE build or
              server) or "opence" (OpenCE's broker, or a game with no clear
              origin); the site lists the two apart
    machines  {platform: count} from a Delta host, else {}
    arch, build   a ChupathingyCE host's, else ""
    opence_dedicated  true for an OpenCE dedicated server's game (its
              listing has OpenCE's dedicated flag, 32, without ours, 128:
              lobby.py; or an OpenCE master lists it as dedicated:
              opence_masters.py), else false; the site's neutral "OpenCE
              dedicated" label, never a badge
    badge     "official", "developer" or "community": a dedicated server's
              signed badge, checked on each announcement (server_badges.py:
              a badge key's certificate, not expired or revoked, and the
              server's proof that it holds the key the certificate names);
              "" for every other game. badge_label: the certificate's label
              (a developer's handle, a group), "" if none. badge_key: the
              server key the certificate names (64 hexadecimal digits, ""
              if none), so a game can match the proof it gets on joining.
              hosting is not changed by them

Nothing here is an address, and nothing names a player.

SPDX-FileCopyrightText: 2026 The Chupathingy contributors
SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: MIT
"""

import re

import blocked_names
import mcc_maps

# the platform registry (the game's delta.h, enum delta_platform): a key's
# first byte, never reused
PLATFORMS = ("unknown", "pc_windows", "pc_macos", "pc_linux", "android", "steam_deck", "xbox", "xbox360", "wiiu",
             "switch", "psp", "vita", "xbox_uwp", "pc_freebsd", "ps3", "ps4", "ps5", "n64", "pc_legacy", "steamlink", "ios",
             "tvos", "dreamcast")
PLATFORM_LABELS = {
    "unknown": "Unknown", "pc_windows": "Windows", "pc_macos": "Mac", "pc_linux": "Linux", "android": "Android",
    "steam_deck": "SteamOS", "xbox": "Xbox", "xbox360": "Xbox 360", "wiiu": "Wii U", "switch": "Switch",
    "psp": "PSP", "vita": "Vita", "xbox_uwp": "Xbox Series", "pc_freebsd": "FreeBSD", "ps3": "PS3", "ps4": "PS4",
    "ps5": "PS5", "n64": "Nintendo 64", "pc_legacy": "Legacy PC", "steamlink": "Steam Link", "ios": "iPhone and iPad",
    "tvos": "Apple TV", "dreamcast": "Dreamcast",
}
# the filters' groups of platforms
PLATFORM_GROUPS = {
    "pc": ("pc_windows", "pc_macos", "pc_linux", "pc_freebsd", "pc_legacy"),
    "console": ("xbox", "xbox360", "wiiu", "switch", "xbox_uwp", "ps3", "ps4", "ps5", "n64", "steamlink", "tvos", "dreamcast"),
    "handheld": ("android", "steam_deck", "psp", "vita", "ios"),
}
# the platform key's flags (delta.h, DELTA_PLATFORM_KEY_*)
KEY_OPTED_IN = 0x01
KEY_DEDICATED = 0x02
ARCHES = ("x64", "x86", "arm64", "arm")
# a machine mix's names: the registry's, and a machine without Delta
MACHINE_NAMES = PLATFORMS + ("legacy",)
MAXIMUM_MACHINES = 128
DELTA_MAJORS = range(0, 16)
FAMILIES = ("xbox", "ce", "pc", "md", "pack", "mcc")
# an Xbox map pack's name (the game's halo_map_families.h): 1 to 8 letters
# and digits, none of the Halo PC families' nor the Xbox's language folders'
PACK_ID = re.compile(r"[a-z0-9]{1,8}")
RESERVED_PACK_IDS = frozenset(("ce", "md", "pc", "de", "fr", "es", "it"))
# an announced pack map's names: their fields and lengths
MAP_PACK_FIELDS = (("map_title", 47), ("map_pack", 47), ("map_tag", 4))
HOSTINGS = ("official", "dedicated", "player")
PROTOCOLS = ("delta", "opence")
MODES = ("multiplayer", "coop")
# what a listing's filters take (/v1/games?platform=...): each a comma list;
# "" is "not known" for platform, hosting and protocol
FILTERS = {
    "platform": PLATFORMS + tuple(PLATFORM_GROUPS) + ("dedicated", ""),
    "family": FAMILIES,
    "mode": MODES,
    "hosting": HOSTINGS + ("",),
    "protocol": PROTOCOLS + ("",),
}
BUILD = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,23}\Z")
HEX = re.compile(r"^[0-9a-fA-F]+\Z")


def decode_key(text: str):
    """a platform key from its hexadecimal digits: {"platform", "version",
    "dedicated", "opted_in", "host_players", "join_players",
    "join_players_opt_in", "memory_class"}, or None. A platform this list
    doesn't know is "unknown"; a longer key (a later version's) is read for
    the 8 bytes this one knows"""
    text = str(text or "").strip()
    if not 16 <= len(text) <= 64 or len(text) % 2 or not HEX.match(text):
        return None
    key = bytes.fromhex(text[:16])
    if key[1] < 1:
        return None
    return {"platform": PLATFORMS[key[0]] if key[0] < len(PLATFORMS) else "unknown", "version": key[1],
            "dedicated": bool(key[2] & KEY_DEDICATED), "opted_in": bool(key[2] & KEY_OPTED_IN),
            "host_players": key[3], "join_players": key[4], "join_players_opt_in": key[5], "memory_class": key[6]}


def parse_machines(text: str) -> dict:
    """a machine mix ("pc_linux:2,xbox:1,legacy:1") as {name: count}: names
    this list doesn't know are "unknown"; {} if it is malformed"""
    machines = {}
    text = str(text or "").strip()
    if not text:
        return {}
    for part in text.split(",")[:len(MACHINE_NAMES) + 8]:
        name, _, count = part.strip().partition(":")
        name = name.strip().lower()
        if not re.fullmatch(r"[a-z0-9_]{1,24}", name) or not re.fullmatch(r"\d{1,3}", count.strip()):
            return {}
        name = name if name in MACHINE_NAMES else "unknown"
        machines[name] = machines.get(name, 0) + int(count)
    machines = {name: count for name, count in machines.items() if count > 0}
    if sum(machines.values()) > MAXIMUM_MACHINES:
        return {}
    return machines


def machines_text(machines: dict) -> str:
    """a machine mix as the text list gives it ("pc_linux:2,xbox:1"), in the
    registry's order, legacy last"""
    return ",".join(f"{name}:{machines[name]}" for name in MACHINE_NAMES if machines.get(name))


def parse_announce(form: dict) -> dict:
    """an announcement's Delta fields (see the top), each checked on its own:
    {"delta", "key", "arch", "build", "capabilities", "machines"}, those sent
    and well formed only; {} from a build that sends none"""
    host = {}
    if "delta" in form and re.fullmatch(r"\d{1,2}", str(form["delta"]).strip()):
        major = int(str(form["delta"]).strip())
        if major in DELTA_MAJORS:
            host["delta"] = major
    key = decode_key(form.get("platform_key", ""))
    if key:
        host["key"] = key
    arch = str(form.get("arch", "")).strip().lower()
    if arch in ARCHES:
        host["arch"] = arch
    build = str(form.get("build", "")).strip()
    if BUILD.match(build):
        host["build"] = build
    capabilities = str(form.get("capabilities", "")).strip()
    if 1 <= len(capabilities) <= 8 and HEX.match(capabilities):
        host["capabilities"] = int(capabilities, 16)
    if "machines" in form:
        machines = parse_machines(form["machines"])
        if machines:
            host["machines"] = machines
    # (an Xbox map pack's map's names: printable ASCII, else left out)
    for name, limit in MAP_PACK_FIELDS:
        value = str(form.get(name, "")).strip()
        if value and len(value) <= limit and all(" " <= c <= "~" for c in value):
            host[name] = value
    # (an MCC map's Workshop item and title, from the settings' Workshop tail)
    workshop = mcc_maps.clean_workshop_id(form.get("workshop_id", ""))
    if workshop:
        host["workshop_id"] = workshop
    title = str(form.get("workshop_title", "")).strip()
    if title and len(title) <= 47 and all(" " <= c <= "~" for c in title) and not blocked_names.blocked(title):
        host["workshop_title"] = title
    # (the playlist a dedicated server plays, HALO_PLAYLIST_ID: an id)
    playlist = str(form.get("playlist", "")).strip()
    if re.fullmatch(r"[a-z0-9_]{1,32}", playlist):
        host["playlist"] = playlist
    return host


def pack_id(map_name) -> str:
    """an Xbox map pack's map's pack (<file>@<pack>, in lowercase), else "" """
    file, at, suffix = str(map_name or "").strip().lower().rpartition("@")
    if at and file and PACK_ID.fullmatch(suffix) and suffix not in RESERVED_PACK_IDS:
        return suffix
    return ""


def family(map_name) -> str:
    """a map's family by its name: <file>@ce Custom Edition, <file>@pc Halo
    PC retail, <file>@md HaloMD, mcc_maps\<package>\<level> MCC, else the
    Xbox's"""
    if mcc_maps.is_mcc(map_name):
        return "mcc"
    suffix = str(map_name or "").strip().lower().rpartition("@")
    if suffix[1] and suffix[2] in ("ce", "pc", "md"):
        return suffix[2]
    if pack_id(map_name):
        return "pack"
    return "xbox"


def origin(game: dict, source: str, fields: dict) -> str:
    """where a game comes from, for the list's two sections: ours when its
    host announced it itself (only our builds and servers do), or it says it
    is a ChupathingyCE build or hosts with Delta; else OpenCE's (its broker,
    or a game of no clear origin)"""
    if source == "broker":
        return "opence"
    if source == "announced" or fields["build"] or fields["protocol"] == "delta" or fields["hosting"] in ("official", "dedicated"):
        return "chupathingyce"
    return "opence"


def listing_fields(game: dict, source: str, mode: str) -> dict:
    """the fields /v1/games shows of a listing (see the top): from its
    host's announcement (game["host_report"], parse_announce's), or what its
    source says (an OpenCE public game is OpenCE's protocol)"""
    host = game.get("host_report") or {}
    key = host.get("key") or {}
    fields = {"platform": key.get("platform", ""), "hosting": "", "protocol": "", "family": family(game.get("map")),
              "machines": {}, "arch": host.get("arch", ""), "build": host.get("build", ""), "capabilities": "",
              "badge": "", "badge_label": "", "badge_key": ""}
    # (an Xbox map pack's map's names, as its host says them)
    for name, _ in MAP_PACK_FIELDS:
        fields[name] = host.get(name, "") if fields["family"] == "pack" else ""
    # (an MCC map's Workshop item: its package folder's digits, else its host's word)
    mcc = mcc_maps.parse(game.get("map"))
    fields["workshop_id"] = (mcc["workshop_id"] or host.get("workshop_id", "")) if mcc else ""
    fields["workshop_title"] = host.get("workshop_title", "") if mcc else ""
    # (an MCC map's name for players without it, marked MCC: its host's
    # ("Blood Gulch": a Workshop item's file may be just a number, "20"),
    # else the item's title its host says)
    if mcc:
        title = host.get("map_title", "")
        if not title or blocked_names.blocked(title):
            title = fields["workshop_title"]
        fields["map_title"] = title
        fields["map_tag"] = "MCC" if title else ""
    fields["opence_dedicated"] = False
    if source == "broker":
        fields["protocol"] = "opence"
        fields["origin"] = "opence"
        fields["opence_dedicated"] = bool(game.get("opence_dedicated"))
        return fields
    if source != "announced":
        fields["origin"] = origin(game, source, fields)
        return fields
    # (8 hexadecimal digits, as announced: the game's Online Games pings only
    # the hosts whose ping bit, 12, is set)
    if "capabilities" in host:
        fields["capabilities"] = f"{host['capabilities']:08x}"
    if key:
        fields["hosting"] = ("official" if game.get("official") else "dedicated") if key.get("dedicated") else "player"
    # (checked by list_server.py on the announcement, from a dedicated
    # server alone: server_badges.py)
    if key.get("dedicated") and host.get("badge"):
        fields["badge"] = host["badge"]["tier"]
        fields["badge_label"] = host["badge"]["label"]
        fields["badge_key"] = host["badge"].get("key", "")
    if "delta" in host:
        fields["protocol"] = "delta" if host["delta"] else "opence"
    if host.get("delta") and host.get("machines"):
        fields["machines"] = dict(host["machines"])
    fields["origin"] = origin(game, source, fields)
    return fields


def parse_filters(query: dict) -> dict:
    """/v1/games's filters ({name: "a,b"}) as {name: set}; ValueError for a
    value no filter takes"""
    filters = {}
    for name, allowed in FILTERS.items():
        if name not in query:
            continue
        values = {value.strip().lower() for value in str(query[name]).split(",")}
        if not values or len(values) > len(allowed) or not values <= set(allowed):
            raise ValueError(name)
        filters[name] = values
    return filters


def matches(game: dict, filters: dict) -> bool:
    """whether a listing (with listing_fields's fields and "mode") is one the
    filters ask for: any of each filter's values, every filter"""
    for name, values in filters.items():
        if name == "platform":
            wanted = set()
            for value in values:
                wanted.update(PLATFORM_GROUPS.get(value, (value,)))
            dedicated = "dedicated" in values and game.get("hosting") in ("official", "dedicated")
            if game.get("platform", "") not in wanted and not dedicated:
                return False
        elif game.get(name, "") not in values:
            return False
    return True


def console_fields(game: dict) -> tuple:
    """the console list's trailing fields (after its tenth): the host's
    platform, its hosting and its protocol, as listing_fields gives them,
    then an Xbox map pack's map's name and its pack's tag (fields 14 and
    15; a console of a build before them reads none), then "opence_server"
    for an OpenCE dedicated server's game (field 16), else empty"""
    return (game.get("platform", ""), game.get("hosting", ""), game.get("protocol", ""), game.get("map_title", ""),
            game.get("map_tag", ""), "opence_server" if game.get("opence_dedicated") is True else "")
