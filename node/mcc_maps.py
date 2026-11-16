"""Halo MCC maps (Steam Workshop packages): their names as games give them,
and their Workshop items' titles, makers and pictures from Steam.

A game on an MCC map names it by its package path, mcc_maps\\<package>\\<level>
(our builds' folder maps_mcc\\<package>\\<level> too, either slash). A
Workshop package's folder is its Workshop item id (digits); a host may also
say the id beside the map (the announcement's workshop_id, from the
settings' Workshop tail). The pages key such a map mcc/<package>/<level>.

Workshop details come from Steam's public call that needs no key
(ISteamRemoteStorage/GetPublishedFileDetails), only for items of Halo: The
Master Chief Collection (app 976730); the maker's name from their public
community profile. Each is kept a day (an answer Steam doesn't have, an
hour), at most MAXIMUM_ITEMS, and Steam is asked at most FETCH_BUDGET times
a FETCH_WINDOW, and only for items a game listed or played names (known):
past that, or with Steam unreachable, the pages show the
map's own name. Pictures: the item's preview, from Steam's image CDN only,
shrunk by the CDN to a JPEG of PICTURE_WIDTH x PICTURE_HEIGHT, kept on disk
(JPEG only, at most PICTURE_BYTES each, PICTURE_STORE_BYTES in all, the
oldest dropped first) and served at /art/maps/mcc/<id>.jpg, where the game
fetches its map pictures too. The site has no image library (standard
library only), so a picture is not decoded and made again: it is taken only
as Steam's CDN's JPEG answer that starts and ends as a JPEG does. Test: python3 -m unittest test_mcc_maps

SPDX-FileCopyrightText: 2026 The Chupathingy contributors
SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: GPL-3.0-or-later
"""

import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

MCC_APP_ID = 976730
DETAILS_URL = "https://api.steampowered.com/ISteamRemoteStorage/GetPublishedFileDetails/v1/"
PROFILE_URL = "https://steamcommunity.com/profiles/{}/?xml=1"
WORKSHOP_URL = "https://steamcommunity.com/sharedfiles/filedetails/?id={}"
# Steam's image CDN: the only hosts a preview is fetched from (https)
PICTURE_HOSTS = frozenset(("images.steamusercontent.com", "steamuserimages-a.akamaihd.net",
                           "steamusercontent-a.akamaihd.net", "cdn.akamai.steamstatic.com",
                           "shared.akamai.steamstatic.com", "cdn.cloudflare.steamstatic.com"))
DETAILS_TIME = 86400
MISSING_TIME = 3600
MAXIMUM_ITEMS = 2000
FETCH_BUDGET = 60
FETCH_WINDOW = 600
TIMEOUT = 8
DETAILS_BYTES = 256 * 1024
PROFILE_BYTES = 64 * 1024
# (the game takes a picture of 256 KB at most: map_art.c)
PICTURE_WIDTH, PICTURE_HEIGHT = 384, 216
PICTURE_BYTES = 256 * 1024
PICTURE_STORE_BYTES = 64 * 1024 * 1024
TITLE_LENGTH, AUTHOR_LENGTH = 64, 32

FOLDERS = ("mcc_maps", "maps_mcc")
WORKSHOP_ID = re.compile(r"[1-9][0-9]{0,19}")
PACKAGE = re.compile(r"[a-z0-9_][a-z0-9_.-]{0,63}")
STEAM_ID = re.compile(r"7656119[0-9]{10}")


def parse(name) -> dict:
    """an MCC map's name as {"package", "level", "workshop_id"} (the
    package and level in lowercase, made safe for a key; workshop_id the
    package when it is one, else ""), or None for any other map. Takes
    mcc_maps\\<package>\\<level>, maps_mcc\\<package>\\<level> (either
    slash, any case, a .map kept off) and the pages' key mcc/<package>/<level>"""
    parts = [p for p in re.split(r"[\\/]", str(name or "").strip()) if p]
    if len(parts) < 3 or parts[-3].lower() not in FOLDERS + ("mcc",):
        return None
    package, level = parts[-2].lower(), parts[-1].lower()
    if level.endswith(".map"):
        level = level[:-4]
    package = re.sub(r"[^a-z0-9_.\-]", "_", package)[:64]
    level = re.sub(r"[^a-z0-9_.\-]", "_", level)[:64]
    if not PACKAGE.fullmatch(package) or not PACKAGE.fullmatch(level):
        return None
    return {"package": package, "level": level, "workshop_id": package if WORKSHOP_ID.fullmatch(package) else ""}


def is_mcc(name) -> bool:
    return parse(name) is not None


def site_key(name) -> str:
    """an MCC map's key on the pages, mcc/<package>/<level>, else "" """
    found = parse(name)
    return f"mcc/{found['package']}/{found['level']}" if found else ""


def clean_workshop_id(value) -> str:
    """a Workshop item id (decimal digits), else "" """
    value = str(value or "").strip()
    return value if WORKSHOP_ID.fullmatch(value) and int(value) < 2 ** 64 else ""


def clean_text(value, limit: int) -> str:
    value = "".join(c for c in str(value or "") if c.isprintable())
    return re.sub(r"\s+", " ", value).strip()[:limit]


def workshop_link(item: str) -> str:
    return WORKSHOP_URL.format(item)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """a redirect is followed only to Steam's image CDN, over https"""

    def redirect_request(self, request, fp, code, message, headers, new_url):
        parsed = urllib.parse.urlsplit(new_url)
        if parsed.scheme != "https" or parsed.hostname not in PICTURE_HOSTS:
            return None
        return super().redirect_request(request, fp, code, message, headers, new_url)


OPENER = urllib.request.build_opener(NoRedirect)


def http(url: str, data: bytes = None, limit: int = DETAILS_BYTES) -> tuple:
    """(content type, body) of a GET (or a form POST with data); raises
    OSError for a failure or a body over limit"""
    request = urllib.request.Request(url, data=data, headers={"User-Agent": "chupathingy-site"})
    with OPENER.open(request, timeout=TIMEOUT) as answer:
        body = answer.read(limit + 1)
        if len(body) > limit:
            raise OSError("too large")
        return answer.headers.get("Content-Type", ""), body


def picture_url(preview: str) -> str:
    """a preview's address on Steam's image CDN, asked for as a small JPEG;
    "" for an address elsewhere"""
    parsed = urllib.parse.urlsplit(str(preview or ""))
    if parsed.scheme != "https" or parsed.hostname not in PICTURE_HOSTS:
        return ""
    query = urllib.parse.urlencode({"imw": PICTURE_WIDTH, "imh": PICTURE_HEIGHT, "ima": "fit", "impolicy": "Letterbox",
                                    "imcolor": "#000000", "letterbox": "true"})
    return urllib.parse.urlunsplit(("https", parsed.netloc, parsed.path, query, ""))


def is_jpeg(data: bytes) -> bool:
    return len(data) > 4 and data[:3] == b"\xff\xd8\xff" and data[-2:] == b"\xff\xd9"


class Workshop:
    """Workshop items' details and pictures, kept (see the top). fetch(url,
    data, limit) -> (content type, body) is Steam (tests pass their own)"""

    def __init__(self, folder=None, fetch=http, clock=time.time, known=lambda item: True):
        # (known(id): whether a game listed or played names the item: Steam
        # is asked only of those, so a visitor's made-up ids cost nothing)
        self.known = known
        self.fetch = fetch
        self.clock = clock
        self.lock = threading.Lock()
        self.items = {}  # id -> {"time", "details" or None}
        self.fetching = {}  # id -> threading.Event
        self.fetches = []  # times Steam was asked
        self.folder = Path(folder) / "workshop_art" if folder else None
        self.store = Path(folder) / "workshop_details.json" if folder else None
        if self.store and self.store.exists():
            try:
                kept = json.loads(self.store.read_text())
                self.items = {k: v for k, v in kept.items() if clean_workshop_id(k) and isinstance(v, dict)}
            except (OSError, ValueError):
                self.items = {}

    def allowed(self) -> bool:
        """one more question to Steam within the budget (counted)"""
        now = self.clock()
        self.fetches = [t for t in self.fetches if now - t < FETCH_WINDOW]
        if len(self.fetches) >= FETCH_BUDGET:
            return False
        self.fetches.append(now)
        return True

    def fresh(self, entry) -> bool:
        if not isinstance(entry, dict) or not isinstance(entry.get("time"), (int, float)):
            return False
        age = self.clock() - entry.get("time", 0)
        return age < (DETAILS_TIME if entry.get("details") else MISSING_TIME)

    def details(self, item: str, ask: bool = True):
        """an item's {"id", "title", "author", "link", "preview"} (preview:
        Steam's address of its picture, "" for none), or None when it is
        not known (not an MCC item, Steam unreachable or over the budget)"""
        item = clean_workshop_id(item)
        if not item:
            return None
        with self.lock:
            entry = self.items.get(item)
            if not isinstance(entry, dict):
                entry = None
            if self.fresh(entry) or not ask:
                return (entry or {}).get("details")
        if not self.known(item):
            return (entry or {}).get("details")
        with self.lock:
            waiting = self.fetching.get(item)
            if waiting is None:
                if not self.allowed():
                    return (entry or {}).get("details")
                self.fetching[item] = threading.Event()
        if waiting is not None:
            waiting.wait(TIMEOUT * 2 + 1)
            with self.lock:
                return (self.items.get(item) or {}).get("details")
        found = (entry or {}).get("details")
        try:
            found = self.ask_steam(item)
        except Exception:  # (unreachable, or an answer not as expected: the older details, if any)
            pass
        finally:
            with self.lock:
                self.items[item] = {"time": self.clock(), "details": found}
                if len(self.items) > MAXIMUM_ITEMS:
                    age = lambda k: self.items[k].get("time", 0) if isinstance(self.items[k], dict) else 0
                    for old in sorted(self.items, key=age)[:len(self.items) - MAXIMUM_ITEMS]:
                        del self.items[old]
                self.fetching.pop(item).set()
                self.save()
        return found

    def ask_steam(self, item: str):
        data = urllib.parse.urlencode({"itemcount": 1, "publishedfileids[0]": item}).encode()
        _, body = self.fetch(DETAILS_URL, data, DETAILS_BYTES)
        found = json.loads(body.decode("utf-8"))["response"]["publishedfiledetails"][0]
        if int(found.get("result", 0)) != 1 or int(found.get("consumer_app_id", 0)) != MCC_APP_ID:
            return None
        if str(found.get("publishedfileid", "")) != item:
            return None
        author = ""
        creator = str(found.get("creator", ""))
        with self.lock:
            may_ask = STEAM_ID.fullmatch(creator) and self.allowed()
        if may_ask:
            try:
                _, profile = self.fetch(PROFILE_URL.format(creator), None, PROFILE_BYTES)
                match = re.search(rb"<steamID><!\[CDATA\[(.*?)\]\]></steamID>", profile, re.S)
                author = clean_text(match.group(1).decode("utf-8", "replace"), AUTHOR_LENGTH) if match else ""
            except Exception:
                author = ""
        return {"id": item, "title": clean_text(found.get("title"), TITLE_LENGTH), "author": author,
                "link": workshop_link(item), "preview": picture_url(found.get("preview_url")),
                "updated": int(found.get("time_updated", 0) or 0)}

    def save(self):
        """the details kept on disk (under the lock), so a restart doesn't ask Steam again"""
        if not self.store:
            return
        try:
            temporary = self.store.with_suffix(".tmp")
            temporary.write_text(json.dumps(self.items))
            os.replace(temporary, self.store)
        except OSError:
            pass

    def public(self, item: str, blocked=lambda text: False):
        """/v1/workshop/<id>'s answer: the details the pages show, or only
        the id and its Workshop link when they aren't known; a title or
        maker's name that blocked() refuses is left out; None for an id no
        game names (a 404)"""
        item = clean_workshop_id(item)
        if not item or (not self.known(item) and not self.details(item, ask=False)):
            return None
        found = self.details(item)
        answer = {"id": item, "link": workshop_link(item), "known": bool(found)}
        if found:
            answer.update(title="" if blocked(found["title"]) else found["title"],
                          author="" if blocked(found["author"]) else found["author"],
                          picture=f"/art/maps/mcc/{item}.jpg" if found["preview"] else "")
        return answer

    def picture(self, item: str):
        """an item's picture (JPEG bytes), from the disk, else from Steam's
        CDN and kept; None when there is none"""
        item = clean_workshop_id(item)
        if not item or not self.folder:
            return None
        path = self.folder / f"{item}.jpg"
        if not self.known(item):
            return self.kept_picture(path)
        try:
            if path.exists() and self.clock() - path.stat().st_mtime < DETAILS_TIME:
                return path.read_bytes()
        except OSError:
            pass
        found = self.details(item)
        if not found or not found.get("preview"):
            return self.kept_picture(path)
        with self.lock:
            if not self.allowed():
                return self.kept_picture(path)
        try:
            kind, data = self.fetch(found["preview"], None, PICTURE_BYTES)
        except Exception:
            return self.kept_picture(path)
        if not kind.lower().startswith("image/jpeg") or not is_jpeg(data):
            return self.kept_picture(path)
        try:
            self.folder.mkdir(parents=True, exist_ok=True)
            temporary = path.with_suffix(".tmp")
            temporary.write_bytes(data)
            os.replace(temporary, path)
            self.trim()
        except OSError:
            pass
        return data

    @staticmethod
    def kept_picture(path: Path):
        try:
            return path.read_bytes() if path.exists() else None
        except OSError:
            return None

    def trim(self):
        """the pictures kept within PICTURE_STORE_BYTES, the oldest dropped"""
        files = sorted(self.folder.glob("*.jpg"), key=lambda p: p.stat().st_mtime, reverse=True)
        total = 0
        for path in files:
            total += path.stat().st_size
            if total > PICTURE_STORE_BYTES:
                path.unlink(missing_ok=True)
