#!/usr/bin/env python3
"""delta-server: a Delta network node (the game list, device identity and
the social services), standard-library Python.

    python3 node/delta_node.py serve [--config config.toml]
    python3 node/delta_node.py profile-add HANDLE (--player-key HEX | --player-id HEX) [--config ...]
    python3 node/delta_node.py link COPY_ID HANDLE [--config ...]

Serves on node.address:node.port (127.0.0.1:8390 by default); put a reverse
proxy with TLS in front of it for anything but local tests. Nothing is
shown or written with a whole IP address.

The interface is the Chupathingy site's (its list server's), where a node
has the same part:

    GET  /v1/health                 "ok"
    GET  /v1/node                   {"domain", "software", "version", "federation": false, "services"}
    POST /v1/announce, /v1/withdraw the game list (form fields, as the game sends them)
    GET  /v1/games, /v1/games.txt   the list (JSON, text)
    GET  /v1/console/games          the console list (plain text, warthog-list 1)
    GET  /v1/anchors.txt            the ping anchors (list.anchors_file)
    GET  /v1/delta/legacy(.sig)     Delta's signed legacy table, when delta_table.source is set
    GET  /v1/identity/nonce, /v1/identity/revoked
    POST /v1/identity/legacy/enroll, refresh, token, device/start, device/poll,
         device/confirm, device/signout, devices, device/revoke
    GET  /v1/clients                approved Delta clients
    POST /v1/presence               {"key"|token, "invite"}
    GET  /v1/presence               {"online": n}
    POST /v1/social/state, /v1/social/join, /v1/social/invite, /v1/party
    POST /v1/game/friends, /v1/game/clan

A copy of the game proves itself with its player key ({"key": hex}) or a
device token (Authorization: Delta ...), as on the site.

TODO(federation): handle:domain names, other nodes' issuers and lists, and
friends between nodes are delta-spec's federation.md; none of it is here.

SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: GPL-3.0-or-later
"""

import argparse
import json
import sqlite3
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parent))

import accounts  # noqa: E402
import addresses  # noqa: E402
import blocked_names  # noqa: E402
import clans  # noqa: E402
import config  # noqa: E402
import delta_clients  # noqa: E402
import delta_list  # noqa: E402
import delta_table  # noqa: E402
import doorbell  # noqa: E402
import friends  # noqa: E402
import game_list  # noqa: E402
import game_list_rules  # noqa: E402
import identity  # noqa: E402
import party  # noqa: E402
import social  # noqa: E402

VERSION = "0.1.0"
MAXIMUM_BODY = 2048
REQUEST_TIMEOUT = 20
GAME_AGENT_PREFIX = "chupathingyce"
LOCKED_ERROR = "This profile is locked."
FIRST_COPY_ERROR = "This is the copy that made the profile."
DELTA_LEGACY_FILES = {
    "/v1/delta/legacy": ("delta_legacy.json", "application/json"),
    "/v1/delta/legacy.sig": ("delta_legacy.json.sig", "text/plain; charset=us-ascii"),
}
DELTA_LEGACY_SIZE = 16384
SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
)
IDENTITY_POST_PATHS = ("/v1/identity/legacy/enroll", "/v1/identity/refresh", "/v1/identity/token",
                       "/v1/identity/device/start", "/v1/identity/device/poll", "/v1/identity/device/confirm",
                       "/v1/identity/device/signout", "/v1/identity/devices", "/v1/identity/device/revoke")
SOCIAL_PATHS = ("/v1/social/state", "/v1/social/join", "/v1/social/invite", "/v1/party")


class Node:
    """everything one node keeps: made from its settings"""

    def __init__(self, settings: dict, log=print):
        self.settings = settings
        self.log = log
        self.domain = settings["node"]["domain"]
        database_path = settings["node"]["database"]
        if database_path == ":memory:":
            self.data = None
        else:
            self.data = config.data_folder(settings)
            database_path = database_path or str(self.data / "node.db")
        self.database = sqlite3.connect(database_path, check_same_thread=False)
        self.lock = threading.RLock()
        self.address_key = addresses.load_key(self.data)
        self.games = game_list.GameList(settings["list"]["games_per_address"])
        self.console = game_list.ConsoleCache()
        self.console_hosts = {host.lower() for host in settings["list"]["console_hosts"]}
        self.anchors = ""
        if settings["list"]["anchors_file"]:
            text = Path(settings["list"]["anchors_file"]).read_text()
            self.anchors = "".join(line + "\n" for line in text.splitlines()
                                   if game_list.ANCHOR_LINE.fullmatch(line))
        self.accounts = accounts.Accounts(self.database, self.lock, settings["node"]["reserved_names"])
        self.clans = clans.Clans(self.database, self.lock)
        self.friends = friends.Friends(self.database, self.lock)
        self.clans.blocks = self.friends.blocks
        self.parties = party.Parties(self.friends.are_friends, self.friends.blocks)
        self.doorbell = self._doorbell()
        if self.doorbell is not None:
            self.friends.ring = self.doorbell.ring
            self.parties.ring = self.doorbell.ring
            self.accounts.on_presence = lambda player_id: self.ring_friends_of(player_id, "presence")
        self.clients = delta_clients.Clients(self.database, self.lock, delta_list.PLATFORMS)
        self.identity = self._identity()
        if self.identity is not None:
            self.identity.clients = self.clients
        social.configure(self.accounts, self.games, self.friends, self.parties, self.clans)
        self.versions = game_list_rules.Versions(self.data) if self.data else None
        self.table = None
        source = settings["delta_table"]["source"]
        if source and self.data:
            keys = {f"key{n}": bytes.fromhex(key) for n, key in enumerate(settings["delta_table"]["keys"])}
            if not keys:
                raise config.ConfigError("delta_table.source needs delta_table.keys (the table's public keys)")
            self.table = delta_table.Puller(self.data, source=source, keys=keys, log=log)

    def _doorbell(self):
        settings = self.settings["doorbell"]
        if not settings["key_file"] or not settings["brokers"]:
            return None
        password = settings.get("password", "")
        if not password and settings["password_file"]:
            password = Path(settings["password_file"]).read_text().strip()
        brokers = [doorbell.Broker(url, settings["user"] or doorbell.DEFAULT_USER, password, log=self.log)
                   for url in settings["brokers"]]
        ring = doorbell.Doorbell(doorbell.load_key(settings["key_file"]), brokers, self.accounts.copies_of)
        ring.start()
        self.log("doorbell: ringing on " + ", ".join(b.host for b in brokers))
        return ring

    def _identity(self):
        settings = self.settings["identity"]
        audiences = settings["audiences"] or [self.domain]
        return identity.setup(self.database, self.lock, settings["issuer_cert_file"], ",".join(settings["roots"]),
                              settings["signer_socket"], settings["issuer_key_file"], self.accounts.account_of,
                              None, delta_list.PLATFORMS, log=self.log, audiences_text=",".join(audiences),
                              hooks={"copies_of": self.accounts.copies_of, "link_copy": self.accounts.link_copy,
                                     "unlink_copy": self.accounts.unlink_copy})

    def ring_friends_of(self, player_id: str, kind: str):
        if self.doorbell is None:
            return
        if self.friends.privacy_of(player_id)["appear_offline"] or self.accounts.presence_hidden(player_id):
            return
        self.doorbell.ring(self.friends.friend_ids(player_id), kind)

    def ring_clan_invite(self, handle: str, inviter: str):
        if self.doorbell is None:
            return
        found = self.accounts.by_handle(str(handle).strip().lower().lstrip("@")[:24])
        if not found or found[2] or self.friends.blocks(found[0], inviter):
            return
        self.doorbell.ring([found[0]], "clan")

    def legacy_key_refused(self, game_id: str) -> bool:
        return self.identity is not None and self.identity.legacy_key_off(game_id)

    def join_versions(self):
        return self.versions.get() if self.versions else None

    def info(self) -> dict:
        return {"domain": self.domain, "software": "delta-server", "version": VERSION, "federation": False,
                "services": {"list": True, "identity": self.identity is not None, "social": True,
                             "doorbell": self.doorbell is not None, "legacy_table": self.table is not None}}

    def start(self):
        if self.table is not None:
            self.table.start()

    def close(self):
        if self.doorbell is not None:
            self.doorbell.stop()
        self.database.close()


def parse_json(data: bytes):
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ValueError("not JSON") from None


class Handler(BaseHTTPRequestHandler):
    server_version = "delta-server/" + VERSION.split(".")[0]
    trusted_proxies = ("127.0.0.1", "::1")
    timeout = REQUEST_TIMEOUT
    node: Node = None

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, format, *args):
        # (no address in the log: the request line and status only)
        sys.stderr.write("%s\n" % (format % args))

    def end_headers(self):
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        super().end_headers()

    def client_address_text(self) -> str:
        address = self.client_address[0]
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded and self.node.settings["node"]["behind_proxy"] and address in self.trusted_proxies:
            address = forwarded.split(",")[-1].strip()
        return address

    def host(self) -> str:
        host = self.headers.get("Host", "").strip().lower()
        return host.partition("]")[0] + "]" if host.startswith("[") else host.partition(":")[0]

    def from_game(self) -> bool:
        return self.headers.get("User-Agent", "").lower().startswith(GAME_AGENT_PREFIX)

    def reply(self, code: int, body: str, content_type: str = "text/plain; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def reply_json(self, code: int, body):
        self.reply(code, json.dumps(body), "application/json")

    def read_body(self, most: int = MAXIMUM_BODY):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > most:
            return None
        return self.rfile.read(length)

    def read_json(self):
        raw = self.read_body()
        if raw is None:
            return None
        try:
            body = parse_json(raw)
        except ValueError:
            return None
        return body if isinstance(body, dict) else None

    def copy_of(self, body: dict, capability: str):
        """(game ID, None) of the copy asking, by its key or its device
        token, or (None, (status, answer))"""
        node = self.node
        if "key" not in body and identity.delta_header(self.headers.get("Authorization")):
            return identity.bearer_copy(node.identity, self.headers.get("Authorization"), capability)
        key = str(body.get("key", "")).lower()
        if not accounts.PLAYER_KEY.match(key):
            return None, (400, {"error": "bad key"})
        game_id = accounts.player_id_of(key)
        if node.legacy_key_refused(game_id):
            return None, (403, {"error": identity.LEGACY_OFF_ERROR, "legacy_key_off": True})
        if node.identity is not None:
            node.identity.note_key_seen(game_id)
        return game_id, None

    # ---------- GET

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        node = self.node
        path, _, query = self.path.partition("?")
        address = self.client_address_text()
        if path.startswith("/v1/") and not node.games.allow(address):
            return self.reply(429, "slow down\n")
        if path == game_list.CONSOLE_PATH or self.host() in node.console_hosts:
            if path not in (game_list.CONSOLE_PATH, "/"):
                return self.reply(404, "not found\n")
            node.games.expire()
            return self.reply(200, node.console.get(node.games, game_list.console_players(query),
                                                    game_list.console_packs(query), game_list.console_coop(query)),
                              "text/plain; charset=us-ascii")
        if path == "/v1/health":
            return self.reply(200, "ok\n")
        if path == "/v1/node":
            return self.reply_json(200, node.info())
        if path == "/v1/games":
            fields = {k: v[0] for k, v in parse_qs(query, keep_blank_values=True).items()}
            try:
                filters = delta_list.parse_filters(fields)
            except ValueError as problem:
                return self.reply(400, f"bad filter ({problem})\n")
            coop = fields.get("coop") == "1" or "coop" in filters.get("mode", ())
            node.games.expire()
            versions = node.join_versions()
            games = [dict(g, joinable=game_list_rules.game_joinable(g, versions)) for g in node.games.public_snapshot()
                     if delta_list.matches(g, filters) and (coop or g.get("mode") != "coop")]
            if fields.get("joinable") == "1":
                games = [g for g in games if g["joinable"]]
            return self.reply_json(200, {"games": games})
        if path == "/v1/games.txt":
            fields = {k: v[0] for k, v in parse_qs(query).items()}
            coop = fields.get("coop") == "1"
            try:
                count = game_list.clean_integer(fields.get("fields", str(game_list.TEXT_FIELDS_READ)),
                                                game_list.TEXT_FIELDS_READ, 255)
            except ValueError:
                return self.reply(400, "bad query\n")
            knows_bomb = count >= game_list.TEXT_FIELDS_BOMB or self.from_game()
            node.games.expire()
            lines = ["\t".join(game_list.text_field(g, k) for k in game_list.TEXT_FIELDS[:count])
                     for g in node.games.public_snapshot()
                     if g["map"] and g["invite"] and (knows_bomb or g.get("engine") != game_list.ENGINE_BOMB)
                     and (coop or g.get("mode") != "coop")]
            return self.reply(200, "".join(line + "\n" for line in lines))
        if path == "/v1/anchors.txt":
            return self.reply(200, node.anchors)
        if path in DELTA_LEGACY_FILES:
            name, content_type = DELTA_LEGACY_FILES[path]
            try:
                data = (node.data / name).read_bytes()[:DELTA_LEGACY_SIZE] if node.data else None
            except OSError:
                data = None
            if data is None:
                return self.reply(404, "no table yet\n")
            return self.reply(200, data.decode("utf-8", "replace"), content_type)
        if path in ("/v1/identity/nonce", "/v1/identity/revoked"):
            return self.identity_request(path, {})
        if path == "/v1/clients":
            return self.reply_json(200, {"clients": node.clients.directory()})
        if path == "/v1/presence":
            return self.reply_json(200, {"online": node.accounts.presence_online()})
        return self.reply(404, "not found\n")

    # ---------- POST

    def do_POST(self):
        node = self.node
        path = self.path.partition("?")[0]
        address = self.client_address_text()
        if self.host() in node.console_hosts:
            return self.reply(405, "not allowed\n")
        if not node.games.allow(address):
            return self.reply(429, "slow down\n")
        if path in ("/v1/announce", "/v1/withdraw"):
            return self.list_request(path, address)
        if path in IDENTITY_POST_PATHS:
            body = self.read_json()
            if body is None:
                return self.reply_json(400, {"error": "bad request"})
            return self.identity_request(path, body)
        if path == "/v1/presence":
            return self.presence_request(address)
        if path in SOCIAL_PATHS:
            return self.social_request(path, address)
        if path in ("/v1/game/friends", "/v1/game/clan"):
            return self.game_request(path, address)
        return self.reply(404, "not found\n")

    def list_request(self, path: str, address: str):
        raw = self.read_body(game_list.MAXIMUM_ANNOUNCE_BODY)
        if raw is None:
            return self.reply(400, "bad length\n")
        form = {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace")).items()}
        invite = form.get("invite", "").lower()
        if not game_list.INVITE.match(invite):
            return self.reply(400, "bad invite\n")
        self.node.games.expire()
        if path == "/v1/withdraw":
            self.node.games.withdraw(address, invite)
            return self.reply(200, "ok\n")
        try:
            fields = game_list.parse_announce(form)
        except ValueError as problem:
            return self.reply(400, f"{problem if str(problem) == 'bad map' else 'bad field'}\n")
        refused = self.node.games.announce(address, fields)
        if refused:
            return self.reply(403, refused + "\n")
        return self.reply(200, f"ok {game_list.EXPIRY}\n")

    def identity_request(self, path: str, body: dict):
        """device identity (identity.py); 503 until the node has an issuer.
        Never logs a key, signature or token"""
        service = self.node.identity
        if service is None:
            return self.reply_json(503, {"error": "Device certificates aren't issued here yet."})
        rate = game_list.rate_key(self.client_address_text())
        if path == "/v1/identity/nonce":
            status, answer = service.nonce(rate)
        elif path == "/v1/identity/revoked":
            status, answer = service.revoked()
        elif path == "/v1/identity/legacy/enroll":
            status, answer = service.enroll(body, rate)
        elif path == "/v1/identity/refresh":
            status, answer = service.refresh(body, rate)
        elif path == "/v1/identity/token":
            status, answer = service.token(body, rate)
        elif path == "/v1/identity/device/start":
            status, answer = service.start_code(body, rate)
        elif path == "/v1/identity/device/poll":
            status, answer = service.poll(body, rate)
        elif path == "/v1/identity/device/confirm":
            status, answer = service.confirm(body, rate)
            answer.pop("added", None)
        elif path == "/v1/identity/device/signout":
            status, answer = service.signout(body, rate)
        else:
            status, answer = self.device_request(path, body)
        return self.reply_json(status, answer)

    def device_request(self, path: str, body: dict):
        """a signed-in device's list of its account's devices, or another
        one revoked (TODO: approving a code from a device, as the site
        does, needs the account sign-up decision first)"""
        service = self.node.identity
        capability = "profile" if path == "/v1/identity/devices" else "devices"
        row, why = service.bearer_device(self.headers.get("Authorization"), capability)
        if not row:
            return 401, {"error": "token", "token": why}
        found = self.node.accounts.profile_of_game(row["copy_id"] or row["account_id"])
        if not found:
            return 404, {"linked": False, "error": "This device isn't signed in to a Delta profile."}
        account, locked = found
        if locked:
            return 403, {"error": LOCKED_ERROR}
        if not self.node.accounts.allow_game_request(row["device_id"], self.client_address_text()):
            return 429, {"error": "too many requests"}
        if path == "/v1/identity/devices":
            return 200, {"devices": service.devices_of(account, row["device_id"])}
        target = str(body.get("device_id", "")).lower()
        if target == row["device_id"]:
            return 409, {"error": "Sign out on this device instead.", "this": True}
        if not service.revoke_for(account, target, from_site=False):
            return 404, {"error": "No such device on your profile."}
        return 200, {"ok": True}

    def presence_request(self, address: str):
        body = self.read_json()
        if body is None:
            return self.reply(400, "bad request\n")
        game_id, refused = self.copy_of(body, "social")
        if refused:
            return self.reply_json(*refused)
        invite = str(body.get("invite", "")).lower()
        if not game_list.INVITE.match(invite):
            return self.reply(400, "bad request\n")
        answer = self.node.accounts.note_presence(game_id, invite, address)
        return self.reply(200 if answer else 429, (answer or "too many requests") + "\n")

    def social_request(self, path: str, address: str):
        """/v1/social/* and /v1/party from the game (list_server.py's
        social_request without the site's session half)"""
        node = self.node
        body = self.read_json()
        if body is None:
            return self.reply_json(400, {"error": "bad request"})
        if not self.from_game():
            return self.reply_json(403, {"error": "not the game"})
        game_id, refused = self.copy_of(body, "social")
        if refused:
            return self.reply_json(*refused)
        action = path in ("/v1/social/join", "/v1/social/invite") or (path == "/v1/party" and bool(body.get("action")))
        if not node.accounts.allow_social_request(game_id, address, action):
            return self.reply_json(429, {"error": "Too many tries. Wait a minute.", "reason": "busy"})
        found = node.accounts.profile_of_game(game_id)
        if not found and path == "/v1/party":
            status, answer = social.party_action(social.party_member(None, game_id, body, address), body)
            return self.reply_json(status, answer)
        if not found:
            return self.reply_json(404, {"linked": False, "error": "This copy isn't linked to a Delta profile."})
        player_id, locked = found
        if locked:
            return self.reply_json(403, {"error": LOCKED_ERROR})
        if path == "/v1/social/state":
            since = str(body.get("since", ""))
            limit = body.get("limit", 0)
            if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
                return self.reply_json(400, {"error": "bad request"})
            state = social.social_state(player_id, mark=True, limit=limit, clan=body.get("clan") is True)
            extra = {"doorbell": node.doorbell.heard(game_id)} if node.doorbell is not None else {}
            if since and since == state["cursor"]:
                return self.reply_json(200, dict({"cursor": state["cursor"], "same": True}, **extra))
            return self.reply_json(200, dict(state, same=False, **extra))
        if path == "/v1/social/join":
            status, answer = social.social_join(player_id, str(body.get("friend", "")))
            return self.reply_json(status, answer)
        if path == "/v1/party":
            node.friends.mark_online(player_id)
            status, answer = social.party_action(social.party_member(player_id, None, body, address), body)
            return self.reply_json(status, answer)
        invite = ""
        if body.get("invite"):
            match = social.JOIN_LINK.match(str(body.get("invite", "")).strip())
            if not match:
                return self.reply_json(400, {"error": "bad invite"})
            invite = match.group(1).lower()
        status, answer = social.social_invite(player_id, str(body.get("to", "")), invite)
        return self.reply_json(status, answer)

    def game_request(self, path: str, address: str):
        """/v1/game/friends and /v1/game/clan (list_server.py's game_request,
        those two)"""
        node = self.node
        if not self.from_game():
            return self.reply_json(403, {"error": "not the game"})
        body = self.read_json()
        if body is None:
            return self.reply_json(400, {"error": "bad request"})
        game_id, refused = self.copy_of(body, "social")
        if refused:
            return self.reply_json(*refused)
        if not node.accounts.allow_game_request(game_id, address):
            return self.reply_json(429, {"error": "too many requests"})
        found = node.accounts.profile_of_game(game_id)
        if not found:
            return self.reply_json(404, {"linked": False, "error": "This copy isn't linked to a Delta profile."})
        player_id, locked = found
        if locked:
            return self.reply_json(403, {"error": LOCKED_ERROR})
        if path == "/v1/game/friends":
            status, answer = social.friends_action(player_id, body, None)
            if status != 200:
                return self.reply_json(status, answer)
            return self.reply_json(200, dict(social.social_state(player_id, mark=True), **answer))
        action = body.get("action")
        target = body.get("handle")
        if action in ("invite", "kick") and (not isinstance(target, str) or not 0 < len(target) <= 64):
            return self.reply_json(400, {"error": "bad request"})
        try:
            if action in ("accept", "decline"):
                node.clans.answer_invite(player_id, body.get("clan"), action == "accept")
            elif action == "leave":
                node.clans.leave(player_id)
            elif action == "invite":
                node.clans.invite(player_id, target[:24])
                node.ring_clan_invite(target[:24], player_id)
            elif action == "kick":
                node.clans.kick(player_id, target[:24])
            elif action != "roster":
                return self.reply_json(400, {"error": "bad request"})
        except clans.Refused as refused:
            return self.reply_json(refused.status, {"error": refused.message})
        return self.reply_json(200, blocked_names.scrub(social.game_clan(player_id, presence=True)))


class Server(ThreadingHTTPServer):
    daemon_threads = True


def make_server(node: Node, address: str, port: int) -> Server:
    handler = type("NodeHandler", (Handler,), {"node": node})
    return Server((address, port), handler)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="delta-server: a Delta network node")
    parser.add_argument("--config", default="", help="the settings file (config.example.toml has every setting)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve")
    command = commands.add_parser("profile-add", help="make a profile (until account sign-up is decided)")
    command.add_argument("handle")
    group = command.add_mutually_exclusive_group(required=True)
    group.add_argument("--player-key", help="the copy's player key (64 hex digits): its player ID is worked out")
    group.add_argument("--player-id", help="the copy's player ID (32 hex digits)")
    command.add_argument("--display", default="")
    command = commands.add_parser("link", help="count a copy of the game for a profile")
    command.add_argument("copy_id")
    command.add_argument("handle")
    arguments = parser.parse_args(argv)
    try:
        settings = config.load(arguments.config)
    except (OSError, config.ConfigError) as problem:
        print(f"config: {problem}", file=sys.stderr)
        return 2
    node = Node(settings, log=lambda text: print(text, flush=True))
    if arguments.command == "profile-add":
        player_id = accounts.player_id_of(arguments.player_key.lower()) if arguments.player_key else \
            arguments.player_id.lower()
        problem = node.accounts.create(player_id, arguments.handle, arguments.display)
        print(problem or f"made {arguments.handle.lower()}")
        return 1 if problem else 0
    if arguments.command == "link":
        found = node.accounts.by_handle(arguments.handle.lower())
        if not found or not accounts.PLAYER_ID.match(arguments.copy_id.lower()):
            print("no such profile, or a bad copy ID")
            return 1
        problem = node.accounts.link_copy(arguments.copy_id.lower(), found[0])
        print(problem or "linked")
        return 1 if problem else 0
    node.start()
    httpd = make_server(node, settings["node"]["address"], settings["node"]["port"])
    print(f"delta-server {VERSION}: {node.domain} on port {httpd.server_address[1]}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        node.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
