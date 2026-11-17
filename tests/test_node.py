# SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
# SPDX-License-Identifier: MIT
"""The node running on 127.0.0.1 with an in-memory database: the list, the
console list, device identity, presence, friends, invites, parties and
clans, through HTTP as a game would use them:
python3 -m unittest tests.test_node"""

import http.client
import json
import os
import secrets
import tempfile
import time
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode

import accounts
import config
import delta_node
import ed25519
import identity
from test_identity import ISSUER, ROOT, fresh_issuer

GAME_AGENT = "ChupathingyCE/0.9.2 (linux; x86_64)"
AUDIENCE = "node.test"


class Copy:
    """a copy of the game: its player key and a device key"""

    def __init__(self):
        self.player_key = secrets.token_hex(32)
        self.copy = accounts.player_id_of(self.player_key)
        self.seed = secrets.token_bytes(32)
        self.public = ed25519.public_key(self.seed)
        self.id = identity.device_id(self.public)


def invite() -> str:
    return secrets.token_hex(32)


class Node(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        folder = Path(cls.folder.name)
        cert = folder / "issuer.cert"
        cert.write_text("# test\n" + fresh_issuer().hex() + "\n")
        key = folder / "issuer.key"
        key.write_text(ISSUER.hex())
        os.chmod(key, 0o600)
        (folder / "anchors.txt").write_text("anchor\tping.node.test\t443\tEU\nnot a line\n")
        settings = config.load("", environ={})
        settings["node"].update(domain=AUDIENCE, data=str(folder / "data"), database=":memory:")
        settings["identity"].update(issuer_cert_file=str(cert), issuer_key_file=str(key),
                                    roots=[ed25519.public_key(ROOT).hex()])
        settings["list"].update(console_hosts=["consoles.node.test"], anchors_file=str(folder / "anchors.txt"))
        cls.node = delta_node.Node(settings, log=lambda text: None)
        cls.httpd = delta_node.make_server(cls.node, "127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.copies = {}
        for handle in ("church", "tucker", "caboose", "donut", "sarge"):
            cls.copies[handle] = Copy()
            assert cls.node.accounts.create(cls.copies[handle].copy, handle) == ""

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.node.close()
        cls.folder.cleanup()

    def setUp(self):
        self.node.games.requests.clear()
        self.node.accounts.counts.clear()
        self.node.identity.counts.clear()

    def call(self, method, path, body=None, agent=GAME_AGENT, form=None, token=None, host=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        data = None
        headers = {"User-Agent": agent, "Host": host or f"127.0.0.1:{self.port}"}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if form is not None:
            data = urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if token:
            headers["Authorization"] = f"Delta {token}"
        connection.request(method, path, body=data, headers=headers)
        answer = connection.getresponse()
        raw = answer.read().decode()
        connection.close()
        return answer.status, (json.loads(raw) if raw.startswith("{") else raw)

    def announce(self, invite_hex, **fields):
        form = dict(invite=invite_hex, name="Blood Gulch CTF", map="levels\\test\\bloodgulch\\bloodgulch", engine=1,
                    players=3, maximum_players=16, open=1, version=44, score_limit=3, teams=1, roster="0:church|1:tucker")
        form.update(fields)
        return self.call("POST", "/v1/announce", form=form)

    def social(self, handle, path="/v1/social/state", **body):
        return self.call("POST", path, dict(body, key=self.copies[handle].player_key))

    def test_health_and_node(self):
        self.assertEqual(self.call("GET", "/v1/health"), (200, "ok\n"))
        status, answer = self.call("GET", "/v1/node")
        self.assertEqual(status, 200)
        self.assertEqual(answer["domain"], AUDIENCE)
        self.assertFalse(answer["federation"])
        self.assertTrue(answer["services"]["identity"])

    def test_list(self):
        game = invite()
        self.assertEqual(self.announce(game), (200, "ok 75\n"))
        status, answer = self.call("GET", "/v1/games")
        self.assertEqual(status, 200)
        listed = [g for g in answer["games"] if g["invite"] == game]
        self.assertEqual(len(listed), 1)
        self.assertNotIn("address", listed[0])
        self.assertNotIn("127.0.0.1", json.dumps(answer))
        status, text = self.call("GET", "/v1/games.txt")
        self.assertIn(game + "\tBlood Gulch CTF\t", text)
        status, text = self.call("GET", "/v1/console/games")
        self.assertTrue(text.startswith("warthog-list 1 "), text)
        self.assertIn(game, text)
        self.assertTrue(text.endswith("end\n"))
        # (the console host serves the console list only)
        self.assertEqual(self.call("GET", "/", host="consoles.node.test")[0], 200)
        self.assertEqual(self.call("GET", "/v1/games", host="consoles.node.test")[0], 404)
        self.assertEqual(self.call("POST", "/v1/withdraw", form={"invite": game}), (200, "ok\n"))
        status, answer = self.call("GET", "/v1/games")
        self.assertFalse([g for g in answer["games"] if g["invite"] == game])

    def test_list_refusals(self):
        self.assertEqual(self.announce("zz")[0], 400)
        self.assertEqual(self.announce(invite(), map="")[0], 400)
        self.assertEqual(self.announce(invite(), players="x")[0], 400)

    def test_anchors(self):
        self.assertEqual(self.call("GET", "/v1/anchors.txt"), (200, "anchor\tping.node.test\t443\tEU\n"))

    def test_legacy_table_off(self):
        self.assertEqual(self.call("GET", "/v1/delta/legacy")[0], 404)

    def test_friends_invite_and_join(self):
        status, answer = self.call("POST", "/v1/game/friends",
                                   {"key": self.copies["church"].player_key, "action": "request", "handle": "tucker"})
        self.assertEqual(status, 200, answer)
        self.assertEqual(answer["result"], "sent")
        status, answer = self.call("POST", "/v1/game/friends",
                                   {"key": self.copies["tucker"].player_key, "action": "accept", "handle": "church"})
        self.assertEqual(status, 200, answer)
        self.assertEqual([f["handle"] for f in answer["friends"]], ["church"])
        # (church hosts and says so: tucker sees it, joins, and is invited)
        game = invite()
        self.assertEqual(self.announce(game)[0], 200)
        self.assertEqual(self.call("POST", "/v1/presence", {"key": self.copies["church"].player_key, "invite": game}),
                         (200, "ok\n"))
        status, answer = self.social("tucker")
        church = answer["friends"][0]
        self.assertTrue(church["online"] and church["playing"] and church["joinable"])
        self.assertEqual(church["game"]["name"], "Blood Gulch CTF")
        self.assertNotIn("invite", church["game"])
        status, answer = self.social("tucker", "/v1/social/join", friend="church")
        self.assertEqual((status, answer["join"]), (200, "halo://join/" + game))
        status, answer = self.social("church", "/v1/social/invite", to="tucker")
        self.assertEqual(status, 200, answer)
        status, answer = self.social("tucker")
        self.assertEqual(answer["invites"][0]["from"], "church")
        # (the same state again: the cursor says nothing changed)
        status, again = self.social("tucker", since=answer["cursor"])
        self.assertTrue(again["same"])
        # (no friend: no join, and a stranger learns nothing: not
        # "friends only", which would say church is playing)
        status, answer = self.social("caboose", "/v1/social/join", friend="church")
        self.assertEqual((status, answer["reason"]), (409, "not_available"))
        # (an unknown handle stays unknown)
        self.assertEqual(self.social("caboose", "/v1/social/join", friend="nobody")[0], 404)

    def test_strangers_learn_nothing(self):
        # (to someone who isn't their friend and has no invite from them,
        # playing and offline read the same)
        game = invite()
        self.assertEqual(self.announce(game)[0], 200)
        self.assertEqual(self.call("POST", "/v1/presence", {"key": self.copies["church"].player_key, "invite": game}),
                         (200, "ok\n"))
        playing = self.social("donut", "/v1/social/join", friend="church")
        self.assertEqual((playing[0], playing[1]["reason"]), (409, "not_available"))
        self.node.accounts.presence.clear()
        offline = self.social("donut", "/v1/social/join", friend="church")
        self.assertEqual((offline[0], offline[1]), playing)

    def test_party(self):
        status, answer = self.social("caboose", "/v1/party", action="create")
        self.assertEqual(status, 200, answer)
        code = answer["party"]["code"]
        # (a party takes its leader's friends by default)
        self.node.friends.request(self.copies["donut"].copy, "caboose")
        self.node.friends.answer(self.copies["caboose"].copy, "donut", True)
        status, answer = self.social("donut", "/v1/party", action="join", code=code)
        self.assertEqual(status, 200, answer)
        self.assertEqual(sorted(m["handle"] for m in answer["party"]["members"]), ["caboose", "donut"])
        # (a copy with no profile joins by code too, once the party takes
        # anyone, and is marked unverified)
        self.assertEqual(self.social("caboose", "/v1/party", action="rule", join="anyone")[0], 200)
        stranger = Copy()
        status, answer = self.call("POST", "/v1/party", {"key": stranger.player_key, "action": "join", "code": code,
                                                         "name": "Sister"})
        self.assertEqual(status, 200, answer)
        self.assertIn(False, [m["verified"] for m in answer["party"]["members"]])

    def test_unlinked_and_not_the_game(self):
        self.assertEqual(self.call("POST", "/v1/social/state", {"key": Copy().player_key})[0], 404)
        self.assertEqual(self.call("POST", "/v1/social/state", {"key": self.copies["church"].player_key},
                                   agent="curl/8")[0], 403)
        self.assertEqual(self.call("POST", "/v1/social/state", {"key": "zz"})[0], 400)

    def test_clan_roster(self):
        clan = self.node.clans.create(self.copies["donut"].copy, "Gold Team", "GOLD")
        self.assertTrue(clan)
        status, answer = self.call("POST", "/v1/game/clan", {"key": self.copies["donut"].player_key,
                                                             "action": "roster"})
        self.assertEqual(status, 200, answer)
        self.assertEqual(answer["clan"]["tag"], "GOLD")

    def nonce(self) -> str:
        status, answer = self.call("GET", "/v1/identity/nonce")
        self.assertEqual(status, 200, answer)
        return answer["nonce"]

    def test_device_identity(self):
        device = self.copies["sarge"]
        nonce = self.nonce()
        signature = ed25519.sign(device.seed, identity.enroll_message(
            AUDIENCE, bytes.fromhex(nonce), bytes.fromhex(device.copy), device.public)).hex()
        status, answer = self.call("POST", "/v1/identity/legacy/enroll", {
            "key": device.player_key, "device_key": device.public.hex(), "nonce": nonce, "signature": signature,
            "platform": "pc_linux", "build": "0.9.2-test", "name": "Test PC"})
        self.assertEqual(status, 200, answer)
        issuer = identity.parse_issuer(bytes.fromhex(answer["issuer"]))
        self.assertEqual(identity.check_issuer(issuer, [ed25519.public_key(ROOT)], int(time.time())), "")
        fields = identity.parse_device(bytes.fromhex(answer["certificate"]))
        self.assertEqual(identity.check_device(fields, issuer, int(time.time())), "")
        self.assertEqual((fields["account"].hex(), fields["handle"]), (device.copy, "sarge"))
        nonce = self.nonce()
        status, answer = self.call("POST", "/v1/identity/token", {
            "device_id": device.id.hex(), "nonce": nonce,
            "signature": ed25519.sign(device.seed, identity.token_message(AUDIENCE, bytes.fromhex(nonce),
                                                                          device.id)).hex()})
        self.assertEqual(status, 200, answer)
        token = answer["token"]
        # (the token in place of the key)
        status, answer = self.call("POST", "/v1/social/state", {}, token=token)
        self.assertEqual(status, 200, answer)
        self.assertEqual(answer["you"]["handle"], "sarge")
        status, answer = self.call("POST", "/v1/identity/devices", {}, token=token)
        self.assertEqual(status, 200, answer)
        self.assertEqual(answer["devices"][0]["id"], device.id.hex())
        status, answer = self.call("GET", "/v1/identity/revoked")
        self.assertEqual(status, 200, answer)
        # (a signature for another node's name is refused)
        nonce = self.nonce()
        other = ed25519.sign(device.seed, identity.token_message("other.test", bytes.fromhex(nonce), device.id)).hex()
        self.assertNotEqual(self.call("POST", "/v1/identity/token", {"device_id": device.id.hex(), "nonce": nonce,
                                                                     "signature": other})[0], 200)


class Settings(unittest.TestCase):
    def test_defaults_and_environment(self):
        settings = config.load("", environ={"DELTA_NODE__DOMAIN": "example.org",
                                            "DELTA_DOORBELL_PASSWORD": "from-the-environment"})
        self.assertEqual(settings["node"]["domain"], "example.org")
        self.assertEqual(settings["node"]["address"], "127.0.0.1")
        self.assertEqual(settings["doorbell"]["password"], "from-the-environment")

    def test_example_file_loads(self):
        if config.tomllib is None:
            self.skipTest("Python 3.11 or newer reads TOML")
        example = Path(__file__).resolve().parent.parent / "config.example.toml"
        settings = config.load(str(example), environ={})
        self.assertEqual(settings["node"]["address"], "127.0.0.1")

    def test_refused(self):
        with self.assertRaises(config.ConfigError):
            config.load("", environ={"DELTA_NODE__DOMAIN": "Not A Host!"})


if __name__ == "__main__":
    unittest.main()
