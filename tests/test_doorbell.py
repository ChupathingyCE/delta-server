# SPDX-FileCopyrightText: 2026 The Chupathingy contributors
# SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
# SPDX-License-Identifier: MIT
"""Tests of the doorbell (doorbell.py): copies' doorbells, the rings each
friends change makes, the game's answers carrying the doorbell, and (when
mosquitto is installed) rings through a local broker set up as ours are:
python3 -m unittest test_doorbell"""

import os
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

import hashlib
import hmac

import doorbell
import friends
from test_clans import make_profiles


class FakeBroker:
    """keeps what it was given"""

    def __init__(self):
        self.rings = []

    def put(self, topic, payload):
        self.rings.append((topic, payload))


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


class Doorbells(unittest.TestCase):
    def test_names_no_network(self):
        # (the brokers are the node's setting: the module names no network's hosts)
        self.assertNotIn("chupathingy.org", doorbell.__doc__)
        self.assertNotIn("1883", doorbell.__doc__)

    def test_topic_ids(self):
        key = bytes(range(32))
        one = doorbell.topic_id(key, "0123456789abcdef0123456789abcdef", 2900)
        self.assertRegex(one, r"^[0-9a-f]{32}$")
        self.assertEqual(one, doorbell.topic_id(key, "0123456789abcdef0123456789abcdef", 2900))
        # (HMAC-SHA256(key, "doorbell:" + ID + ":" + week), its first 16 bytes)
        self.assertEqual(one, hmac.new(key, b"doorbell:0123456789abcdef0123456789abcdef:2900",
                                       hashlib.sha256).hexdigest()[:32])
        # (another copy, another key or another week: another doorbell,
        # nothing in common)
        self.assertNotEqual(one, doorbell.topic_id(key, "0123456789abcdef0123456789abcdee", 2900))
        self.assertNotEqual(one, doorbell.topic_id(bytes(32), "0123456789abcdef0123456789abcdef", 2900))
        self.assertNotEqual(one, doorbell.topic_id(key, "0123456789abcdef0123456789abcdef", 2901))
        self.assertNotIn("0123456789abcdef", one)
        # (a week each)
        self.assertEqual(doorbell.period_of(doorbell.PERIOD * 2900), 2900)
        self.assertEqual(doorbell.period_of(doorbell.PERIOD * 2901 - 1), 2900)

    def test_weekly_doorbells(self):
        clock = Clock()
        clock.now = doorbell.PERIOD * 2900 + doorbell.PERIOD - 30
        broker = FakeBroker()
        bell = doorbell.Doorbell(b"k" * 32, [broker], lambda p: [p], clock)
        handed = bell.heard("copy")
        self.assertEqual(handed, doorbell.topic_id(b"k" * 32, "copy", 2900))
        # (the week turns between its asks: the ring goes to the doorbell it
        # was handed, which it still listens on)
        clock.now += 60
        self.assertNotEqual(bell.topic_id("copy"), handed)
        self.assertEqual(bell.ring(["copy"], "invite"), 1)
        self.assertEqual(broker.rings, [("doorbell/" + handed, b"\x02")])
        # (its next ask hands it this week's, and the rings follow)
        broker.rings.clear()
        new = bell.heard("copy")
        self.assertEqual(new, doorbell.topic_id(b"k" * 32, "copy", 2901))
        self.assertNotEqual(new, handed)
        bell.ring(["copy"], "invite")
        self.assertEqual(broker.rings, [("doorbell/" + new, b"\x02")])

    def test_key_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "doorbell-key")
            key = doorbell.load_key(path)
            self.assertEqual(len(key), 32)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(doorbell.load_key(path), key)
            with open(path, "wb") as file:
                file.write(b"short")
            with self.assertRaises(ValueError):
                doorbell.load_key(path)

    def test_packets(self):
        packet = doorbell.connect_packet("site-1", "doorbell-site", "pw")
        self.assertEqual(packet[:2], bytes([0x10, len(packet) - 2]))
        self.assertEqual(packet[2:12], b"\x00\x04MQTT\x04\xc2\x00\x3c")
        self.assertTrue(packet.endswith(b"\x00\x0ddoorbell-site\x00\x02pw"))
        ring = doorbell.publish_packet("doorbell/" + "a" * 32, b"\x02")
        self.assertEqual(ring, b"\x30" + bytes([2 + 41 + 1]) + b"\x00\x29doorbell/" + b"a" * 32 + b"\x02")
        long = doorbell.publish_packet("t", b"x" * 200)
        self.assertEqual(long[:3], b"\x30\xcb\x01")

    def test_rings_only_listening_copies(self):
        clock = Clock()
        brokers = [FakeBroker(), FakeBroker()]
        copies = {"profile": ["copy1", "copy2"], "other": ["copy3"]}
        bell = doorbell.Doorbell(b"k" * 32, brokers, lambda p: copies.get(p, [p]), clock)
        # (no copy asked lately: nobody to ring)
        self.assertEqual(bell.ring(["profile"], "invite"), 0)
        answer = bell.heard("copy2")
        self.assertEqual(answer, bell.topic_id("copy2"))
        self.assertEqual(bell.ring(["profile", "profile"], "invite"), 1)
        for broker in brokers:
            self.assertEqual(broker.rings, [("doorbell/" + answer, b"\x02")])
        # (each kind its byte; an unknown one is a plain ring)
        bell.ring(["profile"], "presence")
        bell.ring(["profile"], "party")
        bell.ring(["profile"], "nonsense")
        self.assertEqual([r[1] for r in brokers[0].rings[1:]], [b"\x04", b"\x03", b"\x00"])
        # (a copy that stopped asking is let go)
        clock.now += doorbell.LISTEN_LIFETIME + 1
        self.assertEqual(bell.ring(["profile"], "friends"), 0)

    def test_rings_a_minute(self):
        clock = Clock()
        broker = FakeBroker()
        bell = doorbell.Doorbell(b"k" * 32, [broker], lambda p: [p], clock)
        bell.heard("copy")
        for _ in range(doorbell.RINGS_PER_MINUTE + 5):
            bell.ring(["copy"], "friends")
        self.assertEqual(len(broker.rings), doorbell.RINGS_PER_MINUTE)
        clock.now += 60
        bell.heard("copy")
        self.assertEqual(bell.ring(["copy"], "friends"), 1)

    def test_no_setup_without_flags(self):
        self.assertIsNone(doorbell.setup("", [], "", "", lambda p: [p]))
        self.assertIsNone(doorbell.setup("key", [], "", "", lambda p: [p]))
        with self.assertRaises(ValueError):
            doorbell.Broker("https://example.org:443", "u", "p")


class FriendsRings(unittest.TestCase):
    """the rings each friends change makes (friends.py)"""

    def setUp(self):
        self.database = sqlite3.connect(":memory:", check_same_thread=False)
        self.ids = make_profiles(self.database, ["church", "tucker", "caboose", "grif"])
        self.names = {v: k for k, v in self.ids.items()}
        self.clock = Clock()
        self.friends = friends.Friends(self.database, threading.RLock(), self.clock)
        self.rings = []
        self.friends.ring = lambda ids, kind: self.rings.append((sorted(self.names[i] for i in ids), kind))

    def took(self):
        rings, self.rings = self.rings, []
        return rings

    def test_requests(self):
        self.friends.request(self.ids["church"], "tucker")
        self.assertEqual(self.took(), [(["tucker"], "friends")])
        # (asked again: nothing new, no ring)
        self.friends.request(self.ids["church"], "tucker")
        self.assertEqual(self.took(), [])
        self.friends.answer(self.ids["tucker"], "church", True)
        self.assertEqual(self.took(), [(["church", "tucker"], "friends")])
        # (both asked: friends at once, both rung)
        self.friends.request(self.ids["caboose"], "grif")
        self.took()
        self.assertEqual(self.friends.request(self.ids["grif"], "caboose"), "friends")
        self.assertEqual(self.took(), [(["caboose", "grif"], "friends")])
        # (a decline: the one who declined only)
        self.friends.request(self.ids["caboose"], "church")
        self.took()
        self.friends.answer(self.ids["church"], "caboose", False)
        self.assertEqual(self.took(), [(["church"], "friends")])
        self.friends.remove(self.ids["church"], "tucker")
        self.assertEqual(self.took(), [(["church", "tucker"], "friends")])
        # (refused requests ring nobody)
        self.friends.set_privacy(self.ids["grif"], requests="nobody")
        with self.assertRaises(friends.Refused):
            self.friends.request(self.ids["church"], "grif")
        self.assertEqual(self.took(), [])

    def test_blocks_stay_silent(self):
        self.friends.request(self.ids["church"], "tucker")
        self.friends.answer(self.ids["tucker"], "church", True)
        self.took()
        self.friends.block(self.ids["tucker"], "church")
        self.assertEqual(self.took(), [(["tucker"], "friends")])
        # (church's request to someone who blocks him goes nowhere, and rings nobody)
        self.assertEqual(self.friends.request(self.ids["church"], "tucker"), "sent")
        self.assertEqual(self.took(), [])
        with self.assertRaises(friends.Refused):
            self.friends.invite(self.ids["church"], "tucker", "ab" * 32)
        self.assertEqual(self.took(), [])

    def test_invites_and_presence(self):
        self.friends.request(self.ids["church"], "tucker")
        self.friends.answer(self.ids["tucker"], "church", True)
        self.friends.request(self.ids["church"], "caboose")
        self.friends.answer(self.ids["caboose"], "church", True)
        self.took()
        self.friends.invite(self.ids["church"], "tucker", "ab" * 32)
        self.assertEqual(self.took(), [(["tucker"], "invite")])
        # (coming online rings the friends once, not every poll)
        self.friends.mark_online(self.ids["church"])
        self.assertEqual(self.took(), [(["caboose", "tucker"], "presence")])
        self.clock.now += 20
        self.friends.mark_online(self.ids["church"])
        self.assertEqual(self.took(), [])
        self.clock.now += friends.ONLINE_LIFETIME + 1
        self.friends.mark_online(self.ids["church"])
        self.assertEqual(self.took(), [(["caboose", "tucker"], "presence")])
        # (appearing offline rings nobody, nor do its polls)
        self.friends.set_privacy(self.ids["church"], appear_offline=True)
        self.assertEqual(self.took(), [])
        self.friends.mark_online(self.ids["church"])
        self.friends.set_privacy(self.ids["church"], join="anyone")
        self.assertEqual(self.took(), [])
        self.friends.set_privacy(self.ids["church"], appear_offline=False)
        self.assertEqual(self.took(), [(["caboose", "tucker"], "presence")])
        # (back on when it was already: nothing changed, nobody rung)
        self.friends.set_privacy(self.ids["church"], appear_offline=False)
        self.assertEqual(self.took(), [])
        # (no friends: nobody)
        self.friends.mark_online(self.ids["grif"])
        self.assertEqual(self.took(), [([], "presence")])


def mosquitto_tool(name):
    found = shutil.which(name)
    if found:
        return found
    for folder in ("/opt/homebrew/opt/mosquitto/sbin", "/opt/homebrew/opt/mosquitto/bin",
                   "/usr/local/opt/mosquitto/sbin", "/usr/local/opt/mosquitto/bin", "/usr/sbin"):
        if (Path(folder) / name).exists():
            return str(Path(folder) / name)
    return None


@unittest.skipUnless(mosquitto_tool("mosquitto") and mosquitto_tool("mosquitto_passwd") and mosquitto_tool("mosquitto_sub"),
                     "mosquitto is not installed")
class LocalBroker(unittest.TestCase):
    """the site's publisher on a local mosquitto with the brokers' ACL (one
    plain listener here: ours have the game's on 1883 and the site's, TLS,
    on 8883)"""

    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        folder = Path(cls.folder.name)
        cls.password = "site-test-password"
        subprocess.run([mosquitto_tool("mosquitto_passwd"), "-c", "-b", str(folder / "passwords"), doorbell.DEFAULT_USER,
                        cls.password], check=True, capture_output=True)
        os.chmod(folder / "passwords", 0o600)
        # (as our brokers: the game's signalling listener, and the site's)
        (folder / "acl").write_text("topic readwrite hceu/#\npattern readwrite hceu/#\npattern read doorbell/%u\n")
        (folder / "site-acl").write_text("user doorbell-site\ntopic write doorbell/+\n")
        for name in ("acl", "site-acl"):
            os.chmod(folder / name, 0o600)
        ports = []
        for _ in range(2):
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                ports.append(probe.getsockname()[1])
        cls.port, cls.site_port = ports
        (folder / "mosquitto.conf").write_text(
            "per_listener_settings true\npersistence false\nlog_dest stderr\nlog_type error\n"
            f"listener {cls.port} 127.0.0.1\nallow_anonymous true\nacl_file {folder / 'acl'}\n"
            f"listener {cls.site_port} 127.0.0.1\nallow_anonymous false\npassword_file {folder / 'passwords'}\n"
            f"acl_file {folder / 'site-acl'}\n")
        cls.process = subprocess.Popen([mosquitto_tool("mosquitto"), "-c", str(folder / "mosquitto.conf")],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.2).close()
                socket.create_connection(("127.0.0.1", cls.site_port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=5)
        cls.folder.cleanup()

    def subscriber(self, user, topic):
        """a client as the game's signalling is: a client ID of its own, the
        doorbell as its user name (none for "")"""
        return subprocess.Popen([mosquitto_tool("mosquitto_sub"), "-h", "127.0.0.1", "-p", str(self.port), "-V", "mqttv311",
                                 "-i", "hceu-" + os.urandom(4).hex(), "-t", topic, "-C", "1", "-W", "4"] +
                                (["-u", user] if user else []),
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def test_rings_reach_their_copy_only(self):
        logs = []
        broker = doorbell.Broker(f"mqtt://127.0.0.1:{self.site_port}", doorbell.DEFAULT_USER, self.password, log=logs.append)
        bell = doorbell.Doorbell(b"s" * 32, [broker], lambda p: [p])
        bell.start()
        try:
            for _ in range(50):
                if broker.connected:
                    break
                time.sleep(0.1)
            self.assertTrue(broker.connected, logs)
            mine, theirs = bell.heard("copy-one"), bell.topic_id("copy-two")
            owner = self.subscriber(mine, "doorbell/" + mine)
            snoopers = [self.subscriber(theirs, "doorbell/" + mine), self.subscriber(theirs, "doorbell/+"),
                        self.subscriber(theirs, "doorbell/#"), self.subscriber("", "doorbell/#"),
                        self.subscriber("#", "#")]
            time.sleep(1)
            self.assertEqual(bell.ring(["copy-one"], "invite"), 1)
            self.assertEqual(owner.communicate(timeout=10)[0], b"\x02\n")
            for snooper in snoopers:
                self.assertEqual(snooper.communicate(timeout=10)[0], b"")
        finally:
            bell.stop()

    def test_wrong_password_is_refused(self):
        logs = []
        broker = doorbell.Broker(f"mqtt://127.0.0.1:{self.site_port}", doorbell.DEFAULT_USER, "wrong", log=logs.append)
        broker.start()
        time.sleep(1)
        broker.stop()
        self.assertFalse(broker.connected)
        self.assertTrue(any("refused" in line for line in logs), logs)


if __name__ == "__main__":
    unittest.main()
