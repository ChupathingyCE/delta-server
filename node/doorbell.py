"""Delta's doorbell (list_server.py): a ring to a copy of the game when
something changed for its profile (a friend request, becoming friends, an
invite, a party, a clan's invite, a friend coming online), so its Guide asks for its friends
state at once instead of on its next poll (chupathingyce's docs/delta.md,
"The doorbell").

Each linked copy has a doorbell: the first 128 bits of HMAC-SHA256 under
the doorbell key (a secret only this process has) over its player ID and
the week (PERIOD), as 32 hex digits, so a doorbell that got out goes stale
within a week. The site remembers the doorbell it last handed each copy and
rings that one, so a ring at the turn of the week still reaches the topic
the copy listens on; its next ask hands it the new one. The friends state the game asks for carries it; the copy
listens on the MQTT topic doorbell/<doorbell> over the connections internet
play's signalling already keeps to our brokers (doorbell.chupathingy.org and
mqtt.chupathingy.org, port 1883), with the doorbell as its MQTT user name.
The brokers let a client read only doorbell/<its user name>, and only the
site (the user doorbell-site, on their TLS listener, 8883) write, so a
doorbell can't be guessed, listened to by anyone else or rung by anyone but
us.

A ring is MQTT 3.1.1 QoS 0, not retained, one byte: what kind of change
(RING_KINDS). Nothing else: no handle, no profile, no game. It goes to every
broker, and only to copies that asked for their friends state in the last
LISTEN_LIFETIME seconds (heard), at most RINGS_PER_MINUTE a minute each.
Rings wait in memory at most RING_LIFETIME seconds for a broker; a broker
that is down costs the game nothing but the speed (it polls as before).

SPDX-FileCopyrightText: 2026 The Chupathingy contributors
SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: GPL-3.0-or-later
"""

import hashlib
import hmac
import os
import secrets
import select
import socket
import ssl
import struct
import threading
import time
from collections import deque

RING_KINDS = {"any": 0, "friends": 1, "invite": 2, "party": 3, "presence": 4, "clan": 5}
PERIOD = 7 * 24 * 3600  # (a doorbell lasts a week)
LISTEN_LIFETIME = 180  # (the game asks every 20 s in menus, 60 s in a game)
RINGS_PER_MINUTE = 12
RING_LIFETIME = 10
QUEUE_MOST = 5000
KEEP_ALIVE = 60
RETRY_FIRST = 1
RETRY_MOST = 60
TOPIC_PREFIX = "doorbell/"
DEFAULT_USER = "doorbell-site"


def period_of(when: float) -> int:
    """the week a time falls in (PERIOD)"""
    return int(when // PERIOD)


def topic_id(key: bytes, game_id: str, period: int) -> str:
    """a copy's doorbell in a week (period_of): 32 hex digits"""
    message = "doorbell:%s:%d" % (game_id, period)
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()[:32]


def load_key(path: str) -> bytes:
    """the doorbell key at path (32 random bytes), made (0600) if missing"""
    try:
        with open(path, "rb") as file:
            key = file.read()
    except FileNotFoundError:
        key = secrets.token_bytes(32)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as file:
            file.write(key)
    if len(key) < 32:
        raise ValueError("the doorbell key is too short")
    return key


# ---------- MQTT 3.1.1, the little the site needs

def _length(value: int) -> bytes:
    out = bytearray()
    while True:
        byte, value = value % 128, value // 128
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _string(text: str) -> bytes:
    data = text.encode()
    return struct.pack("!H", len(data)) + data


def connect_packet(client_id: str, user: str, password: str, keep_alive: int = KEEP_ALIVE) -> bytes:
    """CONNECT: a clean session, a user name and password, no will"""
    body = _string("MQTT") + bytes([4, 0x80 | 0x40 | 0x02]) + struct.pack("!H", keep_alive)
    body += _string(client_id) + _string(user) + _string(password)
    return b"\x10" + _length(len(body)) + body


def publish_packet(topic: str, payload: bytes) -> bytes:
    """PUBLISH at QoS 0, not retained"""
    body = _string(topic) + payload
    return b"\x30" + _length(len(body)) + body


PING = b"\xc0\x00"
DISCONNECT = b"\xe0\x00"


class Broker(threading.Thread):
    """one broker's connection: rings published from a queue, reconnecting
    with a growing wait; mqtts://host:port (TLS, the host's certificate
    checked) or mqtt://host:port (tests)"""

    def __init__(self, url: str, user: str, password: str, log=print, context=None, clock=time.monotonic):
        super().__init__(daemon=True, name="doorbell " + url)
        scheme, _, rest = url.partition("://")
        if scheme not in ("mqtt", "mqtts") or ":" not in rest:
            raise ValueError("a doorbell broker is mqtts://host:port")
        self.host, port = rest.rsplit(":", 1)
        self.port = int(port)
        self.secure = scheme == "mqtts"
        self.user = user
        self.password = password
        self.log = log
        self.context = context
        self.clock = clock
        self.queue = deque(maxlen=QUEUE_MOST)
        self.wake = threading.Event()
        self.stopping = False
        self.connected = False
        self.sent = 0

    def put(self, topic: str, payload: bytes):
        self.queue.append((self.clock(), topic, payload))
        self.wake.set()

    def stop(self):
        self.stopping = True
        self.wake.set()

    def _open(self):
        raw = socket.create_connection((self.host, self.port), timeout=10)
        try:
            if self.secure:
                context = self.context or ssl.create_default_context()
                raw = context.wrap_socket(raw, server_hostname=self.host)
            raw.sendall(connect_packet("site-" + secrets.token_hex(8), self.user, self.password))
            answer = b""
            while len(answer) < 4:
                chunk = raw.recv(4 - len(answer))
                if not chunk:
                    raise ConnectionError("the broker closed the connection")
                answer += chunk
            if answer[0] != 0x20 or answer[3] != 0:
                raise ConnectionError("the broker refused the connection (%d)" % answer[3])
        except BaseException:
            raw.close()
            raise
        raw.settimeout(10)
        return raw

    def _serve(self, connection):
        """publishes until the connection fails or the broker stops"""
        last_sent = self.clock()
        while not self.stopping:
            self.wake.wait(5)
            self.wake.clear()
            now = self.clock()
            while self.queue:
                queued, topic, payload = self.queue.popleft()
                if now - queued > RING_LIFETIME:
                    continue
                connection.sendall(publish_packet(topic, payload))
                self.sent += 1
                last_sent = now
            if now - last_sent >= KEEP_ALIVE * 3 // 4:
                connection.sendall(PING)
                last_sent = now
            # (what the broker sends: PINGRESP, read and let go; nothing at
            # the end of the connection)
            pending = connection.pending() if self.secure else 0
            if pending or select.select([connection], [], [], 0)[0]:
                if not connection.recv(4096):
                    raise ConnectionError("the broker closed the connection")
        try:
            connection.sendall(DISCONNECT)
        except OSError:
            pass

    def run(self):
        wait = RETRY_FIRST
        while not self.stopping:
            connection = None
            try:
                connection = self._open()
                self.connected = True
                self.log("Doorbell: publishing to %s" % self.host)
                wait = RETRY_FIRST
                self._serve(connection)
            except (OSError, ConnectionError, ssl.SSLError) as error:
                if self.connected or wait == RETRY_FIRST:
                    self.log("Doorbell: %s: %s" % (self.host, error))
            finally:
                self.connected = False
                if connection is not None:
                    try:
                        connection.close()
                    except OSError:
                        pass
            if self.stopping:
                break
            # (rings that waited too long for a broker are let go)
            now = self.clock()
            while self.queue and now - self.queue[0][0] > RING_LIFETIME:
                self.queue.popleft()
            self.wake.wait(wait)
            self.wake.clear()
            wait = min(wait * 2, RETRY_MOST)


class Doorbell:
    """the doorbells of linked copies, and the rings to them

    copies_of(profile ID) -> the player IDs of its copies (its own and the
    ones linked to it)"""

    def __init__(self, key: bytes, brokers: list, copies_of, clock=time.time):
        self.key = key
        self.brokers = brokers
        self.copies_of = copies_of
        self.clock = clock
        self.memory = threading.Lock()
        # copy's player ID -> (when it last asked for its friends, the
        # doorbell it was handed then)
        self.listening = {}
        self.rung = {}  # doorbell -> [times]

    def start(self):
        for broker in self.brokers:
            broker.start()

    def stop(self):
        for broker in self.brokers:
            broker.stop()

    def topic_id(self, game_id: str, when: float = None) -> str:
        """a copy's doorbell for the week of when (default: now)"""
        return topic_id(self.key, game_id, period_of(self.clock() if when is None else when))

    def heard(self, game_id: str) -> str:
        """a copy asked for its friends state (it may be listening): its
        doorbell for this week, for the answer, remembered for the rings"""
        now = self.clock()
        doorbell = self.topic_id(game_id, now)
        with self.memory:
            self.listening[game_id] = (now, doorbell)
            if len(self.listening) > 100000:
                for stale in [g for g, (t, _) in self.listening.items() if now - t > LISTEN_LIFETIME]:
                    del self.listening[stale]
        return doorbell

    def ring(self, profile_ids, kind: str = "any") -> int:
        """the copies of these profiles that may be listening rung: how
        many doorbells"""
        payload = bytes([RING_KINDS.get(kind, 0)])
        now = self.clock()
        doorbells = []
        for profile_id in dict.fromkeys(profile_ids):
            for game_id in self.copies_of(profile_id):
                with self.memory:
                    heard = self.listening.get(game_id)
                    if heard is None or now - heard[0] > LISTEN_LIFETIME:
                        continue
                    # (the one it was handed: at the turn of the week, the
                    # copy listens on last week's until it asks again)
                    doorbell = heard[1]
                    times = [t for t in self.rung.get(doorbell, ()) if now - t < 60]
                    if len(times) >= RINGS_PER_MINUTE:
                        self.rung[doorbell] = times
                        continue
                    times.append(now)
                    self.rung[doorbell] = times
                    if len(self.rung) > 100000:
                        for stale in [d for d, v in self.rung.items() if not v or now - v[-1] > 60]:
                            del self.rung[stale]
                doorbells.append(doorbell)
        for doorbell in doorbells:
            for broker in self.brokers:
                broker.put(TOPIC_PREFIX + doorbell, payload)
        return len(doorbells)


def setup(key_file: str, urls: list, password_file: str, user: str, copies_of, log=print):
    """the doorbell of list_server's flags, started; None without a key file
    or a broker"""
    if not key_file or not urls:
        return None
    with open(password_file, encoding="utf-8") as file:
        password = file.read().strip()
    key = load_key(key_file)
    brokers = [Broker(url, user or DEFAULT_USER, password, log=log) for url in urls]
    doorbell = Doorbell(key, brokers, copies_of)
    doorbell.start()
    log("Doorbell: ringing on " + ", ".join(b.host for b in brokers))
    return doorbell
