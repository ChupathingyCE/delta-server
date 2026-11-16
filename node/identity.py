"""Delta device identity (chupathingyce's docs/delta.md, "Device identity"
and "Devices"): device keys and the site's short-lived certificates for them,
beside the old player key. Stage A enrolls a copy's device with its key;
stage B signs a device in by code (Quick Connect) and keeps each account's
device list, with revoke and sign out everywhere; stage C turns an
account's player key off for new things once every copy has its device.
A device may come through another app's client ID (delta_clients.py), which
limits what its certificate and tokens may do.

A copy of the game makes its own Ed25519 key, its device key. It proves its
old player key once (legacy enrollment) and gets a device certificate
(CDEV) signed by the site's issuer key, which a root key of the identity key
set vouches for (CISS, from command's identity-issuer.yml). From then on it
asks for an hour's bearer token with a signature of its device key, and
sends the token instead of the player key. A revoked device is on the
revocation list (CREV) until every certificate it could hold has expired.

Everything binary is little-endian and read byte by byte, so the game's C
reader works the same on big-endian consoles.

CISS, the issuer certificate (format 1, 112 bytes):

    0   4   magic "CISS"
    4   1   format, 1
    5   3   reserved, 0
    8   4   valid from, Unix seconds
    12  4   valid until
    16  32  the issuer's public key
    48  64  Ed25519 signature by a root key of ISSUER_LABEL + bytes 0-47

CDEV, the device certificate (format 1, 148 + L bytes, at most 168):

    0   4   magic "CDEV"
    4   1   format, 1
    5   1   platform (delta_list.PLATFORMS' index; the game's platform key)
    6   1   handle length L: 0 (no profile yet) or 3 to 20
    7   1   flags: 0x01 legacy enrolled, 0x02 console
    8   4   issued
    12  4   expires
    16  8   serial (random)
    24  8   the issuer's key ID
    32  16  account: the profile's player ID (the copy's own ID while it
            has no profile)
    48  32  the device's public key
    80  4   capabilities (CAPABILITIES)
    84  L   the handle, lowercase
    84+L 64 Ed25519 signature by the issuer of DEVICE_LABEL + bytes before it

CREV, the revocation list (format 1, 32 + 16 N + 64 bytes):

    0   4   magic "CREV"
    4   1   format, 1
    5   3   reserved, 0
    8   4   serial (rises with each new list)
    12  4   issued
    16  4   next update
    20  8   the issuer's key ID
    28  2   count N (at most REVOKED_MOST)
    30  2   reserved, 0
    32  16N device IDs, sorted
    ... 64  Ed25519 signature by the issuer of REVOKED_LABEL + bytes before it

CSIN, a sign-in for another site (format 1, 72 + A + L + 64 bytes): the
site's answer that a person signed in here is this profile, for one sign-in
on one of our other sites (sign_in_sites, like maps.chupathingy.org), which
checks it with the issuer certificate and the root keys alone. It is no
device: it is never in the device list and carries no capabilities.

    0   4   magic "CSIN"
    4   1   format, 1
    5   1   handle length L, 3 to 20
    6   1   audience length A, 1 to 253
    7   1   reserved, 0
    8   4   issued
    12  4   expires, at most SITE_SECONDS after
    16  8   the issuer's key ID
    24  16  account: the profile's player ID
    40  32  the other site's nonce (it binds the answer to one browser's
            sign-in there)
    72  A   audience: the other site's host, lowercase
    72+A L  the handle, lowercase
    ... 64  Ed25519 signature by the issuer of SITE_LABEL + bytes before it

Key ID: the first 8 bytes of SHA-256 of the issuer's public key. Device ID:
the first 16 bytes of SHA-256(DEVICE_ID_LABEL + the device's public key).

Every device signature names its audience, the site's host (AUDIENCE), so
one made for another site is no use here.

The site never holds the issuer key in the web process when a signer runs
(identity.py signer: its own process, over a Unix socket). The signer signs
only well-formed certificates of its own key ID issued now, and lists of its
own key ID whose serial rises, and counts them; the site checks every
signature it gets back. A signer that is down makes the requests answer 503
until it is back.

Signatures are checked as Monocypher 4 checks them (ed25519.py): S below the
group order, cofactored ([8]R = [8]([S]B - [h]A)), points that aren't
canonically encoded allowed, and keys of small order refused here.

    identity.py issuer-key --out FILE
        a new issuer key (FILE, 0600, the seed as 64 hex digits) and its
        public half, for command's identity-issuer.yml
    identity.py signer --key FILE --socket PATH
        the signer process
    identity.py show FILE
        a certificate or list's fields (one hex line, or a JSON answer)

SPDX-FileCopyrightText: 2026 The Chupathingy contributors
SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: MIT
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import socketserver
import stat
import struct
import sys
import threading
import time
from collections import defaultdict

import ed25519

ISSUER_MAGIC = b"CISS"
DEVICE_MAGIC = b"CDEV"
REVOKED_MAGIC = b"CREV"
FORMAT = 1
ISSUER_LABEL = b"chupathingy identity issuer v1\n"
DEVICE_LABEL = b"chupathingy device cert v1\n"
REVOKED_LABEL = b"chupathingy device revocations v1\n"
DEVICE_ID_LABEL = b"chupathingy device id\n"
ENROLL_LABEL = b"chupathingy legacy enroll v1\n"
REFRESH_LABEL = b"chupathingy device refresh v1\n"
TOKEN_LABEL = b"chupathingy device token v1\n"
START_LABEL = b"chupathingy device start v1\n"
CONFIRM_LABEL = b"chupathingy device confirm v1\n"
SIGNOUT_LABEL = b"chupathingy device signout v1\n"
CODE_LABEL = b"chupathingy device code v1\n"
SITE_MAGIC = b"CSIN"
SITE_LABEL = b"chupathingy site sign-in v1\n"

ISSUER_SIZE = 48 + 64
SITE_HEADER = 72
SITE_SECONDS = 120
DEVICE_HEADER = 84
SIGNATURE = 64
DEVICE_MOST = DEVICE_HEADER + 20 + SIGNATURE
REVOKED_HEADER = 32
REVOKED_MOST = 4096

FLAG_LEGACY = 0x01
FLAG_CONSOLE = 0x02
CAPABILITIES = {"play": 0x01, "stats": 0x02, "profile": 0x04, "moderate": 0x08, "social": 0x10, "devices": 0x20}
# (a device enrolled with its player key, or one approved from another
# device: everything but "devices", so approving and revoking devices never
# passes down a chain; only a device approved from a password session on
# the site gets it)
LEGACY_CAPABILITIES = 0x1F
DEVICE_CAPABILITIES = 0x1F
TRUSTED_CAPABILITIES = 0x3F

DESKTOP_DAYS = 7
CONSOLE_DAYS = 14
CONSOLE_PLATFORMS = ("xbox", "xbox360", "wiiu", "switch", "psp", "vita", "xbox_uwp", "ps3", "ps4", "ps5", "n64")
# (a revoked device stays on the list this long after: its last
# certificate's longest life, and a day's grace)
REVOKED_KEPT = (CONSOLE_DAYS + 1) * 86400
REVOKED_REBUILD = 600
REVOKED_NEXT = 86400
# (an issuer certificate's validity, at most; the workflow makes 90 days)
ISSUER_MOST_DAYS = 120
# (the time a check allows a clock to be off by)
GRACE = 600

# Quick Connect (stage B): a code's life, how long the device has to say yes
# once it is approved, how long the answer is kept after, and the limits
CODE_LIFETIME = 600
CONFIRM_LIFETIME = 120
CONNECTED_KEPT = 120
POLL_INTERVAL = 5
CODE_STARTS_PER_HOUR = 10
POLLS_PER_CODE = 400
POLLS_PER_ADDRESS = 2000
CONFIRMS_PER_CODE = 5
CONFIRMS_PER_ADDRESS = 30
CODES_MOST = 2000
DEVICES_PER_ACCOUNT = 64
DEVICES_SHOWN = 32
# (stage C: an account's player key)
LEGACY_SETTINGS = ("auto", "on", "off")
LEGACY_OFF_ERROR = "Update Chupathingy to keep using your profile."
# (a copy that moved to a device but whose key a game used after, this long
# after its move and within this many days, still counts as on the key)
KEY_SEEN_GRACE = 60
KEY_SEEN_DAYS = 30
# (a console's own-key claim marks its ID a console's this long)
CONSOLE_DAYS_KEPT = 60
# (shown with a device whose code was typed in, before it is approved)
CODE_WARNING = "Only enter a code shown on your own screen."

HANDLE = re.compile(r"^[a-z0-9_-]{3,20}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")


def key_id(public: bytes) -> bytes:
    return hashlib.sha256(public).digest()[:8]


def device_id(public: bytes) -> bytes:
    return hashlib.sha256(DEVICE_ID_LABEL + public).digest()[:16]


def small_order(public: bytes) -> bool:
    """a key anyone can sign for (refused as a device or issuer key)"""
    return ed25519.to_x25519(public) is None


# ---------- CISS


def issuer_body(valid_from: int, valid_until: int, public: bytes) -> bytes:
    if len(public) != 32 or not 0 < valid_from < valid_until <= 0xFFFFFFFF:
        raise ValueError("not an issuer key, or not a validity")
    return ISSUER_MAGIC + bytes((FORMAT, 0, 0, 0)) + struct.pack("<II", valid_from, valid_until) + public


def parse_issuer(data: bytes):
    """{"valid_from", "valid_until", "public", "key_id", "body",
    "signature"}, or None if it is not a format 1 issuer certificate"""
    if len(data) != ISSUER_SIZE or data[:4] != ISSUER_MAGIC or data[4] != FORMAT or data[5:8] != bytes(3):
        return None
    valid_from, valid_until = struct.unpack("<II", data[8:16])
    if not valid_from < valid_until:
        return None
    return {"valid_from": valid_from, "valid_until": valid_until, "public": data[16:48],
            "key_id": key_id(data[16:48]), "body": data[:48], "signature": data[48:]}


def check_issuer(fields, roots, now: int) -> str:
    """why an issuer certificate is not one to trust now, or "" """
    if not fields:
        return "not an issuer certificate"
    if not any(ed25519.verify(root, ISSUER_LABEL + fields["body"], fields["signature"]) for root in roots):
        return "not signed by a root key"
    if small_order(fields["public"]):
        return "a weak issuer key"
    if now + GRACE < fields["valid_from"]:
        return "not valid yet"
    if now >= fields["valid_until"] + GRACE:
        return "expired"
    return ""


# ---------- CDEV


def device_body(platform: int, flags: int, issued: int, expires: int, serial: bytes, issuer_key_id: bytes,
                account: bytes, public: bytes, capabilities: int, handle: str) -> bytes:
    raw = handle.encode("ascii") if handle else b""
    if raw and not HANDLE.match(handle):
        raise ValueError("a handle is 3 to 20 of a-z, 0-9, _ and -")
    if len(serial) != 8 or len(issuer_key_id) != 8 or len(account) != 16 or len(public) != 32:
        raise ValueError("a field of the wrong size")
    if not 0 <= platform < 256 or not 0 <= flags < 256 or not 0 < issued < expires <= 0xFFFFFFFF:
        raise ValueError("not a platform, flags or lifetime")
    return (DEVICE_MAGIC + bytes((FORMAT, platform, len(raw), flags)) + struct.pack("<II", issued, expires) +
            serial + issuer_key_id + account + public + struct.pack("<I", capabilities & 0xFFFFFFFF) + raw)


def parse_device(data: bytes):
    """{"platform", "flags", "issued", "expires", "serial", "issuer",
    "account", "public", "device_id", "capabilities", "handle", "body",
    "signature"}, or None if it is not a format 1 device certificate"""
    if len(data) < DEVICE_HEADER + SIGNATURE or data[:4] != DEVICE_MAGIC or data[4] != FORMAT:
        return None
    length = data[6]
    if (length and not 3 <= length <= 20) or len(data) != DEVICE_HEADER + length + SIGNATURE:
        return None
    handle = data[DEVICE_HEADER:DEVICE_HEADER + length]
    try:
        handle = handle.decode("ascii")
    except UnicodeDecodeError:
        return None
    if handle and not HANDLE.match(handle):
        return None
    issued, expires = struct.unpack("<II", data[8:16])
    if not issued < expires:
        return None
    return {"platform": data[5], "flags": data[7], "issued": issued, "expires": expires, "serial": data[16:24],
            "issuer": data[24:32], "account": data[32:48], "public": data[48:80], "device_id": device_id(data[48:80]),
            "capabilities": struct.unpack("<I", data[80:84])[0], "handle": handle,
            "body": data[:DEVICE_HEADER + length], "signature": data[DEVICE_HEADER + length:]}


def check_device(fields, issuer, now: int, revoked=frozenset()) -> str:
    """why a device certificate is not one to trust now under a trusted
    issuer certificate's fields (check_issuer first), or "" """
    if not fields:
        return "not a device certificate"
    if not issuer or fields["issuer"] != issuer["key_id"]:
        return "another issuer's"
    if not ed25519.verify(issuer["public"], DEVICE_LABEL + fields["body"], fields["signature"]):
        return "not signed by its issuer"
    if not issuer["valid_from"] <= fields["issued"] <= issuer["valid_until"]:
        return "issued outside its issuer's time"
    if small_order(fields["public"]):
        return "a weak device key"
    if now + GRACE < fields["issued"]:
        return "issued in the future"
    if now >= fields["expires"] + GRACE:
        return "expired"
    if fields["device_id"] in revoked:
        return "revoked"
    return ""


# ---------- CREV


def revoked_body(serial: int, issued: int, next_update: int, issuer_key_id: bytes, device_ids) -> bytes:
    ids = sorted(set(device_ids))
    if len(ids) > REVOKED_MOST or any(len(i) != 16 for i in ids) or len(issuer_key_id) != 8:
        raise ValueError("not a list of device IDs")
    if not 0 <= serial <= 0xFFFFFFFF or not 0 < issued < next_update <= 0xFFFFFFFF:
        raise ValueError("not a serial or times")
    return (REVOKED_MAGIC + bytes((FORMAT, 0, 0, 0)) + struct.pack("<III", serial, issued, next_update) +
            issuer_key_id + struct.pack("<HH", len(ids), 0) + b"".join(ids))


def parse_revoked(data: bytes):
    """{"serial", "issued", "next_update", "issuer", "device_ids", "body",
    "signature"}, or None"""
    if len(data) < REVOKED_HEADER + SIGNATURE or data[:4] != REVOKED_MAGIC or data[4] != FORMAT or \
            data[5:8] != bytes(3):
        return None
    serial, issued, next_update = struct.unpack("<III", data[8:20])
    count, reserved = struct.unpack("<HH", data[28:32])
    if reserved or count > REVOKED_MOST or len(data) != REVOKED_HEADER + 16 * count + SIGNATURE:
        return None
    ids = [data[REVOKED_HEADER + 16 * i:REVOKED_HEADER + 16 * (i + 1)] for i in range(count)]
    if ids != sorted(set(ids)):
        return None
    return {"serial": serial, "issued": issued, "next_update": next_update, "issuer": data[20:28],
            "device_ids": ids, "body": data[:REVOKED_HEADER + 16 * count], "signature": data[-SIGNATURE:]}


def check_revoked(fields, issuer) -> str:
    if not fields:
        return "not a revocation list"
    if not issuer or fields["issuer"] != issuer["key_id"]:
        return "another issuer's"
    if not ed25519.verify(issuer["public"], REVOKED_LABEL + fields["body"], fields["signature"]):
        return "not signed by its issuer"
    return ""
# ---------- what a device signs
#
# Every device signature names its audience, the site's host as the device
# addresses it (lowercase, no scheme or port), so a signature made for one
# site can't be spent at another: one byte of length, then the host.

# ---------- CSIN


def site_body(issued: int, expires: int, issuer_key_id: bytes, account: bytes, nonce: bytes, audience: str,
              handle: str) -> bytes:
    if not HANDLE.match(handle or "") or not AUDIENCE.match(audience or ""):
        raise ValueError("a handle is 3 to 20 of a-z, 0-9, _ and -, and an audience a host name")
    if len(issuer_key_id) != 8 or len(account) != 16 or len(nonce) != 32:
        raise ValueError("a field of the wrong size")
    if not 0 < issued < expires <= 0xFFFFFFFF:
        raise ValueError("not a lifetime")
    raw_audience, raw_handle = audience.encode("ascii"), handle.encode("ascii")
    return (SITE_MAGIC + bytes((FORMAT, len(raw_handle), len(raw_audience), 0)) + struct.pack("<II", issued, expires) +
            issuer_key_id + account + nonce + raw_audience + raw_handle)


def parse_site(data: bytes):
    """{"issued", "expires", "issuer", "account", "nonce", "audience",
    "handle", "body", "signature"}, or None if it is not a format 1
    sign-in for another site"""
    if len(data) < SITE_HEADER + SIGNATURE or data[:4] != SITE_MAGIC or data[4] != FORMAT or data[7] != 0:
        return None
    handle_length, audience_length = data[5], data[6]
    end = SITE_HEADER + audience_length + handle_length
    if not 3 <= handle_length <= 20 or not 1 <= audience_length <= 253 or len(data) != end + SIGNATURE:
        return None
    try:
        audience = data[SITE_HEADER:SITE_HEADER + audience_length].decode("ascii")
        handle = data[SITE_HEADER + audience_length:end].decode("ascii")
    except UnicodeDecodeError:
        return None
    if not AUDIENCE.match(audience) or not HANDLE.match(handle):
        return None
    issued, expires = struct.unpack("<II", data[8:16])
    if not issued < expires:
        return None
    return {"issued": issued, "expires": expires, "issuer": data[16:24], "account": data[24:40],
            "nonce": data[40:72], "audience": audience, "handle": handle, "body": data[:end],
            "signature": data[end:]}


def check_site(fields, issuer, audience: str, nonce: bytes, now: int) -> str:
    """why a sign-in is not one for this site and this browser now, under a
    trusted issuer certificate's fields (check_issuer first), or "" (the
    other site's side, here for the tests and as its reference)"""
    if not fields:
        return "not a sign-in"
    if not issuer or fields["issuer"] != issuer["key_id"]:
        return "another issuer's"
    if not ed25519.verify(issuer["public"], SITE_LABEL + fields["body"], fields["signature"]):
        return "not signed by its issuer"
    if not issuer["valid_from"] <= fields["issued"] <= issuer["valid_until"]:
        return "issued outside its issuer's time"
    if fields["audience"] != audience:
        return "for another site"
    if not hmac.compare_digest(fields["nonce"], nonce):
        return "for another sign-in"
    if fields["expires"] - fields["issued"] > SITE_SECONDS:
        return "too long"
    if now + GRACE < fields["issued"]:
        return "issued in the future"
    if now >= fields["expires"]:
        return "expired"
    return ""


AUDIENCE = re.compile(r"^[a-z0-9.-]{1,253}$")
# (a node names its own host names: config identity.audiences, else node.domain)
DEFAULT_AUDIENCES = ("localhost",)


def audience_bytes(audience: str) -> bytes:
    if not AUDIENCE.match(audience):
        raise ValueError("an audience is a host name")
    return bytes((len(audience),)) + audience.encode("ascii")


def enroll_message(audience: str, nonce: bytes, copy_id: bytes, public: bytes) -> bytes:
    return ENROLL_LABEL + audience_bytes(audience) + nonce + copy_id + public


def refresh_message(audience: str, nonce: bytes, device: bytes) -> bytes:
    return REFRESH_LABEL + audience_bytes(audience) + nonce + device


def token_message(audience: str, nonce: bytes, device: bytes) -> bytes:
    return TOKEN_LABEL + audience_bytes(audience) + nonce + device


def start_message(audience: str, nonce: bytes, public: bytes) -> bytes:
    """Quick Connect's start: the device proves its key before a code is
    made for it"""
    return START_LABEL + audience_bytes(audience) + nonce + public


def confirm_message(audience: str, nonce: bytes, device: bytes, accept: bool, handle: str) -> bytes:
    """the device's answer to an approval: yes or no, for the profile its
    player was shown"""
    raw = handle.encode("ascii")
    return CONFIRM_LABEL + audience_bytes(audience) + nonce + device + bytes((1 if accept else 0, len(raw))) + raw


def signout_message(audience: str, nonce: bytes, device: bytes) -> bytes:
    return SIGNOUT_LABEL + audience_bytes(audience) + nonce + device


# ---------- Quick Connect codes
#
# The device works its code out itself, from its key and a nonce the site
# picks after it has seen the key, so someone in the middle who swaps in
# their own key gets a code that isn't the one on the screen. Same alphabet,
# length and life as a console's Link Profile code (console_link.py), so
# both are typed into the same box at /connect.

CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
CODE_LENGTH = 8


def device_code(public: bytes, code_nonce: bytes) -> str:
    """the code (CODE_LENGTH characters of CODE_ALPHABET, no dash)"""
    digest = hashlib.sha256(CODE_LABEL + public + code_nonce).digest()
    return "".join(CODE_ALPHABET[digest[index] % len(CODE_ALPHABET)] for index in range(CODE_LENGTH))


# ---------- the issuer key: in this process, or the signer's

# (how far a certificate's "issued" may be from the signer's clock)
SIGNER_GRACE = 300


class SignerError(Exception):
    """the signer could not sign (down, refused, or a bad answer)"""


class LocalSigner:
    """the issuer key, and the signer's rules: a certificate issued now, a
    revocation list whose serial rises (and isn't ahead of the clock). The
    signer process keeps one; a site without one keeps one in its own
    process"""

    def __init__(self, seed: bytes, clock=time.time):
        if len(seed) != 32:
            raise ValueError("an issuer key is a 32-byte seed")
        self._seed = seed
        self.public = ed25519.public_key(seed)
        self.clock = clock
        self.last_serial = 0
        self.lock = threading.Lock()

    def sign(self, kind: str, body: bytes) -> bytes:
        with self.lock:
            refused = signable(kind, body, key_id(self.public), int(self.clock()), self.last_serial)
            if refused:
                raise SignerError(refused)
            if kind == "revoked":
                self.last_serial = struct.unpack("<I", body[8:12])[0]
            return ed25519.sign(self._seed, SIGNED_LABELS[kind] + body)


class SocketSigner:
    """the signer process's key, over its Unix socket: connected for each
    request (so a restarted signer is picked up), its signatures checked
    against the key the issuer certificate names"""

    def __init__(self, path: str, public: bytes):
        self.path = path
        self.public = public

    def _ask(self, request: dict) -> dict:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(5)
                connection.connect(self.path)
                connection.sendall(json.dumps(request).encode() + b"\n")
                answer = b""
                while not answer.endswith(b"\n") and len(answer) < 8192:
                    part = connection.recv(4096)
                    if not part:
                        break
                    answer += part
            reply = json.loads(answer or b"{}")
        except (OSError, ValueError) as problem:
            raise SignerError(f"the signer: {problem.__class__.__name__}") from None
        if not isinstance(reply, dict) or "error" in reply:
            raise SignerError(str(reply.get("error", "no answer") if isinstance(reply, dict) else "no answer")[:200])
        return reply

    def sign(self, kind: str, body: bytes) -> bytes:
        try:
            signature = bytes.fromhex(str(self._ask({"sign": kind, "body": body.hex()})["signature"]))
        except (KeyError, ValueError):
            raise SignerError("the signer gave no signature") from None
        if kind not in SIGNED_LABELS or not ed25519.verify(self.public, SIGNED_LABELS[kind] + body, signature):
            raise SignerError("the signer's signature does not check")
        return signature


SIGNED_LABELS = {"device": DEVICE_LABEL, "revoked": REVOKED_LABEL, "site": SITE_LABEL}


def signable(kind: str, body: bytes, own_key_id: bytes, now: int, last_serial: int) -> str:
    """why the signer won't sign a body, or "": a certificate of its own key
    ID issued now, of at most CONSOLE_DAYS; a list of its own key ID issued
    now, its serial above the last one and not ahead of the clock; a
    sign-in for another site of its own key ID issued now, of at most
    SITE_SECONDS"""
    if kind == "device":
        fields = parse_device(body + bytes(SIGNATURE))
        if not fields or fields["issuer"] != own_key_id:
            return "not a device certificate of this issuer"
        if abs(fields["issued"] - now) > SIGNER_GRACE:
            return "not issued now"
        if fields["expires"] - fields["issued"] > CONSOLE_DAYS * 86400:
            return "too long a certificate"
        return ""
    if kind == "revoked":
        fields = parse_revoked(body + bytes(SIGNATURE))
        if not fields or fields["issuer"] != own_key_id:
            return "not a revocation list of this issuer"
        if abs(fields["issued"] - now) > SIGNER_GRACE:
            return "not issued now"
        if not last_serial < fields["serial"] <= now + SIGNER_GRACE:
            return "a serial that does not rise"
        return ""
    if kind == "site":
        fields = parse_site(body + bytes(SIGNATURE))
        if not fields or fields["issuer"] != own_key_id:
            return "not a sign-in of this issuer"
        if abs(fields["issued"] - now) > SIGNER_GRACE:
            return "not issued now"
        if fields["expires"] - fields["issued"] > SITE_SECONDS:
            return "too long a sign-in"
        return ""
    return "not a kind the signer signs"


def read_seed(path: str) -> bytes:
    """an issuer key file's seed (64 hex digits): refused unless this user
    alone can read it"""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        mode = os.fstat(descriptor).st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ValueError(f"{path} must be readable by its owner alone (chmod 600)")
        text = os.read(descriptor, 256).decode("ascii", "replace").strip()
    finally:
        os.close(descriptor)
    if not HEX64.match(text):
        raise ValueError(f"{path} is not an issuer key (64 hexadecimal digits)")
    return bytes.fromhex(text)


def serve_signer(key_path: str, socket_path: str, log=print) -> None:
    signer = LocalSigner(read_seed(key_path))
    counts = defaultdict(int)
    count_lock = threading.Lock()

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                request = json.loads(self.rfile.readline(4096) or b"{}")
                if not isinstance(request, dict):
                    raise ValueError("not a request")
                if request.get("public"):
                    reply = {"public": signer.public.hex()}
                else:
                    kind = str(request.get("sign", ""))
                    reply = {"signature": signer.sign(kind, bytes.fromhex(str(request.get("body", "")))).hex()}
                    with count_lock:
                        counts[kind] += 1
                        if sum(counts.values()) % 100 == 1:
                            log(f"signer: {dict(counts)} signed since it started")
            except (ValueError, TypeError, AttributeError, SignerError) as problem:
                reply = {"error": str(problem)[:200]}
            self.wfile.write(json.dumps(reply).encode() + b"\n")

    if os.path.exists(socket_path):
        os.unlink(socket_path)
    # (the site's user reaches it through the socket's group, no one else)
    old_mask = os.umask(0o117)
    try:
        server = socketserver.ThreadingUnixStreamServer(socket_path, Handler)
    finally:
        os.umask(old_mask)
    log(f"signer: issuer {key_id(signer.public).hex()} on {socket_path}")
    server.serve_forever()


# ---------- tokens


class Tokens:
    """an hour's bearer tokens: the device, its capabilities and the expiry,
    with an HMAC by a key made when the site starts (a restart ends them,
    and the game asks for a new one)"""

    LIFETIME = 3600
    PREFIX = "d1."
    TOKEN = re.compile(r"^d1\.[0-9a-f]{48}\.[0-9a-f]{64}$")

    def __init__(self, key: bytes = None, clock=time.time):
        self._key = key or secrets.token_bytes(32)
        self.clock = clock

    def _mac(self, payload: str) -> str:
        return hmac.new(self._key, TOKEN_LABEL + payload.encode(), hashlib.sha256).hexdigest()

    def make(self, device: bytes, capabilities: int):
        expires = int(self.clock()) + self.LIFETIME
        payload = device.hex() + struct.pack(">II", expires, capabilities & 0xFFFFFFFF).hex()
        return self.PREFIX + payload + "." + self._mac(payload), self.LIFETIME

    def read(self, token: str):
        """(device ID, capabilities) of a token in date, else (None, why)"""
        if not self.TOKEN.match(token or ""):
            return None, "unknown"
        payload, mac = token[len(self.PREFIX):].split(".")
        if not hmac.compare_digest(self._mac(payload), mac):
            return None, "unknown"
        expires, capabilities = struct.unpack(">II", bytes.fromhex(payload[32:]))
        if self.clock() >= expires:
            return None, "expired"
        return (bytes.fromhex(payload[:32]), capabilities), ""


class Nonces:
    """one-use nonces (memory only), LIFETIME seconds; past MOST waiting, the
    oldest go first, so a flood costs its sender, not everyone"""

    LIFETIME = 300
    MOST = 20000

    def __init__(self, clock=time.time):
        self.clock = clock
        self.lock = threading.Lock()
        self.issued = {}

    def issue(self) -> str:
        now = self.clock()
        with self.lock:
            while len(self.issued) >= self.MOST:
                del self.issued[next(iter(self.issued))]
            nonce = secrets.token_hex(16)
            self.issued[nonce] = now + self.LIFETIME
        return nonce

    def take(self, nonce: str) -> bool:
        with self.lock:
            expires = self.issued.pop(nonce, None)
        return expires is not None and self.clock() < expires


# ---------- the devices and the service


def forget(database, player_ids, now: int = None) -> None:
    """(under the lock, not committed) the devices of deleted profiles: those
    naming them as their account, and those enrolled with their copies. Each
    is revoked and keeps only its device ID and when it was revoked, which
    the revocation list needs until REVOKED_KEPT has passed (purge)"""
    if not database.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'devices'").fetchone():
        return
    now = int(time.time() if now is None else now)
    for player_id in player_ids:
        database.execute(
            "UPDATE devices SET revoked = CASE WHEN revoked > 0 THEN revoked ELSE ? END, account_id = '', copy_id = '', "
            "public_key = '', platform = '', name = '', build = '', last_refresh = 0, last_used = 0, created = 0 "
            "WHERE account_id = ? OR copy_id = ?", (now, player_id, player_id))


def purge(database, now: int = None) -> int:
    """(under the lock, not committed) revoked devices whose last certificate
    has run out (REVOKED_KEPT): gone for good. How many"""
    if not database.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'devices'").fetchone():
        return 0
    now = int(time.time() if now is None else now)
    return database.execute("DELETE FROM devices WHERE revoked > 0 AND revoked <= ?", (now - REVOKED_KEPT,)).rowcount


class Identity:
    """the devices table (in reports.db, beside the profiles), the
    endpoints' work and the tokens.

    Locks: self.lock is the site's database lock (REPORTS.lock, which
    Profiles shares); self.memory guards the codes and counts and is a leaf:
    nothing else is taken while it is held. The site never calls in here
    while it holds its own lock, and nothing here calls the site's hooks
    (account_of, copies_of, link_copy, unlink_copy) while holding either. account_of(copy ID) gives (account ID,
    handle, locked) of the profile a copy counts for, or None; known_copy(copy
    ID) whether the site has seen that copy (a profile, a link or a
    confirmed game); note_player_key(key hex) keeps a player key's moderator
    key"""

    DEVICES_PER_COPY = 32
    ENROLLS_PER_ADDRESS = 20  # an hour
    ENROLLS_ALL = 3000  # an hour, everyone together
    NONCES_PER_ADDRESS = 60  # a minute
    SIGNED_PER_ADDRESS = 120  # an hour (refresh and token requests)
    REQUESTS_PER_DEVICE = 30  # an hour

    def __init__(self, database, lock, signer, issuer_certificate: bytes, roots, account_of, note_player_key=None,
                 platforms=(), clock=time.time, audiences=DEFAULT_AUDIENCES, known_copy=None, copies_of=None,
                 link_copy=None, unlink_copy=None, clients=None):
        self.database = database
        # (delta_clients.Clients: other apps' client IDs and their scopes;
        # None, everything is first party)
        self.clients = clients
        # (the site's own: the IDs whose games count for a profile, its own
        # first; a copy's games moved to a profile, or what that would do
        # (Profiles.link_game); a console's link taken away)
        self.copies_of = copies_of or (lambda account: [account])
        self.link_copy = link_copy or (lambda copy_id, account, foresee=False: "Linking isn't kept here.")
        self.unlink_copy = unlink_copy or (lambda copy_id: None)
        self.codes = {}
        self.polls = {}
        self.claims = {}
        self.lock = lock
        self.signer = signer
        self.issuer_certificate = issuer_certificate
        self.issuer = parse_issuer(issuer_certificate)
        self.account_of = account_of
        self.known_copy = known_copy or (lambda copy_id: account_of(copy_id) is not None)
        self.note_player_key = note_player_key or (lambda key: None)
        self.platforms = tuple(platforms)
        self.clock = clock
        self.audiences = tuple(audience.lower() for audience in audiences)
        if not self.audiences or not all(AUDIENCE.match(audience) for audience in self.audiences):
            raise ValueError("audiences are the site's host names")
        self.tokens = Tokens(clock=clock)
        self.nonces = Nonces(clock=clock)
        self.counts = {}
        self.memory = threading.Lock()
        self.revoked_cache = None
        refused = check_issuer(self.issuer, roots, int(clock()))
        if refused:
            raise ValueError(f"the issuer certificate: {refused}")
        if self.issuer["public"] != signer.public:
            raise ValueError("the issuer certificate is not the signer's key's")
        with self.lock:
            self.database.execute("""CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY, account_id TEXT NOT NULL, copy_id TEXT NOT NULL DEFAULT '',
                public_key TEXT NOT NULL, platform TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '',
                build TEXT NOT NULL DEFAULT '', flags INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL,
                last_refresh INTEGER NOT NULL DEFAULT 0, last_used INTEGER NOT NULL DEFAULT 0,
                signed_out INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0)""")
            # (stage B: the device that approved this one's code, if a device
            # did; revoking it revokes this one too)
            columns = [row[1] for row in self.database.execute("PRAGMA table_info(devices)")]
            if "approved_by" not in columns:
                self.database.execute("ALTER TABLE devices ADD COLUMN approved_by TEXT NOT NULL DEFAULT ''")
            # (what each device may do as the account: CAPABILITIES' bits)
            if "capabilities" not in columns:
                self.database.execute(f"ALTER TABLE devices ADD COLUMN capabilities INTEGER NOT NULL "
                                      f"DEFAULT {LEGACY_CAPABILITIES}")
            # (the client the device came through: '' Chupathingy's own,
            # else delta_clients' client ID)
            if "client_id" not in columns:
                self.database.execute("ALTER TABLE devices ADD COLUMN client_id TEXT NOT NULL DEFAULT ''")
            # (stage C, per copy, kept past a device's purge: when it moved to a
            # device, when its key was last taken from a game, and when it last
            # proved itself a console with its own key (a console's signed
            # claim, which the self-reported paths can't write); retired is
            # unused, kept for the column's sake)
            self.database.execute("""CREATE TABLE IF NOT EXISTS identity_copies (
                copy_id TEXT PRIMARY KEY, moved INTEGER NOT NULL DEFAULT 0, key_seen INTEGER NOT NULL DEFAULT 0,
                retired INTEGER NOT NULL DEFAULT 0, console INTEGER NOT NULL DEFAULT 0)""")
            self.database.execute("""INSERT OR IGNORE INTO identity_copies (copy_id, moved)
                SELECT copy_id, MIN(created) FROM devices WHERE copy_id != '' AND flags & 2 = 0 GROUP BY copy_id""")
            # (the site sessions a device's token opened, ended with it)
            self.database.execute("""CREATE TABLE IF NOT EXISTS identity_sessions (
                session TEXT PRIMARY KEY, device_id TEXT NOT NULL, created INTEGER NOT NULL)""")
            self.database.execute("CREATE INDEX IF NOT EXISTS devices_account ON devices (account_id)")
            self.database.execute("CREATE INDEX IF NOT EXISTS devices_copy ON devices (copy_id)")
            self.database.execute("""CREATE TABLE IF NOT EXISTS identity_state (
                name TEXT PRIMARY KEY, value INTEGER NOT NULL)""")
            # (stage C: an account's player key; legacy_key LEGACY_AUTO, ON
            # or OFF, and when an Xbox identity file was last made for it)
            self.database.execute("""CREATE TABLE IF NOT EXISTS identity_accounts (
                account_id TEXT PRIMARY KEY, legacy_key INTEGER NOT NULL DEFAULT 0,
                changed INTEGER NOT NULL DEFAULT 0, key_file INTEGER NOT NULL DEFAULT 0)""")
            # (an earlier draft marked consoles from line_claims; those marks
            # carry no time, and lapse: CONSOLE_DAYS_KEPT)
            # (once, when this comes in: the copies games already reported,
            # as seen from a game then, so no account that played before has
            # its own copy taken for a site-made one; key_seen is kept from
            # the game's requests after)
            if not self.database.execute("SELECT 1 FROM identity_state WHERE name = 'key_seen_backfill'").fetchone():
                if self.database.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND "
                                         "name = 'player_platforms'").fetchone():
                    self.database.execute("INSERT OR IGNORE INTO identity_copies (copy_id) SELECT DISTINCT player_id "
                                          "FROM player_platforms")
                    self.database.execute(
                        "UPDATE identity_copies SET key_seen = MAX(key_seen, (SELECT MAX(last) FROM player_platforms "
                        "WHERE player_id = copy_id)) WHERE copy_id IN (SELECT player_id FROM player_platforms) AND "
                        "moved = 0")
                self.database.execute("INSERT INTO identity_state (name, value) VALUES ('key_seen_backfill', ?)",
                                      (int(clock()),))
            self.database.commit()

    # (the counts: memory only)
    COUNTS_MOST = 50000

    def _allow(self, key: str, most: int, window: int) -> bool:
        now = self.clock()
        with self.memory:
            times = [t for t in self.counts.get(key, ()) if t > now - window]
            if len(times) >= most:
                self.counts[key] = times
                return False
            times.append(now)
            # (moved to the end: the oldest keys are first, and go first)
            self.counts.pop(key, None)
            self.counts[key] = times
            while len(self.counts) > self.COUNTS_MOST:
                del self.counts[next(iter(self.counts))]
        return True

    def _day(self) -> int:
        return int(self.clock()) // 86400 * 86400

    def device(self, device_hex: str):
        with self.lock:
            row = self.database.execute(
                "SELECT device_id, account_id, copy_id, public_key, platform, flags, signed_out, revoked, capabilities, "
                "client_id FROM devices WHERE device_id = ?", (device_hex,)).fetchone()
        if not row:
            return None
        return dict(zip(("device_id", "account_id", "copy_id", "public_key", "platform", "flags", "signed_out",
                         "revoked", "capabilities", "client_id"), row))

    # ---------- other apps' clients (delta_clients.py)

    def _client(self, client_id):
        """(client, None), (None, None) for the first party, or (None,
        refusal)"""
        if self.clients is None:
            return None, None
        return self.clients.resolve(client_id)

    def _client_refused(self, client, platform: str, account):
        """why a client's device can't go on: a platform it didn't register,
        or a pending client and another profile than its developer's
        (account None: not known yet)"""
        if platform not in client["platforms"]:
            return 403, {"error": "This app isn't registered for this platform.", "client": "platform"}
        if account is not None and not self.clients.allows_account(client, account):
            return 403, {"error": "This app isn't open to everyone yet. Only its developer can sign in with it.",
                         "client": "pending"}
        return None

    @staticmethod
    def _other_client(row, client):
        """a device key that is already another app's (or Chupathingy's
        own, asked for by an app) stays with it: a fork built from our tree
        finds the player's own device key, and signing that in through the
        fork would hand the fork the player's device and what it approved"""
        if row and row["client_id"] != (client["client_id"] if client else ""):
            return 409, {"error": "That device key belongs to another app.", "other_client": True}
        return None

    def _client_mask(self, row) -> int:
        """the capabilities a device's client lets it use now: all for the
        first party, none for a client suspended or gone (an admin can narrow
        a client's scopes; its devices' certificates and tokens follow)"""
        if not row.get("client_id") or self.clients is None:
            return 0xFFFFFFFF
        return self.clients.mask(row["client_id"])

    def _locked(self, row: dict) -> bool:
        found = self.account_of(row["copy_id"] or row["account_id"])
        return bool(found and found[2])

    def _certificate(self, row: dict):
        """a new certificate for a device row, and the account it names: its
        copy's (the profile it counts for), or for a device signed in by
        code with no copy, its account's"""
        found = self.account_of(row["copy_id"] or row["account_id"])
        account, handle = (found[0], found[1]) if found else (row["copy_id"] or row["account_id"], "")
        platform = row["platform"]
        console = platform in CONSOLE_PLATFORMS
        flags = (row["flags"] & FLAG_LEGACY) | (FLAG_CONSOLE if console else 0)
        issued = int(self.clock())
        expires = min(issued + (CONSOLE_DAYS if console else DESKTOP_DAYS) * 86400, self.issuer["valid_until"])
        if expires <= issued:
            raise SignerError("the issuer certificate has run out")
        number = self.platforms.index(platform) if platform in self.platforms else 0
        body = device_body(number, flags, issued, expires, secrets.token_bytes(8), self.issuer["key_id"],
                           bytes.fromhex(account), bytes.fromhex(row["public_key"]),
                           row["capabilities"] & self._client_mask(row),
                           handle if handle and HANDLE.match(handle) else "")
        certificate = body + self.signer.sign("device", body)
        with self.lock:
            self.database.execute("UPDATE devices SET account_id = ?, last_refresh = ?, last_used = ? WHERE device_id = ?",
                                  (account, self._day(), self._day(), row["device_id"]))
            self.database.commit()
        return certificate, account, handle, issued, expires

    def _answer(self, row: dict):
        try:
            certificate, account, handle, issued, expires = self._certificate(row)
        except SignerError:
            return 503, {"error": "busy"}
        return 200, {"device_id": row["device_id"], "certificate": certificate.hex(),
                     "issuer": self.issuer_certificate.hex(), "account": account, "handle": handle,
                     "expires": expires, "refresh_after": (expires - issued) // 2}

    def _signed_by(self, public: bytes, signature: bytes, message_of) -> bool:
        """whether the signature is the key's over the message for one of
        this site's audiences"""
        return any(ed25519.verify(public, message_of(audience), signature) for audience in self.audiences)

    def nonce(self, address_key: str):
        if not self._allow("nonce:" + address_key, self.NONCES_PER_ADDRESS, 60):
            return 429, {"error": "too many requests"}
        return 200, {"nonce": self.nonces.issue(), "expires_in": Nonces.LIFETIME}

    def _signed(self, body: dict, message_of, address_key: str):
        """(device row, None), or (None, (status, answer)), for a refresh or
        token request; the device's own count only once it has proved itself"""
        device_hex = str(body.get("device_id", "")).lower()
        nonce = str(body.get("nonce", "")).lower()
        signature = str(body.get("signature", "")).lower()
        if not HEX32.match(device_hex) or not HEX32.match(nonce) or not HEX128.match(signature):
            return None, (400, {"error": "bad request"})
        if not self._allow("signed:" + address_key, self.SIGNED_PER_ADDRESS, 3600):
            return None, (429, {"error": "too many requests"})
        if not self.nonces.take(nonce):
            return None, (401, {"error": "nonce", "nonce": "unknown"})
        row = self.device(device_hex)
        if not row:
            return None, (404, {"error": "unknown device", "enroll": True})
        if not self._signed_by(bytes.fromhex(row["public_key"]), bytes.fromhex(signature),
                               lambda audience: message_of(audience, bytes.fromhex(nonce), bytes.fromhex(device_hex))):
            return None, (401, {"error": "signature"})
        if not self._allow("device:" + device_hex, self.REQUESTS_PER_DEVICE, 3600):
            return None, (429, {"error": "too many requests"})
        if row["revoked"]:
            return None, (403, {"error": "This device was removed from its profile.", "revoked": True})
        if row["signed_out"]:
            return None, (403, {"error": "This device is signed out.", "signed_out": True})
        if self._locked(row):
            return None, (403, {"error": "locked", "locked": True})
        if not self._client_mask(row):
            return None, (403, {"error": "This app was suspended on this site.", "client": "suspended"})
        return row, None

    def enroll(self, body: dict, address_key: str):
        """POST /v1/identity/legacy/enroll"""
        key = str(body.get("key", "")).lower()
        public_hex = str(body.get("device_key", "")).lower()
        nonce = str(body.get("nonce", "")).lower()
        signature = str(body.get("signature", "")).lower()
        platform = str(body.get("platform", ""))[:16]
        build = re.sub(r"[^ -~]", "", str(body.get("build", "")))[:40]
        name = re.sub(r"[^ -~]", "", str(body.get("name", "")))[:32]
        if not HEX64.match(key) or not HEX64.match(public_hex) or not HEX32.match(nonce) or \
                not HEX128.match(signature):
            return 400, {"error": "bad request"}
        if not self._allow("enroll:" + address_key, self.ENROLLS_PER_ADDRESS, 3600):
            return 429, {"error": "too many requests"}
        client, refused = self._client(body.get("client_id"))
        if refused:
            return refused
        if not self.nonces.take(nonce):
            return 401, {"error": "nonce", "nonce": "unknown"}
        public = bytes.fromhex(public_hex)
        copy_id = hashlib.sha256(b"halo-ce-universal player id\n" + bytes.fromhex(key)).hexdigest()[:32]
        if small_order(public) or not self._signed_by(public, bytes.fromhex(signature), lambda audience: enroll_message(
                audience, bytes.fromhex(nonce), bytes.fromhex(copy_id), public)):
            return 401, {"error": "signature"}
        device_hex = device_id(public).hex()
        found = self.account_of(copy_id)
        if found and found[2]:
            return 403, {"error": "locked", "locked": True}
        capabilities = LEGACY_CAPABILITIES
        if client:
            refused = self._client_refused(client, platform, found[0] if found else "")
            if refused:
                return refused
            capabilities &= self.clients.requested(client, body.get("scopes"))
            if not capabilities:
                return 400, {"error": "No scopes asked for that this app has.", "client": "scopes"}
        row = self.device(device_hex)
        if row:
            if row["copy_id"] != copy_id:
                return 409, {"error": "That device key belongs to another copy.", "other_copy": True}
            if row["client_id"] != (client["client_id"] if client else ""):
                return 409, {"error": "That device key belongs to another app.", "other_client": True}
            if row["revoked"]:
                return 403, {"error": "This device was removed from its profile.", "revoked": True}
            if row["signed_out"]:
                return 403, {"error": "This device is signed out.", "signed_out": True}
            with self.lock:
                self.database.execute("UPDATE devices SET build = ?, platform = ? WHERE device_id = ?",
                                      (build, platform, device_hex))
                self.database.commit()
        else:
            if self.legacy_key_off(copy_id):
                # (stage C: every copy of the account has its device, or this
                # key's device was revoked, so the key makes no new ones; a new
                # install signs in by code)
                return 403, {"error": LEGACY_OFF_ERROR, "legacy_key_off": True}
            if not self.known_copy(copy_id):
                return 403, {"error": "This copy isn't known here yet.", "unknown_copy": True}
            if not self._allow("enroll:everyone", self.ENROLLS_ALL, 3600):
                return 503, {"error": "busy"}
            with self.lock:
                count = self.database.execute("SELECT COUNT(*) FROM devices WHERE copy_id = ? AND revoked = 0",
                                              (copy_id,)).fetchone()[0]
                if count >= self.DEVICES_PER_COPY:
                    return 409, {"error": "Too many devices for this copy.", "too_many": True}
                # (two enrollments of one new key at once: the second finds the first's row)
                self.database.execute(
                    "INSERT OR IGNORE INTO devices (device_id, account_id, copy_id, public_key, platform, name, build, "
                    "flags, created, capabilities, client_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (device_hex, found[0] if found else copy_id, copy_id, public_hex, platform, name, build,
                     FLAG_LEGACY, self._day(), capabilities, client["client_id"] if client else ""))
                self.database.commit()
            row = self.device(device_hex)
            if not row or row["copy_id"] != copy_id:
                return 409, {"error": "That device key belongs to another copy.", "other_copy": True}
        self.note_player_key(key)
        self._copy_moved(copy_id)
        return self._answer(self.device(device_hex))

    def refresh(self, body: dict, address_key: str = ""):
        """POST /v1/identity/refresh"""
        row, refused = self._signed(body, refresh_message, address_key)
        if refused:
            return refused
        return self._answer(row)

    def token(self, body: dict, address_key: str = ""):
        """POST /v1/identity/token"""
        row, refused = self._signed(body, token_message, address_key)
        if refused:
            return refused
        if row["client_id"] and self.clients is not None:
            client = self.clients.get(row["client_id"])
            if not client or not self._allow("client tokens:" + client["client_id"], client["tokens_per_hour"], 3600):
                return 429, {"error": "too many requests", "client": "limit"}
        capabilities = row["capabilities"] & self._client_mask(row)
        token, lifetime = self.tokens.make(bytes.fromhex(row["device_id"]), capabilities)
        with self.lock:
            self.database.execute("UPDATE devices SET last_used = ? WHERE device_id = ?", (self._day(), row["device_id"]))
            self.database.commit()
        return 200, {"token": token, "expires_in": lifetime,
                     "scopes": [name for name, bit in CAPABILITIES.items() if capabilities & bit]}

    def bearer(self, header: str, capability: str):
        """the copy ID an Authorization: Delta header's token acts for, and
        "" (or None and why: "unknown", "expired", "revoked", "scope")"""
        scheme, _, token = (header or "").strip().partition(" ")
        if scheme.lower() != "delta":
            return None, "unknown"
        found, why = self.tokens.read(token.strip())
        if not found:
            return None, why
        device, capabilities = found
        if not capabilities & CAPABILITIES[capability]:
            return None, "scope"
        row = self.device(device.hex())
        if not row or row["revoked"] or row["signed_out"] or not self._client_mask(row):
            return None, "revoked"
        if not row["capabilities"] & self._client_mask(row) & CAPABILITIES[capability]:
            return None, "scope"
        return row["copy_id"] or row["account_id"], ""

    # ---------- Quick Connect: sign-in by code (stage B)
    #
    # An entry's states: "open" (its code shown on the device), "shown" (the
    # code typed in: the approver sees the device, and approves or denies),
    # "waiting" (approved: the device asks its player), "linking", then
    # "connected", "declined" or "expired".

    def _drop_old_codes(self, now: float) -> None:
        """(under memory) codes past their life, entries past kept"""
        for digest in [d for d, entry in self.codes.items() if entry["expires"] < now]:
            del self.codes[digest]
        for table in (self.polls, self.claims):
            for digest in [d for d, entry in table.items() if entry["kept"] < now]:
                del table[digest]

    def _state(self, entry, now: float) -> str:
        """(under memory) an entry's state, a code or an approval left
        unanswered past its time expired"""
        if entry["state"] == "open" and entry["expires"] < now:
            entry["state"] = "expired"
        if entry["state"] in ("shown", "waiting") and entry["claimed"] + CONFIRM_LIFETIME < now:
            entry["state"] = "expired"
        return entry["state"]

    def start_code(self, body: dict, address_key: str):
        """POST /v1/identity/device/start: a code for a device with no
        account yet (or one that signs in to another), signed by its key"""
        public_hex = str(body.get("device_key", "")).lower()
        nonce = str(body.get("nonce", "")).lower()
        signature = str(body.get("signature", "")).lower()
        platform = str(body.get("platform", ""))[:16]
        build = re.sub(r"[^ -~]", "", str(body.get("build", "")))[:40]
        name = re.sub(r"[^ -~]", "", str(body.get("name", "")))[:32].strip()
        if not HEX64.match(public_hex) or not HEX32.match(nonce) or not HEX128.match(signature):
            return 400, {"error": "bad request"}
        if not self._allow("start:" + address_key, CODE_STARTS_PER_HOUR, 3600):
            return 429, {"error": "too many codes, try again later"}
        if not self.nonces.take(nonce):
            return 401, {"error": "nonce", "nonce": "unknown"}
        public = bytes.fromhex(public_hex)
        if small_order(public) or not self._signed_by(public, bytes.fromhex(signature), lambda audience: start_message(
                audience, bytes.fromhex(nonce), public)):
            return 401, {"error": "signature"}
        # (the key's own count only once it has proved itself)
        if not self._allow("start key:" + public_hex, CODE_STARTS_PER_HOUR, 3600):
            return 429, {"error": "too many codes, try again later"}
        client, refused = self._client(body.get("client_id"))
        if refused:
            return refused
        scopes = None
        if client:
            refused = self._client_refused(client, platform, None)
            if refused:
                return refused
            scopes = self.clients.requested(client, body.get("scopes"))
            if not scopes:
                return 400, {"error": "No scopes asked for that this app has.", "client": "scopes"}
            if not self._allow("client start:" + client["client_id"], client["starts_per_hour"], 3600):
                return 429, {"error": "too many codes, try again later", "client": "limit"}
        device_hex = device_id(public).hex()
        row = self.device(device_hex)
        if row and row["revoked"]:
            return 403, {"error": "This device was removed from its profile.", "revoked": True}
        refused = self._other_client(row, client)
        if refused:
            return refused
        now = self.clock()
        poll_token = secrets.token_hex(32)
        with self.memory:
            self._drop_old_codes(now)
            if len(self.polls) >= CODES_MOST:
                return 503, {"error": "busy"}
            while True:
                code_nonce = secrets.token_bytes(16)
                digest = hashlib.sha256(device_code(public, code_nonce).encode()).hexdigest()
                if digest not in self.codes:
                    break
            entry = {"device_id": device_hex, "public_key": public_hex, "platform": platform, "build": build,
                     "name": name, "expires": now + CODE_LIFETIME, "kept": now + CODE_LIFETIME, "state": "open",
                     "client_id": client["client_id"] if client else "", "scopes": scopes}
            self.codes[digest] = entry
            self.polls[hashlib.sha256(poll_token.encode()).hexdigest()] = entry
        return 200, {"code_nonce": code_nonce.hex(), "poll_token": poll_token, "interval": POLL_INTERVAL,
                     "expires_in": CODE_LIFETIME}

    def claim_code(self, code: str, account: str, claim_key: str, trusted: bool):
        """a code typed in by a signed-in account (the site's /connect, a
        password session: trusted; or another signed-in device's Link a
        device): (status, answer), or None when the code is no device's (the
        caller counts it as a wrong one). The code is spent. The approver
        sees the device next, then approves or denies (approve_code)"""
        if len(code) != CODE_LENGTH:
            return None
        now = self.clock()
        with self.memory:
            entry = self.codes.pop(hashlib.sha256(code.encode()).hexdigest(), None)
            if not entry or self._state(entry, now) != "open":
                return None
        found = self.account_of(account)
        refused = self._claim_client(entry, account)
        if refused:
            with self.memory:
                entry["state"] = "expired"
            return refused
        if not found or found[0] != account or found[2]:
            with self.memory:
                entry["state"] = "expired"
            if not found:
                return 403, {"error": "Make your profile first, to connect a game."}
            if found[2]:
                return 403, {"error": "locked"}
            return 409, {"error": "This profile's games count for another profile. Sign in there to add a device."}
        with self.memory:
            # (a device's approval: "device:<its ID>", list_server's claim key)
            entry.update(state="shown", claimed=now, account=account, handle=found[1], previous=None,
                         kept=now + CONFIRM_LIFETIME + CONNECTED_KEPT, trusted=trusted,
                         approved_by=claim_key[7:] if claim_key.startswith("device:") else "")
            self.claims[claim_key] = entry
        return 202, {"shown": True, "handle": found[1], "confirm_seconds": CONFIRM_LIFETIME,
                     "device": self._shown(entry), "warning": CODE_WARNING}

    def _claim_client(self, entry, account: str):
        """(a code typed in) the client its device came through, still
        there and open to this profile: a refusal, or None"""
        if not entry.get("client_id"):
            return None
        client, refused = self._client(entry["client_id"])
        if refused:
            return refused
        if client:
            entry["client"] = self.clients.shown(client, entry["scopes"])
            return self._client_refused(client, entry["platform"], account)
        return None

    def approve_code(self, claim_key: str, approve: bool):
        """the approver's answer to the device it was shown: approved (the
        device asks its player next) or denied (the code is dead):
        (status, answer)"""
        now = self.clock()
        with self.memory:
            entry = self.claims.get(claim_key)
            state = self._state(entry, now) if entry else "expired"
            if state != "shown":
                return 409, {"error": "No device is waiting for your answer.", "state": state}
            if not approve:
                entry.update(state="declined", kept=now + CONNECTED_KEPT)
                return 200, {"state": "declined"}
        row = self.device(entry["device_id"])
        previous = None
        if row and row["copy_id"]:
            # (a device enrolled with its player key: its copy moves too, as
            # Link Profile moves it; refused as Link Profile refuses)
            done = self.link_copy(row["copy_id"], entry["account"], True)
            if isinstance(done, str):
                with self.memory:
                    entry.update(state="expired", kept=now + CONNECTED_KEPT)
                return 409, {"error": done}
            previous = None if done["same"] else done["before"] or done["other"]
        elif row and not row["signed_out"] and row["account_id"] != entry["account"]:
            other = self.account_of(row["account_id"])
            previous = other[1] if other else None
        with self.memory:
            if self._state(entry, now) != "shown":
                return 409, {"error": "No device is waiting for your answer.", "state": entry["state"]}
            # (previous goes to the device alone, never to the approver)
            entry.update(state="waiting", claimed=now, previous=previous)
        return 202, {"waiting": True, "handle": entry["handle"], "confirm_seconds": CONFIRM_LIFETIME,
                     "device": self._shown(entry)}

    def forget_claim(self, claim_key: str) -> None:
        """(another kind of code was typed in there since)"""
        with self.memory:
            self.claims.pop(claim_key, None)

    def _shown(self, entry) -> dict:
        shown = {"name": entry["name"], "platform": entry["platform"], "build": entry["build"]}
        if entry.get("client"):
            # (another app's device: its name, homepage and the scopes it
            # asked for; Chupathingy's own show as before)
            shown["client"] = entry["client"]
        return shown

    def claimed(self, claim_key: str):
        """this session's (or device's) latest approval: its state and the
        device, or None"""
        now = self.clock()
        with self.memory:
            entry = self.claims.get(claim_key)
            if not entry:
                return None
            state = self._state(entry, now)
            answer = {"state": "waiting" if state == "linking" else state, "handle": entry["handle"],
                      "device": self._shown(entry), "name": entry["name"]}
            answer["confirm_seconds"] = max(0, int(entry["claimed"] + CONFIRM_LIFETIME - now)) \
                if answer["state"] in ("shown", "waiting") else 0
            if state == "shown":
                answer["warning"] = CODE_WARNING
            return answer

    def poll(self, body: dict, address_key: str = ""):
        """POST /v1/identity/device/poll {"poll_token"}: how the code is
        going (pending, confirm, connected, declined or expired)"""
        token = str(body.get("poll_token", "")).lower()
        if not HEX64.match(token):
            return 400, {"error": "bad request"}
        if not self._allow("poll address:" + address_key, POLLS_PER_ADDRESS, 600):
            return 429, {"error": "too many requests"}
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.memory:
            known = digest in self.polls
        # (counted by code only for a code there is)
        if known and not self._allow("poll:" + digest, POLLS_PER_CODE, CODE_LIFETIME):
            return 429, {"error": "too many requests"}
        with self.memory:
            entry = self.polls.get(digest)
            state = self._state(entry, self.clock()) if entry else "expired"
            if state in ("open", "shown"):
                return 200, {"state": "pending"}
            if state in ("waiting", "linking"):
                return 200, {"state": "confirm", "handle": entry["handle"], "previous": entry["previous"]}
            if state == "connected":
                return 200, {"state": "connected", "handle": entry["handle"]}
            return 200, {"state": state}

    def confirm(self, body: dict, address_key: str):
        """POST /v1/identity/device/confirm: the device's yes (a
        certificate for the account) or no, signed by its key over the
        profile it showed"""
        token = str(body.get("poll_token", "")).lower()
        device_hex = str(body.get("device_id", "")).lower()
        nonce = str(body.get("nonce", "")).lower()
        signature = str(body.get("signature", "")).lower()
        accept = body.get("accept") is True
        if not HEX64.match(token) or not HEX32.match(device_hex) or not HEX32.match(nonce) or \
                not HEX128.match(signature):
            return 400, {"error": "bad request"}
        if not self._allow("confirm address:" + address_key, CONFIRMS_PER_ADDRESS, CODE_LIFETIME):
            return 429, {"error": "too many requests"}
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.memory:
            entry = self.polls.get(digest)
        if not entry or entry["device_id"] != device_hex:
            return 200, {"state": "expired"}
        if not self._allow("confirm:" + digest, CONFIRMS_PER_CODE, CODE_LIFETIME):
            return 429, {"error": "too many requests"}
        if not self.nonces.take(nonce):
            return 401, {"error": "nonce", "nonce": "unknown"}
        now = self.clock()
        with self.memory:
            state = self._state(entry, now)
            public = bytes.fromhex(entry["public_key"])
            handle = entry.get("handle") or ""
        if not self._signed_by(public, bytes.fromhex(signature), lambda audience: confirm_message(
                audience, bytes.fromhex(nonce), bytes.fromhex(device_hex), accept, handle)):
            return 401, {"error": "signature"}
        if state == "connected" and accept:
            # (its answer was lost: a new certificate, nothing done again; out
            # of memory's lock, which is a leaf)
            row = self.device(device_hex)
            if not row or row["revoked"] or row["signed_out"] or row["account_id"] != entry["account"] or \
                    not self._client_mask(row):
                return 200, {"state": "expired"}
            if self._locked(row):
                return 403, {"error": "locked", "locked": True}
            return self._connected(self._answer(row))
        with self.memory:
            state = self._state(entry, now)
            if state == "linking":
                return 503, {"error": "busy"}
            if state != "waiting":
                return 200, {"state": "declined" if state == "declined" else "expired"}
            if not accept:
                entry.update(state="declined", kept=now + CONNECTED_KEPT)
                return 200, {"state": "declined"}
            entry["state"] = "linking"
        refused = self._sign_in(entry)
        with self.memory:
            entry.update(state="expired" if refused else "connected", kept=now + CONNECTED_KEPT)
        if refused:
            return refused
        answer = self._connected(self._answer(self.device(device_hex)))
        if answer[0] == 200:
            answer[1]["added"] = True
        return answer

    @staticmethod
    def _connected(answer):
        status, body = answer
        if status == 200:
            body["state"] = "connected"
        return status, body

    def _sign_in(self, entry):
        """the approved device signed in to the account: a refusal, or None.
        "devices" only for one a password session approved"""
        account = entry["account"]
        capabilities = TRUSTED_CAPABILITIES if entry.get("trusted") and not entry.get("approved_by") \
            else DEVICE_CAPABILITIES
        client_id = entry.get("client_id") or ""
        if client_id:
            # (another app's: no more than it asked for and the client has
            # now, never "devices"; checked again, it may be suspended since)
            client, refused = self._client(client_id)
            if refused:
                return refused
            if client:
                refused = self._client_refused(client, entry["platform"], account)
                if refused:
                    return refused
                capabilities &= entry["scopes"] & self.clients.requested(client, None)
        row = self.device(entry["device_id"])
        if row and row["revoked"]:
            return 403, {"error": "This device was removed from its profile.", "revoked": True}
        refused = self._other_client(row, {"client_id": client_id} if client_id else None)
        if refused:
            return refused
        if row and row["copy_id"]:
            found = self.account_of(row["copy_id"])
            if not found or found[0] != account:
                done = self.link_copy(row["copy_id"], account, False)
                if isinstance(done, str):
                    return 409, {"error": done}
        with self.lock:
            if row:
                self.database.execute(
                    "UPDATE devices SET account_id = ?, signed_out = 0, platform = ?, build = ?, approved_by = ?, "
                    "capabilities = ?, client_id = ? WHERE device_id = ?",
                    (account, entry["platform"] or row["platform"], entry["build"], entry.get("approved_by", ""),
                     capabilities, client_id, entry["device_id"]))
            else:
                count = self.database.execute("SELECT COUNT(*) FROM devices WHERE account_id = ? AND revoked = 0",
                                              (account,)).fetchone()[0]
                if count >= DEVICES_PER_ACCOUNT:
                    return 409, {"error": "Too many devices on this profile.", "too_many": True}
                self.database.execute(
                    "INSERT INTO devices (device_id, account_id, copy_id, public_key, platform, name, build, flags, "
                    "created, approved_by, capabilities, client_id) VALUES (?, ?, '', ?, ?, ?, ?, 0, ?, ?, ?, ?)",
                    (entry["device_id"], account, entry["public_key"], entry["platform"], entry["name"], entry["build"],
                     self._day(), entry.get("approved_by", ""), capabilities, client_id))
            self.database.commit()
        if client_id:
            # (suspended while this one went in: a suspension's revoke may
            # have looked before its row was there, so it is revoked here)
            client, refused = self._client(client_id)
            if refused:
                self.revoke(entry["device_id"])
                self._end_sessions([entry["device_id"]])
                return refused
        if row and row["copy_id"]:
            self._copy_moved(row["copy_id"])
        return None

    def signout(self, body: dict, address_key: str = ""):
        """POST /v1/identity/device/signout: this device signed out, by its
        own key (its key stays: signing in again is a new code)"""
        device_hex = str(body.get("device_id", "")).lower()
        nonce = str(body.get("nonce", "")).lower()
        signature = str(body.get("signature", "")).lower()
        if not HEX32.match(device_hex) or not HEX32.match(nonce) or not HEX128.match(signature):
            return 400, {"error": "bad request"}
        if not self._allow("signed:" + address_key, self.SIGNED_PER_ADDRESS, 3600):
            return 429, {"error": "too many requests"}
        if not self.nonces.take(nonce):
            return 401, {"error": "nonce", "nonce": "unknown"}
        row = self.device(device_hex)
        if not row:
            return 404, {"error": "unknown device", "enroll": True}
        if not self._signed_by(bytes.fromhex(row["public_key"]), bytes.fromhex(signature), lambda audience: signout_message(
                audience, bytes.fromhex(nonce), bytes.fromhex(device_hex))):
            return 401, {"error": "signature"}
        with self.lock:
            self.database.execute("UPDATE devices SET signed_out = ? WHERE device_id = ? AND signed_out = 0",
                                  (int(self.clock()), device_hex))
            self.database.commit()
        return 200, {"ok": True}

    # ---------- the device list (the site, the game; never an address)

    def bearer_device(self, header: str, capability: str):
        """(the device row an Authorization: Delta token is for, "") or
        (None, why)"""
        scheme, _, token = (header or "").strip().partition(" ")
        if scheme.lower() != "delta":
            return None, "unknown"
        found, why = self.tokens.read(token.strip())
        if not found:
            return None, why
        device, capabilities = found
        if not capabilities & CAPABILITIES[capability]:
            return None, "scope"
        row = self.device(device.hex())
        if not row or row["revoked"] or row["signed_out"] or not self._client_mask(row):
            return None, "revoked"
        # (the device's capabilities now, not only the token's)
        if not row["capabilities"] & self._client_mask(row) & CAPABILITIES[capability]:
            return None, "scope"
        return row, ""

    def _rows_of(self, account: str, copies) -> list:
        """(under the lock; copies from copies_of, asked before it) an
        account's devices not revoked: those signed in to it by code, and
        those of the copies whose games count for it; and a console still
        linked even if its row was revoked (its link is its key: never
        hidden while it works)"""
        copies = set(copies) | {account}
        rows = self.database.execute(
            "SELECT device_id, account_id, copy_id, platform, name, build, flags, created, last_refresh, last_used, "
            "signed_out, revoked, client_id FROM devices WHERE (revoked = 0 OR flags & 2) AND "
            "(account_id = ? OR copy_id IN (%s))" %
            ",".join("?" * len(copies)), (account, *copies)).fetchall()
        return [dict(zip(("device_id", "account_id", "copy_id", "platform", "name", "build", "flags", "created",
                          "last_refresh", "last_used", "signed_out", "revoked", "client_id"), row)) for row in rows
                if ((row[2] in copies) if row[2] else row[1] == account) and
                (not row[11] or (row[6] & FLAG_CONSOLE and row[2] in copies))]

    def devices_of(self, account: str, this: str = "") -> list:
        """an account's devices, for its owner: [{"id" (the device ID),
        "name", "platform", "build", "created", "last_seen" (days),
        "legacy", "console", "signed_out", "this"}], this device first,
        then the latest seen. Never a key or an address"""
        copies = self.copies_of(account)
        with self.lock:
            rows = self._rows_of(account, copies)
        found = [{"id": row["device_id"], "name": row["name"], "platform": row["platform"], "build": row["build"],
                  "created": row["created"], "last_seen": max(row["last_used"], row["last_refresh"]) or None,
                  "legacy": bool(row["flags"] & FLAG_LEGACY), "console": bool(row["flags"] & FLAG_CONSOLE),
                  "signed_out": bool(row["signed_out"]), "this": row["device_id"] == this} for row in rows]
        # (the app a device came through, when it isn't Chupathingy's own)
        for device, row in zip(found, rows):
            if row["client_id"] and self.clients is not None:
                device["client"] = self.clients.public(row["client_id"])
        found.sort(key=lambda device: (not device["this"], -(device["last_seen"] or 0), -device["created"]))
        return found[:DEVICES_SHOWN]

    def revoke_for(self, account: str, device_hex: str, from_site: bool = True, unlink: bool = True) -> bool:
        """one of an account's devices revoked by its owner (the site, or
        another of its devices): its tokens stop at once, its certificate
        goes on the revocation list, the site sessions it opened end, and
        every device it approved goes with it, and theirs, so a stolen device
        leaves none behind. The device alone stops: a player key it was
        enrolled with keeps working for the copy's other installs (the
        account's switch turns a key off). A computer's copy is unlinked
        (unlink) once no other device of that copy is left. A console's link
        is its key, so a console revoked is always unlinked, down a chain
        too. From another device (not from_site), a console is never the one
        picked to revoke: that takes a password session"""
        device_hex = str(device_hex or "").lower()
        copies = self.copies_of(account)
        with self.lock:
            rows = {r["device_id"]: r for r in self._rows_of(account, copies)}
        if device_hex not in rows or (not from_site and rows[device_hex]["flags"] & FLAG_CONSOLE):
            return False
        done, waiting = [], [device_hex]
        while waiting:
            current = waiting.pop()
            row = rows.get(current)
            if not row or current in done:
                continue
            console = bool(row["flags"] & FLAG_CONSOLE)
            if self.revoke(current) or (console and row["revoked"]):
                done.append(current)
                copy_id = row["copy_id"]
                # (a console's link is its key: always taken, from the site or
                # down a chain, and by sign out everywhere too; a computer's
                # copy only when asked (unlink), once no other device of it is
                # left; the profile's own player ID has no link to take away)
                if console and copy_id and copy_id != account:
                    self.unlink_copy(copy_id)
                elif unlink and copy_id and copy_id != account:
                    with self.lock:
                        others = self.database.execute(
                            "SELECT 1 FROM devices WHERE copy_id = ? AND revoked = 0 AND signed_out = 0 LIMIT 1",
                            (copy_id,)).fetchone()
                    if not others:
                        self.unlink_copy(copy_id)
            with self.lock:
                waiting.extend(r[0] for r in self.database.execute(
                    "SELECT device_id FROM devices WHERE approved_by = ? AND revoked = 0", (current,)))
        self._end_sessions(done)
        return device_hex in done

    def signout_everywhere(self, account: str) -> int:
        """every device of an account revoked (from the site): how many"""
        copies = self.copies_of(account)
        with self.lock:
            rows = self._rows_of(account, copies)
        # (every device revoked and its sessions ended; no copy unlinked: the
        # games stay where they count)
        for row in rows:
            self.revoke_for(account, row["device_id"], unlink=False)
        with self.lock:
            return len(rows) - len(self._rows_of(account, copies))

    # ---------- signing in to another of our sites (CSIN)

    SITE_SIGN_INS_PER_HOUR = 30

    def site_sign_in(self, account_hex: str, handle: str, audience: str, nonce: bytes):
        """(status, answer): a signed-in profile's sign-in for another of our
        sites (the site checks its sites first), SITE_SECONDS long; nothing
        is kept, and it is no device"""
        if not self._allow("site:" + account_hex, self.SITE_SIGN_INS_PER_HOUR, 3600):
            return 429, {"error": "Too many sign-ins. Try again in an hour."}
        now = int(self.clock())
        try:
            body = site_body(now, now + SITE_SECONDS, self.issuer["key_id"], bytes.fromhex(account_hex), nonce,
                             audience, handle)
            signature = self.signer.sign("site", body)
        except ValueError:
            return 400, {"error": "Bad request."}
        except SignerError:
            return 503, {"error": "Signing in is off just now. Try again in a few minutes."}
        return 200, {"assertion": (body + signature).hex(), "issuer": self.issuer_certificate.hex()}

    # ---------- sessions a device opened (/v1/link with its token)

    def note_session(self, session_hash: str, device_hex: str) -> None:
        """a site session a device's token opened: it ends with the device"""
        with self.lock:
            self.database.execute("INSERT OR REPLACE INTO identity_sessions (session, device_id, created) "
                                  "VALUES (?, ?, ?)", (session_hash, device_hex, int(self.clock())))
            self.database.execute("DELETE FROM identity_sessions WHERE created < ?", (int(self.clock()) - 90 * 86400,))
            self.database.commit()

    def session_allows(self, session_hash: str, capability: str) -> bool:
        """whether a site session a device opened (its game's link) may do
        what capability covers: always for Chupathingy's own devices and
        sessions no device opened; for another app's device, only while
        its scopes and its app's have it"""
        with self.lock:
            found = self.database.execute("SELECT device_id FROM identity_sessions WHERE session = ?",
                                          (session_hash,)).fetchone()
        row = self.device(found[0]) if found else None
        if not row or not row["client_id"]:
            return True
        return not row["revoked"] and bool(row["capabilities"] & self._client_mask(row) & CAPABILITIES[capability])

    def _end_sessions(self, device_ids) -> None:
        end_sessions(self.database, self.lock, device_ids)

    def rename(self, account: str, device_hex: str, name: str) -> bool:
        name = re.sub(r"[^ -~]", "", str(name or ""))[:32].strip()
        device_hex = str(device_hex or "").lower()
        copies = self.copies_of(account)
        with self.lock:
            if not any(r["device_id"] == device_hex for r in self._rows_of(account, copies)):
                return False
            self.database.execute("UPDATE devices SET name = ? WHERE device_id = ?", (name, device_hex))
            self.database.commit()
        return True

    def note_console(self, public_hex: str, console_id: str, account: str, platform: str,
                     approved_by: str = "") -> None:
        """a console linked by its own Link Profile (console_link.py): its
        key in the device list, so its owner sees it and can revoke it. A
        console revoked before and linked again comes back (it holds no
        certificate yet, so the list has nothing of it to carry)"""
        public_hex = public_hex.lower()
        if not HEX64.match(public_hex):
            return
        device_hex = device_id(bytes.fromhex(public_hex)).hex()
        with self.lock:
            row = self.database.execute("SELECT revoked, last_refresh FROM devices WHERE device_id = ?",
                                        (device_hex,)).fetchone()
            if row and row[0] and row[1]:
                return
            if row:
                self.database.execute(
                    "UPDATE devices SET account_id = ?, copy_id = ?, platform = ?, flags = flags | ?, signed_out = 0, "
                    "revoked = 0, last_used = ?, approved_by = ? WHERE device_id = ?",
                    (account, console_id, platform, FLAG_CONSOLE, self._day(), approved_by, device_hex))
            else:
                self.database.execute(
                    "INSERT INTO devices (device_id, account_id, copy_id, public_key, platform, flags, created, last_used, "
                    "approved_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (device_hex, account, console_id, public_hex, platform, FLAG_CONSOLE, self._day(), self._day(),
                     approved_by))
            self.database.commit()
        with self.memory:
            self.revoked_cache = None

    # ---------- stage C: the player key winds down, per account

    def legacy_setting(self, account: str) -> str:
        with self.lock:
            row = self.database.execute("SELECT legacy_key FROM identity_accounts WHERE account_id = ?",
                                        (account,)).fetchone()
        return LEGACY_SETTINGS[row[0]] if row and 0 <= row[0] < len(LEGACY_SETTINGS) else "auto"

    def set_legacy(self, account: str, setting: str) -> None:
        with self.lock:
            self.database.execute(
                "INSERT INTO identity_accounts (account_id, legacy_key, changed) VALUES (?, ?, ?) "
                "ON CONFLICT(account_id) DO UPDATE SET legacy_key = excluded.legacy_key, changed = excluded.changed",
                (account, LEGACY_SETTINGS.index(setting), int(self.clock())))
            self.database.commit()

    def note_key_file(self, account: str) -> None:
        """an Xbox identity file made for the account (the profile page's
        Download for Xbox): its key is in use on a console, so it is never
        turned off on its own"""
        with self.lock:
            self.database.execute(
                "INSERT INTO identity_accounts (account_id, key_file) VALUES (?, ?) "
                "ON CONFLICT(account_id) DO UPDATE SET key_file = excluded.key_file",
                (account, int(self.clock())))
            self.database.commit()

    # ---------- stage C, per copy (identity_copies)

    def _copy_set(self, copy_id: str, column: str, value: int) -> None:
        with self.lock:
            self.database.execute(f"INSERT OR IGNORE INTO identity_copies (copy_id) VALUES (?)", (copy_id,))
            self.database.execute(f"UPDATE identity_copies SET {column} = ? WHERE copy_id = ?", (value, copy_id))
            self.database.commit()

    def _copy_moved(self, copy_id: str) -> None:
        """a copy's own device now (enrolled, or signed in by code): kept past
        any purge of its device rows"""
        with self.lock:
            row = self.database.execute("SELECT moved FROM identity_copies WHERE copy_id = ?", (copy_id,)).fetchone()
        if not row or not row[0]:
            self._copy_set(copy_id, "moved", int(self.clock()))

    def note_key_seen(self, copy_id: str) -> None:
        """a player key that did something from a game (a request the site
        took): another install may still use it (at most once a day kept)"""
        now = int(self.clock())
        with self.lock:
            row = self.database.execute("SELECT key_seen FROM identity_copies WHERE copy_id = ?", (copy_id,)).fetchone()
        if not row or now - row[0] > 3600:
            self._copy_set(copy_id, "key_seen", now)

    def note_console_use(self, copy_id: str) -> None:
        """a console proved itself with its own key (a console claim signed
        by its console key; never a player key's claim): its ID is a
        console's, not a player key's, for CONSOLE_DAYS_KEPT"""
        self._copy_set(copy_id, "console", int(self.clock()))

    def waiting_copies(self, account: str) -> list:
        """the copies of an account still on the player key:
        - one that never moved to a device (but the profile's own player ID
          when no game ever used its key: a profile made on the site, whose
          key was never installed);
        - one that moved, but whose key a game still used after (another
          install; a request the site took), in the last KEY_SEEN_DAYS.
        A console (linked by its own Link Profile, or one that proved itself
        with its own key within CONSOLE_DAYS_KEPT) is a device, not a key"""
        copies = self.copies_of(account)
        now = int(self.clock())
        waiting = []
        with self.lock:
            for copy_id in copies:
                if self.database.execute("SELECT 1 FROM devices WHERE copy_id = ? AND flags & 2 LIMIT 1",
                                         (copy_id,)).fetchone():
                    continue
                row = self.database.execute("SELECT moved, key_seen, console FROM identity_copies WHERE copy_id = ?",
                                            (copy_id,)).fetchone()
                moved, key_seen, console = row or (0, 0, 0)
                if console > now - CONSOLE_DAYS_KEPT * 86400:
                    continue
                if not moved:
                    if copy_id == account and not key_seen:
                        continue
                    waiting.append(copy_id)
                elif key_seen > moved + KEY_SEEN_GRACE and key_seen > now - KEY_SEEN_DAYS * 86400:
                    waiting.append(copy_id)
        return waiting

    def legacy_key(self, account: str) -> dict:
        """{"setting" (auto, on or off), "on" (whether the key works for new
        things now), "waiting" (copies still on the key)}"""
        setting = self.legacy_setting(account)
        with self.lock:
            row = self.database.execute("SELECT key_file FROM identity_accounts WHERE account_id = ?",
                                        (account,)).fetchone()
        waiting = len(self.waiting_copies(account))
        # (automatic needs one copy moved at least: an account none of whose
        # copies has a device yet is all on the key)
        copies = self.copies_of(account) or [account]
        with self.lock:
            moved = self.database.execute(
                "SELECT 1 FROM identity_copies WHERE moved > 0 AND copy_id IN (%s) LIMIT 1" %
                ",".join("?" * len(copies)), tuple(copies)).fetchone()
        on = setting == "on" or (setting == "auto" and (waiting > 0 or not moved or bool(row and row[0])))
        # (no copy of the account ever used its key from a game: a profile
        # made on the site, with devices signed in by code alone)
        used = bool(moved) or waiting > 0 or bool(row and row[0])
        return {"setting": setting, "on": on, "waiting": waiting, "used": used}

    def legacy_key_off(self, copy_id: str) -> bool:
        """whether a player key may no longer do new things (open a
        session, enroll a device, act on /v1/game/*): its account's switch,
        or with it on auto, every copy of the account enrolled"""
        found = self.account_of(copy_id)
        if not found:
            return False
        return not self.legacy_key(found[0])["on"]

    def revoke_client(self, client_id: str) -> int:
        """every device that came through a client revoked (it was
        suspended), and the site sessions they opened; codes of it waiting
        are dropped. Only the client's own devices: one of them can never
        approve another ("devices" is never a client's), and a device key
        can't move between apps, so nothing of Chupathingy's own is touched.
        Games stay where they count. How many devices"""
        client_id = str(client_id or "").lower()
        if not client_id:
            return 0
        with self.memory:
            for table in (self.codes, self.polls, self.claims):
                for entry in table.values():
                    if entry.get("client_id") == client_id and entry["state"] not in ("connected", "declined"):
                        entry["state"] = "expired"
        revoked = revoke_client(self.database, self.lock, client_id, int(self.clock()))
        if revoked:
            with self.memory:
                self.revoked_cache = None
        return revoked

    def end_client_sessions(self, client_id: str) -> int:
        """(a client lost "profile") the site sessions its devices opened
        ended. How many devices had one"""
        return end_client_sessions(self.database, self.lock, client_id)

    def revoke(self, device_hex: str) -> bool:
        """a device revoked (admin.py device-revoke, and revoke_for)"""
        changed = revoke_device(self.database, self.lock, device_hex, int(self.clock()))
        if changed:
            with self.memory:
                self.revoked_cache = None
        return changed

    def _next_serial(self, now: int) -> int:
        """(under the lock) the revocation list's next serial: above every one
        before it, across restarts, even within one second"""
        row = self.database.execute("SELECT value FROM identity_state WHERE name = 'revoked_serial'").fetchone()
        serial = max(now, (row[0] if row else 0) + 1)
        self.database.execute("INSERT OR REPLACE INTO identity_state (name, value) VALUES ('revoked_serial', ?)",
                              (serial,))
        self.database.commit()
        return serial

    def revoked(self):
        """GET /v1/identity/revoked: the list, rebuilt at most every
        REVOKED_REBUILD seconds or when a device is revoked here"""
        now = int(self.clock())
        with self.memory:
            cached = self.revoked_cache
        if cached and now < cached[0]:
            return 200, cached[1]
        with self.lock:
            purge(self.database, now)
            rows = self.database.execute("SELECT device_id FROM devices WHERE revoked > ? ORDER BY device_id",
                                         (now - REVOKED_KEPT,)).fetchall()
            serial = self._next_serial(now)
        ids = [bytes.fromhex(row[0]) for row in rows][:REVOKED_MOST]
        body = revoked_body(serial, now, now + REVOKED_NEXT, self.issuer["key_id"], ids)
        try:
            signature = self.signer.sign("revoked", body)
        except SignerError:
            return 503, {"error": "busy"}
        answer = {"revoked": (body + signature).hex(), "issuers": [self.issuer_certificate.hex()], "serial": serial}
        with self.memory:
            self.revoked_cache = (now + REVOKED_REBUILD, answer)
        return 200, answer


def revoke_device(database, lock, device_hex: str, now: int) -> bool:
    """a device revoked in reports.db (the site, or admin.py with the site
    running: the list picks it up within REVOKED_REBUILD, tokens at once)"""
    with lock:
        changed = database.execute("UPDATE devices SET revoked = ? WHERE device_id = ? AND revoked = 0",
                                   (now, device_hex)).rowcount
        database.commit()
    return bool(changed)


def end_sessions(database, lock, device_ids) -> None:
    """the site sessions these devices opened (their game's link) ended"""
    device_ids = list(device_ids)
    if not device_ids:
        return
    marks = ",".join("?" * len(device_ids))
    with lock:
        if database.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sessions'").fetchone():
            database.execute(f"DELETE FROM sessions WHERE token IN (SELECT session FROM identity_sessions "
                             f"WHERE device_id IN ({marks}))", tuple(device_ids))
        if database.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'identity_sessions'").fetchone():
            database.execute(f"DELETE FROM identity_sessions WHERE device_id IN ({marks})", tuple(device_ids))
        database.commit()


def client_devices(database, lock, client_id: str) -> list:
    """the device IDs that came through a client and aren't revoked"""
    with lock:
        if not database.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'devices'").fetchone():
            return []
        return [r[0] for r in database.execute("SELECT device_id FROM devices WHERE client_id = ? AND revoked = 0",
                                               (client_id,))]


def end_client_sessions(database, lock, client_id: str) -> int:
    """the site sessions a client's devices opened ended (it lost
    "profile", or was suspended). How many devices"""
    devices = client_devices(database, lock, client_id) if client_id else []
    end_sessions(database, lock, devices)
    return len(devices)


def revoke_client(database, lock, client_id: str, now: int) -> int:
    """(the site, or admin.py with the site running) every device that came
    through a client revoked, and the site sessions they opened ended. How
    many devices"""
    devices = client_devices(database, lock, client_id) if client_id else []
    done = [device for device in devices if revoke_device(database, lock, device, now)]
    end_sessions(database, lock, devices)
    return len(done)


def delta_header(header) -> bool:
    """whether an Authorization header carries a device token"""
    return (header or "").strip().lower().startswith("delta ")


def bearer_copy(service, header: str, capability: str):
    """(the copy ID a token acts for, None), or (None, (401, answer)) when
    the site can't use it; service is None on a site without identity"""
    if service is None:
        return None, (401, {"error": "token", "token": "unknown"})
    copy_id, why = service.bearer(header, capability)
    if not copy_id:
        return None, (401, {"error": "token", "token": why})
    return copy_id, None


def setup(database, lock, issuer_cert_path: str, roots_text: str, signer_socket: str, issuer_key_path: str,
          account_of, note_player_key, platforms, log=print, audiences_text: str = "", known_copy=None, hooks=None):
    """the site's Identity from its options, or None (each said in the log,
    never a key): no certificate or roots yet, or no signer. A signer
    process that is down only makes requests answer 503 until it is back"""
    if not issuer_cert_path:
        return None
    try:
        roots = [bytes.fromhex(text.strip()) for text in roots_text.split(",") if text.strip()]
        if not roots or any(len(root) != 32 for root in roots):
            raise ValueError("--identity-roots: the identity set's public keys, 64 hex digits each")
        certificate = read_hex_file(issuer_cert_path)
        issuer = parse_issuer(certificate)
        if not issuer:
            raise ValueError("--identity-issuer-cert is not an issuer certificate")
        if signer_socket:
            signer = SocketSigner(signer_socket, issuer["public"])
        elif issuer_key_path:
            signer = LocalSigner(read_seed(issuer_key_path))
        else:
            raise ValueError("no signer (--identity-signer) or issuer key (--identity-issuer-key)")
        audiences = [text.strip().lower() for text in (audiences_text or "").split(",") if text.strip()]
        service = Identity(database, lock, signer, certificate, roots, account_of, note_player_key, platforms,
                           audiences=audiences or DEFAULT_AUDIENCES, known_copy=known_copy, **(hooks or {}))
    except (OSError, ValueError) as problem:
        log(f"device identity off: {problem}")
        return None
    log(f"device identity: issuer {service.issuer['key_id'].hex()} until "
        f"{time.strftime('%Y-%m-%d', time.gmtime(service.issuer['valid_until']))}"
        f"{' (signer process)' if signer_socket else ' (key in this process)'}")
    return service


def read_hex_file(path: str) -> bytes:
    """a certificate file's first hex line (lines starting with # left out)"""
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith("#"):
                return bytes.fromhex(line)
    return b""


def show(data: bytes) -> int:
    for kind, parse in (("issuer", parse_issuer), ("device", parse_device), ("revoked", parse_revoked)):
        fields = parse(data)
        if fields:
            print(f"{kind}:")
            for name, value in fields.items():
                if name in ("body", "signature"):
                    continue
                if isinstance(value, bytes):
                    value = value.hex()
                elif isinstance(value, list):
                    value = [v.hex() for v in value]
                print(f"  {name:13} {value}")
            return 0
    print("not a certificate or list")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("issuer-key")
    command.add_argument("--out", required=True)
    command = commands.add_parser("signer")
    command.add_argument("--key", required=True)
    command.add_argument("--socket", required=True)
    command = commands.add_parser("show")
    command.add_argument("file")
    arguments = parser.parse_args()
    if arguments.command == "issuer-key":
        seed = secrets.token_bytes(32)
        descriptor = os.open(arguments.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "w") as handle:
            handle.write(seed.hex() + "\n")
        public = ed25519.public_key(seed)
        del seed
        print(f"issuer public key {public.hex()} (key ID {key_id(public).hex()}): give it to command's "
              "identity-issuer.yml")
        return 0
    if arguments.command == "signer":
        serve_signer(arguments.key, arguments.socket, lambda text: print(text, flush=True))
        return 0
    text = open(arguments.file).read().strip()
    if text.startswith("{"):
        answer = json.loads(text)
        for name in ("certificate", "issuer", "revoked"):
            if name in answer:
                show(bytes.fromhex(answer[name]))
        return 0
    return show(read_hex_file(arguments.file))


if __name__ == "__main__":
    sys.exit(main())
