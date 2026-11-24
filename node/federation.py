"""Federation (delta-spec's federation.md and link.md, "Networks"): names
as handle:domain, each network's published root keys (roots.json), the
signed list of networks, and the offline check of a player's certificates
against them. Standard-library Python, the same rules a game follows.

A network is a domain with its own root keys. Its root keys sign its
issuer certificates (CISS) and its issuer signs device certificates (CDEV),
exactly as link.md's "Device identity" says; nothing in those bytes
changes. The network a certificate belongs to is the one whose root key
signed its CISS, so a game finds it by trying the root keys of the networks
it trusts. Today's certificates are signed by chupathingy.org's root keys,
so they read as chupathingy.org with no change at all.

roots.json, at https://<domain>/.well-known/open-network/roots.json (at most
ROOTS_MOST bytes):

    {"open_network_roots": 1,
     "domain": "example.org",
     "roots": [{"key": 64 hex, "use": "primary", "until": 0, "proof": 128 hex}, ...],
     "revoked": "https://example.org/v1/identity/revoked"}

    1 to 4 roots; "until" is Unix seconds, 0 or left out for no end; "use"
    and "revoked" are optional. "proof" is the root key's Ed25519 signature
    of ROOTS_LABEL + the domain's length (1 byte) + the domain + the key (32)
    + until (4, little-endian): proof that whoever publishes the file holds
    the key, for this domain.

The signed list of networks (at most LIST_MOST bytes of document; the
signature is the list key's over LIST_LABEL + the document's exact bytes):

    {"open_networks": 1, "serial": 1, "issued": 1790000000,
     "networks": {"example.org": {"roots": [{"key": 64 hex, "until": 0}, ...]}, ...}}

    0 to NETWORKS_MOST networks, 1 to 4 roots each, no root key twice in the
    whole list. A serial's top byte is its epoch, as the signed table's:
    each list key signs serials up to its own last epoch (the primary 0,
    the recovery key 255). The list has a key set of its own, a primary and
    a recovery key used for nothing else, never the signed table's keys.

Other networks' revocation lists aren't read: a game applies its home
network's list alone, and another network's revoked device stays verified
until its certificate expires (7 days, 14 on consoles). Checking them is
later.

The parsers are strict: a size limit first, then (for the list) the
signature, then JSON with no repeated keys, no fractions, no NaN, nesting
at most DEPTH_MOST, whole numbers inside their ranges, keys and proofs as
plain hex digits (no backslash escapes, as the game reads them). Unknown
members are skipped. Anything else refuses the whole file.

    federation.py root-keys --domain D --dir DIR [--until UNIX]
        a network's two root keys (DIR/<D>-root-primary.key and
        -recovery.key, 0600, seeds as hex) and its roots.json (DIR/roots.json)
    federation.py roots --domain D --key FILE [--key FILE] [--until UNIX] [--revoked URL] --out FILE
        roots.json again from root key files (a rotation, a new "until")
    federation.py issuer-cert --root-key FILE --issuer-public HEX [--days 90] --out FILE
        an issuer certificate (CISS) for a network's issuer, signed by a root key
    federation.py list-keys --dir DIR
        the list's own key set: DIR/list-primary.key and DIR/list-recovery.key
        (0600); never the signed table's keys
    federation.py list-make --serial N [--from FILE] [--issued UNIX] --roots FILE... --out FILE
        a list of networks from networks' roots.json files (each one checked)
    federation.py list-sign --key FILE LIST                (writes LIST.sig)
    federation.py list-verify --public-key HEX [--last-epoch N] LIST
    federation.py check --list LIST --list-key HEX [--add "DOMAIN KEY..."]
                        [--home DOMAIN --home-root HEX...] --issuer HEX --device HEX [--now UNIX]
        the name a pair of certificates proves, offline (the home network is
        chupathingy.org with its root keys unless --home and --home-root say)

Chupathingy's site keeps a copy of this file, byte for byte; keep the two
alike.

SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: MIT
"""

import argparse
import json
import json.decoder
import json.scanner
import os
import re
import secrets
import struct
import sys
import time

import ed25519
import identity

ROOTS_PATH = "/.well-known/open-network/roots.json"
LIST_PATHS = ("/v1/delta/networks", "/v1/delta/networks.sig")
ROOTS_LABEL = b"open network roots v1\n"
LIST_LABEL = b"open network list v1\n"
ROOTS_FORMAT = 1
LIST_FORMAT = 1
ROOTS_MOST = 8192
LIST_MOST = 16384
NETWORKS_MOST = 64
ROOT_KEYS_MOST = 4
DEPTH_MOST = 8
URL_MOST = 256
LOCAL_MOST = 16
# (issuer certificates remembered: which network each one is, and which
# network each issuer key was certified by)
ISSUERS_MOST = 256
TIME_MOST = 0xFFFFFFFF
SERIAL_MOST = 0xFFFFFFFE
# the network today's certificates belong to (their root keys are the
# identity key set every Chupathingy build has: link.md, "Keys")
CHUPATHINGY = "chupathingy.org"
# (its root keys, the identity key set: link.md, "Keys")
CHUPATHINGY_ROOTS = (
    "9c1c4454400fc0138630d63b8e2bbdeb0f31c99409763becd076b70f3189468e",
    "a3124502702cd3b2f610155c28c622cbab72c6f0df483b339439a14964f1d29f",
)

# (every pattern here is used with fullmatch alone: "$" would let a
# trailing line feed through)
HANDLE = re.compile(r"[a-z0-9_-]{3,20}")
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX128 = re.compile(r"[0-9a-f]{128}")
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
TOP_LABEL = re.compile(r"[a-z]{2,63}")
USE = re.compile(r"[a-z]{1,16}")
URL = re.compile(r"https://[\x21-\x7e]{1,248}")
SIGNATURE_TEXT = re.compile(rb"([0-9a-f]{128})\n?")


class FederationError(ValueError):
    pass


# ---------- names


def valid_domain(domain) -> bool:
    """a network's domain: lowercase ASCII host name (a-z, 0-9, - and .
    alone) of two labels or more, 253 characters at most, a last label of
    letters (so never an address), and no punycode (xn--) label, which
    could look like another network"""
    if not isinstance(domain, str) or not 4 <= len(domain) <= 253 or not domain.isascii():
        return False
    labels = domain.split(".")
    if len(labels) < 2 or not TOP_LABEL.fullmatch(labels[-1]):
        return False
    return all(LABEL.fullmatch(label) and not label.startswith("xn--") for label in labels)


def qualified(handle: str, domain: str) -> str:
    """handle:domain, lowercase"""
    if not isinstance(handle, str) or not HANDLE.fullmatch(handle) or not valid_domain(domain):
        raise FederationError("not a handle or a domain")
    return f"{handle}:{domain}"


def parse_qualified(text, home: str):
    """(handle, domain) from what a player typed: "handle:domain", or a
    handle alone for the home network; any capitals; None if it isn't one"""
    if not isinstance(text, str) or len(text) > 20 + 1 + 253 or not text.isascii():
        return None
    # (ASCII checked before lowercasing: Unicode lowercases some letters,
    # such as the Kelvin sign, to ASCII ones)
    text = text.strip().lower()
    handle, colon, domain = text.partition(":")
    if not colon:
        domain = home
    if not HANDLE.fullmatch(handle) or ":" in domain or not valid_domain(domain):
        return None
    return handle, domain


def shown(name: str, domain: str, home: str) -> str:
    """what a game shows: the name (the handle in its owner's capitals)
    alone for the home network's players, name:domain for everyone else's"""
    return name if domain == home else f"{name}:{domain}"


# ---------- strict JSON


def _no_repeats(pairs):
    found = {}
    for name, value in pairs:
        if name in found:
            raise FederationError("a member twice in one object")
        found[name] = value
    return found


def _refuse(text):
    raise FederationError("not a whole number")


def _depth(value, depth=1):
    if depth > DEPTH_MOST:
        raise FederationError("nested too deep")
    if isinstance(value, dict):
        for item in value.values():
            _depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _depth(item, depth + 1)


class _Escaped(str):
    """a JSON string written with a backslash escape: never a key or a proof,
    whose hex digits are taken only as written (as the game reads them)"""


def _scanstring(text, end, strict=True):
    value, after = json.decoder.scanstring(text, end, strict)
    if "\\" in text[end:after]:
        value = _Escaped(value)
    return value, after


class _Decoder(json.JSONDecoder):
    def __init__(self, **options):
        super().__init__(**options)
        self.parse_string = _scanstring
        self.scan_once = json.scanner.py_make_scanner(self)


def strict_json(data: bytes, most: int):
    if not isinstance(data, (bytes, bytearray)) or len(data) > most:
        raise FederationError("too big")
    try:
        text = bytes(data).decode("utf-8")
        value = json.loads(text, cls=_Decoder, object_pairs_hook=_no_repeats, parse_float=_refuse,
                           parse_constant=_refuse)
    except (UnicodeDecodeError, ValueError, RecursionError) as problem:
        if isinstance(problem, FederationError):
            raise
        raise FederationError("not JSON") from None
    _depth(value)
    if not isinstance(value, dict):
        raise FederationError("not an object")
    return value


def _whole(value, low: int, high: int, what: str) -> int:
    if type(value) is not int or not low <= value <= high:
        raise FederationError(f"{what} is not a whole number from {low} to {high}")
    return value


def _key(text, what="a root key") -> bytes:
    if type(text) is not str or not HEX64.fullmatch(text):
        raise FederationError(f"{what} is not 64 lowercase hex digits")
    key = bytes.fromhex(text)
    if identity.small_order(key):
        raise FederationError(f"{what} is a weak key")
    return key


# ---------- roots.json


def roots_message(domain: str, key: bytes, until: int) -> bytes:
    raw = domain.encode("ascii")
    return ROOTS_LABEL + bytes((len(raw),)) + raw + key + struct.pack("<I", until)


def make_roots(domain: str, roots, revoked: str = "") -> bytes:
    """roots.json for a domain from [(seed, use, until)], each key's proof
    signed with its seed"""
    if not valid_domain(domain) or not 1 <= len(roots) <= ROOT_KEYS_MOST:
        raise FederationError("not a domain, or not 1 to 4 root keys")
    entries = []
    for seed, use, until in roots:
        key = ed25519.public_key(seed)
        entry = {"key": key.hex(), "use": use, "until": until,
                 "proof": ed25519.sign(seed, roots_message(domain, key, until)).hex()}
        entries.append(entry)
    document = {"open_network_roots": ROOTS_FORMAT, "domain": domain, "roots": entries}
    if revoked:
        document["revoked"] = revoked
    data = (json.dumps(document, indent=2) + "\n").encode()
    parse_roots(data, domain)
    return data


def parse_roots(data: bytes, domain: str = None) -> dict:
    """{"domain", "roots": [{"key", "use", "until"}], "revoked"} from a
    roots.json whose every proof checks; domain, when given, is the domain
    it was fetched from, which it must name. FederationError if not"""
    document = strict_json(data, ROOTS_MOST)
    if document.get("open_network_roots") != ROOTS_FORMAT or type(document.get("open_network_roots")) is not int:
        raise FederationError("not roots.json format 1")
    name = document.get("domain")
    if not valid_domain(name):
        raise FederationError("not a domain")
    if domain is not None and name != domain:
        raise FederationError("roots.json of another domain")
    entries = document.get("roots")
    if not isinstance(entries, list) or not 1 <= len(entries) <= ROOT_KEYS_MOST:
        raise FederationError("not 1 to 4 root keys")
    roots, seen = [], set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise FederationError("a root that isn't an object")
        key = _key(entry.get("key"))
        if key in seen:
            raise FederationError("a root key twice")
        seen.add(key)
        until = _whole(entry.get("until", 0), 0, TIME_MOST, "until")
        use = entry.get("use", "")
        if "use" in entry and (not isinstance(use, str) or not USE.fullmatch(use)):
            raise FederationError("use is not a short word")
        proof = entry.get("proof")
        if type(proof) is not str or not HEX128.fullmatch(proof):
            raise FederationError("a proof is not 128 lowercase hex digits")
        if not ed25519.verify(key, roots_message(name, key, until), bytes.fromhex(proof)):
            raise FederationError("a root key's proof doesn't check")
        roots.append({"key": key, "use": use, "until": until})
    revoked = document.get("revoked", "")
    if "revoked" in document and (not isinstance(revoked, str) or len(revoked) > URL_MOST or
                                  not URL.fullmatch(revoked)):
        raise FederationError("revoked is not an https address")
    return {"domain": name, "roots": roots, "revoked": revoked}


# ---------- the signed list of networks


def make_list(serial: int, networks: dict, issued: int = 0) -> bytes:
    """the list's document from {domain: [(key, until)]}, in domain order"""
    document = {"open_networks": LIST_FORMAT, "serial": serial}
    if issued:
        document["issued"] = issued
    document["networks"] = {domain: {"roots": [{"key": key.hex(), "until": until} for key, until in roots]}
                            for domain, roots in sorted(networks.items())}
    data = (json.dumps(document, indent=2) + "\n").encode()
    read_list_document(data)
    return data


def read_list_document(data: bytes) -> dict:
    """{"serial", "issued", "networks": {domain: [(key, until)]}} from a
    list's document (its signature checked elsewhere). FederationError if
    it isn't one"""
    document = strict_json(data, LIST_MOST)
    if document.get("open_networks") != LIST_FORMAT or type(document.get("open_networks")) is not int:
        raise FederationError("not a list of networks of format 1")
    serial = _whole(document.get("serial"), 1, SERIAL_MOST, "serial")
    issued = _whole(document.get("issued", 0), 0, TIME_MOST, "issued")
    entries = document.get("networks")
    if not isinstance(entries, dict) or len(entries) > NETWORKS_MOST:
        raise FederationError("networks is not an object of at most 64")
    networks, seen = {}, set()
    for domain, entry in entries.items():
        if not valid_domain(domain):
            raise FederationError("a network that isn't a domain")
        roots = entry.get("roots") if isinstance(entry, dict) else None
        if not isinstance(roots, list) or not 1 <= len(roots) <= ROOT_KEYS_MOST:
            raise FederationError("a network without 1 to 4 root keys")
        keys = []
        for root in roots:
            if not isinstance(root, dict):
                raise FederationError("a root that isn't an object")
            key = _key(root.get("key"))
            if key in seen:
                raise FederationError("a root key in two places")
            seen.add(key)
            keys.append((key, _whole(root.get("until", 0), 0, TIME_MOST, "until")))
        networks[domain] = keys
    return {"serial": serial, "issued": issued, "networks": networks}


def sign_list(seed: bytes, document: bytes) -> str:
    return ed25519.sign(seed, LIST_LABEL + document).hex()


def check_list(document: bytes, signature_text: bytes, keys) -> dict:
    """the list (read_list_document's) when the signature is one of keys'
    [(public, last_epoch)] over it and the serial's epoch is the key's to
    sign; FederationError if not. The size first, then the signature, then
    the JSON"""
    if not isinstance(document, (bytes, bytearray)) or len(document) > LIST_MOST:
        raise FederationError("too big")
    match = SIGNATURE_TEXT.fullmatch(signature_text or b"")
    if not match:
        raise FederationError("the signature is not 128 lowercase hex digits")
    signature = bytes.fromhex(match.group(1).decode())
    signer = next((epoch for key, epoch in keys
                   if ed25519.verify(key, LIST_LABEL + bytes(document), signature)), None)
    if signer is None:
        raise FederationError("not signed by a list key")
    listed = read_list_document(bytes(document))
    if listed["serial"] >> 24 > signer:
        raise FederationError("a serial past its key's last epoch")
    return listed


def signed_form(document: bytes, signature_hex: str) -> bytes:
    """the list as one file: the signature's 128 hex digits, a line feed,
    the document (as the signed table travels)"""
    return signature_hex.encode() + b"\n" + document


def split_signed(data: bytes):
    if not isinstance(data, (bytes, bytearray)) or len(data) < 129 or data[128:129] != b"\n":
        raise FederationError("not a signed list")
    return bytes(data[129:]), bytes(data[:128])


# ---------- the networks a game trusts


def parse_local(text: str):
    """(domain, [keys]) from a local addition, "domain key [key...]"
    (spaces between), or FederationError"""
    words = str(text).split()
    if not str(text).isascii() or len(words) < 2 or len(words) > 1 + ROOT_KEYS_MOST or not valid_domain(words[0].lower()):
        raise FederationError("a local network is a domain and 1 to 4 root keys")
    return words[0].lower(), [_key(word.lower()) for word in words[1:]]


class Networks:
    """the networks whose names a game checks: its home network (built in,
    never changed by a list or a setting), the signed list's, and local
    additions and removals. A root key belongs to one network only"""

    def __init__(self, home: str, home_roots, listed=None, add=(), remove=(), log=None):
        self.home = home
        self.networks = {home: [(key, 0) for key in home_roots]}
        self.local = set()
        owner = {key: home for key in home_roots}
        removed = {str(domain).strip().lower() for domain in remove if str(domain).isascii()} - {home}

        def take(domain, roots, local):
            if domain in self.networks or domain in removed:
                if log and domain != home:
                    log(f"networks: {domain} {'removed' if domain in removed else 'already listed'}")
                return
            if any(key in owner for key, _ in roots):
                if log:
                    log(f"networks: {domain} left out, a root key of another network")
                return
            for key, _ in roots:
                owner[key] = domain
            self.networks[domain] = list(roots)
            if local:
                self.local.add(domain)

        self._found = {}
        self._issuers = {}
        self.conflicts = set()

        for domain, roots in ((listed or {}).get("networks") or {}).items():
            take(domain, roots, False)
        for text in list(add)[:LOCAL_MOST]:
            try:
                domain, keys = parse_local(text)
            except FederationError as problem:
                if log:
                    log(f"networks: a local network left out ({problem})")
                continue
            take(domain, [(key, 0) for key in keys], True)

    def network_of(self, issuer_fields, now: int):
        """the domain whose root key signed an issuer certificate (a key in
        date now), or None. Each certificate is looked for once (up to 64 +
        16 networks of 4 keys: 320 signature checks), then remembered. An
        issuer key certified by two networks' roots is refused for both"""
        if not issuer_fields:
            return None
        data = issuer_fields["body"] + issuer_fields["signature"]
        found = self._found.get(data)
        if found is None:
            found = ("", 0)
            message = identity.ISSUER_LABEL + issuer_fields["body"]
            for domain, roots in self.networks.items():
                for key, until in roots:
                    # (one signature has one signer, so the key is found
                    # whatever the time; its until is checked below)
                    if ed25519.verify(key, message, issuer_fields["signature"]):
                        found = (domain, until)
                        break
                if found[0]:
                    break
            if len(self._found) >= ISSUERS_MOST:
                self._found.clear()
            self._found[data] = found
        domain, until = found
        if not domain or (until and now > until):
            return None
        issuer = issuer_fields["public"]
        if len(self._issuers) >= ISSUERS_MOST and issuer not in self._issuers:
            self._issuers.clear()
        if self._issuers.setdefault(issuer, domain) != domain:
            if len(self.conflicts) < ISSUERS_MOST:
                self.conflicts.add(issuer)
        if issuer in self.conflicts:
            return None
        return domain


def check_name(networks: Networks, issuer_data: bytes, device_data: bytes, now: int, revoked=None) -> dict:
    """what a pair of certificates proves, offline: {"why": "" or a reason,
    "domain", "handle", "account", "device_id", "name": handle:domain}.
    revoked is {domain: device IDs}, each network's own list where a game
    has it"""
    answer = {"why": "", "domain": "", "handle": "", "account": "", "device_id": "", "name": ""}
    issuer = identity.parse_issuer(issuer_data or b"")
    if not issuer:
        answer["why"] = "not an issuer certificate"
        return answer
    domain = networks.network_of(issuer, now)
    if domain is None:
        answer["why"] = "no network trusted"
        return answer
    why = identity.check_issuer(issuer, [key for key, _ in networks.networks[domain]], now)
    device = identity.parse_device(device_data or b"")
    if not why:
        why = identity.check_device(device, issuer, now, frozenset((revoked or {}).get(domain, ())))
    if not why and not device["handle"]:
        why = "no handle"
    if not why and not HANDLE.fullmatch(device["handle"]):
        why = "not a handle"
    if not why and not device["capabilities"] & identity.CAPABILITIES["play"]:
        why = "can't play"
    if why:
        answer.update(why=why, domain=domain)
        return answer
    answer.update(domain=domain, handle=device["handle"], account=device["account"].hex(),
                  device_id=device["device_id"].hex(), name=qualified(device["handle"], domain))
    return answer


# ---------- the tool


def write_secret(path: str, seed: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(seed.hex() + "\n")


def issuer_certificate(root_seed: bytes, issuer_public: bytes, valid_from: int, valid_until: int) -> bytes:
    body = identity.issuer_body(valid_from, valid_until, issuer_public)
    return body + ed25519.sign(root_seed, identity.ISSUER_LABEL + body)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("root-keys")
    command.add_argument("--domain", required=True)
    command.add_argument("--dir", required=True)
    command.add_argument("--until", type=int, default=0)
    command.add_argument("--revoked", default="")
    command = commands.add_parser("roots")
    command.add_argument("--domain", required=True)
    command.add_argument("--key", action="append", required=True)
    command.add_argument("--until", type=int, default=0)
    command.add_argument("--revoked", default="")
    command.add_argument("--out", required=True)
    command = commands.add_parser("issuer-cert")
    command.add_argument("--root-key", required=True)
    command.add_argument("--issuer-public", required=True)
    command.add_argument("--days", type=int, default=90)
    command.add_argument("--out", required=True)
    command = commands.add_parser("list-keys")
    command.add_argument("--dir", required=True)
    command = commands.add_parser("list-make")
    command.add_argument("--serial", type=int, required=True)
    command.add_argument("--from", dest="previous", default="")
    command.add_argument("--issued", type=int, default=0)
    command.add_argument("--roots", nargs="*", default=[])
    command.add_argument("--out", required=True)
    command = commands.add_parser("list-sign")
    command.add_argument("--key", required=True)
    command.add_argument("list")
    command = commands.add_parser("list-verify")
    command.add_argument("--public-key", action="append", required=True)
    command.add_argument("--last-epoch", type=int, default=255)
    command.add_argument("list")
    command = commands.add_parser("check")
    command.add_argument("--list", default="")
    command.add_argument("--list-key", action="append", default=[])
    command.add_argument("--home", default=CHUPATHINGY)
    command.add_argument("--home-root", action="append", default=[])
    command.add_argument("--add", action="append", default=[])
    command.add_argument("--remove", action="append", default=[])
    command.add_argument("--issuer", required=True)
    command.add_argument("--device", required=True)
    command.add_argument("--now", type=int, default=0)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "root-keys":
            if not valid_domain(arguments.domain):
                raise FederationError("not a domain")
            os.makedirs(arguments.dir, exist_ok=True)
            seeds = []
            for use in ("primary", "recovery"):
                seed = secrets.token_bytes(32)
                write_secret(os.path.join(arguments.dir, f"{arguments.domain}-root-{use}.key"), seed)
                seeds.append((seed, use, arguments.until))
                print(f"{use} root key {ed25519.public_key(seed).hex()}")
            path = os.path.join(arguments.dir, "roots.json")
            with open(path, "xb") as handle:
                handle.write(make_roots(arguments.domain, seeds, arguments.revoked))
            print(f"wrote {path}: publish it at https://{arguments.domain}{ROOTS_PATH}")
            return 0
        if arguments.command == "roots":
            seeds = [(identity.read_seed(path), "primary" if n == 0 else "recovery", arguments.until)
                     for n, path in enumerate(arguments.key)]
            with open(arguments.out, "xb") as handle:
                handle.write(make_roots(arguments.domain, seeds, arguments.revoked))
            return 0
        if arguments.command == "issuer-cert":
            public = _key(arguments.issuer_public.lower(), "the issuer key")
            now = int(time.time())
            certificate = issuer_certificate(identity.read_seed(arguments.root_key), public, now - 3600,
                                             now + max(1, min(arguments.days, 400)) * 86400)
            with open(arguments.out, "x") as handle:
                handle.write(certificate.hex() + "\n")
            print(f"issuer {identity.key_id(public).hex()} certificate written")
            return 0
        if arguments.command == "list-keys":
            os.makedirs(arguments.dir, exist_ok=True)
            for use in ("primary", "recovery"):
                seed = secrets.token_bytes(32)
                write_secret(os.path.join(arguments.dir, f"list-{use}.key"), seed)
                print(f"list {use} key {ed25519.public_key(seed).hex()} (last epoch "
                      f"{0 if use == 'primary' else 255})")
            return 0
        if arguments.command == "list-make":
            networks = {}
            if arguments.previous:
                with open(arguments.previous, "rb") as handle:
                    networks = read_list_document(handle.read())["networks"]
            for path in arguments.roots:
                with open(path, "rb") as handle:
                    roots = parse_roots(handle.read())
                networks[roots["domain"]] = [(root["key"], root["until"]) for root in roots["roots"]]
            with open(arguments.out, "xb") as handle:
                handle.write(make_list(arguments.serial, networks, arguments.issued))
            return 0
        if arguments.command == "list-sign":
            with open(arguments.list, "rb") as handle:
                document = handle.read()
            read_list_document(document)
            with open(arguments.list + ".sig", "x") as handle:
                handle.write(sign_list(identity.read_seed(arguments.key), document) + "\n")
            return 0
        if arguments.command == "list-verify":
            with open(arguments.list, "rb") as handle:
                document = handle.read()
            with open(arguments.list + ".sig", "rb") as handle:
                signature = handle.read()
            keys = [(_key(key.lower(), "a list key"), arguments.last_epoch) for key in arguments.public_key]
            listed = check_list(document, signature, keys)
            print(f"list serial {listed['serial']}: " + ", ".join(sorted(listed["networks"])))
            return 0
        listed = None
        if arguments.list:
            with open(arguments.list, "rb") as handle:
                document = handle.read()
            with open(arguments.list + ".sig", "rb") as handle:
                signature = handle.read()
            listed = check_list(document, signature, [(_key(key.lower(), "a list key"), 255)
                                                      for key in arguments.list_key])
        home_roots = arguments.home_root
        if not home_roots:
            if arguments.home != CHUPATHINGY:
                raise FederationError("--home-root: the home network's root keys")
            home_roots = list(CHUPATHINGY_ROOTS)
        if not valid_domain(arguments.home):
            raise FederationError("--home is not a domain")
        networks = Networks(arguments.home, [_key(key.lower()) for key in home_roots], listed,
                            arguments.add, arguments.remove, log=print)
        answer = check_name(networks, bytes.fromhex(arguments.issuer), bytes.fromhex(arguments.device),
                            arguments.now or int(time.time()))
        print(json.dumps(answer))
        return 0 if not answer["why"] else 1
    except (OSError, ValueError) as problem:
        print(f"refused: {problem}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
