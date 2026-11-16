"""IP addresses, as the site may keep or show them: never whole.

The game list needs a request's address only for the moment it serves it
(rate limits, a claim's tag, a region), and keeps it in memory only. What
is written down or shown, the admin panel's audit log included, is a tag
instead: "addr#" and 8 hexadecimal digits of an HMAC of the address with
the site's own key (address.key in the --data folder, made once), so the
same address always has the same tag, and a tag says nothing of the
address to anyone without the key. Text that goes out (Discord posts) has
any public address in it replaced by scrub().

    tag(address, key)    -> "addr#1a2b3c4d" ("" for no address)
    load_key(folder)     -> the site's key, made if there is none
    scrub(text)          -> the text, with every public address "[address]"

Standard library only.

SPDX-FileCopyrightText: 2026 The Chupathingy contributors
SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: GPL-3.0-or-later
"""

import hashlib
import hmac
import ipaddress
import os
import re
import secrets
from pathlib import Path

KEY_FILE = "address.key"
KEY_SIZE = 32
TAG_DIGITS = 8
TAG = re.compile(r"addr#[0-9a-f]{%d}\Z" % TAG_DIGITS)

# an IPv4 address (a port may follow), or something IPv6-like; each checked
# by ipaddress after
CANDIDATE = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?!\w|\.\d)"
                       r"|(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")


def load_key(folder) -> bytes:
    """the site's key for tags, in folder (made, readable by its owner only,
    if it has none); a new one for this run only without a folder"""
    if not folder:
        return secrets.token_bytes(KEY_SIZE)
    path = Path(folder) / KEY_FILE
    try:
        key = path.read_bytes()
        if len(key) == KEY_SIZE:
            return key
    except FileNotFoundError:
        pass
    key = secrets.token_bytes(KEY_SIZE)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as file:
        file.write(key)
    return key


def tag(address: str, key: bytes) -> str:
    """an address as the site keeps or shows it: "addr#" and its keyed hash;
    a tag already is one; "" for none"""
    address = str(address or "").strip()
    if not address or TAG.match(address):
        return address
    try:
        address = ipaddress.ip_address(address).compressed
    except ValueError:
        pass
    return "addr#" + hmac.new(key, address.encode(), hashlib.sha256).hexdigest()[:TAG_DIGITS]


def public_address(text: str) -> bool:
    """whether text is an address someone on the internet has (not a local
    network's, loopback, or a documentation range's)"""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return address.is_global


def scrub(text: str) -> str:
    """text with every public address in it as "[address]" (and its port, if
    one follows, kept)"""
    return CANDIDATE.sub(lambda match: "[address]" if public_address(match.group(0)) else match.group(0), text or "")
