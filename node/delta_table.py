"""Delta's legacy table, pulled from GitHub (the game's docs/delta.md, "The
legacy table as config").

CI (command's delta-table.yml) signs each table and commits legacy.json and
legacy.json.sig to chupathingyce's delta-table branch. The site pulls the two
from there every few minutes, checks the signature against ChupathingyCE's
published keys (the game's port/linux/src/delta_key.h: the primary and the
recovery key) and that the serial is newer than the one it serves, and only
then puts them in the data folder as delta_legacy.json and
delta_legacy.json.sig, which /v1/delta/legacy and /v1/delta/legacy.sig serve
as they are. Nothing is deployed and no secret is needed; a table that
doesn't verify is never served, and the game checks it again itself.

    puller = Puller(data_folder)        # then puller.start(), a thread
    puller.pull()                        # once: "taken", "same", or why not

SPDX-FileCopyrightText: 2026 The Chupathingy contributors
SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: GPL-3.0-or-later
"""

import json
import os
import re
import threading
import time
import urllib.request
from pathlib import Path

import ed25519

# (where the table is pulled from: config delta_table.source; none by default)
SOURCE = ""
# (the game's delta_key.h, and command's keys/delta.pub.json)
KEYS = {
    "primary": bytes.fromhex("d51bd85346bf889b6bc5aa21dcc7a43488657b64f2432e17f6e0e7fe976933ce"),
    "recovery": bytes.fromhex("97cde84d8b9b6ba8a275d412b49422d4c07970653ee53ae54285e96640a5e456"),
}
DOCUMENT = "delta_legacy.json"
SIGNATURE = "delta_legacy.json.sig"
DOCUMENT_SIZE = 16384
SIGNATURE_SIZE = 200
INTERVAL = 300
TIMEOUT = 15
SIGNATURE_TEXT = re.compile(rb"([0-9a-fA-F]{128})[ \t\r\n]*")


class TableError(ValueError):
    pass


def signature_bytes(text: bytes) -> bytes:
    match = SIGNATURE_TEXT.fullmatch(text)
    if not match:
        raise TableError("the signature is not 128 hex digits")
    return bytes.fromhex(match.group(1).decode())


def check(document: bytes, signature_text: bytes, keys=None) -> dict:
    """the table, if the signature is one of the keys' and it reads as a
    table (the size first, then the signature, then the document); else
    TableError"""
    if len(document) > DOCUMENT_SIZE:
        raise TableError(f"it is {len(document)} bytes, more than {DOCUMENT_SIZE}")
    signature = signature_bytes(signature_text)
    if not any(ed25519.verify(key, document, signature) for key in (keys or KEYS).values()):
        raise TableError("its signature is not ChupathingyCE's")
    try:
        table = json.loads(document.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise TableError("it is not JSON") from None
    serial = table.get("serial") if isinstance(table, dict) else None
    if table.get("delta_legacy") != 1 or not isinstance(serial, int) or isinstance(serial, bool) or \
            not 1 <= serial <= 4294967294 or not isinstance(table.get("wires"), dict):
        raise TableError("it is not a legacy table of format 1")
    return table


def summary(table: dict) -> list:
    """the table's rows, for the Delta page: wire, announce, minimum,
    maximum, and the OpenCE build it follows (or None)"""
    rows = []
    for wire, row in sorted((table or {}).get("wires", {}).items()):
        if isinstance(row, dict):
            rows.append({"wire": wire, "announce": row.get("announce"), "minimum": row.get("minimum"),
                         "maximum": row.get("maximum"), "follows": row.get("follows")})
    return rows


def fetch(url: str, limit: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "delta-server legacy table"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as answer:
        data = answer.read(limit + 1)
    if len(data) > limit:
        raise TableError(f"{url}: more than {limit} bytes")
    return data


class Puller:
    def __init__(self, data: Path, source: str = SOURCE, interval: int = INTERVAL, keys=None, log=print, fetch=fetch):
        self.data = Path(data)
        self.source = source
        self.interval = interval
        self.keys = keys or KEYS
        self.log = log
        self.fetch = fetch
        self.lock = threading.Lock()
        self.last = None

    def served(self):
        """the table served now (checked again), or None"""
        try:
            return check((self.data / DOCUMENT).read_bytes(), (self.data / SIGNATURE).read_bytes(), self.keys)
        except (OSError, TableError):
            return None

    def pull(self) -> str:
        """one pull: "taken", "same" (not newer), or why it wasn't"""
        with self.lock:
            try:
                document = self.fetch(self.source + "legacy.json", DOCUMENT_SIZE)
                signature = self.fetch(self.source + "legacy.json.sig", SIGNATURE_SIZE)
                table = check(document, signature, self.keys)
            except TableError as error:
                return self.note(f"not taken: {error}")
            except Exception as error:  # (the network: tried again next time)
                return self.note(f"not reached: {type(error).__name__}")
            current = self.served()
            if current and table["serial"] <= current["serial"]:
                return self.note("same")
            # (the signature first, then the document: a game that reads the
            # two between the moves gets a pair that doesn't verify, drops
            # it quietly and tries again later)
            try:
                for name, data in ((SIGNATURE, signature), (DOCUMENT, document)):
                    temporary = self.data / (name + ".new")
                    temporary.write_bytes(data)
                    os.replace(temporary, self.data / name)
            except OSError as error:  # (the data folder: tried again next time)
                return self.note(f"not written: {type(error).__name__}: {error}")
            return self.note(f"taken: serial {table['serial']}", force=True)

    def note(self, text: str, force: bool = False) -> str:
        result = "same" if text == "same" else ("taken" if text.startswith("taken") else text)
        if force or text != self.last:
            self.log(f"legacy table: {text}")
        self.last = text
        return result

    def run(self):
        # (nothing ends the thread: before, an error pull() didn't catch
        # ended it without a word, and the site served its old table for
        # good)
        while True:
            try:
                self.pull()
            except Exception as error:
                self.note(f"failed: {type(error).__name__}: {error}")
            time.sleep(self.interval)

    def start(self):
        threading.Thread(target=self.run, daemon=True).start()
