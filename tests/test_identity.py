# SPDX-FileCopyrightText: 2026 The Chupathingy contributors
# SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
# SPDX-License-Identifier: MIT
"""Device identity, stage A (identity.py, /v1/identity/*, tokens in place of
the player key): the shared test vectors (chupathingyce's docs/delta.md,
"Device identity"; command's and the game's tests check the same bytes),
malformed certificates and lists, tokens, the signer process, and the
endpoints over HTTP with the key still working beside them:
python3 -m unittest test_identity"""
import hashlib
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

import ed25519
import accounts
import identity

VECTORS = json.loads((Path(__file__).resolve().parent / "testdata" / "identity_vectors.json").read_text())


def seed(text: str) -> bytes:
    return hashlib.sha256(text.encode()).digest()


ROOT = seed(VECTORS["root_seed_text"])
ISSUER = seed(VECTORS["issuer_seed_text"])
DEVICE = seed(VECTORS["device_seed_text"])


def fresh_issuer(now=None, days=90):
    """an issuer certificate of the test issuer, signed by the test root, in date now"""
    now = int(now or time.time())
    body = identity.issuer_body(now - 3600, now + days * 86400, ed25519.public_key(ISSUER))
    return body + ed25519.sign(ROOT, identity.ISSUER_LABEL + body)


class Vectors(unittest.TestCase):
    def test_keys_and_ids(self):
        self.assertEqual(ed25519.public_key(ROOT).hex(), VECTORS["root_public"])
        issuer = ed25519.public_key(ISSUER)
        self.assertEqual(issuer.hex(), VECTORS["issuer_public"])
        self.assertEqual(identity.key_id(issuer).hex(), VECTORS["issuer_key_id"])
        device = ed25519.public_key(DEVICE)
        self.assertEqual(device.hex(), VECTORS["device_public"])
        self.assertEqual(identity.device_id(device).hex(), VECTORS["device_id"])
        player = seed(VECTORS["player_key_text"])
        self.assertEqual(player.hex(), VECTORS["player_key"])
        self.assertEqual(accounts.player_id_of(player.hex()), VECTORS["copy_id"])

    def test_certificates_made_again(self):
        """the vectors' bytes, made from their fields"""
        issuer = ed25519.public_key(ISSUER)
        body = identity.issuer_body(VECTORS["valid_from"], VECTORS["valid_until"], issuer)
        self.assertEqual((body + ed25519.sign(ROOT, identity.ISSUER_LABEL + body)).hex(), VECTORS["issuer_certificate"])
        body = identity.device_body(1, identity.FLAG_LEGACY, VECTORS["issued"], VECTORS["expires"], bytes(range(1, 9)),
                                    identity.key_id(issuer), bytes.fromhex(VECTORS["copy_id"]),
                                    ed25519.public_key(DEVICE), 0x1F, "milenko")
        self.assertEqual((body + ed25519.sign(ISSUER, identity.DEVICE_LABEL + body)).hex(),
                         VECTORS["device_certificate"])
        body = identity.revoked_body(VECTORS["issued"], VECTORS["issued"], VECTORS["issued"] + 86400,
                                     identity.key_id(issuer), [b"\x11" * 16, bytes.fromhex(VECTORS["device_id"])])
        self.assertEqual((body + ed25519.sign(ISSUER, identity.REVOKED_LABEL + body)).hex(), VECTORS["revoked"])

    def test_chain_checks(self):
        roots = [bytes.fromhex(VECTORS["root_public"])]
        issuer = identity.parse_issuer(bytes.fromhex(VECTORS["issuer_certificate"]))
        device = identity.parse_device(bytes.fromhex(VECTORS["device_certificate"]))
        self.assertEqual(identity.check_issuer(issuer, roots, VECTORS["issued"]), "")
        self.assertEqual(identity.check_device(device, issuer, VECTORS["issued"] + 10), "")
        self.assertEqual((device["handle"], device["platform"], device["flags"], device["capabilities"]),
                         ("milenko", 1, 1, 0x1F))
        self.assertEqual(device["account"].hex(), VECTORS["copy_id"])
        self.assertEqual(device["device_id"].hex(), VECTORS["device_id"])
        self.assertEqual(identity.check_device(device, issuer, VECTORS["expires"] + identity.GRACE), "expired")
        self.assertEqual(identity.check_device(device, issuer, VECTORS["issued"] - identity.GRACE - 1),
                         "issued in the future")
        self.assertEqual(identity.check_issuer(issuer, [ed25519.public_key(ISSUER)], VECTORS["issued"]),
                         "not signed by a root key")
        self.assertEqual(identity.check_issuer(issuer, roots, VECTORS["valid_until"] + identity.GRACE), "expired")
        revoked = identity.parse_revoked(bytes.fromhex(VECTORS["revoked"]))
        self.assertEqual(identity.check_revoked(revoked, issuer), "")
        self.assertEqual([i.hex() for i in revoked["device_ids"]], ["11" * 16, VECTORS["device_id"]])
        self.assertEqual(identity.check_device(device, issuer, VECTORS["issued"] + 10, set(revoked["device_ids"])),
                         "revoked")

    def test_request_signatures(self):
        device = ed25519.public_key(DEVICE)
        nonce = bytes.fromhex(VECTORS["nonce"])
        did = bytes.fromhex(VECTORS["device_id"])
        audience = VECTORS["audience"]
        for message, name in ((identity.enroll_message(audience, nonce, bytes.fromhex(VECTORS["copy_id"]), device),
                               "enroll_signature"),
                              (identity.refresh_message(audience, nonce, did), "refresh_signature"),
                              (identity.token_message(audience, nonce, did), "token_signature")):
            self.assertEqual(ed25519.sign(DEVICE, message).hex(), VECTORS[name])
            self.assertTrue(ed25519.verify(device, message, bytes.fromhex(VECTORS[name])))
        # (a refresh's signature is not a token's)
        self.assertFalse(ed25519.verify(device, identity.token_message(audience, nonce, did),
                                        bytes.fromhex(VECTORS["refresh_signature"])))
        # (nor is another site's)
        self.assertFalse(ed25519.verify(device, identity.token_message("evil.example", nonce, did),
                                        bytes.fromhex(VECTORS["token_signature"])))
        self.assertEqual(identity.audience_bytes(audience), bytes((21,)) + audience.encode())


class Malformed(unittest.TestCase):
    def test_device(self):
        data = bytes.fromhex(VECTORS["device_certificate"])
        issuer = identity.parse_issuer(bytes.fromhex(VECTORS["issuer_certificate"]))
        for broken in (data[:-1], data + b"\0", b"XDEV" + data[4:], data[:4] + b"\x02" + data[5:],
                       data[:6] + b"\x02" + data[7:], data[:6] + b"\x15" + data[7:]):
            self.assertIsNone(identity.parse_device(broken))
        # (an uppercase handle is not one)
        self.assertIsNone(identity.parse_device(data[:84] + b"M" + data[85:]))
        # (expires before issued)
        self.assertIsNone(identity.parse_device(data[:12] + data[8:12] + data[16:]))
        # (any changed byte breaks the signature)
        for index in (5, 7, 20, 40, 60, 82, 86):
            changed = bytearray(data)
            changed[index] ^= 1
            fields = identity.parse_device(bytes(changed))
            if fields:
                self.assertNotEqual(identity.check_device(fields, issuer, VECTORS["issued"] + 10), "")
        # (no handle: a copy without a profile yet)
        body = identity.device_body(1, 1, 10, 20, bytes(8), issuer["key_id"], bytes(16), ed25519.public_key(DEVICE),
                                    1, "")
        self.assertEqual(identity.parse_device(body + bytes(64))["handle"], "")
        with self.assertRaises(ValueError):
            identity.device_body(1, 1, 10, 20, bytes(8), issuer["key_id"], bytes(16), bytes(32), 1, "Milenko")

    def test_weak_device_key(self):
        """a device key of small order is refused: anyone could sign for it"""
        weak = (1).to_bytes(32, "little")  # the neutral point
        self.assertTrue(identity.small_order(weak))
        self.assertFalse(identity.small_order(ed25519.public_key(DEVICE)))

    def test_issuer_and_list(self):
        data = bytes.fromhex(VECTORS["issuer_certificate"])
        for broken in (data[:-1], data + b"\0", data[:5] + b"\x01" + data[6:], data[:8] + data[12:16] + data[8:12] +
                       data[16:]):
            self.assertIsNone(identity.parse_issuer(broken))
        data = bytes.fromhex(VECTORS["revoked"])
        for broken in (data[:-1], data[:28] + b"\x03\x00" + data[30:], data[:30] + b"\x01\x00" + data[32:],
                       data[:32] + data[48:64] + data[32:48] + data[64:]):
            self.assertIsNone(identity.parse_revoked(broken))


class Tokens(unittest.TestCase):
    def test_tokens(self):
        now = [1000.0]
        tokens = identity.Tokens(clock=lambda: now[0])
        token, lifetime = tokens.make(b"\x01" * 16, 0x12)
        self.assertEqual(lifetime, 3600)
        self.assertLessEqual(len(token), 200)
        self.assertEqual(tokens.read(token), ((b"\x01" * 16, 0x12), ""))
        self.assertEqual(tokens.read(token[:-1] + ("0" if token[-1] != "0" else "1")), (None, "unknown"))
        self.assertEqual(identity.Tokens(clock=lambda: now[0]).read(token), (None, "unknown"))
        now[0] += 3600
        self.assertEqual(tokens.read(token), (None, "expired"))
        self.assertEqual(tokens.read(""), (None, "unknown"))

    def test_nonces(self):
        now = [0.0]
        nonces = identity.Nonces(clock=lambda: now[0])
        nonce = nonces.issue()
        self.assertTrue(nonces.take(nonce))
        self.assertFalse(nonces.take(nonce))
        nonce = nonces.issue()
        now[0] += identity.Nonces.LIFETIME
        self.assertFalse(nonces.take(nonce))
        # (a full pool lets the oldest go, never refuses)
        nonces.MOST = 3
        issued = [nonces.issue() for _ in range(5)]
        self.assertEqual(len(nonces.issued), 3)
        self.assertFalse(nonces.take(issued[0]))
        self.assertTrue(nonces.take(issued[-1]))


class Signer(unittest.TestCase):
    def test_local_signer_signs_only_its_own(self):
        now = 1790000000
        signer = identity.LocalSigner(ISSUER, clock=lambda: now)
        own = identity.key_id(signer.public)
        device = ed25519.public_key(DEVICE)
        body = identity.device_body(1, 1, now, now + 86400, bytes(8), own, bytes(16), device, 1, "abc")
        self.assertTrue(ed25519.verify(signer.public, identity.DEVICE_LABEL + body, signer.sign("device", body)))
        for refused in (identity.device_body(1, 1, now, now + 1, bytes(8), b"\x01" * 8, bytes(16), device, 1, "abc"),
                        identity.device_body(1, 1, now, now + 30 * 86400, bytes(8), own, bytes(16), device, 1, "abc"),
                        # (backdated, or issued ahead: a certificate is issued now)
                        identity.device_body(1, 1, now - 3600, now + 86400, bytes(8), own, bytes(16), device, 1, "abc"),
                        identity.device_body(1, 1, now + 3600, now + 86400, bytes(8), own, bytes(16), device, 1, "abc")):
            with self.assertRaises(identity.SignerError):
                signer.sign("device", refused)
        with self.assertRaises(identity.SignerError):
            signer.sign("anything", b"chupathingy")
        # a list's serial only rises, and never runs ahead of the clock
        first = identity.revoked_body(now - 5, now, now + 86400, own, [])
        signer.sign("revoked", first)
        for refused in (first, identity.revoked_body(now - 6, now, now + 86400, own, []),
                        identity.revoked_body(0xFFFFFFFF, now, now + 86400, own, []),
                        identity.revoked_body(now + 1, now - 3600, now + 86400, own, [])):
            with self.assertRaises(identity.SignerError):
                signer.sign("revoked", refused)
        signer.sign("revoked", identity.revoked_body(now, now, now + 86400, own, []))

    def test_signer_process(self):
        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder, "issuer.key")
            key.write_text(ISSUER.hex() + "\n")
            os.chmod(key, 0o644)
            with self.assertRaises(ValueError):
                identity.read_seed(str(key))
            os.chmod(key, 0o600)
            path = str(Path(folder, "signer.sock"))
            threading.Thread(target=identity.serve_signer, args=(str(key), path, lambda text: None),
                             daemon=True).start()
            for _ in range(100):
                if os.path.exists(path):
                    break
                time.sleep(0.02)
            signer = identity.SocketSigner(path, ed25519.public_key(ISSUER))
            now = int(time.time())
            body = identity.device_body(1, 1, now, now + 86400, bytes(8), identity.key_id(signer.public), bytes(16),
                                        ed25519.public_key(DEVICE), 1, "abc")
            self.assertTrue(ed25519.verify(signer.public, identity.DEVICE_LABEL + body, signer.sign("device", body)))
            with self.assertRaises(identity.SignerError):
                signer.sign("revoked", body)
            # (a signer of another key: its signatures are refused)
            with self.assertRaises(identity.SignerError):
                identity.SocketSigner(path, ed25519.public_key(ROOT)).sign("device", body)
            # (no signer there: an error the site answers 503 for, not a crash)
            with self.assertRaises(identity.SignerError):
                identity.SocketSigner(str(Path(folder, "none.sock")), signer.public).sign("device", body)


AUDIENCE = "127.0.0.1"


if __name__ == "__main__":
    unittest.main()
