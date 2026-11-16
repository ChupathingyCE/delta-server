"""Ed25519 signature verification, and the X25519 form of an Ed25519 key, in
pure Python (standard library only): enough to check OpenCE's public game
listings (lobby.py), with no signing.

Derived from the reference code of RFC 8032 (Edwards-Curve Digital Signature
Algorithm), section 6, and RFC 7748's X25519, changed to accept exactly what
the game accepts (Monocypher 4's crypto_ed25519_check, and OpenCE's
p2p_ed25519_verify, port/linux/src/p2p_crypto.c):

- A and R are decoded without requiring y < p (y is taken mod p), and a
  point whose x is 0 may have its sign bit set;
- S must be below the group's order L;
- the check is [8]([S]B - [h]A - R) == the identity (cofactored), with
  h = SHA-512(R || A || message) mod L;
- a key of small order (whose X25519 form X25519(2^254, u) is 0) has no valid
  signature.

Speed: about 3 ms a signature on one core (test_lobby.py measures it);
lobby.py caps how many it checks each second.

The RFC's code carries this notice:

    Copyright (c) 2017 IETF Trust and the persons identified as authors of
    the code (S. Josefsson, I. Liusvaara). All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, is permitted pursuant to, and subject to the license terms
    contained in, the Simplified BSD License set forth in Section 4.c of the
    IETF Trust's Legal Provisions Relating to IETF Documents
    (https://trustee.ietf.org/license-info).

    The Simplified BSD License: Redistribution and use in source and binary
    forms, with or without modification, are permitted provided that the
    following conditions are met: (1) Redistributions of source code must
    retain the above copyright notice, this list of conditions and the
    following disclaimer. (2) Redistributions in binary form must reproduce
    the above copyright notice, this list of conditions and the following
    disclaimer in the documentation and/or other materials provided with the
    distribution. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
    CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT
    NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
    PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
    CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
    EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
    PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
    PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

SPDX-FileCopyrightText: 2017 IETF Trust and the persons identified as authors of the code (S. Josefsson, I. Liusvaara)
SPDX-FileCopyrightText: 2026 The Chupathingy contributors
SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: MIT AND BSD-2-Clause
"""

import hashlib

# the base field, the curve's constant, the group's order
p = 2 ** 255 - 19
d = -121665 * pow(121666, p - 2, p) % p
L = 2 ** 252 + 27742317777372353535851937790883648493
SQRT_M1 = pow(2, (p - 1) // 4, p)

# points in extended coordinates (X, Y, Z, T): x = X/Z, y = Y/Z, x*y = T/Z
IDENTITY = (0, 1, 1, 0)


def point_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % p, G * H % p, F * G % p, E * H % p)


def point_double(P):
    A = P[0] * P[0] % p
    B = P[1] * P[1] % p
    C = 2 * P[2] * P[2] % p
    H = A + B
    E = H - (P[0] + P[1]) * (P[0] + P[1])
    G = A - B
    F = C + G
    return (E * F % p, G * H % p, F * G % p, E * H % p)


def point_negate(P):
    return (-P[0] % p, P[1], P[2], -P[3] % p)


def is_identity(P):
    return P[0] % p == 0 and (P[1] - P[2]) % p == 0


def recover_x(y: int, sign: int):
    """x of a point with this y (any integer, taken mod p) and sign: None
    if there is none (Monocypher keeps x = 0 whatever the sign)"""
    y %= p
    x2 = (y * y - 1) * pow(d * y * y + 1, p - 2, p) % p
    if x2 == 0:
        return 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * SQRT_M1 % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


def decode_point(s: bytes):
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = recover_x(y, sign)
    if x is None:
        return None
    y %= p
    return (x, y, 1, x * y % p)


B = (lambda y: (recover_x(y, 0), y, 1, recover_x(y, 0) * y % p))(4 * pow(5, p - 2, p) % p)


def double_scalar_mul(a: int, P, b: int, Q):
    """[a]P + [b]Q (Straus: one chain of doublings)"""
    PQ = point_add(P, Q)
    R = IDENTITY
    for bit in range(max(a.bit_length(), b.bit_length()) - 1, -1, -1):
        R = point_double(R)
        pick = (a >> bit & 1) | (b >> bit & 1) << 1
        if pick == 1:
            R = point_add(R, P)
        elif pick == 2:
            R = point_add(R, Q)
        elif pick == 3:
            R = point_add(R, PQ)
    return R


def x25519(scalar: bytes, u_bytes: bytes) -> bytes:
    """RFC 7748's X25519 (the scalar clamped, u's top bit ignored)"""
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    x1 = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    a24 = 121665
    for t in range(254, -1, -1):
        bit = k >> t & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        A = (x2 + z2) % p
        AA = A * A % p
        Bv = (x2 - z2) % p
        BB = Bv * Bv % p
        E = (AA - BB) % p
        C = (x3 + z3) % p
        D = (x3 - z3) % p
        DA = D * A % p
        CB = C * Bv % p
        x3 = (DA + CB) * (DA + CB) % p
        z3 = x1 * (DA - CB) * (DA - CB) % p
        x2 = AA * BB % p
        z2 = E * (AA + a24 * E) % p
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


def to_x25519(public_key: bytes):
    """the X25519 public key of an Ed25519 one, u = (1 + y) / (1 - y)
    (Monocypher's crypto_eddsa_to_x25519): None if the key has a small order
    (OpenCE's p2p_ed25519_to_x25519)"""
    if len(public_key) != 32:
        return None
    y = (int.from_bytes(public_key, "little") & ((1 << 255) - 1)) % p
    u = (1 + y) * pow((1 - y) % p, p - 2, p) % p
    u_bytes = u.to_bytes(32, "little")
    if x25519(b"\x01" + bytes(31), u_bytes) == bytes(32):
        return None
    return u_bytes


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """whether the signature is the key's, of the message, as the game
    decides (p2p_ed25519_verify)"""
    if len(public_key) != 32 or len(signature) != 64 or to_x25519(public_key) is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    A = decode_point(public_key)
    R = decode_point(signature[:32])
    if A is None or R is None:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % L
    check = point_add(double_scalar_mul(s, B, h, point_negate(A)), point_negate(R))
    for _ in range(3):
        check = point_double(check)
    return is_identity(check)


# ---------- keys and signing (RFC 8032, section 5.1.5 and 5.1.6)
#
# The site never signs anything of its own: these make the public key of a
# moderator's seed (control.py: the key the game derives from its player
# key), and sign for the tests and the reference client (control_client.py).


def scalar_mul(k: int, P):
    """[k]P"""
    R = IDENTITY
    while k:
        if k & 1:
            R = point_add(R, P)
        P = point_double(P)
        k >>= 1
    return R


def encode_point(P) -> bytes:
    z = pow(P[2], p - 2, p)
    x = P[0] * z % p
    y = P[1] * z % p
    return (y | (x & 1) << 255).to_bytes(32, "little")


def _expand(seed: bytes):
    if len(seed) != 32:
        raise ValueError("an Ed25519 seed is 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    """the public key of a 32-byte seed (RFC 8032's secret key)"""
    a, _ = _expand(seed)
    return encode_point(scalar_mul(a, B))


def sign(seed: bytes, message: bytes) -> bytes:
    """the seed's signature of the message (for tests and the reference
    client: the site never signs)"""
    a, prefix = _expand(seed)
    A = encode_point(scalar_mul(a, B))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    R = encode_point(scalar_mul(r, B))
    h = int.from_bytes(hashlib.sha512(R + A + message).digest(), "little") % L
    s = (r + h * a) % L
    return R + s.to_bytes(32, "little")
