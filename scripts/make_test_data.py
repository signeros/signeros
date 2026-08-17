#!/usr/bin/env python3
"""SignerOS test fixtures: build an unsigned PSBT, and verify what came back.

Why this file is 100% standard library and reimplements the crypto by hand:

    The QEMU harness has to answer "did the signer produce a *correct*
    signature", and it must answer it without asking libwally-core - the very
    library under test - to confirm its own work.  So this script derives the
    expected keys with its own BIP32/BIP39, computes its own BIP143 sighash and
    verifies the ECDSA signature with its own secp256k1 arithmetic.  Two
    independent implementations agreeing is evidence; one implementation
    agreeing with itself is not.

    It also means the harness runs on any machine with python3 and no packages
    to install, on an air-gapped build host included.

The implementations here are correct but deliberately unoptimised, and
`--self-check` proves them against published test vectors (BIP32 vector 1,
the BIP84 reference wallet, RIPEMD-160 and bech32) before they are trusted.

    python3 scripts/make_test_data.py generate --out-dir DIR [--network testnet]
    python3 scripts/make_test_data.py verify --dir DIR
    python3 scripts/make_test_data.py self-check
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import struct
import sys

# ===========================================================================
# RIPEMD-160
#
# Not optional: OpenSSL 3 moved ripemd160 to the legacy provider, so
# hashlib.new("ripemd160") raises on most current distributions - and every
# Bitcoin address needs it.
# ===========================================================================

_RMD_R = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]
_RMD_RP = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]
_RMD_S = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]
_RMD_SP = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]
_RMD_K = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_RMD_KP = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]


def _rol(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _rmd_f(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & 0xFFFFFFFF & z)
    if j < 48:
        return (x | (~y & 0xFFFFFFFF)) ^ z
    if j < 64:
        return (x & z) | (y & (~z & 0xFFFFFFFF))
    return x ^ (y | (~z & 0xFFFFFFFF))


def ripemd160(data: bytes) -> bytes:
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

    msg = bytearray(data)
    bitlen = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += struct.pack("<Q", bitlen)

    for off in range(0, len(msg), 64):
        x = list(struct.unpack("<16I", msg[off:off + 64]))
        a, b, c, d, e = h
        ap, bp, cp, dp, ep = h
        for j in range(80):
            rnd = j // 16
            t = _rol(a + _rmd_f(j, b, c, d) + x[_RMD_R[j]] + _RMD_K[rnd], _RMD_S[j])
            t = (t + e) & 0xFFFFFFFF
            a, e, d, c, b = e, d, _rol(c, 10), b, t

            t = _rol(ap + _rmd_f(79 - j, bp, cp, dp) + x[_RMD_RP[j]] + _RMD_KP[rnd],
                     _RMD_SP[j])
            t = (t + ep) & 0xFFFFFFFF
            ap, ep, dp, cp, bp = ep, dp, _rol(cp, 10), bp, t

        t = (h[1] + c + dp) & 0xFFFFFFFF
        h[1] = (h[2] + d + ep) & 0xFFFFFFFF
        h[2] = (h[3] + e + ap) & 0xFFFFFFFF
        h[3] = (h[4] + a + bp) & 0xFFFFFFFF
        h[4] = (h[0] + b + cp) & 0xFFFFFFFF
        h[0] = t

    return b"".join(struct.pack("<I", v) for v in h)


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def dsha256(b: bytes) -> bytes:
    return sha256(sha256(b))


def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))


# ===========================================================================
# secp256k1
# ===========================================================================

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

Point = tuple  # (x, y) in affine coordinates, or None for infinity


def pt_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def pt_mul(k: int, p=(GX, GY)):
    k %= N
    result = None
    addend = p
    while k:
        if k & 1:
            result = pt_add(result, addend)
        addend = pt_add(addend, addend)
        k >>= 1
    return result


def compress(p) -> bytes:
    x, y = p
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def decompress(b: bytes):
    if len(b) != 33 or b[0] not in (2, 3):
        raise ValueError("not a compressed pubkey")
    x = int.from_bytes(b[1:], "big")
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        raise ValueError("point not on curve")
    if (y & 1) != (b[0] & 1):
        y = P - y
    return (x, y)


def ecdsa_verify(pubkey: bytes, msg32: bytes, sig64: bytes) -> bool:
    """Textbook ECDSA verification, plus the low-S rule Bitcoin requires."""
    r = int.from_bytes(sig64[:32], "big")
    s = int.from_bytes(sig64[32:], "big")
    if not (1 <= r < N and 1 <= s < N):
        return False
    if s > N // 2:                      # BIP62 low-S
        return False
    z = int.from_bytes(msg32, "big")
    w = pow(s, N - 2, N)
    u1 = z * w % N
    u2 = r * w % N
    pt = pt_add(pt_mul(u1), pt_mul(u2, decompress(pubkey)))
    if pt is None:
        return False
    return pt[0] % N == r


def ecdsa_sign(priv: bytes, msg32: bytes) -> bytes:
    """RFC6979 deterministic ECDSA, so this script and libwally must agree
    byte-for-byte on the signature for the same key and message."""
    x = int.from_bytes(priv, "big")
    z = int.from_bytes(msg32, "big")

    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + priv + msg32, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + priv + msg32, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        nonce = int.from_bytes(v, "big")
        if 1 <= nonce < N:
            pt = pt_mul(nonce)
            r = pt[0] % N
            if r != 0:
                s = pow(nonce, N - 2, N) * (z + r * int.from_bytes(priv, "big")) % N
                if s != 0:
                    if s > N // 2:
                        s = N - s
                    return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def der_to_sig64(der: bytes) -> bytes:
    """Minimal DER decoder for an ECDSA signature, tolerant of the leading
    zero padding Bitcoin signatures carry, strict about everything else."""
    if len(der) < 8 or der[0] != 0x30:
        raise ValueError("not a DER sequence")
    if der[1] != len(der) - 2:
        raise ValueError("bad DER length")
    if der[2] != 0x02:
        raise ValueError("bad DER r marker")
    rlen = der[3]
    r = int.from_bytes(der[4:4 + rlen], "big")
    off = 4 + rlen
    if der[off] != 0x02:
        raise ValueError("bad DER s marker")
    slen = der[off + 1]
    s = int.from_bytes(der[off + 2:off + 2 + slen], "big")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# ===========================================================================
# base58, bech32
# ===========================================================================

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check_encode(payload: bytes) -> str:
    data = payload + dsha256(payload)[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58[rem] + out
    for b in data:
        if b != 0:
            break
        out = "1" + out
    return out


_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    data = [witver] + _convertbits(witprog, 8, 5)
    const = 0x2BC830A3 if witver > 0 else 1
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data + checksum)


# ===========================================================================
# BIP39 / BIP32
# ===========================================================================

VERSION_PRIV = {"mainnet": 0x0488ADE4, "testnet": 0x04358394}
VERSION_PUB = {"mainnet": 0x0488B21E, "testnet": 0x043587CF}
HRP = {"mainnet": "bc", "testnet": "tb", "signet": "tb", "regtest": "bcrt"}
COIN_TYPE = {"mainnet": 0, "testnet": 1, "signet": 1, "regtest": 1}


def bip39_seed(mnemonic: str, passphrase: str = "") -> bytes:
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"),
                               ("mnemonic" + passphrase).encode("utf-8"), 2048)


class HDKey:
    __slots__ = ("priv", "chain", "depth", "parent_fp", "child_num", "net")

    def __init__(self, priv: bytes, chain: bytes, depth=0, parent_fp=b"\x00" * 4,
                 child_num=0, net="mainnet"):
        self.priv = priv
        self.chain = chain
        self.depth = depth
        self.parent_fp = parent_fp
        self.child_num = child_num
        self.net = net

    @classmethod
    def from_seed(cls, seed: bytes, net="mainnet") -> "HDKey":
        h = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        return cls(h[:32], h[32:], net=net)

    @property
    def pub(self) -> bytes:
        return compress(pt_mul(int.from_bytes(self.priv, "big")))

    @property
    def fingerprint(self) -> bytes:
        return hash160(self.pub)[:4]

    def derive(self, index: int) -> "HDKey":
        hardened = bool(index & 0x80000000)
        if hardened:
            data = b"\x00" + self.priv + struct.pack(">I", index)
        else:
            data = self.pub + struct.pack(">I", index)
        h = hmac.new(self.chain, data, hashlib.sha512).digest()
        child = (int.from_bytes(h[:32], "big") +
                 int.from_bytes(self.priv, "big")) % N
        if child == 0 or int.from_bytes(h[:32], "big") >= N:
            raise ValueError("derivation produced an invalid key; use the next index")
        return HDKey(child.to_bytes(32, "big"), h[32:], self.depth + 1,
                     self.fingerprint, index, self.net)

    def derive_path(self, path: str) -> "HDKey":
        key = self
        for part in path.split("/"):
            if part in ("m", ""):
                continue
            if part.endswith("'") or part.endswith("h"):
                key = key.derive(int(part[:-1]) | 0x80000000)
            else:
                key = key.derive(int(part))
        return key

    def xprv(self) -> str:
        return b58check_encode(
            struct.pack(">IB4sI", VERSION_PRIV[self.net], self.depth,
                        self.parent_fp, self.child_num) +
            self.chain + b"\x00" + self.priv)

    def xpub(self) -> str:
        """The account-level extended PUBLIC key a watch-only wallet imports.

        Same 78-byte serialisation as xprv() with the public version bytes and
        the compressed point in place of 0x00||priv. This is what the wallet
        creation feature writes to the data partition, so it is worth having a
        second implementation of: an xpub that is subtly wrong sends the owner's
        coins to addresses their seed does not control, and nothing about the
        mistake is visible until the money is gone.
        """
        return b58check_encode(
            struct.pack(">IB4sI", VERSION_PUB[self.net], self.depth,
                        self.parent_fp, self.child_num) +
            self.chain + self.pub)

    def wif(self) -> str:
        prefix = b"\x80" if self.net == "mainnet" else b"\xef"
        return b58check_encode(prefix + self.priv + b"\x01")


def path_to_ints(path: str):
    out = []
    for part in path.split("/"):
        if part in ("m", ""):
            continue
        if part.endswith("'") or part.endswith("h"):
            out.append(int(part[:-1]) | 0x80000000)
        else:
            out.append(int(part))
    return out


# ===========================================================================
# Transaction / PSBT serialisation
# ===========================================================================

def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def varbytes(b: bytes) -> bytes:
    return varint(len(b)) + b


def p2wpkh_script(pubkey: bytes) -> bytes:
    return b"\x00\x14" + hash160(pubkey)


def p2wpkh_address(pubkey: bytes, net: str) -> str:
    return bech32_encode(HRP[net], 0, hash160(pubkey))


# --- the other three address types the wallet export covers -----------------
#
# Only the wallet-creation feature needs these: the PSBT fixture is BIP84
# throughout. They exist so that every xpub and first address SignerOS writes
# into a watch-only export can be re-derived here, by code that shares nothing
# with libwally-core.

B58_P2PKH_VERSION = {"mainnet": 0x00, "testnet": 0x6F, "signet": 0x6F, "regtest": 0x6F}
B58_P2SH_VERSION = {"mainnet": 0x05, "testnet": 0xC4, "signet": 0xC4, "regtest": 0xC4}


def p2pkh_address(pubkey: bytes, net: str) -> str:
    return b58check_encode(bytes([B58_P2PKH_VERSION[net]]) + hash160(pubkey))


def p2sh_p2wpkh_address(pubkey: bytes, net: str) -> str:
    """BIP49: the P2WPKH program is the redeem script of an ordinary P2SH."""
    redeem = p2wpkh_script(pubkey)
    return b58check_encode(bytes([B58_P2SH_VERSION[net]]) + hash160(redeem))


def tagged_hash(tag: str, msg: bytes) -> bytes:
    t = sha256(tag.encode())
    return sha256(t + t + msg)


def p2tr_address(pubkey: bytes, net: str) -> str:
    """BIP86: a key-path-only taproot output.

    The output key is not the derived key. It is that key tweaked by
    t = H_TapTweak(x(P)) with no script tree, which is the step a signer that
    treated taproot like segwit v0 would silently get wrong.
    """
    x_only = pubkey[1:]
    # lift_x: the BIP340 point with this x coordinate and an even y.
    point = decompress(b"\x02" + x_only)
    t = int.from_bytes(tagged_hash("TapTweak", x_only), "big")
    if t >= N:
        raise ValueError("taproot tweak out of range")
    output_point = pt_add(point, pt_mul(t))
    return bech32_encode(HRP[net], 1, compress(output_point)[1:])


class TxOut:
    def __init__(self, value: int, script: bytes):
        self.value = value
        self.script = script

    def serialize(self) -> bytes:
        return struct.pack("<Q", self.value) + varbytes(self.script)


class TxIn:
    def __init__(self, txid_le: bytes, vout: int, sequence=0xFFFFFFFD):
        self.txid_le = txid_le          # internal byte order
        self.vout = vout
        self.sequence = sequence

    def outpoint(self) -> bytes:
        return self.txid_le + struct.pack("<I", self.vout)

    def serialize(self) -> bytes:
        return self.outpoint() + varbytes(b"") + struct.pack("<I", self.sequence)


class Tx:
    def __init__(self, version=2, locktime=0):
        self.version = version
        self.locktime = locktime
        self.vin: list[TxIn] = []
        self.vout: list[TxOut] = []

    def serialize(self) -> bytes:
        out = struct.pack("<I", self.version)
        out += varint(len(self.vin)) + b"".join(i.serialize() for i in self.vin)
        out += varint(len(self.vout)) + b"".join(o.serialize() for o in self.vout)
        out += struct.pack("<I", self.locktime)
        return out

    def txid(self) -> str:
        return dsha256(self.serialize())[::-1].hex()

    def bip143_sighash(self, index: int, script_code: bytes, amount: int,
                       sighash_type=0x01) -> bytes:
        """BIP143 signature hash, for a segwit v0 input."""
        hash_prevouts = dsha256(b"".join(i.outpoint() for i in self.vin))
        hash_sequence = dsha256(b"".join(struct.pack("<I", i.sequence)
                                         for i in self.vin))
        hash_outputs = dsha256(b"".join(o.serialize() for o in self.vout))

        vin = self.vin[index]
        pre = struct.pack("<I", self.version)
        pre += hash_prevouts + hash_sequence
        pre += vin.outpoint()
        pre += varbytes(script_code)
        pre += struct.pack("<Q", amount)
        pre += struct.pack("<I", vin.sequence)
        pre += hash_outputs
        pre += struct.pack("<I", self.locktime)
        pre += struct.pack("<I", sighash_type)
        return dsha256(pre)


# PSBT key types we need (BIP174).
PSBT_GLOBAL_UNSIGNED_TX = 0x00
PSBT_IN_NON_WITNESS_UTXO = 0x00
PSBT_IN_WITNESS_UTXO = 0x01
PSBT_IN_PARTIAL_SIG = 0x02
PSBT_IN_SIGHASH_TYPE = 0x03
PSBT_IN_BIP32_DERIVATION = 0x06
PSBT_OUT_BIP32_DERIVATION = 0x02


def kv(key: bytes, value: bytes) -> bytes:
    return varbytes(key) + varbytes(value)


def keypath_value(fingerprint: bytes, path: str) -> bytes:
    return fingerprint + b"".join(struct.pack("<I", e) for e in path_to_ints(path))


def build_psbt(tx: Tx, inputs_meta, outputs_meta) -> bytes:
    """inputs_meta:  list of dicts {witness_utxo: TxOut, pubkey, fingerprint, path}
       outputs_meta: list of dicts {} or {pubkey, fingerprint, path} for change"""
    out = b"psbt\xff"
    out += kv(bytes([PSBT_GLOBAL_UNSIGNED_TX]), tx.serialize())
    out += b"\x00"                                        # end of globals

    for meta in inputs_meta:
        body = b""
        utxo: TxOut = meta["witness_utxo"]
        body += kv(bytes([PSBT_IN_WITNESS_UTXO]), utxo.serialize())
        body += kv(bytes([PSBT_IN_SIGHASH_TYPE]), struct.pack("<I", 0x01))
        body += kv(bytes([PSBT_IN_BIP32_DERIVATION]) + meta["pubkey"],
                   keypath_value(meta["fingerprint"], meta["path"]))
        out += body + b"\x00"

    for meta in outputs_meta:
        body = b""
        if meta.get("pubkey"):
            body += kv(bytes([PSBT_OUT_BIP32_DERIVATION]) + meta["pubkey"],
                       keypath_value(meta["fingerprint"], meta["path"]))
        out += body + b"\x00"

    return out


# ===========================================================================
# PSBT reader (only as much as verification needs)
# ===========================================================================

class Reader:
    def __init__(self, data: bytes):
        self.d = data
        self.i = 0

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.d):
            raise ValueError("truncated PSBT")
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def varint(self) -> int:
        b = self.take(1)[0]
        if b < 0xFD:
            return b
        if b == 0xFD:
            return struct.unpack("<H", self.take(2))[0]
        if b == 0xFE:
            return struct.unpack("<I", self.take(4))[0]
        return struct.unpack("<Q", self.take(8))[0]

    def varbytes(self) -> bytes:
        return self.take(self.varint())

    def eof(self) -> bool:
        return self.i >= len(self.d)


def parse_psbt(data: bytes):
    """Returns (globals_map, [input_map, ...], [output_map, ...]) where each map
    is {key_bytes: value_bytes}."""
    if data[:5] != b"psbt\xff":
        # Maybe base64.
        import base64
        text = "".join(data.decode("ascii", "ignore").split())
        data = base64.b64decode(text)
        if data[:5] != b"psbt\xff":
            raise ValueError("not a PSBT")

    r = Reader(data)
    r.take(5)

    def read_map():
        m = {}
        while True:
            klen = r.varint()
            if klen == 0:
                return m
            key = r.take(klen)
            m[key] = r.varbytes()

    g = read_map()
    unsigned = g.get(bytes([PSBT_GLOBAL_UNSIGNED_TX]))
    if unsigned is None:
        raise ValueError("no global unsigned transaction (PSBTv2 is not parsed here)")

    n_in, n_out = count_tx_io(unsigned)
    ins = [read_map() for _ in range(n_in)]
    outs = [read_map() for _ in range(n_out)]
    return g, ins, outs, unsigned


def count_tx_io(raw_tx: bytes):
    r = Reader(raw_tx)
    r.take(4)
    n_in = r.varint()
    for _ in range(n_in):
        r.take(36)
        r.varbytes()
        r.take(4)
    n_out = r.varint()
    for _ in range(n_out):
        r.take(8)
        r.varbytes()
    return n_in, n_out


def parse_tx(raw: bytes) -> Tx:
    r = Reader(raw)
    tx = Tx(version=struct.unpack("<I", r.take(4))[0])
    n_in = r.varint()
    for _ in range(n_in):
        txid_le = r.take(32)
        vout = struct.unpack("<I", r.take(4))[0]
        r.varbytes()
        seq = struct.unpack("<I", r.take(4))[0]
        tx.vin.append(TxIn(txid_le, vout, seq))
    n_out = r.varint()
    for _ in range(n_out):
        value = struct.unpack("<Q", r.take(8))[0]
        tx.vout.append(TxOut(value, r.varbytes()))
    tx.locktime = struct.unpack("<I", r.take(4))[0]
    return tx


def parse_txout(raw: bytes) -> TxOut:
    r = Reader(raw)
    value = struct.unpack("<Q", r.take(8))[0]
    return TxOut(value, r.varbytes())


# ===========================================================================
# Fixture generation
# ===========================================================================

# The BIP39 reference mnemonic. Using a published, deliberately worthless test
# wallet means the fixture can be committed and shared without anyone having to
# wonder whether real funds are involved.
TEST_MNEMONIC = ("abandon abandon abandon abandon abandon abandon "
                 "abandon abandon abandon abandon abandon about")


def generate(out_dir: str, network: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)

    net_keys = "mainnet" if network == "mainnet" else "testnet"
    coin = COIN_TYPE[network]

    seed = bip39_seed(TEST_MNEMONIC)
    master = HDKey.from_seed(seed, net=net_keys)
    fp = master.fingerprint

    # BIP84 account 0. Two inputs from the first two receiving addresses, so the
    # fixture exercises multi-input signing and the fee arithmetic over several
    # UTXOs rather than the trivial one-in case.
    in_paths = [f"m/84'/{coin}'/0'/0/0", f"m/84'/{coin}'/0'/0/1"]
    in_keys = [master.derive_path(p) for p in in_paths]
    in_values = [150_000, 90_000]

    change_path = f"m/84'/{coin}'/0'/1/0"
    change_key = master.derive_path(change_path)

    # A destination that is deliberately NOT ours, so the signer has something
    # real to label "payment to someone else".
    dest_key = HDKey.from_seed(b"signeros-destination-not-our-wallet", net=net_keys)
    dest_script = p2wpkh_script(dest_key.pub)

    tx = Tx(version=2, locktime=0)
    # Fabricated but well-formed outpoints. The signer never looks them up - it
    # has no network - it only reports and commits to them.
    for i in range(len(in_keys)):
        fake_txid = dsha256(f"signeros-fixture-input-{i}".encode())
        tx.vin.append(TxIn(fake_txid, i, sequence=0xFFFFFFFD))

    send_value = 200_000
    change_value = 38_000            # fee = 240000 - 238000 = 2000 sat
    tx.vout.append(TxOut(send_value, dest_script))
    tx.vout.append(TxOut(change_value, p2wpkh_script(change_key.pub)))

    inputs_meta = []
    for key, value, path in zip(in_keys, in_values, in_paths):
        inputs_meta.append({
            "witness_utxo": TxOut(value, p2wpkh_script(key.pub)),
            "pubkey": key.pub,
            "fingerprint": fp,
            "path": path,
        })

    outputs_meta = [
        {},
        {"pubkey": change_key.pub, "fingerprint": fp, "path": change_path},
    ]

    psbt = build_psbt(tx, inputs_meta, outputs_meta)

    psbt_path = os.path.join(out_dir, "test_unsigned.psbt")
    with open(psbt_path, "wb") as f:
        f.write(psbt)

    # ----------------------------------------------------------------------
    # The negative fixture: a forged change label.
    #
    # Identical to the transaction above except that the "change" output pays
    # an address nobody here controls, while still carrying our master
    # fingerprint, our change derivation path and our change pubkey in
    # PSBT_OUT_BIP32_DERIVATION. A signer that decides what is change by
    # comparing fingerprints - the obvious implementation - shows this as
    # "0.00038 BTC coming back to you" and the operator authorises the loss
    # themselves. SignerOS must derive the key and rebuild the scriptPubKey,
    # find that it does not match, and refuse.
    #
    # The name deliberately does not end in .psbt: this file must never be
    # offered as something to sign, only handed to --expect-blocked.
    thief_key = HDKey.from_seed(b"signeros-change-forgery-attacker", net=net_keys)

    attack_tx = Tx(version=2, locktime=0)
    attack_tx.vin = list(tx.vin)
    attack_tx.vout.append(TxOut(send_value, dest_script))
    attack_tx.vout.append(TxOut(change_value, p2wpkh_script(thief_key.pub)))

    attack_psbt = build_psbt(attack_tx, inputs_meta, outputs_meta)
    attack_path = os.path.join(out_dir, "forged_change.psbt.bad")
    with open(attack_path, "wb") as f:
        f.write(attack_psbt)

    mnemonic_path = os.path.join(out_dir, "test_mnemonic.txt")
    with open(mnemonic_path, "w") as f:
        f.write(TEST_MNEMONIC + "\n")

    fee = sum(in_values) - (send_value + change_value)
    expected = {
        "network": network,
        "mnemonic": TEST_MNEMONIC,
        "master_fingerprint": fp.hex(),
        "txid_unsigned": tx.txid(),
        "inputs": [
            {"path": p, "pubkey": k.pub.hex(), "value": v,
             "address": p2wpkh_address(k.pub, network)}
            for p, k, v in zip(in_paths, in_keys, in_values)
        ],
        "outputs": [
            {"value": send_value, "address": p2wpkh_address(dest_key.pub, network),
             "mine": False},
            {"value": change_value, "address": p2wpkh_address(change_key.pub, network),
             "mine": True, "path": change_path},
        ],
        "total_in": sum(in_values),
        "total_out": send_value + change_value,
        "fee": fee,
        "psbt_file": os.path.basename(psbt_path),
        "mnemonic_file": os.path.basename(mnemonic_path),
        # Must be refused: same fingerprint and path, an address that is not ours.
        "forged_change_file": os.path.basename(attack_path),
        "forged_change_address": p2wpkh_address(thief_key.pub, network),
        "unsigned_psbt_hex": psbt.hex(),
    }

    with open(os.path.join(out_dir, "expected.json"), "w") as f:
        json.dump(expected, f, indent=2)
        f.write("\n")

    return expected


# ===========================================================================
# Verification of what the signer produced
# ===========================================================================

def verify(out_dir: str, signed_path: str | None = None) -> int:
    with open(os.path.join(out_dir, "expected.json")) as f:
        expected = json.load(f)

    if signed_path is None:
        candidates = sorted(f for f in os.listdir(out_dir)
                            if f.startswith("signed_") and f.endswith(".psbt"))
        if not candidates:
            print("VERIFY: FAIL no signed_*.psbt in %s" % out_dir)
            return 1
        signed_path = os.path.join(out_dir, candidates[-1])

    print("VERIFY: file=%s" % os.path.basename(signed_path))

    with open(signed_path, "rb") as f:
        signed_raw = f.read()

    try:
        _, ins, _outs, unsigned = parse_psbt(signed_raw)
    except Exception as exc:                                  # noqa: BLE001
        print("VERIFY: FAIL cannot parse the signed PSBT: %s" % exc)
        return 1

    tx = parse_tx(unsigned)

    if tx.txid() != expected["txid_unsigned"]:
        print("VERIFY: FAIL the signed PSBT describes a different transaction "
              "(%s, expected %s)" % (tx.txid(), expected["txid_unsigned"]))
        return 1
    print("VERIFY: txid=%s matches the unsigned fixture" % tx.txid())

    if len(ins) != len(expected["inputs"]):
        print("VERIFY: FAIL expected %d inputs, found %d"
              % (len(expected["inputs"]), len(ins)))
        return 1

    failures = 0
    checked = 0

    for idx, (in_map, exp_in) in enumerate(zip(ins, expected["inputs"])):
        want_pub = bytes.fromhex(exp_in["pubkey"])

        sig = None
        for key, value in in_map.items():
            if key[0] == PSBT_IN_PARTIAL_SIG and key[1:] == want_pub:
                sig = value
                break

        if sig is None:
            print("VERIFY: FAIL input %d carries no signature for pubkey %s"
                  % (idx, exp_in["pubkey"]))
            failures += 1
            continue

        sighash_byte = sig[-1]
        if sighash_byte != 0x01:
            print("VERIFY: FAIL input %d signature has sighash 0x%02x, expected "
                  "SIGHASH_ALL" % (idx, sighash_byte))
            failures += 1
            continue

        try:
            sig64 = der_to_sig64(sig[:-1])
        except Exception as exc:                              # noqa: BLE001
            print("VERIFY: FAIL input %d signature is not valid DER: %s" % (idx, exc))
            failures += 1
            continue

        # BIP143 scriptCode for p2wpkh is the equivalent p2pkh script.
        script_code = (b"\x76\xa9\x14" + hash160(want_pub) + b"\x88\xac")
        digest = tx.bip143_sighash(idx, script_code, exp_in["value"], 0x01)

        if not ecdsa_verify(want_pub, digest, sig64):
            print("VERIFY: FAIL input %d signature does not verify against the "
                  "BIP143 sighash we computed independently" % idx)
            failures += 1
            continue

        # RFC6979 makes the correct signature unique, so this also proves the
        # signer used deterministic nonces. A mismatch here with a *valid*
        # signature above would mean a random k - not fatal, but worth knowing.
        priv_key = HDKey.from_seed(bip39_seed(expected["mnemonic"]),
                                   net="mainnet" if expected["network"] == "mainnet"
                                   else "testnet").derive_path(exp_in["path"])
        ours = ecdsa_sign(priv_key.priv, digest)
        note = "identical" if ours == sig64 else "different (non-deterministic k?)"

        print("VERIFY: input %d signature VALID for %s (path %s), RFC6979 %s"
              % (idx, exp_in["address"], exp_in["path"], note))
        checked += 1

    if failures:
        print("VERIFY: FAIL %d of %d inputs failed" % (failures, len(ins)))
        return 1

    print("VERIFY: PASS %d/%d input signatures independently verified"
          % (checked, len(ins)))
    return 0


# ===========================================================================
# Self-check against published test vectors
# ===========================================================================

# ===========================================================================
# Watch-only export expectations
#
# The signer's --self-test derives the same four account keys from the same
# fixture mnemonic and prints them; scripts/host_selftest.sh diffs the two
# lists. That is the whole point of this file existing: libwally-core must not
# be the thing that confirms libwally-core, least of all for the one artefact
# that decides which wallet the owner's future coins land in.
# ===========================================================================

# Order and spelling match kStandards in src/core/wallet_export.cpp.
EXPORT_STANDARDS = [
    (84, "BIP84", p2wpkh_address),
    (86, "BIP86", p2tr_address),
    (49, "BIP49", p2sh_p2wpkh_address),
    (44, "BIP44", p2pkh_address),
]

# Order and spelling match kCosignerStandards in src/core/wallet_export.cpp.
# No address column: a multisig cosigner key has no address of its own, which
# is why these are a separate section rather than four more EXPORT_STANDARDS.
MULTISIG_STANDARDS = [
    (2, "BIP48/2h"),
    (1, "BIP48/1h"),
]


def wallet_expect(network: str, mnemonic: str = None, passphrase: str = "",
                  account_index: int = 0, section: str = "accounts") -> int:
    net_keys = "mainnet" if network == "mainnet" else "testnet"
    coin = COIN_TYPE[network]
    master = HDKey.from_seed(bip39_seed(mnemonic or TEST_MNEMONIC, passphrase),
                             net=net_keys)

    # The fingerprint is line 1 of either section, so a caller diffing one of
    # them drops the same single line whichever it asked for.
    print("fingerprint %s" % master.fingerprint.hex())

    if section == "cosigners":
        for script_type, name in MULTISIG_STANDARDS:
            path = "m/48'/%d'/%d'/%d'" % (coin, account_index, script_type)
            print("%s %s %s" % (name, path, master.derive_path(path).xpub()))
        return 0

    for purpose, name, address_of in EXPORT_STANDARDS:
        path = "m/%d'/%d'/%d'" % (purpose, coin, account_index)
        acct = master.derive_path(path)
        first = acct.derive_path("0/0")
        print("%s %s %s %s"
              % (name, path, acct.xpub(), address_of(first.pub, network)))
    return 0


def self_check() -> int:
    failures = []

    def check(name, got, want):
        if got != want:
            failures.append("%s\n     got:  %s\n     want: %s" % (name, got, want))
            print("  FAIL  %s" % name)
        else:
            print("  ok    %s" % name)

    print("self-check: primitives")
    check("RIPEMD-160 of empty string",
          ripemd160(b"").hex(), "9c1185a5c5e9fc54612808977ee8f548b2258d31")
    check("RIPEMD-160 of 'abc'",
          ripemd160(b"abc").hex(), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
    check("RIPEMD-160 of 'message digest'",
          ripemd160(b"message digest").hex(),
          "5d0689ef49d2fae572b881b123a85ffa21595f36")

    print("self-check: secp256k1")
    check("generator times 1 is G",
          compress(pt_mul(1)).hex(),
          "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    check("generator times 2",
          compress(pt_mul(2)).hex(),
          "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")

    print("self-check: BIP32 test vector 1")
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    m = HDKey.from_seed(seed)
    check("m xprv", m.xprv(),
          "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNK"
          "mPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
    check("m/0' xprv", m.derive_path("m/0'").xprv(),
          "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5h"
          "j6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
    check("m/0'/1 xprv", m.derive_path("m/0'/1").xprv(),
          "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1U"
          "mYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs")

    print("self-check: BIP84 reference wallet")
    b84 = HDKey.from_seed(bip39_seed(TEST_MNEMONIC))
    first = b84.derive_path("m/84'/0'/0'/0/0")
    check("m/84'/0'/0'/0/0 pubkey", first.pub.hex(),
          "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c")
    check("m/84'/0'/0'/0/0 address", p2wpkh_address(first.pub, "mainnet"),
          "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
    check("m/84'/0'/0'/0/0 WIF", first.wif(),
          "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d")
    second = b84.derive_path("m/84'/0'/0'/0/1")
    check("m/84'/0'/0'/0/1 address", p2wpkh_address(second.pub, "mainnet"),
          "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g")
    chg = b84.derive_path("m/84'/0'/0'/1/0")
    check("m/84'/0'/0'/1/0 address", p2wpkh_address(chg.pub, "mainnet"),
          "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el")

    print("self-check: extended public keys and the other address types")
    # BIP32 test vector 1: the published master xpub. Checks the public
    # serialisation - version bytes, depth, parent fingerprint, point - which is
    # the format every watch-only export is written in.
    check("BIP32 vector 1 m xpub", m.xpub(),
          "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFj"
          "qJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")
    # BIP86 test vector, same mnemonic as the fixture.
    tr_account = b84.derive_path("m/86'/0'/0'")
    check("BIP86 m/86'/0'/0' xpub", tr_account.xpub(),
          "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky"
          "7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ")
    check("BIP86 m/86'/0'/0'/0/0 address",
          p2tr_address(tr_account.derive_path("0/0").pub, "mainnet"),
          "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")
    # BIP49 test vector: testnet, so it also exercises the other base58 prefix.
    check("BIP49 m/49'/1'/0'/0/0 address",
          p2sh_p2wpkh_address(
              HDKey.from_seed(bip39_seed(TEST_MNEMONIC), net="testnet")
              .derive_path("m/49'/1'/0'/0/0").pub, "testnet"),
          "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2")
    check("BIP44 m/44'/0'/0'/0/0 address",
          p2pkh_address(b84.derive_path("m/44'/0'/0'/0/0").pub, "mainnet"),
          "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA")

    print("self-check: ECDSA round trip")
    digest = sha256(b"signeros self check")
    sig = ecdsa_sign(first.priv, digest)
    check("sign then verify", ecdsa_verify(first.pub, digest, sig), True)
    check("verify rejects a tampered digest",
          ecdsa_verify(first.pub, sha256(b"different message"), sig), False)
    check("DER round trip", der_to_sig64(sig64_to_der(sig)).hex(), sig.hex())

    print("self-check: PSBT round trip")
    exp = generate_to_temp()
    check("generated PSBT re-parses", exp is True, True)

    if failures:
        print("\nself-check FAILED:\n  " + "\n  ".join(failures))
        return 1
    print("\nself-check: all vectors match")
    return 0


def sig64_to_der(sig64: bytes) -> bytes:
    """Only used by the self-check, to prove der_to_sig64 round-trips."""
    def enc(v: bytes) -> bytes:
        v = v.lstrip(b"\x00") or b"\x00"
        if v[0] & 0x80:
            v = b"\x00" + v
        return b"\x02" + bytes([len(v)]) + v
    body = enc(sig64[:32]) + enc(sig64[32:])
    return b"\x30" + bytes([len(body)]) + body


def generate_to_temp() -> bool:
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        exp = generate(d, "testnet")
        with open(os.path.join(d, exp["psbt_file"]), "rb") as f:
            raw = f.read()
        _, ins, outs, unsigned = parse_psbt(raw)
        tx = parse_tx(unsigned)
        assert tx.txid() == exp["txid_unsigned"], "txid mismatch"
        assert len(ins) == len(exp["inputs"]), "input count mismatch"
        assert len(outs) == len(exp["outputs"]), "output count mismatch"
        for in_map, exp_in in zip(ins, exp["inputs"]):
            utxo = parse_txout(in_map[bytes([PSBT_IN_WITNESS_UTXO])])
            assert utxo.value == exp_in["value"], "witness utxo value mismatch"
            wanted = bytes([PSBT_IN_BIP32_DERIVATION]) + bytes.fromhex(exp_in["pubkey"])
            assert wanted in in_map, "missing bip32 derivation"
        return True


# ===========================================================================

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="write test_unsigned.psbt, "
                                        "test_mnemonic.txt and expected.json")
    g.add_argument("--out-dir", required=True)
    g.add_argument("--network", default="testnet",
                   choices=["mainnet", "testnet", "signet", "regtest"])
    g.add_argument("--quiet", action="store_true")

    v = sub.add_parser("verify", help="independently verify a signed PSBT")
    v.add_argument("--dir", required=True)
    v.add_argument("--signed", default=None)

    sub.add_parser("self-check", help="check the crypto here against published "
                                      "test vectors")

    w = sub.add_parser("wallet-expect",
                       help="print the account xpubs and first addresses a "
                            "watch-only export of the fixture mnemonic must "
                            "contain")
    w.add_argument("--network", default="testnet",
                   choices=["mainnet", "testnet", "signet", "regtest"])
    w.add_argument("--mnemonic", default=None)
    w.add_argument("--passphrase", default="")
    w.add_argument("--account", type=int, default=0,
                   help="account index; the import screen lets the operator "
                        "choose one, so it is checked for more than 0")
    w.add_argument("--section", default="accounts",
                   choices=["accounts", "cosigners"],
                   help="which half of the export to print: the "
                        "single-signature accounts (BIP44/49/84/86, with their "
                        "first address) or the multisig cosigner keys (BIP48, "
                        "which have none)")

    args = ap.parse_args()

    if args.cmd == "generate":
        exp = generate(args.out_dir, args.network)
        if not args.quiet:
            print("fixture written to %s" % args.out_dir)
            print("  network            %s" % exp["network"])
            print("  master fingerprint %s" % exp["master_fingerprint"])
            print("  unsigned txid      %s" % exp["txid_unsigned"])
            for i, inp in enumerate(exp["inputs"]):
                print("  input  %d           %s sat  %s  (%s)"
                      % (i, inp["value"], inp["address"], inp["path"]))
            for i, out in enumerate(exp["outputs"]):
                print("  output %d           %s sat  %s%s"
                      % (i, out["value"], out["address"],
                         "  [change]" if out["mine"] else ""))
            print("  fee                %s sat" % exp["fee"])
            print("  forged fixture     %s  (change label points at %s)"
                  % (exp["forged_change_file"], exp["forged_change_address"]))
        return 0

    if args.cmd == "verify":
        return verify(args.dir, args.signed)

    if args.cmd == "wallet-expect":
        return wallet_expect(args.network, args.mnemonic, args.passphrase,
                             args.account, args.section)

    return self_check()


if __name__ == "__main__":
    sys.exit(main())
