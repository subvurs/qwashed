# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mark Eatherly
"""OpenPGP public-key probe for the Qwashed HNDL auditor (§3.2).

Why hand-parse?
---------------
The probe needs only the *primary public-key algorithm* and (for
length-parameterized algorithms like RSA / DSA / ElGamal) the modulus
bit length. That is one byte of algorithm ID and at most one MPI per
key, well inside the scope of a few hundred lines of pure Python.

Pulling in a full OpenPGP library (``pgpy``, ``sequoia-python``,
``python-gnupg``) for that one byte would:

* Add a heavyweight optional dependency to a defensive auditing tool
  meant to run on offline / civil-society laptops.
* Introduce signature-verification surface we do not need (and that
  would be a footgun: this probe is *not* a key-trust evaluator;
  classifying an invalid signature as ``unknown`` or ``classical``
  would mislead).
* Couple Qwashed to the security-update cadence of an upstream OpenPGP
  parser the team does not control.

The hand-rolled parser handles the public-key-packet subset we need
under both RFC 4880 (v4 keys, dominant deployed format in 2026) and
RFC 9580 (v6 keys, the algorithm-23/25-28 native curve formats).
Anything we cannot classify becomes an empty ``signature_algorithm``
field on :class:`~qwashed.audit.schemas.ProbeResult` and the classifier
maps it to ``unknown`` for fail-closed scoring.

Hard guarantees
---------------
* No network access. Ever.
* Reads at most :data:`MAX_PGP_BYTES` from disk (file-size cap defends
  against a malicious fixture trying to exhaust memory).
* Never raises on a malformed key: returns
  ``ProbeStatus.malformed`` with a summary ``error_detail`` string.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from qwashed.audit.probe_base import Probe
from qwashed.audit.schemas import AuditTarget, ProbeResult

__all__ = [
    "MAX_PGP_BYTES",
    "PgpProbe",
    "parse_primary_public_key",
]

#: Hard ceiling on PGP key file size. A single primary public key plus
#: a couple of subkeys, signatures, and user IDs is comfortably under
#: 64 KiB even for RSA-8192. We cap at 1 MiB to be safe against
#: pathological inputs without rejecting unusual but legitimate keyrings.
MAX_PGP_BYTES: Final[int] = 1_048_576

# OpenPGP packet tags we care about.
# RFC 4880 §4.3, RFC 9580 §5
_PACKET_TAG_PUBLIC_KEY: Final[int] = 6
_PACKET_TAG_PUBLIC_SUBKEY: Final[int] = 14

# RFC 4880 §9.1 + RFC 6637 + RFC 9580 algorithm IDs.
_ALGO_RSA: Final[int] = 1
_ALGO_RSA_ENCRYPT_ONLY: Final[int] = 2
_ALGO_RSA_SIGN_ONLY: Final[int] = 3
_ALGO_ELGAMAL: Final[int] = 16
_ALGO_DSA: Final[int] = 17
_ALGO_ECDH: Final[int] = 18
_ALGO_ECDSA: Final[int] = 19
_ALGO_EDDSA_LEGACY: Final[int] = 22  # RFC 4880bis EdDSA with curve OID
_ALGO_X25519: Final[int] = 25  # RFC 9580 native X25519
_ALGO_X448: Final[int] = 26  # RFC 9580 native X448
_ALGO_ED25519: Final[int] = 27  # RFC 9580 native Ed25519
_ALGO_ED448: Final[int] = 28  # RFC 9580 native Ed448

# OID byte sequences used in algorithm-22 (EdDSA), 18 (ECDH), 19 (ECDSA).
# Encoding: the curve OID is serialized as just the DER content bytes
# (no 0x06 tag), prefixed by a 1-byte length. See RFC 6637 §11.
_OID_TO_CURVE: Final[dict[bytes, str]] = {
    bytes.fromhex("2a8648ce3d030107"): "nistp256",
    bytes.fromhex("2b81040022"): "nistp384",
    bytes.fromhex("2b81040023"): "nistp521",
    bytes.fromhex("2b2403030208010107"): "brainpoolp256r1",
    bytes.fromhex("2b240303020801010b"): "brainpoolp384r1",
    bytes.fromhex("2b240303020801010d"): "brainpoolp512r1",
    # Ed25519 (RFC 4880bis): 1.3.6.1.4.1.11591.15.1
    bytes.fromhex("2b06010401da470f01"): "curve25519",
    # Curve25519 (ECDH RFC 6637): 1.3.6.1.4.1.3029.1.5.1
    bytes.fromhex("2b060104019755010501"): "curve25519",
    # Ed448: 1.3.101.113
    bytes.fromhex("2b6571"): "curve448",
    # X448: 1.3.101.111
    bytes.fromhex("2b656f"): "curve448",
}


@dataclass(frozen=True)
class PgpKeyInfo:
    """Result of parsing an OpenPGP primary public-key packet.

    Attributes
    ----------
    algorithm_id:
        The 1-byte algorithm identifier from the packet body
        (RFC 4880 §9.1 / RFC 9580 §9.1).
    friendly_name:
        Wire-name suitable for the algorithm-tables lookup, e.g.
        ``"rsa_2048"``, ``"ed25519"``, ``"ecdh_curve25519"``. Empty
        string if the algorithm is recognized at the ID level but the
        sub-parameter (curve / bit length) could not be extracted.
    bit_length:
        For RSA / DSA / ElGamal, the modulus bit length read from the
        first MPI. Zero for ECC and native-curve algorithms.
    family:
        Coarse algorithm family used by §3.5 (richer HNDL) scoring:
        ``"rsa"``, ``"dsa"``, ``"elgamal"``, ``"ec"`` (NIST / Brainpool /
        Ed/X-curve), or ``""`` for unknown algorithm IDs. Empty so a
        completely unknown algorithm cannot be silently classified.
    """

    algorithm_id: int
    friendly_name: str
    bit_length: int = 0
    family: str = ""


def _strip_armor(data: bytes) -> bytes:
    """If ``data`` is ASCII-armored, return the decoded binary; otherwise
    return ``data`` unchanged.

    A best-effort armor stripper: we do not validate the CRC24 footer
    (it has no security value here — invalid CRC just means the file
    was corrupted, which the binary parser will surface anyway).
    """
    text_head = data[:64].lstrip()
    if not text_head.startswith(b"-----BEGIN PGP"):
        return data
    try:
        text = data.decode("ascii", errors="replace")
    except Exception:
        return data
    lines = text.splitlines()
    in_body = False
    body_lines: list[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not in_body:
            # Skip armor header until we hit the blank line.
            if line == "":
                in_body = True
            continue
        if line.startswith("-----END "):
            break
        if line.startswith("="):
            # CRC24 line; ignored.
            continue
        body_lines.append(line)
    if not body_lines:
        return data
    try:
        return base64.b64decode("".join(body_lines), validate=False)
    except Exception:
        return data


def _read_packet_header(buf: bytes, offset: int) -> tuple[int, int, int] | None:
    """Read the next OpenPGP packet header from ``buf`` at ``offset``.

    Returns ``(tag, body_start, body_end)`` or ``None`` if there is no
    valid packet at this offset (out of bytes / corrupt header).

    Handles both old-format and new-format packet framing per RFC 4880
    §4.2. Partial body lengths (only legal on Literal Data, Compressed
    Data, Encrypted Data, and similar streaming packets) are not
    expected for public-key packets and are rejected.
    """
    n = len(buf)
    if offset >= n:
        return None
    first = buf[offset]
    if not (first & 0x80):
        # Not a valid packet header.
        return None
    if first & 0x40:
        # New-format packet (RFC 4880 §4.2.2).
        tag = first & 0x3F
        if offset + 1 >= n:
            return None
        b1 = buf[offset + 1]
        if b1 < 192:
            length = b1
            body_start = offset + 2
        elif b1 < 224:
            if offset + 2 >= n:
                return None
            length = ((b1 - 192) << 8) + buf[offset + 2] + 192
            body_start = offset + 3
        elif b1 == 255:
            if offset + 5 >= n:
                return None
            length = int.from_bytes(buf[offset + 2 : offset + 6], "big")
            body_start = offset + 6
        else:
            # Partial body length — illegal for public-key packets.
            return None
    else:
        # Old-format packet (RFC 4880 §4.2.1).
        tag = (first >> 2) & 0x0F
        len_type = first & 0x03
        if len_type == 0:
            if offset + 1 >= n:
                return None
            length = buf[offset + 1]
            body_start = offset + 2
        elif len_type == 1:
            if offset + 2 >= n:
                return None
            length = int.from_bytes(buf[offset + 1 : offset + 3], "big")
            body_start = offset + 3
        elif len_type == 2:
            if offset + 4 >= n:
                return None
            length = int.from_bytes(buf[offset + 1 : offset + 5], "big")
            body_start = offset + 5
        else:
            # Indeterminate length — illegal for public-key packets.
            return None
    body_end = body_start + length
    if body_end > n:
        return None
    return tag, body_start, body_end


def _parse_public_key_body(body: bytes) -> PgpKeyInfo | None:
    """Parse the body of a Public-Key (or Public-Subkey) packet.

    Returns ``None`` if the body is too short or otherwise malformed.
    """
    if len(body) < 6:
        return None
    version = body[0]
    if version not in (3, 4, 5, 6):
        return None
    if version >= 5:
        # v5 / v6 prepends a 4-byte key-material length field after
        # creation time; the algorithm byte is at offset 9.
        # v5 layout (RFC 4880bis): version | created (4) | algo (1) |
        #   key_material_length (4) | key_material...
        # v6 layout (RFC 9580 §5.5.2): version | created (4) | algo (1) |
        #   key_material_length (4) | key_material...
        if len(body) < 10:
            return None
        algo = body[5]
        material_offset = 10
    elif version == 4:
        # v4: version | created (4) | algo (1) | key_material...
        algo = body[5]
        material_offset = 6
    else:  # version == 3
        # v3: version | created (4) | validity_days (2) | algo (1) | material
        if len(body) < 8:
            return None
        algo = body[7]
        material_offset = 8

    material = body[material_offset:]
    return _classify_algorithm(algo, material)


def _classify_algorithm(algo: int, material: bytes) -> PgpKeyInfo:
    """Map an algorithm ID + key-material bytes to a :class:`PgpKeyInfo`.

    Returns a populated :class:`PgpKeyInfo` even when sub-parameters
    cannot be extracted; the caller's algorithm-tables lookup will then
    fall back to ``unknown``.
    """
    if algo in (_ALGO_RSA, _ALGO_RSA_ENCRYPT_ONLY, _ALGO_RSA_SIGN_ONLY):
        bits = _read_first_mpi_bit_length(material)
        if bits == 0:
            return PgpKeyInfo(algo, "rsa", 0, "rsa")
        return PgpKeyInfo(algo, _bucket_rsa_bits(bits), bits, "rsa")
    if algo == _ALGO_DSA:
        bits = _read_first_mpi_bit_length(material)
        if bits == 0:
            return PgpKeyInfo(algo, "dsa", 0, "dsa")
        return PgpKeyInfo(algo, f"dsa_{_bucket_dsa_bits(bits)}", bits, "dsa")
    if algo == _ALGO_ELGAMAL:
        bits = _read_first_mpi_bit_length(material)
        if bits == 0:
            return PgpKeyInfo(algo, "elgamal", 0, "elgamal")
        return PgpKeyInfo(
            algo, f"elgamal_{_bucket_elgamal_bits(bits)}", bits, "elgamal"
        )
    if algo == _ALGO_ECDSA:
        curve = _read_oid_curve(material)
        if curve:
            return PgpKeyInfo(algo, f"ecdsa_{curve}", 0, "ec")
        return PgpKeyInfo(algo, "ecdsa", 0, "ec")
    if algo == _ALGO_ECDH:
        curve = _read_oid_curve(material)
        if curve:
            return PgpKeyInfo(algo, f"ecdh_{curve}", 0, "ec")
        return PgpKeyInfo(algo, "ecdh", 0, "ec")
    if algo == _ALGO_EDDSA_LEGACY:
        curve = _read_oid_curve(material)
        # Algorithm 22 with the Ed25519 curve OID is conventionally
        # named just "ed25519" in deployed keyrings even though the
        # underlying field is "curve25519". Match the convention.
        if curve == "curve25519":
            return PgpKeyInfo(algo, "ed25519", 0, "ec")
        if curve == "curve448":
            return PgpKeyInfo(algo, "ed448", 0, "ec")
        if curve:
            return PgpKeyInfo(algo, f"eddsa_{curve}", 0, "ec")
        return PgpKeyInfo(algo, "eddsa", 0, "ec")
    if algo == _ALGO_X25519:
        return PgpKeyInfo(algo, "x25519", 0, "ec")
    if algo == _ALGO_X448:
        return PgpKeyInfo(algo, "x448", 0, "ec")
    if algo == _ALGO_ED25519:
        return PgpKeyInfo(algo, "ed25519", 0, "ec")
    if algo == _ALGO_ED448:
        return PgpKeyInfo(algo, "ed448", 0, "ec")
    return PgpKeyInfo(algo, "", 0, "")


def _read_first_mpi_bit_length(material: bytes) -> int:
    """Read the bit length from the first MPI in ``material``.

    OpenPGP MPI encoding (RFC 4880 §3.2): 2-byte bit length (big-endian)
    followed by ceil(bits/8) bytes of integer data. We only need the
    length; ignore the value.
    """
    if len(material) < 2:
        return 0
    return int.from_bytes(material[0:2], "big")


def _read_oid_curve(material: bytes) -> str:
    """Read the OID at the start of ``material`` (RFC 6637 §11) and map
    it to a curve nickname. Returns empty string if the OID is unknown.
    """
    if not material:
        return ""
    oid_len = material[0]
    if oid_len in (0, 0xFF):
        # 0xFF is reserved per RFC 6637 to forbid this length encoding.
        return ""
    if 1 + oid_len > len(material):
        return ""
    oid_bytes = material[1 : 1 + oid_len]
    return _OID_TO_CURVE.get(oid_bytes, "")


def _bucket_rsa_bits(bits: int) -> str:
    """Bucket an RSA modulus bit length into the nearest standard size.

    The PGP key tables use the nominal sizes (1024/2048/3072/4096/8192).
    A 2047- or 2049-bit key is conventionally reported as "rsa_2048"
    in the security-posture sense; the bucketing also defends against
    off-by-one MPI-length encodings.
    """
    for bucket in (1024, 2048, 3072, 4096, 8192):
        if bits <= bucket + 8:
            return f"rsa_{bucket}"
    return f"rsa_{bits}"


def _bucket_dsa_bits(bits: int) -> int:
    for bucket in (1024, 2048, 3072):
        if bits <= bucket + 8:
            return bucket
    return bits


def _bucket_elgamal_bits(bits: int) -> int:
    for bucket in (2048, 3072, 4096):
        if bits <= bucket + 8:
            return bucket
    return bits


def parse_primary_public_key(data: bytes) -> PgpKeyInfo | None:
    """Find and classify the primary public-key packet in ``data``.

    Accepts either binary OpenPGP transferable public-key data or
    ASCII-armored data. Returns ``None`` if no public-key packet is
    found within the first :data:`MAX_PGP_BYTES` bytes.
    """
    binary = _strip_armor(data)
    if len(binary) > MAX_PGP_BYTES:
        binary = binary[:MAX_PGP_BYTES]
    offset = 0
    while offset < len(binary):
        header = _read_packet_header(binary, offset)
        if header is None:
            return None
        tag, body_start, body_end = header
        if tag == _PACKET_TAG_PUBLIC_KEY:
            return _parse_public_key_body(binary[body_start:body_end])
        # Skip subkey / user ID / signature packets while searching for
        # the primary key. Subkeys are not the primary classification
        # target.
        offset = body_end
    return None


class PgpProbe(Probe):
    """File-only probe of an OpenPGP public key.

    Reads :attr:`AuditTarget.key_path`, parses the primary public-key
    packet, and reports the key algorithm in
    :attr:`ProbeResult.signature_algorithm` (the field repurposed for
    "the algorithm being classified" across protocols).
    """

    def probe(self, target: AuditTarget) -> ProbeResult:
        if target.protocol != "pgp":
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail=(
                    f"protocol={target.protocol!r} not supported by PgpProbe"
                ),
            )
        if not target.key_path:
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail="pgp target missing key_path",
            )
        start = time.monotonic()
        path = Path(target.key_path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            return ProbeResult(
                target=target,
                status="unreachable",
                error_detail=f"cannot read pgp key: {type(exc).__name__}: {exc}",
                elapsed_seconds=time.monotonic() - start,
            )
        if not data:
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail="pgp key file is empty",
                elapsed_seconds=time.monotonic() - start,
            )
        if len(data) > MAX_PGP_BYTES:
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail=(
                    f"pgp key file exceeds {MAX_PGP_BYTES}-byte cap; refusing"
                ),
                elapsed_seconds=time.monotonic() - start,
            )
        info = parse_primary_public_key(data)
        elapsed = time.monotonic() - start
        if info is None:
            return ProbeResult(
                target=target,
                status="malformed",
                error_detail="no primary public-key packet found",
                elapsed_seconds=elapsed,
            )
        extras: dict[str, str] = {
            "pgp_algorithm_id": str(info.algorithm_id),
        }
        if info.bit_length:
            extras["pgp_bit_length"] = str(info.bit_length)
        return ProbeResult(
            target=target,
            status="ok",
            signature_algorithm=info.friendly_name,
            public_key_bits=info.bit_length if info.bit_length else None,
            public_key_algorithm_family=info.family or None,
            extras=extras,
            elapsed_seconds=elapsed,
        )
