#!/usr/bin/env python3
"""
DarkSwan DS codec.

Format overview:
- DS1: header + whitespace records.
- DS2: header + whitespace records + metadata trailer.
- Each input line maps to one encoded record.
"""
from __future__ import annotations

import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import hmac
import io
import json
import os
import sys
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterator, List, Optional, Tuple

BRAND = "DarkSwan DS Codec"
TOOL_VERSION = "0.4.0"
MAGIC_V1 = b"DARKSWAN-DS1\n"
MAGIC_V2 = b"DARKSWAN-DS2\n"
META_BEGIN = b"##META\n"
META_END = b"##ENDMETA\n"
NIBBLE_MAX = 0x0F
STEGO_MAGIC_V1 = b"DSSTEG1"
STEGO_MAGIC_V2 = b"DSSTEG2"
STEGO_V1_SEPARATOR = b"\t \t  \t"
DEFAULT_STEGO_CHUNK_SIZE = 64
DEFAULT_STEGO_PROFILE = "balanced"
DEFAULT_SCRYPT_N = 1 << 14
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
STEGO_PROFILES: Dict[str, Dict[str, object]] = {
    "balanced": {"chunk_size": 64, "line_stride": 1, "marker": STEGO_V1_SEPARATOR},
    "low-noise": {"chunk_size": 96, "line_stride": 2, "marker": b" \t \t\t"},
    "high-capacity": {"chunk_size": 128, "line_stride": 1, "marker": b"\t\t "},
}
DEFAULT_ALLOWED_CLASSIFICATIONS = ["public", "internal", "confidential", "restricted"]
SHARD_MAGIC_V1 = b"DSSHARD1"
DEFAULT_TRANSFORMS = [
    "identity",
    "normalize_lf",
    "normalize_crlf",
    "trim_trailing_ws",
    "strip_final_newline",
]
MASCOT = r"""      ,-----.
    ,-,-o-   `\
__.--"`-,)       \
`---------'-.._    \
               `.   :
                |   |
                |   |
                |   |
                ,   ;
               /    |"""

Stats = Dict[str, int]
Report = Dict[str, object]

__all__ = [
    "DecodeError",
    "MAGIC_V1",
    "MAGIC_V2",
    "encode_bytes",
    "decode_bytes",
    "encode_stream",
    "decode_stream",
    "inspect_stream",
    "inspect_file",
    "decode_record",
    "read_record",
    "iter_records",
    "count_records",
    "estimate_capacity",
    "analyze_carrier",
    "evaluate_survivability",
    "load_policy",
    "split_payload",
    "reconstruct_payload",
    "embed_payload",
    "extract_payload",
    "generate_operation_manifest",
    "verify_operation_manifest",
    "cli_main",
]


class DecodeError(RuntimeError):
    """Raised when the input is not valid DS data."""


class _NullWriter:
    """Sink that discards writes, used for inspection without materializing data."""

    def write(self, data: bytes) -> int:
        return len(data)


def _init_stats() -> Stats:
    return {
        "source_bytes": 0,
        "source_lines": 0,
        "encoded_records": 0,
        "sha256": "",
    }


def _finish_stats(stats: Stats, sha: "hashlib._Hash") -> Stats:
    stats["sha256"] = sha.hexdigest()
    return stats


def _encode_record(line: bytes) -> bytes:
    chunks: List[bytes] = []
    for byte in line:
        hi = byte >> 4
        lo = byte & NIBBLE_MAX
        chunks.append((b" " * hi) + b"\t" + (b" " * lo) + b"\t")
    chunks.append(b"\n")
    return b"".join(chunks)


def _decode_record(record: bytes) -> bytes:
    if not record:
        return b""

    runs = record.split(b"\t")
    if runs and runs[-1] == b"":
        runs = runs[:-1]

    if len(runs) % 2 != 0:
        raise DecodeError("Uneven nibble count in record")

    out = bytearray()
    for idx in range(0, len(runs), 2):
        hi_run = runs[idx]
        lo_run = runs[idx + 1]

        if b" " * len(hi_run) != hi_run or b" " * len(lo_run) != lo_run:
            raise DecodeError("Non-space characters detected inside runs")

        hi = len(hi_run)
        lo = len(lo_run)
        if hi > NIBBLE_MAX or lo > NIBBLE_MAX:
            raise DecodeError("Nibble length outside 0-15 range")

        out.append((hi << 4) | lo)
    return bytes(out)


def decode_record(encoded_line: bytes) -> bytes:
    """Decode a single encoded DS record line."""
    return _decode_record(encoded_line.rstrip(b"\n"))


def encode_bytes(data: bytes, *, magic: bytes = MAGIC_V2, include_metadata: bool = True) -> bytes:
    """Encode raw bytes into DS format."""
    in_fp = io.BytesIO(data)
    out_fp = io.BytesIO()
    encode_stream(in_fp, out_fp, magic=magic, include_metadata=include_metadata)
    return out_fp.getvalue()


def decode_bytes(encoded: bytes) -> bytes:
    """Decode DS format back into raw bytes."""
    in_fp = io.BytesIO(encoded)
    out_fp = io.BytesIO()
    decode_stream(in_fp, out_fp)
    return out_fp.getvalue()


def _read_header(in_fp: BinaryIO) -> bytes:
    header = in_fp.readline()
    if header not in (MAGIC_V1, MAGIC_V2):
        raise DecodeError("Missing DS magic header")
    return header


def read_record(in_fp: BinaryIO, n: int) -> bytes:
    """Read and decode the nth DS data record from the current stream position."""
    if n < 0:
        raise ValueError("Record index must be non-negative")

    header = _read_header(in_fp)
    is_ds2 = header == MAGIC_V2

    for idx, raw in enumerate(in_fp):
        if is_ds2 and raw == META_BEGIN:
            break
        if idx == n:
            return decode_record(raw)

    raise IndexError("Record index out of range")


def iter_records(in_fp: BinaryIO) -> Iterator[bytes]:
    """Yield decoded DS records from the current stream position."""
    header = _read_header(in_fp)
    is_ds2 = header == MAGIC_V2
    for raw in in_fp:
        if is_ds2 and raw == META_BEGIN:
            return
        yield decode_record(raw)


def count_records(in_fp: BinaryIO) -> int:
    """Count decoded records in a DS stream from the current position."""
    count = 0
    for _ in iter_records(in_fp):
        count += 1
    return count


def _profile_settings(profile: str, chunk_size: Optional[int] = None) -> Tuple[int, int, bytes]:
    spec = STEGO_PROFILES.get(profile)
    if spec is None:
        raise ValueError(f"Unknown stego profile: {profile}")
    resolved_chunk_size = int(spec["chunk_size"]) if chunk_size is None else chunk_size
    if resolved_chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    return resolved_chunk_size, int(spec["line_stride"]), bytes(spec["marker"])


def _seed_bytes(seed: Optional[str]) -> bytes:
    if seed is None:
        return b"default-stego-seed"
    return seed.encode("utf-8")


def _candidate_indices(line_count: int, line_stride: int, start: int) -> List[int]:
    return list(range(start, line_count, line_stride))


def _choose_start(
    line_count: int,
    line_stride: int,
    required_slots: int,
    *,
    deterministic: bool,
    seed: Optional[str],
) -> int:
    if line_stride <= 1:
        return 0

    candidates = [start for start in range(line_stride) if len(_candidate_indices(line_count, line_stride, start)) >= required_slots]
    if not candidates:
        raise ValueError("Carrier does not have enough lines for payload")

    if deterministic:
        digest = hashlib.sha256(_seed_bytes(seed) + b":" + str(line_count).encode("ascii")).digest()
        return candidates[digest[0] % len(candidates)]

    entropy = os.urandom(1)[0]
    return candidates[entropy % len(candidates)]


def estimate_capacity(
    cover: bytes,
    *,
    chunk_size: Optional[int] = DEFAULT_STEGO_CHUNK_SIZE,
    profile: str = DEFAULT_STEGO_PROFILE,
    deterministic: bool = True,
    seed: Optional[str] = None,
) -> int:
    """Estimate maximum payload bytes a carrier can hold."""
    resolved_chunk_size, line_stride, _ = _profile_settings(profile, chunk_size)
    line_count = len(cover.splitlines(keepends=True))
    if line_count <= 1:
        return 0

    if deterministic:
        start = _choose_start(line_count, line_stride, 1, deterministic=True, seed=seed)
        slots = len(_candidate_indices(line_count, line_stride, start))
    else:
        slots = max(len(_candidate_indices(line_count, line_stride, start)) for start in range(line_stride))
    payload_slots = max(0, slots - 1)
    return payload_slots * resolved_chunk_size


def _split_line_ending(line: bytes) -> Tuple[bytes, bytes]:
    if line.endswith(b"\r\n"):
        return line[:-2], b"\r\n"
    if line.endswith(b"\n"):
        return line[:-1], b"\n"
    if line.endswith(b"\r"):
        return line[:-1], b"\r"
    return line, b""


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def analyze_carrier(cover: bytes) -> Dict[str, object]:
    """Analyze carrier stability and transformation risk."""
    lines = cover.splitlines(keepends=True)
    line_count = len(lines)
    newline_counts = {"lf": 0, "crlf": 0, "cr": 0, "none": 0}
    trailing_ws_lines = 0
    max_line_bytes = 0

    for line in lines:
        body, ending = _split_line_ending(line)
        if ending == b"\n":
            newline_counts["lf"] += 1
        elif ending == b"\r\n":
            newline_counts["crlf"] += 1
        elif ending == b"\r":
            newline_counts["cr"] += 1
        else:
            newline_counts["none"] += 1

        if body.endswith((b" ", b"\t")):
            trailing_ws_lines += 1
        if len(body) > max_line_bytes:
            max_line_bytes = len(body)

    non_zero_newlines = sum(1 for key in ("lf", "crlf", "cr") if newline_counts[key] > 0)
    mixed_newlines = non_zero_newlines > 1
    trailing_ws_ratio = 0.0 if line_count == 0 else trailing_ws_lines / line_count

    risk_score = 0
    if mixed_newlines:
        risk_score += 35
    risk_score += min(35, int(trailing_ws_ratio * 100))
    if newline_counts["none"] > 0:
        risk_score += 10
    if line_count < 4:
        risk_score += 20
    elif line_count < 12:
        risk_score += 10
    risk_score = min(100, risk_score)

    if risk_score >= 67:
        risk_level = "high"
    elif risk_score >= 34:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "carrier_bytes": len(cover),
        "carrier_lines": line_count,
        "newline_counts": newline_counts,
        "mixed_newlines": mixed_newlines,
        "trailing_whitespace_lines": trailing_ws_lines,
        "trailing_whitespace_ratio": round(trailing_ws_ratio, 4),
        "max_line_bytes": max_line_bytes,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }


def _transform_identity(data: bytes) -> bytes:
    return data


def _transform_normalize_lf(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _transform_normalize_crlf(data: bytes) -> bytes:
    normalized = _transform_normalize_lf(data)
    return normalized.replace(b"\n", b"\r\n")


def _transform_trim_trailing_ws(data: bytes) -> bytes:
    out_lines: List[bytes] = []
    for line in data.splitlines(keepends=True):
        body, ending = _split_line_ending(line)
        out_lines.append(body.rstrip(b" \t") + ending)
    return b"".join(out_lines)


def _transform_strip_final_newline(data: bytes) -> bytes:
    if data.endswith(b"\r\n"):
        return data[:-2]
    if data.endswith(b"\n") or data.endswith(b"\r"):
        return data[:-1]
    return data


def _transformers() -> Dict[str, Any]:
    return {
        "identity": _transform_identity,
        "normalize_lf": _transform_normalize_lf,
        "normalize_crlf": _transform_normalize_crlf,
        "trim_trailing_ws": _transform_trim_trailing_ws,
        "strip_final_newline": _transform_strip_final_newline,
    }


def evaluate_survivability(
    cover: bytes,
    payload: bytes,
    *,
    profile: str = DEFAULT_STEGO_PROFILE,
    chunk_size: Optional[int] = DEFAULT_STEGO_CHUNK_SIZE,
    passphrase: Optional[str] = None,
    deterministic: bool = False,
    seed: Optional[str] = None,
    scrypt_n: int = DEFAULT_SCRYPT_N,
    scrypt_r: int = DEFAULT_SCRYPT_R,
    scrypt_p: int = DEFAULT_SCRYPT_P,
    transforms: Optional[List[str]] = None,
) -> Dict[str, object]:
    """Embed then evaluate extraction survivability through common text transforms."""
    stego = embed_payload(
        cover,
        payload,
        profile=profile,
        chunk_size=chunk_size,
        passphrase=passphrase,
        deterministic=deterministic,
        seed=seed,
        scrypt_n=scrypt_n,
        scrypt_r=scrypt_r,
        scrypt_p=scrypt_p,
    )
    selected = DEFAULT_TRANSFORMS if transforms is None else transforms
    available = _transformers()
    results: List[Dict[str, object]] = []
    for name in selected:
        fn = available.get(name)
        if fn is None:
            results.append({"transform": name, "ok": False, "error": "unknown_transform"})
            continue
        candidate = fn(stego)
        try:
            decoded = extract_payload(candidate, passphrase=passphrase)
            ok = decoded == payload
            results.append(
                {
                    "transform": name,
                    "ok": ok,
                    "error": None if ok else "payload_mismatch",
                    "stego_bytes": len(candidate),
                }
            )
        except DecodeError as exc:
            results.append(
                {
                    "transform": name,
                    "ok": False,
                    "error": str(exc),
                    "stego_bytes": len(candidate),
                }
            )

    passed = sum(1 for item in results if item["ok"])
    failed = len(results) - passed
    return {
        "profile": profile,
        "encrypted": passphrase is not None,
        "deterministic": deterministic,
        "seed": seed,
        "transform_count": len(results),
        "passed": passed,
        "failed": failed,
        "pass_rate": round(0.0 if len(results) == 0 else passed / len(results), 4),
        "results": results,
        "base_stego_bytes": len(stego),
    }


def load_policy(path: Optional[str]) -> Dict[str, object]:
    """Load policy controls from JSON; return permissive defaults when absent."""
    policy: Dict[str, object] = {
        "require_authorization_ack": False,
        "approved_engagements": [],
        "allowed_classifications": DEFAULT_ALLOWED_CLASSIFICATIONS,
        "blocked_operations": [],
    }
    if path is None:
        return policy
    with Path(path).open("r", encoding="utf-8") as fp:
        loaded = json.load(fp)
    if not isinstance(loaded, dict):
        raise DecodeError("Policy JSON must be an object")
    policy.update(loaded)
    return policy


def _enforce_policy(
    policy: Dict[str, object],
    *,
    operation: str,
    ack_authorized_use: bool,
    engagement: Optional[str],
    classification: str,
) -> None:
    if bool(policy.get("require_authorization_ack", False)) and not ack_authorized_use:
        raise DecodeError("Policy requires --ack-authorized-use")

    blocked = policy.get("blocked_operations", [])
    if isinstance(blocked, list) and operation in blocked:
        raise DecodeError(f"Operation blocked by policy: {operation}")

    allowed_classifications = policy.get("allowed_classifications", DEFAULT_ALLOWED_CLASSIFICATIONS)
    if isinstance(allowed_classifications, list) and classification not in allowed_classifications:
        raise DecodeError(f"Classification not allowed by policy: {classification}")

    approved_engagements = policy.get("approved_engagements", [])
    if isinstance(approved_engagements, list) and approved_engagements:
        if engagement is None or engagement not in approved_engagements:
            raise DecodeError("Engagement not approved by policy")


def _print_authorization_banner(stream: Any, *, operation: str, engagement: Optional[str], classification: str) -> None:
    _print_section(
        "Authorized Use",
        [
            ("operation", operation),
            ("engagement", "unspecified" if engagement is None else engagement),
            ("classification", classification),
        ],
        stream=stream,
    )


def _deterministic_bytes(seed: bytes, *, context: bytes, size: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        out.extend(hashlib.sha256(seed + b":" + context + b":" + counter.to_bytes(8, "big")).digest())
        counter += 1
    return bytes(out[:size])


def _gf_mul(a: int, b: int) -> int:
    res = 0
    x = a & 0xFF
    y = b & 0xFF
    while y:
        if y & 1:
            res ^= x
        x <<= 1
        if x & 0x100:
            x ^= 0x11B
        y >>= 1
    return res & 0xFF


def _gf_pow(base: int, exponent: int) -> int:
    result = 1
    x = base & 0xFF
    n = exponent
    while n > 0:
        if n & 1:
            result = _gf_mul(result, x)
        x = _gf_mul(x, x)
        n >>= 1
    return result


def _gf_inv(value: int) -> int:
    if value == 0:
        raise DecodeError("Invalid shard: division by zero in interpolation")
    return _gf_pow(value, 254)


def _gf_poly_eval(coeffs: bytes, x: int) -> int:
    acc = 0
    for coeff in reversed(coeffs):
        acc = _gf_mul(acc, x) ^ coeff
    return acc


def _build_shard_header(
    *,
    share_index: int,
    total_shards: int,
    threshold: int,
    payload_len: int,
    payload_hash: str,
) -> bytes:
    return (
        SHARD_MAGIC_V1
        + b":"
        + str(share_index).encode("ascii")
        + b":"
        + str(total_shards).encode("ascii")
        + b":"
        + str(threshold).encode("ascii")
        + b":"
        + str(payload_len).encode("ascii")
        + b":"
        + payload_hash.encode("ascii")
        + b"\n"
    )


def _parse_shard(blob: bytes) -> Tuple[int, int, int, int, str, bytes]:
    header, sep, body = blob.partition(b"\n")
    if sep == b"":
        raise DecodeError("Malformed shard: missing header newline")
    parts = header.split(b":")
    if len(parts) != 6 or parts[0] != SHARD_MAGIC_V1:
        raise DecodeError("Malformed shard header")
    try:
        share_index = int(parts[1].decode("ascii"))
        total_shards = int(parts[2].decode("ascii"))
        threshold = int(parts[3].decode("ascii"))
        payload_len = int(parts[4].decode("ascii"))
        payload_hash = parts[5].decode("ascii")
    except (UnicodeDecodeError, ValueError) as exc:
        raise DecodeError("Malformed shard header") from exc
    if share_index <= 0 or total_shards <= 0 or threshold <= 0 or payload_len < 0:
        raise DecodeError("Malformed shard header")
    return share_index, total_shards, threshold, payload_len, payload_hash, body


def split_payload(
    payload: bytes,
    *,
    total_shards: int,
    threshold: int,
    deterministic: bool = False,
    seed: Optional[str] = None,
) -> List[bytes]:
    """Split payload into threshold shards using GF(256) Shamir sharing."""
    if total_shards < 1 or total_shards > 255:
        raise ValueError("total_shards must be in 1..255")
    if threshold < 1 or threshold > total_shards:
        raise ValueError("threshold must be in 1..total_shards")

    seed_bytes = _seed_bytes(seed)
    payload_hash = _sha256_hex(payload)
    shares = [bytearray() for _ in range(total_shards)]

    for byte_index, secret_byte in enumerate(payload):
        if threshold == 1:
            coeffs = bytes([secret_byte])
        else:
            if deterministic:
                random_coeffs = _deterministic_bytes(
                    seed_bytes,
                    context=b"shamir:" + byte_index.to_bytes(8, "big"),
                    size=threshold - 1,
                )
            else:
                random_coeffs = os.urandom(threshold - 1)
            coeffs = bytes([secret_byte]) + random_coeffs

        for shard_idx in range(total_shards):
            x = shard_idx + 1
            y = _gf_poly_eval(coeffs, x)
            shares[shard_idx].append(y)

    out: List[bytes] = []
    for shard_idx, shard_bytes in enumerate(shares, start=1):
        header = _build_shard_header(
            share_index=shard_idx,
            total_shards=total_shards,
            threshold=threshold,
            payload_len=len(payload),
            payload_hash=payload_hash,
        )
        out.append(header + bytes(shard_bytes))
    return out


def reconstruct_payload(shards: List[bytes]) -> bytes:
    """Reconstruct payload from a threshold set of shards."""
    if not shards:
        raise DecodeError("No shards provided")

    parsed = [_parse_shard(blob) for blob in shards]
    first = parsed[0]
    total_shards, threshold, payload_len, payload_hash = first[1], first[2], first[3], first[4]

    point_map: Dict[int, bytes] = {}
    for share_index, parsed_total, parsed_threshold, parsed_len, parsed_hash, body in parsed:
        if parsed_total != total_shards or parsed_threshold != threshold or parsed_len != payload_len or parsed_hash != payload_hash:
            raise DecodeError("Incompatible shard set")
        if len(body) != payload_len:
            raise DecodeError("Shard payload length mismatch")
        if share_index in point_map:
            raise DecodeError("Duplicate shard index")
        point_map[share_index] = body

    if len(point_map) < threshold:
        raise DecodeError("Insufficient shards for reconstruction")

    selected_points = sorted(point_map.items(), key=lambda item: item[0])[:threshold]
    xs = [item[0] for item in selected_points]
    ys = [item[1] for item in selected_points]

    out = bytearray(payload_len)
    for byte_index in range(payload_len):
        accum = 0
        for j, xj in enumerate(xs):
            yj = ys[j][byte_index]
            numerator = 1
            denominator = 1
            for m, xm in enumerate(xs):
                if m == j:
                    continue
                numerator = _gf_mul(numerator, xm)
                denominator = _gf_mul(denominator, xm ^ xj)
            lagrange_at_zero = _gf_mul(numerator, _gf_inv(denominator))
            accum ^= _gf_mul(yj, lagrange_at_zero)
        out[byte_index] = accum

    payload = bytes(out)
    if _sha256_hex(payload) != payload_hash:
        raise DecodeError("Reconstructed payload hash mismatch")
    return payload


def _canonical_json_bytes(payload: Dict[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_operation_manifest(
    operation: str,
    details: Dict[str, object],
    *,
    signing_key: Optional[str] = None,
) -> Dict[str, object]:
    """Generate an operation manifest and optional signature."""
    manifest: Dict[str, object] = {
        "manifest_version": 1,
        "brand": BRAND,
        "operation": operation,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "details": details,
    }
    manifest["event_hash"] = _sha256_hex(_canonical_json_bytes({"operation": operation, "details": details}))

    if signing_key is not None:
        signature = hmac.digest(signing_key.encode("utf-8"), _canonical_json_bytes(manifest), "sha256").hex()
        manifest["signature"] = {
            "algorithm": "hmac-sha256",
            "key_id": _sha256_hex(signing_key.encode("utf-8"))[:12],
            "value": signature,
        }
    return manifest


def verify_operation_manifest(manifest: Dict[str, object], signing_key: str) -> bool:
    """Verify a signed operation manifest."""
    signature_obj = manifest.get("signature")
    if not isinstance(signature_obj, dict):
        return False
    if signature_obj.get("algorithm") != "hmac-sha256":
        return False
    signature_value = signature_obj.get("value")
    if not isinstance(signature_value, str):
        return False

    unsigned = dict(manifest)
    unsigned.pop("signature", None)
    expected = hmac.digest(signing_key.encode("utf-8"), _canonical_json_bytes(unsigned), "sha256").hex()
    return hmac.compare_digest(signature_value, expected)


def _write_manifest(path: str, manifest: Dict[str, object]) -> None:
    with Path(path).open("w", encoding="utf-8") as fp:
        fp.write(json.dumps(manifest, sort_keys=True, indent=2))
        fp.write("\n")


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _derive_keys(passphrase: str, salt: bytes, *, scrypt_n: int, scrypt_r: int, scrypt_p: int) -> Tuple[bytes, bytes]:
    if not passphrase:
        raise ValueError("passphrase must not be empty")
    key_material = hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=scrypt_n,
        r=scrypt_r,
        p=scrypt_p,
        dklen=64,
    )
    return key_material[:32], key_material[32:]


def _keystream(enc_key: bytes, nonce: bytes, size: int) -> bytes:
    stream = bytearray()
    counter = 0
    while len(stream) < size:
        block = hmac.digest(enc_key, nonce + counter.to_bytes(8, "big"), "sha256")
        stream.extend(block)
        counter += 1
    return bytes(stream[:size])


def _encrypt_payload(
    payload: bytes,
    *,
    passphrase: str,
    deterministic: bool,
    seed: Optional[str],
    scrypt_n: int,
    scrypt_r: int,
    scrypt_p: int,
    aad: bytes,
) -> Dict[str, object]:
    if deterministic:
        seed_bytes = _seed_bytes(seed)
        salt = hashlib.sha256(seed_bytes + b":salt").digest()[:16]
        nonce = hashlib.sha256(seed_bytes + b":nonce").digest()[:16]
    else:
        salt = os.urandom(16)
        nonce = os.urandom(16)

    enc_key, mac_key = _derive_keys(passphrase, salt, scrypt_n=scrypt_n, scrypt_r=scrypt_r, scrypt_p=scrypt_p)
    ciphertext = _xor_bytes(payload, _keystream(enc_key, nonce, len(payload)))
    tag = hmac.digest(mac_key, aad + nonce + ciphertext, "sha256")
    return {
        "ciphertext": ciphertext,
        "salt": salt,
        "nonce": nonce,
        "tag": tag,
    }


def _decrypt_payload(
    ciphertext: bytes,
    *,
    passphrase: str,
    aad: bytes,
    salt: bytes,
    nonce: bytes,
    tag: bytes,
    scrypt_n: int,
    scrypt_r: int,
    scrypt_p: int,
) -> bytes:
    enc_key, mac_key = _derive_keys(passphrase, salt, scrypt_n=scrypt_n, scrypt_r=scrypt_r, scrypt_p=scrypt_p)
    actual_tag = hmac.digest(mac_key, aad + nonce + ciphertext, "sha256")
    if not hmac.compare_digest(actual_tag, tag):
        raise DecodeError("Hidden payload authentication failed")
    return _xor_bytes(ciphertext, _keystream(enc_key, nonce, len(ciphertext)))


def _build_stego_records(
    payload: bytes,
    *,
    chunk_size: int,
    profile: str,
    line_stride: int,
    start: int,
    marker: bytes,
    passphrase: Optional[str],
    deterministic: bool,
    seed: Optional[str],
    scrypt_n: int,
    scrypt_r: int,
    scrypt_p: int,
) -> List[bytes]:
    marker_hex = marker.hex()

    if passphrase is None:
        checksum = hashlib.sha256(payload).hexdigest()
        header = (
            f"{STEGO_MAGIC_V2.decode('ascii')}:plain-v1:{profile}:{chunk_size}:{line_stride}:{start}:{marker_hex}:"
            f"{len(payload)}:{checksum}"
        ).encode("ascii")
        blob = payload
    else:
        aad = (
            f"{STEGO_MAGIC_V2.decode('ascii')}:enc-v1:{profile}:{chunk_size}:{line_stride}:{start}:{marker_hex}:{len(payload)}"
        ).encode("ascii")
        encrypted = _encrypt_payload(
            payload,
            passphrase=passphrase,
            deterministic=deterministic,
            seed=seed,
            scrypt_n=scrypt_n,
            scrypt_r=scrypt_r,
            scrypt_p=scrypt_p,
            aad=aad,
        )
        header = (
            f"{STEGO_MAGIC_V2.decode('ascii')}:enc-v1:{profile}:{chunk_size}:{line_stride}:{start}:{marker_hex}:{len(payload)}:"
            f"{encrypted['salt'].hex()}:{encrypted['nonce'].hex()}:{scrypt_n}:{scrypt_r}:{scrypt_p}:{encrypted['tag'].hex()}"
        ).encode("ascii")
        blob = encrypted["ciphertext"]  # type: ignore[assignment]

    records = [header]
    for idx in range(0, len(blob), chunk_size):
        records.append(blob[idx : idx + chunk_size])
    return records


def embed_payload(
    cover: bytes,
    payload: bytes,
    *,
    chunk_size: Optional[int] = DEFAULT_STEGO_CHUNK_SIZE,
    profile: str = DEFAULT_STEGO_PROFILE,
    passphrase: Optional[str] = None,
    deterministic: bool = False,
    seed: Optional[str] = None,
    scrypt_n: int = DEFAULT_SCRYPT_N,
    scrypt_r: int = DEFAULT_SCRYPT_R,
    scrypt_p: int = DEFAULT_SCRYPT_P,
) -> bytes:
    """Embed a payload into a text carrier using trailing-whitespace records."""
    resolved_chunk_size, line_stride, marker = _profile_settings(profile, chunk_size)
    lines = cover.splitlines(keepends=True)
    start = _choose_start(len(lines), line_stride, 1, deterministic=deterministic, seed=seed)
    records = _build_stego_records(
        payload,
        chunk_size=resolved_chunk_size,
        profile=profile,
        line_stride=line_stride,
        start=start,
        marker=marker,
        passphrase=passphrase,
        deterministic=deterministic,
        seed=seed,
        scrypt_n=scrypt_n,
        scrypt_r=scrypt_r,
        scrypt_p=scrypt_p,
    )
    indices = _candidate_indices(len(lines), line_stride, start)
    if len(indices) < len(records):
        raise ValueError("Carrier does not have enough lines for payload")

    for idx, record in enumerate(records):
        line_index = indices[idx]
        body, ending = _split_line_ending(lines[line_index])
        encoded = _encode_record(record).rstrip(b"\n")
        lines[line_index] = body + marker + encoded + ending

    return b"".join(lines)


def _parse_stego_v1_header(header: bytes) -> Tuple[int, str]:
    if not header.startswith(STEGO_MAGIC_V1 + b":"):
        raise DecodeError("Hidden payload header missing")
    parts = header.split(b":", 2)
    if len(parts) != 3:
        raise DecodeError("Hidden payload header malformed")
    try:
        payload_len = int(parts[1].decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise DecodeError("Hidden payload length is invalid") from exc
    checksum = parts[2].decode("ascii")
    if payload_len < 0:
        raise DecodeError("Hidden payload length is invalid")
    return payload_len, checksum


def _parse_stego_v2_header(header: bytes) -> Dict[str, object]:
    text = header.decode("ascii")
    parts = text.split(":")
    if len(parts) < 8 or parts[0] != STEGO_MAGIC_V2.decode("ascii"):
        raise DecodeError("Hidden payload header malformed")

    mode, profile = parts[1], parts[2]
    if mode not in ("plain-v1", "enc-v1"):
        raise DecodeError("Unsupported hidden payload mode")
    if profile not in STEGO_PROFILES:
        raise DecodeError("Unknown hidden payload profile")

    try:
        chunk_size = int(parts[3])
        line_stride = int(parts[4])
        start = int(parts[5])
        marker = bytes.fromhex(parts[6])
        payload_len = int(parts[7])
    except (ValueError, IndexError) as exc:
        raise DecodeError("Hidden payload header malformed") from exc

    if chunk_size <= 0 or line_stride <= 0 or start < 0 or payload_len < 0:
        raise DecodeError("Hidden payload header malformed")

    parsed: Dict[str, object] = {
        "mode": mode,
        "profile": profile,
        "chunk_size": chunk_size,
        "line_stride": line_stride,
        "start": start,
        "marker": marker,
        "payload_len": payload_len,
    }
    if mode == "plain-v1":
        if len(parts) != 9:
            raise DecodeError("Hidden payload header malformed")
        parsed["checksum"] = parts[8]
    else:
        if len(parts) != 14:
            raise DecodeError("Hidden payload header malformed")
        try:
            parsed["salt"] = bytes.fromhex(parts[8])
            parsed["nonce"] = bytes.fromhex(parts[9])
            parsed["scrypt_n"] = int(parts[10])
            parsed["scrypt_r"] = int(parts[11])
            parsed["scrypt_p"] = int(parts[12])
            parsed["tag"] = bytes.fromhex(parts[13])
        except ValueError as exc:
            raise DecodeError("Hidden payload header malformed") from exc
    return parsed


def _extract_with_marker(stego: bytes, marker: bytes) -> List[bytes]:
    decoded_records: List[bytes] = []
    for line in stego.splitlines(keepends=True):
        body, _ = _split_line_ending(line)
        marker_idx = body.rfind(marker)
        if marker_idx < 0:
            continue
        encoded = body[marker_idx + len(marker) :]
        if not encoded:
            raise DecodeError("Malformed hidden record")
        decoded_records.append(decode_record(encoded))
    return decoded_records


def extract_payload(stego: bytes, *, passphrase: Optional[str] = None) -> bytes:
    """Extract an embedded payload from a text carrier."""
    candidate_markers = [bytes(spec["marker"]) for spec in STEGO_PROFILES.values()]
    if STEGO_V1_SEPARATOR not in candidate_markers:
        candidate_markers.append(STEGO_V1_SEPARATOR)

    for marker in candidate_markers:
        decoded_records = _extract_with_marker(stego, marker)
        if not decoded_records:
            continue

        header = decoded_records[0]
        if header.startswith(STEGO_MAGIC_V1 + b":"):
            payload_len, expected_checksum = _parse_stego_v1_header(header)
            payload = b"".join(decoded_records[1:])
            if len(payload) != payload_len:
                raise DecodeError("Hidden payload length mismatch")
            if hashlib.sha256(payload).hexdigest() != expected_checksum:
                raise DecodeError("Hidden payload checksum mismatch")
            return payload

        if not header.startswith(STEGO_MAGIC_V2 + b":"):
            continue

        parsed = _parse_stego_v2_header(header)
        payload_len = int(parsed["payload_len"])
        chunk_size = int(parsed["chunk_size"])
        record_count = 1 + ((payload_len + chunk_size - 1) // chunk_size)
        if len(decoded_records) < record_count:
            raise DecodeError("Hidden payload length mismatch")
        blob = b"".join(decoded_records[1:record_count])
        if len(blob) != payload_len:
            raise DecodeError("Hidden payload length mismatch")

        if parsed["mode"] == "plain-v1":
            checksum = str(parsed["checksum"])
            if hashlib.sha256(blob).hexdigest() != checksum:
                raise DecodeError("Hidden payload checksum mismatch")
            return blob

        if passphrase is None:
            raise DecodeError("Passphrase required for encrypted hidden payload")

        aad = (
            f"{STEGO_MAGIC_V2.decode('ascii')}:enc-v1:{parsed['profile']}:{chunk_size}:{parsed['line_stride']}:"
            f"{parsed['start']}:{bytes(parsed['marker']).hex()}:{payload_len}"
        ).encode("ascii")
        return _decrypt_payload(
            blob,
            passphrase=passphrase,
            aad=aad,
            salt=bytes(parsed["salt"]),
            nonce=bytes(parsed["nonce"]),
            tag=bytes(parsed["tag"]),
            scrypt_n=int(parsed["scrypt_n"]),
            scrypt_r=int(parsed["scrypt_r"]),
            scrypt_p=int(parsed["scrypt_p"]),
        )

    raise DecodeError("No hidden payload found")


def inspect_file(path: Path, *, verify: bool = True) -> Report:
    """Inspect a DS file without writing output, returning stats and metadata."""
    with path.open("rb") as in_fp:
        return inspect_stream(in_fp, verify=verify)


def encode_stream(
    in_fp: BinaryIO,
    out_fp: BinaryIO,
    *,
    magic: bytes = MAGIC_V2,
    include_metadata: bool = True,
) -> Stats:
    """Stream encoder from a binary file-like input to output."""
    if magic not in (MAGIC_V1, MAGIC_V2):
        raise ValueError("Unsupported magic header")

    out_fp.write(magic)

    sha = hashlib.sha256()
    stats = _init_stats()

    for line in iter(lambda: in_fp.readline(), b""):
        stats["source_bytes"] += len(line)
        stats["source_lines"] += 1
        stats["encoded_records"] += 1
        sha.update(line)
        out_fp.write(_encode_record(line))

    _finish_stats(stats, sha)

    if magic == MAGIC_V2 and include_metadata:
        out_fp.write(META_BEGIN)
        metadata_lines = [
            ("format-version", "2"),
            ("brand", BRAND),
            ("tool", f"ds-codec/{TOOL_VERSION}"),
            ("hash", f"sha256:{stats['sha256']}"),
            ("source-bytes", str(stats["source_bytes"])),
            ("source-lines", str(stats["source_lines"])),
            ("encoded-records", str(stats["encoded_records"])),
        ]
        for key, value in metadata_lines:
            out_fp.write(f"{key}: {value}\n".encode("ascii"))
        out_fp.write(META_END)

    return stats


def _parse_metadata_line(line: bytes) -> Tuple[str, str]:
    try:
        key, value = line.decode("ascii").rstrip("\n").split(":", 1)
    except (UnicodeDecodeError, ValueError) as exc:
        raise DecodeError("Malformed metadata line") from exc
    return key.strip(), value.strip()


def _read_metadata(in_fp: BinaryIO) -> Dict[str, str]:
    metadata: Dict[str, str] = {}
    for raw in in_fp:
        if raw == META_END:
            return metadata
        key, value = _parse_metadata_line(raw)
        metadata[key] = value
    raise DecodeError("Reached EOF while reading metadata")


def _validate_metadata(metadata: Dict[str, str], stats: Stats) -> None:
    if metadata.get("format-version") != "2":
        raise DecodeError("Unsupported metadata format")

    hash_value = metadata.get("hash", "")
    if not hash_value.startswith("sha256:"):
        raise DecodeError("Missing or invalid hash algorithm in metadata")
    if hash_value.split(":", 1)[1] != stats["sha256"]:
        raise DecodeError("Checksum mismatch")

    for key in ("source-bytes", "source-lines", "encoded-records"):
        expected = metadata.get(key)
        if expected is None:
            raise DecodeError(f"Missing metadata field {key}")
        try:
            expected_int = int(expected)
        except ValueError as exc:
            raise DecodeError(f"Non-integer metadata field {key}") from exc
        actual = stats[key.replace("-", "_")]
        if expected_int != actual:
            raise DecodeError(f"Metadata mismatch for {key}: {expected_int} != {actual}")


def _ensure_no_trailing_data(in_fp: BinaryIO) -> None:
    if in_fp.read(1):
        raise DecodeError("Trailing data detected after metadata trailer")


def _decode_v1(in_fp: BinaryIO, out_fp: BinaryIO) -> Report:
    sha = hashlib.sha256()
    stats = _init_stats()

    for raw in in_fp:
        decoded = _decode_record(raw.rstrip(b"\n"))
        out_fp.write(decoded)
        sha.update(decoded)
        stats["source_bytes"] += len(decoded)
        stats["source_lines"] += 1
        stats["encoded_records"] += 1

    _finish_stats(stats, sha)
    return {"format": "ds1", "verified": False, "metadata": None, "stats": stats}


def _decode_v2(in_fp: BinaryIO, out_fp: BinaryIO, *, verify: bool) -> Report:
    sha = hashlib.sha256()
    stats = _init_stats()

    for raw in in_fp:
        if raw == META_BEGIN:
            metadata = _read_metadata(in_fp)
            _finish_stats(stats, sha)
            if verify:
                _validate_metadata(metadata, stats)
            _ensure_no_trailing_data(in_fp)
            return {"format": "ds2", "verified": verify, "metadata": metadata, "stats": stats}

        decoded = _decode_record(raw.rstrip(b"\n"))
        out_fp.write(decoded)
        sha.update(decoded)
        stats["source_bytes"] += len(decoded)
        stats["source_lines"] += 1
        stats["encoded_records"] += 1

    raise DecodeError("Missing metadata block")


def decode_stream(in_fp: BinaryIO, out_fp: BinaryIO, *, verify: bool = True) -> Report:
    """Stream decoder from a binary file-like input to output."""
    header = _read_header(in_fp)
    if header == MAGIC_V1:
        return _decode_v1(in_fp, out_fp)
    return _decode_v2(in_fp, out_fp, verify=verify)


def inspect_stream(in_fp: BinaryIO, *, verify: bool = True) -> Report:
    """Inspect a DS stream without materializing output, returning stats/metadata."""
    header = _read_header(in_fp)
    sink = _NullWriter()
    if header == MAGIC_V1:
        return _decode_v1(in_fp, sink)
    return _decode_v2(in_fp, sink, verify=verify)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"{BRAND} encoder/decoder",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    enc = subparsers.add_parser("encode", help="Encode raw file to .ds")
    enc.add_argument("input", type=str, help="Input file path or '-' for stdin")
    enc.add_argument("output", type=str, help="Output .ds path or '-' for stdout")
    enc.add_argument(
        "--format",
        choices=["ds2", "ds1"],
        default="ds2",
        help="Format version (ds2 adds metadata/checksum)",
    )

    dec = subparsers.add_parser("decode", help="Decode .ds to raw file")
    dec.add_argument("input", type=str, help=".ds input file path or '-' for stdin")
    dec.add_argument("output", type=str, help="Decoded output path or '-' for stdout")

    insp = subparsers.add_parser("inspect", help="Inspect and verify a .ds file")
    insp.add_argument("input", type=str, help=".ds input file path or '-' for stdin")
    insp.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip checksum verification (not recommended for ds2 files)",
    )
    insp.add_argument(
        "--no-metadata",
        action="store_true",
        help="Hide metadata lines in output",
    )
    insp.add_argument(
        "--json",
        action="store_true",
        help="Emit inspection report as JSON (respects --no-metadata)",
    )

    hide = subparsers.add_parser("hide", help="Embed secret bytes into a text carrier")
    hide.add_argument("cover", type=str, help="Carrier text path or '-' for stdin")
    hide.add_argument("secret", type=str, help="Secret input path")
    hide.add_argument("output", type=str, help="Stego output path or '-' for stdout")
    hide.add_argument(
        "--profile",
        choices=sorted(STEGO_PROFILES.keys()),
        default=DEFAULT_STEGO_PROFILE,
        help="Embedding profile",
    )
    hide.add_argument(
        "--chunk-size",
        type=int,
        default=None,
        help="Secret bytes per hidden record line",
    )
    hide.add_argument("--passphrase", type=str, default=None, help="Optional passphrase for encrypted payload mode")
    hide.add_argument("--deterministic", action="store_true", help="Use deterministic stego placement/encryption nonces")
    hide.add_argument("--seed", type=str, default=None, help="Deterministic seed")
    hide.add_argument("--scrypt-n", type=int, default=DEFAULT_SCRYPT_N, help="Scrypt N parameter")
    hide.add_argument("--scrypt-r", type=int, default=DEFAULT_SCRYPT_R, help="Scrypt r parameter")
    hide.add_argument("--scrypt-p", type=int, default=DEFAULT_SCRYPT_P, help="Scrypt p parameter")
    hide.add_argument("--manifest-out", type=str, default=None, help="Optional path to write operation manifest JSON")
    hide.add_argument("--manifest-key", type=str, default=None, help="Optional manifest signing key")
    hide.add_argument("--policy", type=str, default=None, help="Policy JSON path")
    hide.add_argument("--ack-authorized-use", action="store_true", help="Acknowledge authorized and lawful use")
    hide.add_argument("--engagement", type=str, default=None, help="Engagement identifier for policy enforcement")
    hide.add_argument(
        "--classification",
        choices=DEFAULT_ALLOWED_CLASSIFICATIONS,
        default="internal",
        help="Data classification tag",
    )

    reveal = subparsers.add_parser("reveal", help="Extract hidden secret bytes from a stego text")
    reveal.add_argument("input", type=str, help="Stego input path or '-' for stdin")
    reveal.add_argument("output", type=str, help="Recovered secret output path or '-' for stdout")
    reveal.add_argument("--passphrase", type=str, default=None, help="Passphrase for encrypted payload mode")
    reveal.add_argument("--manifest-out", type=str, default=None, help="Optional path to write operation manifest JSON")
    reveal.add_argument("--manifest-key", type=str, default=None, help="Optional manifest signing key")
    reveal.add_argument("--policy", type=str, default=None, help="Policy JSON path")
    reveal.add_argument("--ack-authorized-use", action="store_true", help="Acknowledge authorized and lawful use")
    reveal.add_argument("--engagement", type=str, default=None, help="Engagement identifier for policy enforcement")
    reveal.add_argument(
        "--classification",
        choices=DEFAULT_ALLOWED_CLASSIFICATIONS,
        default="internal",
        help="Data classification tag",
    )

    capacity = subparsers.add_parser("capacity", help="Estimate stego capacity of a text carrier")
    capacity.add_argument("cover", type=str, help="Carrier text path or '-' for stdin")
    capacity.add_argument(
        "--secret",
        type=str,
        default=None,
        help="Optional secret path for preflight fit check",
    )
    capacity.add_argument(
        "--chunk-size",
        type=int,
        default=None,
        help="Secret bytes per hidden record line",
    )
    capacity.add_argument(
        "--profile",
        choices=sorted(STEGO_PROFILES.keys()),
        default=DEFAULT_STEGO_PROFILE,
        help="Embedding profile",
    )
    capacity.add_argument("--deterministic", action="store_true", help="Use deterministic line selection for capacity estimate")
    capacity.add_argument("--seed", type=str, default=None, help="Deterministic seed")
    capacity.add_argument("--manifest-out", type=str, default=None, help="Optional path to write operation manifest JSON")
    capacity.add_argument("--manifest-key", type=str, default=None, help="Optional manifest signing key")
    capacity.add_argument("--policy", type=str, default=None, help="Policy JSON path")
    capacity.add_argument("--ack-authorized-use", action="store_true", help="Acknowledge authorized and lawful use")
    capacity.add_argument("--engagement", type=str, default=None, help="Engagement identifier for policy enforcement")
    capacity.add_argument(
        "--classification",
        choices=DEFAULT_ALLOWED_CLASSIFICATIONS,
        default="internal",
        help="Data classification tag",
    )
    capacity.add_argument(
        "--json",
        action="store_true",
        help="Emit capacity report as JSON",
    )

    carrier = subparsers.add_parser("analyze-carrier", help="Analyze carrier risk and transformation stability")
    carrier.add_argument("cover", type=str, help="Carrier text path or '-' for stdin")
    carrier.add_argument("--manifest-out", type=str, default=None, help="Optional path to write operation manifest JSON")
    carrier.add_argument("--manifest-key", type=str, default=None, help="Optional manifest signing key")
    carrier.add_argument("--policy", type=str, default=None, help="Policy JSON path")
    carrier.add_argument("--ack-authorized-use", action="store_true", help="Acknowledge authorized and lawful use")
    carrier.add_argument("--engagement", type=str, default=None, help="Engagement identifier for policy enforcement")
    carrier.add_argument(
        "--classification",
        choices=DEFAULT_ALLOWED_CLASSIFICATIONS,
        default="internal",
        help="Data classification tag",
    )
    carrier.add_argument("--json", action="store_true", help="Emit carrier report as JSON")

    verify_manifest = subparsers.add_parser("verify-manifest", help="Verify a signed operation manifest")
    verify_manifest.add_argument("input", type=str, help="Manifest JSON file path")
    verify_manifest.add_argument("--manifest-key", type=str, required=True, help="Manifest signing key")
    verify_manifest.add_argument("--json", action="store_true", help="Emit verification report as JSON")

    split_cmd = subparsers.add_parser("split-payload", help="Split secret into threshold shards")
    split_cmd.add_argument("secret", type=str, help="Secret input path")
    split_cmd.add_argument("output_prefix", type=str, help="Output shard file prefix")
    split_cmd.add_argument("--total-shards", type=int, required=True, help="Total number of shards")
    split_cmd.add_argument("--threshold", type=int, required=True, help="Minimum shards required to reconstruct")
    split_cmd.add_argument("--deterministic", action="store_true", help="Deterministic shard generation")
    split_cmd.add_argument("--seed", type=str, default=None, help="Deterministic seed")
    split_cmd.add_argument("--manifest-out", type=str, default=None, help="Optional path to write operation manifest JSON")
    split_cmd.add_argument("--manifest-key", type=str, default=None, help="Optional manifest signing key")
    split_cmd.add_argument("--policy", type=str, default=None, help="Policy JSON path")
    split_cmd.add_argument("--ack-authorized-use", action="store_true", help="Acknowledge authorized and lawful use")
    split_cmd.add_argument("--engagement", type=str, default=None, help="Engagement identifier for policy enforcement")
    split_cmd.add_argument(
        "--classification",
        choices=DEFAULT_ALLOWED_CLASSIFICATIONS,
        default="internal",
        help="Data classification tag",
    )
    split_cmd.add_argument("--json", action="store_true", help="Emit split report as JSON")

    reconstruct_cmd = subparsers.add_parser("reconstruct-payload", help="Reconstruct secret from shard files")
    reconstruct_cmd.add_argument("output", type=str, help="Recovered output path or '-' for stdout")
    reconstruct_cmd.add_argument("shards", nargs="+", type=str, help="Shard file paths")
    reconstruct_cmd.add_argument("--manifest-out", type=str, default=None, help="Optional path to write operation manifest JSON")
    reconstruct_cmd.add_argument("--manifest-key", type=str, default=None, help="Optional manifest signing key")
    reconstruct_cmd.add_argument("--policy", type=str, default=None, help="Policy JSON path")
    reconstruct_cmd.add_argument("--ack-authorized-use", action="store_true", help="Acknowledge authorized and lawful use")
    reconstruct_cmd.add_argument("--engagement", type=str, default=None, help="Engagement identifier for policy enforcement")
    reconstruct_cmd.add_argument(
        "--classification",
        choices=DEFAULT_ALLOWED_CLASSIFICATIONS,
        default="internal",
        help="Data classification tag",
    )
    reconstruct_cmd.add_argument("--json", action="store_true", help="Emit reconstruction report as JSON")

    survivability = subparsers.add_parser("evaluate-survivability", help="Evaluate payload recovery after common text transformations")
    survivability.add_argument("cover", type=str, help="Carrier text path or '-' for stdin")
    survivability.add_argument("secret", type=str, help="Secret input path")
    survivability.add_argument(
        "--profile",
        choices=sorted(STEGO_PROFILES.keys()),
        default=DEFAULT_STEGO_PROFILE,
        help="Embedding profile",
    )
    survivability.add_argument("--chunk-size", type=int, default=None, help="Secret bytes per hidden record line")
    survivability.add_argument("--passphrase", type=str, default=None, help="Optional passphrase for encrypted payload mode")
    survivability.add_argument("--deterministic", action="store_true", help="Use deterministic embedding")
    survivability.add_argument("--seed", type=str, default=None, help="Deterministic seed")
    survivability.add_argument("--scrypt-n", type=int, default=DEFAULT_SCRYPT_N, help="Scrypt N parameter")
    survivability.add_argument("--scrypt-r", type=int, default=DEFAULT_SCRYPT_R, help="Scrypt r parameter")
    survivability.add_argument("--scrypt-p", type=int, default=DEFAULT_SCRYPT_P, help="Scrypt p parameter")
    survivability.add_argument(
        "--transforms",
        type=str,
        default=",".join(DEFAULT_TRANSFORMS),
        help="Comma-separated transforms (identity,normalize_lf,normalize_crlf,trim_trailing_ws,strip_final_newline)",
    )
    survivability.add_argument("--min-pass-rate", type=float, default=0.0, help="Fail with exit code 3 if pass_rate is below threshold")
    survivability.add_argument("--manifest-out", type=str, default=None, help="Optional path to write operation manifest JSON")
    survivability.add_argument("--manifest-key", type=str, default=None, help="Optional manifest signing key")
    survivability.add_argument("--policy", type=str, default=None, help="Policy JSON path")
    survivability.add_argument("--ack-authorized-use", action="store_true", help="Acknowledge authorized and lawful use")
    survivability.add_argument("--engagement", type=str, default=None, help="Engagement identifier for policy enforcement")
    survivability.add_argument(
        "--classification",
        choices=DEFAULT_ALLOWED_CLASSIFICATIONS,
        default="internal",
        help="Data classification tag",
    )
    survivability.add_argument("--json", action="store_true", help="Emit survivability report as JSON")

    return parser


def _supports_color(stream: Any) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    term = os.environ.get("TERM", "")
    if term.lower() == "dumb":
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(callable(isatty) and isatty())


def _paint(text: str, code: str, *, stream: Any) -> str:
    if not _supports_color(stream):
        return text
    return f"\033[{code}m{text}\033[0m"


def _print_mascot(stream: Any = sys.stdout) -> None:
    print(_paint(MASCOT, "36", stream=stream), file=stream)


def _print_section(title: str, rows: List[Tuple[str, str]], *, stream: Any = sys.stdout) -> None:
    title_text = _paint(f"[ {title} ]", "1;35", stream=stream)
    print(title_text, file=stream)
    key_color = "1;34"
    for key, value in rows:
        key_text = _paint(f"{key:<18}", key_color, stream=stream)
        print(f"{key_text} {value}", file=stream)


def _print_summary(
    action: str,
    stats: Stats,
    *,
    format_label: str,
    verified: Optional[bool],
    stream: Any = sys.stdout,
) -> None:
    _print_mascot(stream)
    rows = [
        ("brand", BRAND),
        ("action", action),
        ("format", format_label),
    ]
    if verified is not None:
        rows.append(("verified", "n/a (ds1)" if format_label == "ds1" else ("yes" if verified else "no")))
    rows.extend(
        [
            ("source-bytes", str(stats["source_bytes"])),
            ("source-lines", str(stats["source_lines"])),
            ("encoded-records", str(stats["encoded_records"])),
            ("sha256", str(stats["sha256"])),
        ]
    )
    _print_section("Summary", rows, stream=stream)


def _print_inspection(report: Report, *, show_metadata: bool, stream: Any = sys.stdout) -> None:
    stats: Stats = report["stats"]  # type: ignore[assignment]
    metadata: Optional[Dict[str, str]] = report.get("metadata")  # type: ignore[assignment]

    _print_summary(
        "inspect",
        stats,
        format_label=report["format"],  # type: ignore[arg-type]
        verified=report.get("verified"),  # type: ignore[arg-type]
        stream=stream,
    )
    if show_metadata and metadata:
        metadata_rows = [(key, value) for key, value in metadata.items()]
        _print_section("Metadata", metadata_rows, stream=stream)


def _fail(message: str, exit_code: int = 1) -> None:
    _print_mascot(sys.stderr)
    prefix = _paint(f"{BRAND} error:", "1;31", stream=sys.stderr)
    print(f"{prefix} {message}", file=sys.stderr)
    raise SystemExit(exit_code)


def _guard_distinct_paths(input_path: str, output_path: str) -> None:
    if input_path == "-" or output_path == "-":
        return
    if Path(input_path).resolve() == Path(output_path).resolve():
        _fail("Input and output paths must differ to avoid clobbering data")


@contextlib.contextmanager
def _open_binary_input(path: str) -> Iterator[BinaryIO]:
    if path == "-":
        yield sys.stdin.buffer
        return
    with Path(path).open("rb") as fp:
        yield fp


@contextlib.contextmanager
def _open_binary_output(path: str) -> Iterator[BinaryIO]:
    if path == "-":
        yield sys.stdout.buffer
        return
    with Path(path).open("wb") as fp:
        yield fp


def cli_main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    try:
        if args.command == "encode":
            magic = MAGIC_V2 if args.format == "ds2" else MAGIC_V1
            _guard_distinct_paths(args.input, args.output)
            summary_stream = sys.stderr if args.output == "-" else sys.stdout
            with contextlib.ExitStack() as stack:
                in_fp = stack.enter_context(_open_binary_input(args.input))
                out_fp = stack.enter_context(_open_binary_output(args.output))
                stats = encode_stream(in_fp, out_fp, magic=magic, include_metadata=True)
            _print_summary("encoded", stats, format_label=args.format, verified=magic == MAGIC_V2, stream=summary_stream)
            return

        if args.command == "decode":
            _guard_distinct_paths(args.input, args.output)
            summary_stream = sys.stderr if args.output == "-" else sys.stdout
            with contextlib.ExitStack() as stack:
                in_fp = stack.enter_context(_open_binary_input(args.input))
                out_fp = stack.enter_context(_open_binary_output(args.output))
                info = decode_stream(in_fp, out_fp, verify=True)
            _print_summary(  # type: ignore[arg-type]
                "decoded",
                info["stats"],
                format_label=info["format"],
                verified=info.get("verified"),
                stream=summary_stream,
            )
            return

        if args.command == "inspect":
            with contextlib.ExitStack() as stack:
                in_fp = stack.enter_context(_open_binary_input(args.input))
                report = inspect_stream(in_fp, verify=not args.no_verify)

            if args.json:
                payload = dict(report)
                if args.no_metadata:
                    payload["metadata"] = None
                print(json.dumps(payload), file=sys.stdout)
            else:
                _print_inspection(report, show_metadata=not args.no_metadata)
            return

        if args.command == "hide":
            _guard_distinct_paths(args.cover, args.output)
            _guard_distinct_paths(args.secret, args.output)
            if args.manifest_out is not None:
                _guard_distinct_paths(args.output, args.manifest_out)
            summary_stream = sys.stderr if args.output == "-" else sys.stdout
            deterministic_mode = bool(args.deterministic or args.seed is not None)
            policy = load_policy(args.policy)
            _enforce_policy(
                policy,
                operation="hide",
                ack_authorized_use=args.ack_authorized_use,
                engagement=args.engagement,
                classification=args.classification,
            )
            _print_authorization_banner(
                summary_stream,
                operation="hide",
                engagement=args.engagement,
                classification=args.classification,
            )
            with contextlib.ExitStack() as stack:
                cover_fp = stack.enter_context(_open_binary_input(args.cover))
                secret_fp = stack.enter_context(_open_binary_input(args.secret))
                out_fp = stack.enter_context(_open_binary_output(args.output))
                cover = cover_fp.read()
                secret = secret_fp.read()
                stego = embed_payload(
                    cover,
                    secret,
                    profile=args.profile,
                    chunk_size=args.chunk_size,
                    passphrase=args.passphrase,
                    deterministic=deterministic_mode,
                    seed=args.seed,
                    scrypt_n=args.scrypt_n,
                    scrypt_r=args.scrypt_r,
                    scrypt_p=args.scrypt_p,
                )
                out_fp.write(stego)
            if args.manifest_out is not None:
                manifest = generate_operation_manifest(
                    "hide",
                    {
                        "profile": args.profile,
                        "deterministic": deterministic_mode,
                        "encrypted": args.passphrase is not None,
                        "cover_sha256": _sha256_hex(cover),
                        "secret_sha256": _sha256_hex(secret),
                        "stego_sha256": _sha256_hex(stego),
                        "cover_bytes": len(cover),
                        "secret_bytes": len(secret),
                        "stego_bytes": len(stego),
                        "engagement": args.engagement,
                        "classification": args.classification,
                    },
                    signing_key=args.manifest_key,
                )
                _write_manifest(args.manifest_out, manifest)
            _print_mascot(summary_stream)
            _print_section(
                "Stego Hide",
                [
                    ("brand", BRAND),
                    ("action", "hidden payload"),
                    ("profile", args.profile),
                    ("encrypted", "yes" if args.passphrase else "no"),
                    ("deterministic", "yes" if deterministic_mode else "no"),
                    ("cover-bytes", str(len(cover))),
                    ("secret-bytes", str(len(secret))),
                    ("chunk-size", "profile-default" if args.chunk_size is None else str(args.chunk_size)),
                ],
                stream=summary_stream,
            )
            return

        if args.command == "reveal":
            _guard_distinct_paths(args.input, args.output)
            if args.manifest_out is not None:
                _guard_distinct_paths(args.output, args.manifest_out)
            summary_stream = sys.stderr if args.output == "-" else sys.stdout
            policy = load_policy(args.policy)
            _enforce_policy(
                policy,
                operation="reveal",
                ack_authorized_use=args.ack_authorized_use,
                engagement=args.engagement,
                classification=args.classification,
            )
            _print_authorization_banner(
                summary_stream,
                operation="reveal",
                engagement=args.engagement,
                classification=args.classification,
            )
            with contextlib.ExitStack() as stack:
                in_fp = stack.enter_context(_open_binary_input(args.input))
                out_fp = stack.enter_context(_open_binary_output(args.output))
                stego = in_fp.read()
                secret = extract_payload(stego, passphrase=args.passphrase)
                out_fp.write(secret)
            if args.manifest_out is not None:
                manifest = generate_operation_manifest(
                    "reveal",
                    {
                        "encrypted_input": args.passphrase is not None,
                        "stego_sha256": _sha256_hex(stego),
                        "secret_sha256": _sha256_hex(secret),
                        "stego_bytes": len(stego),
                        "secret_bytes": len(secret),
                        "engagement": args.engagement,
                        "classification": args.classification,
                    },
                    signing_key=args.manifest_key,
                )
                _write_manifest(args.manifest_out, manifest)
            _print_mascot(summary_stream)
            _print_section(
                "Stego Reveal",
                [
                    ("brand", BRAND),
                    ("action", "revealed payload"),
                    ("encrypted", "yes" if args.passphrase else "auto"),
                    ("secret-bytes", str(len(secret))),
                ],
                stream=summary_stream,
            )
            return

        if args.command == "capacity":
            if args.cover == "-" and args.secret == "-":
                _fail("cover and secret cannot both be '-'")
            if args.manifest_out is not None and args.cover != "-" and Path(args.manifest_out).resolve() == Path(args.cover).resolve():
                _fail("Manifest output and cover paths must differ")

            deterministic_mode = bool(args.deterministic or args.seed is not None)
            policy = load_policy(args.policy)
            _enforce_policy(
                policy,
                operation="capacity",
                ack_authorized_use=args.ack_authorized_use,
                engagement=args.engagement,
                classification=args.classification,
            )
            if not args.json:
                _print_authorization_banner(
                    sys.stdout,
                    operation="capacity",
                    engagement=args.engagement,
                    classification=args.classification,
                )
            with contextlib.ExitStack() as stack:
                cover_fp = stack.enter_context(_open_binary_input(args.cover))
                cover = cover_fp.read()
                resolved_chunk_size, _, _ = _profile_settings(args.profile, args.chunk_size)
                max_payload_bytes = estimate_capacity(
                    cover,
                    chunk_size=args.chunk_size,
                    profile=args.profile,
                    deterministic=deterministic_mode,
                    seed=args.seed,
                )
                line_count = len(cover.splitlines(keepends=True))

                payload_bytes: Optional[int] = None
                fits: Optional[bool] = None
                needed_lines: Optional[int] = None
                available_payload_lines = max_payload_bytes // resolved_chunk_size

                if args.secret is not None:
                    secret_fp = stack.enter_context(_open_binary_input(args.secret))
                    payload_bytes = len(secret_fp.read())
                    fits = payload_bytes <= max_payload_bytes
                    needed_lines = 1 + ((payload_bytes + resolved_chunk_size - 1) // resolved_chunk_size)

            report: Dict[str, object] = {
                "profile": args.profile,
                "chunk_size": args.chunk_size,
                "effective_chunk_size": resolved_chunk_size,
                "carrier_lines": line_count,
                "available_payload_lines": available_payload_lines,
                "max_payload_bytes": max_payload_bytes,
                "payload_bytes": payload_bytes,
                "fits": fits,
                "needed_lines": needed_lines,
                "deterministic": deterministic_mode,
            }
            if args.manifest_out is not None:
                manifest = generate_operation_manifest(
                    "capacity",
                    {
                        "profile": args.profile,
                        "deterministic": deterministic_mode,
                        "cover_sha256": _sha256_hex(cover),
                        "report": report,
                        "engagement": args.engagement,
                        "classification": args.classification,
                    },
                    signing_key=args.manifest_key,
                )
                _write_manifest(args.manifest_out, manifest)

            if args.json:
                print(json.dumps(report), file=sys.stdout)
            else:
                _print_mascot(sys.stdout)
                rows = [
                    ("brand", BRAND),
                    ("action", "capacity"),
                    ("profile", str(report["profile"])),
                    ("deterministic", "yes" if deterministic_mode else "no"),
                    ("chunk-size", str(report["effective_chunk_size"])),
                    ("carrier-lines", str(report["carrier_lines"])),
                    ("payload-lines", str(report["available_payload_lines"])),
                    ("max-payload-bytes", str(report["max_payload_bytes"])),
                ]
                if payload_bytes is not None:
                    fit_text = "yes" if fits else "no"
                    rows.extend(
                        [
                            ("secret-bytes", str(payload_bytes)),
                            ("needed-lines", str(needed_lines)),
                            ("fits", fit_text),
                        ]
                    )
                _print_section("Stego Capacity", rows, stream=sys.stdout)
            return

        if args.command == "analyze-carrier":
            if args.manifest_out is not None and args.cover != "-" and Path(args.manifest_out).resolve() == Path(args.cover).resolve():
                _fail("Manifest output and cover paths must differ")
            policy = load_policy(args.policy)
            _enforce_policy(
                policy,
                operation="analyze-carrier",
                ack_authorized_use=args.ack_authorized_use,
                engagement=args.engagement,
                classification=args.classification,
            )
            with contextlib.ExitStack() as stack:
                cover_fp = stack.enter_context(_open_binary_input(args.cover))
                cover = cover_fp.read()
            report = analyze_carrier(cover)
            if args.manifest_out is not None:
                manifest = generate_operation_manifest(
                    "analyze-carrier",
                    {
                        "cover_sha256": _sha256_hex(cover),
                        "report": report,
                        "engagement": args.engagement,
                        "classification": args.classification,
                    },
                    signing_key=args.manifest_key,
                )
                _write_manifest(args.manifest_out, manifest)
            if args.json:
                print(json.dumps(report), file=sys.stdout)
            else:
                _print_authorization_banner(
                    sys.stdout,
                    operation="analyze-carrier",
                    engagement=args.engagement,
                    classification=args.classification,
                )
                _print_mascot(sys.stdout)
                rows = [
                    ("brand", BRAND),
                    ("action", "analyze-carrier"),
                    ("carrier-bytes", str(report["carrier_bytes"])),
                    ("carrier-lines", str(report["carrier_lines"])),
                    ("risk-score", str(report["risk_score"])),
                    ("risk-level", str(report["risk_level"])),
                    ("mixed-newlines", "yes" if report["mixed_newlines"] else "no"),
                    ("trailing-ws-ratio", str(report["trailing_whitespace_ratio"])),
                ]
                _print_section("Carrier Analysis", rows, stream=sys.stdout)
            return

        if args.command == "split-payload":
            if args.manifest_out is not None and Path(args.manifest_out).resolve() == Path(args.secret).resolve():
                _fail("Manifest output and secret paths must differ")
            policy = load_policy(args.policy)
            _enforce_policy(
                policy,
                operation="split-payload",
                ack_authorized_use=args.ack_authorized_use,
                engagement=args.engagement,
                classification=args.classification,
            )
            with contextlib.ExitStack() as stack:
                secret_fp = stack.enter_context(_open_binary_input(args.secret))
                secret = secret_fp.read()
            shards = split_payload(
                secret,
                total_shards=args.total_shards,
                threshold=args.threshold,
                deterministic=bool(args.deterministic or args.seed is not None),
                seed=args.seed,
            )
            written_paths: List[str] = []
            for idx, shard in enumerate(shards, start=1):
                shard_path = f"{args.output_prefix}.part-{idx:02d}.dsshard"
                with Path(shard_path).open("wb") as fp:
                    fp.write(shard)
                written_paths.append(shard_path)

            report: Dict[str, object] = {
                "total_shards": args.total_shards,
                "threshold": args.threshold,
                "deterministic": bool(args.deterministic or args.seed is not None),
                "seed": args.seed,
                "secret_bytes": len(secret),
                "secret_sha256": _sha256_hex(secret),
                "output_prefix": args.output_prefix,
                "written_shards": written_paths,
                "engagement": args.engagement,
                "classification": args.classification,
            }
            if args.manifest_out is not None:
                manifest = generate_operation_manifest(
                    "split-payload",
                    report,
                    signing_key=args.manifest_key,
                )
                _write_manifest(args.manifest_out, manifest)

            if args.json:
                print(json.dumps(report), file=sys.stdout)
            else:
                _print_authorization_banner(
                    sys.stdout,
                    operation="split-payload",
                    engagement=args.engagement,
                    classification=args.classification,
                )
                _print_mascot(sys.stdout)
                rows = [
                    ("brand", BRAND),
                    ("action", "split-payload"),
                    ("total-shards", str(report["total_shards"])),
                    ("threshold", str(report["threshold"])),
                    ("secret-bytes", str(report["secret_bytes"])),
                    ("secret-sha256", str(report["secret_sha256"])),
                ]
                _print_section("Shard Split", rows, stream=sys.stdout)
            return

        if args.command == "reconstruct-payload":
            if args.json and args.output == "-":
                _fail("Cannot use --json when output is '-'")
            if args.manifest_out is not None and args.output != "-" and Path(args.manifest_out).resolve() == Path(args.output).resolve():
                _fail("Manifest output and output paths must differ")
            policy = load_policy(args.policy)
            _enforce_policy(
                policy,
                operation="reconstruct-payload",
                ack_authorized_use=args.ack_authorized_use,
                engagement=args.engagement,
                classification=args.classification,
            )
            shard_blobs: List[bytes] = []
            for shard_path in args.shards:
                with Path(shard_path).open("rb") as fp:
                    shard_blobs.append(fp.read())
            secret = reconstruct_payload(shard_blobs)
            with contextlib.ExitStack() as stack:
                out_fp = stack.enter_context(_open_binary_output(args.output))
                out_fp.write(secret)

            report = {
                "provided_shards": len(args.shards),
                "secret_bytes": len(secret),
                "secret_sha256": _sha256_hex(secret),
                "output": args.output,
                "engagement": args.engagement,
                "classification": args.classification,
            }
            if args.manifest_out is not None:
                manifest = generate_operation_manifest(
                    "reconstruct-payload",
                    report,
                    signing_key=args.manifest_key,
                )
                _write_manifest(args.manifest_out, manifest)

            if args.json:
                print(json.dumps(report), file=sys.stdout)
            else:
                _print_authorization_banner(
                    sys.stdout,
                    operation="reconstruct-payload",
                    engagement=args.engagement,
                    classification=args.classification,
                )
                _print_mascot(sys.stdout)
                rows = [
                    ("brand", BRAND),
                    ("action", "reconstruct-payload"),
                    ("provided-shards", str(report["provided_shards"])),
                    ("secret-bytes", str(report["secret_bytes"])),
                    ("secret-sha256", str(report["secret_sha256"])),
                ]
                _print_section("Shard Reconstruct", rows, stream=sys.stdout)
            return

        if args.command == "evaluate-survivability":
            policy = load_policy(args.policy)
            _enforce_policy(
                policy,
                operation="evaluate-survivability",
                ack_authorized_use=args.ack_authorized_use,
                engagement=args.engagement,
                classification=args.classification,
            )
            transforms = [part.strip() for part in args.transforms.split(",") if part.strip()]
            deterministic_mode = bool(args.deterministic or args.seed is not None)
            with contextlib.ExitStack() as stack:
                cover_fp = stack.enter_context(_open_binary_input(args.cover))
                secret_fp = stack.enter_context(_open_binary_input(args.secret))
                cover = cover_fp.read()
                secret = secret_fp.read()
            report = evaluate_survivability(
                cover,
                secret,
                profile=args.profile,
                chunk_size=args.chunk_size,
                passphrase=args.passphrase,
                deterministic=deterministic_mode,
                seed=args.seed,
                scrypt_n=args.scrypt_n,
                scrypt_r=args.scrypt_r,
                scrypt_p=args.scrypt_p,
                transforms=transforms,
            )
            report["engagement"] = args.engagement
            report["classification"] = args.classification
            report["min_pass_rate"] = args.min_pass_rate

            if args.manifest_out is not None:
                manifest = generate_operation_manifest(
                    "evaluate-survivability",
                    {
                        "profile": args.profile,
                        "deterministic": deterministic_mode,
                        "encrypted": args.passphrase is not None,
                        "cover_sha256": _sha256_hex(cover),
                        "secret_sha256": _sha256_hex(secret),
                        "report": report,
                        "engagement": args.engagement,
                        "classification": args.classification,
                    },
                    signing_key=args.manifest_key,
                )
                _write_manifest(args.manifest_out, manifest)

            if args.json:
                print(json.dumps(report), file=sys.stdout)
            else:
                _print_authorization_banner(
                    sys.stdout,
                    operation="evaluate-survivability",
                    engagement=args.engagement,
                    classification=args.classification,
                )
                _print_mascot(sys.stdout)
                rows = [
                    ("brand", BRAND),
                    ("action", "evaluate-survivability"),
                    ("profile", str(report["profile"])),
                    ("encrypted", "yes" if report["encrypted"] else "no"),
                    ("pass-rate", str(report["pass_rate"])),
                    ("passed", str(report["passed"])),
                    ("failed", str(report["failed"])),
                ]
                _print_section("Survivability", rows, stream=sys.stdout)

            if float(report["pass_rate"]) < args.min_pass_rate:
                raise SystemExit(3)
            return

        if args.command == "verify-manifest":
            with Path(args.input).open("r", encoding="utf-8") as fp:
                manifest_obj = json.load(fp)
            if not isinstance(manifest_obj, dict):
                _fail("Manifest JSON must be an object")
            ok = verify_operation_manifest(manifest_obj, args.manifest_key)
            if args.json:
                print(json.dumps({"verified": ok}), file=sys.stdout)
            else:
                _print_mascot(sys.stdout)
                _print_section("Manifest Verify", [("brand", BRAND), ("verified", "yes" if ok else "no")], stream=sys.stdout)
            if not ok:
                raise SystemExit(2)
            return

        parser.print_help()
    except DecodeError as exc:
        _fail(f"Decode error: {exc}")
    except FileNotFoundError as exc:
        _fail(f"File not found: {exc.filename}")
    except PermissionError as exc:
        _fail(f"Permission denied: {exc.filename}")
    except OSError as exc:
        _fail(str(exc))


if __name__ == "__main__":
    cli_main()
