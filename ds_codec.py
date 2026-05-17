#!/usr/bin/env python3
"""
DarkSwan .ds encoder/decoder.

Format overview:
    - V1: MAGIC b"DARKSWAN-DS1\\n", whitespace records only (no metadata).
    - V2: MAGIC b"DARKSWAN-DS2\\n", whitespace records followed by a metadata
      trailer guarded by sentinels to detect corruption.
    - Each source line is encoded independently as runs of spaces separated by tabs.
      A byte becomes two runs (hi nibble, lo nibble). Each run length is the nibble value.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import sys
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterator, List, Optional, Tuple

BRAND = "DarkSwan(tm)"
TOOL_VERSION = "0.3.0"
MAGIC_V1 = b"DARKSWAN-DS1\n"
MAGIC_V2 = b"DARKSWAN-DS2\n"
META_BEGIN = b"##META\n"
META_END = b"##ENDMETA\n"
NIBBLE_MAX = 0x0F


class DecodeError(RuntimeError):
    """Raised when the input is not valid DS data."""


class _NullWriter:
    """Sink that discards writes, used for inspection without materializing data."""

    def write(self, data: bytes) -> int:  # noqa: D401
        return len(data)


def _encode_record(line: bytes) -> bytes:
    segments: List[bytes] = []
    for byte in line:
        hi = byte >> 4
        lo = byte & NIBBLE_MAX
        segments.append(b" " * hi + b"\t" + b" " * lo + b"\t")
    segments.append(b"\n")
    return b"".join(segments)


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


def encode_bytes(data: bytes, *, magic: bytes = MAGIC_V2, include_metadata: bool = True) -> bytes:
    """Encode raw bytes into DS format."""
    buffer = io.BytesIO(data)
    out = io.BytesIO()
    encode_stream(buffer, out, magic=magic, include_metadata=include_metadata)
    return out.getvalue()


def decode_bytes(encoded: bytes) -> bytes:
    """Decode DS format back into raw bytes."""
    buffer = io.BytesIO(encoded)
    out = io.BytesIO()
    decode_stream(buffer, out)
    return out.getvalue()


def inspect_file(path: Path, *, verify: bool = True) -> Dict[str, object]:
    """Inspect a DS file without writing output, returning stats and metadata."""
    with path.open("rb") as in_fp:
        return inspect_stream(in_fp, verify=verify)


def encode_stream(
    in_fp: BinaryIO, out_fp: BinaryIO, *, magic: bytes = MAGIC_V2, include_metadata: bool = True
) -> Dict[str, int]:
    """Stream encoder from a binary file-like input to output."""
    if magic not in (MAGIC_V1, MAGIC_V2):
        raise ValueError("Unsupported magic header")

    out_fp.write(magic)
    sha = hashlib.sha256()
    source_bytes = 0
    source_lines = 0
    encoded_records = 0

    for line in iter(lambda: in_fp.readline(), b""):
        source_bytes += len(line)
        source_lines += 1
        sha.update(line)
        out_fp.write(_encode_record(line))
        encoded_records += 1

    stats = {
        "source_bytes": source_bytes,
        "source_lines": source_lines,
        "encoded_records": encoded_records,
        "sha256": sha.hexdigest(),
    }

    if magic == MAGIC_V2 and include_metadata:
        out_fp.write(META_BEGIN)
        metadata_lines = [
            ("format-version", "2"),
            ("brand", BRAND),
            ("tool", f"ds-codec/{TOOL_VERSION}"),
            ("hash", f"sha256:{stats['sha256']}"),
            ("source-bytes", str(source_bytes)),
            ("source-lines", str(source_lines)),
            ("encoded-records", str(encoded_records)),
        ]
        for key, value in metadata_lines:
            out_fp.write(f"{key}: {value}\n".encode("ascii"))
        out_fp.write(META_END)

    return stats


def _parse_metadata_line(line: bytes) -> Tuple[str, str]:
    try:
        key, value = line.decode("ascii").rstrip("\n").split(":", 1)
    except ValueError as exc:
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


def _validate_metadata(metadata: Dict[str, str], stats: Dict[str, int]) -> None:
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
    """Raise if any bytes remain after the metadata trailer."""
    leftover = in_fp.read(1)
    if leftover:
        raise DecodeError("Trailing data detected after metadata trailer")


def _decode_v1(in_fp: BinaryIO, out_fp: BinaryIO) -> Dict[str, object]:
    sha = hashlib.sha256()
    source_bytes = 0
    source_lines = 0
    encoded_records = 0
    for raw in in_fp:
        record = raw.rstrip(b"\n")
        decoded = _decode_record(record)
        out_fp.write(decoded)
        sha.update(decoded)
        source_bytes += len(decoded)
        source_lines += 1
        encoded_records += 1

    stats = {
        "source_bytes": source_bytes,
        "source_lines": source_lines,
        "encoded_records": encoded_records,
        "sha256": sha.hexdigest(),
    }
    return {"format": "ds1", "verified": False, "metadata": None, "stats": stats}


def _decode_v2(in_fp: BinaryIO, out_fp: BinaryIO, *, verify: bool = True) -> Dict[str, object]:
    sha = hashlib.sha256()
    source_bytes = 0
    source_lines = 0
    encoded_records = 0
    for raw in in_fp:
        if raw == META_BEGIN:
            metadata = _read_metadata(in_fp)
            stats = {
                "source_bytes": source_bytes,
                "source_lines": source_lines,
                "encoded_records": encoded_records,
                "sha256": sha.hexdigest(),
            }
            if verify:
                _validate_metadata(metadata, stats)
            _ensure_no_trailing_data(in_fp)
            return {"format": "ds2", "verified": verify, "metadata": metadata, "stats": stats}

        record = raw.rstrip(b"\n")
        decoded = _decode_record(record)
        out_fp.write(decoded)
        sha.update(decoded)
        source_bytes += len(decoded)
        source_lines += 1
        encoded_records += 1

    raise DecodeError("Missing metadata block")


def decode_stream(in_fp: BinaryIO, out_fp: BinaryIO, *, verify: bool = True) -> Dict[str, object]:
    """Stream decoder from a binary file-like input to output."""
    header = in_fp.readline()
    if header == MAGIC_V1:
        return _decode_v1(in_fp, out_fp)
    if header == MAGIC_V2:
        return _decode_v2(in_fp, out_fp, verify=verify)
    raise DecodeError("Missing DS magic header")


def inspect_stream(in_fp: BinaryIO, *, verify: bool = True) -> Dict[str, object]:
    """Inspect a DS stream without materializing output, returning stats/metadata."""
    header = in_fp.readline()
    if header == MAGIC_V1:
        return _decode_v1(in_fp, _NullWriter())
    if header == MAGIC_V2:
        return _decode_v2(in_fp, _NullWriter(), verify=verify)
    raise DecodeError("Missing DS magic header")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"{BRAND} .ds encoder/decoder",
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

    return parser


def _print_summary(
    action: str, stats: Dict[str, int], *, format_label: str, verified: Optional[bool], stream: Any = sys.stdout
) -> None:
    lines = [
        f"{BRAND} :: {action}",
        f"  format: {format_label}",
    ]
    if verified is not None:
        if format_label == "ds1":
            lines.append("  verified: n/a (ds1)")
        else:
            lines.append(f"  verified: {'yes' if verified else 'no'}")
    lines.extend(
        [
            f"  source-bytes: {stats['source_bytes']}",
            f"  source-lines: {stats['source_lines']}",
            f"  encoded-records: {stats['encoded_records']}",
            f"  sha256: {stats['sha256']}",
        ]
    )
    print("\n".join(lines), file=stream)


def _print_inspection(report: Dict[str, object], *, show_metadata: bool, stream: Any = sys.stdout) -> None:
    stats: Dict[str, int] = report["stats"]  # type: ignore[assignment]
    metadata: Optional[Dict[str, str]] = report.get("metadata")  # type: ignore[assignment]
    _print_summary(
        "inspect",
        stats,
        format_label=report["format"],
        verified=report.get("verified"),  # type: ignore[arg-type]
        stream=stream,
    )
    if show_metadata and metadata:
        print("  metadata:", file=stream)
        for key, value in metadata.items():
            print(f"    {key}: {value}", file=stream)


def _fail(message: str, exit_code: int = 1) -> None:
    print(f"{BRAND} error: {message}", file=sys.stderr)
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
    else:
        with Path(path).open("rb") as fp:
            yield fp


@contextlib.contextmanager
def _open_binary_output(path: str) -> Iterator[BinaryIO]:
    if path == "-":
        yield sys.stdout.buffer
    else:
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
        elif args.command == "decode":
            _guard_distinct_paths(args.input, args.output)
            summary_stream = sys.stderr if args.output == "-" else sys.stdout
            with contextlib.ExitStack() as stack:
                in_fp = stack.enter_context(_open_binary_input(args.input))
                out_fp = stack.enter_context(_open_binary_output(args.output))
                info = decode_stream(in_fp, out_fp, verify=True)
            _print_summary(  # type: ignore[arg-type]
                "decoded", info["stats"], format_label=info["format"], verified=info.get("verified"), stream=summary_stream
            )
        elif args.command == "inspect":
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
        else:
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
