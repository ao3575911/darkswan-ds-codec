import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ds_codec import (  # noqa: E402
    DecodeError,
    MAGIC_V1,
    MAGIC_V2,
    cli_main,
    decode_bytes,
    decode_stream,
    encode_bytes,
    encode_stream,
    inspect_file,
)


class TestDSCodec(unittest.TestCase):
    def test_round_trip_v2(self) -> None:
        raw = b"Hello\nLine2\n"
        encoded = encode_bytes(raw, magic=MAGIC_V2)
        self.assertTrue(encoded.startswith(MAGIC_V2))
        decoded = decode_bytes(encoded)
        self.assertEqual(raw, decoded)

    def test_empty_file(self) -> None:
        encoded = encode_bytes(b"", magic=MAGIC_V2)
        decoded = decode_bytes(encoded)
        self.assertEqual(b"", decoded)

    def test_v1_compatibility(self) -> None:
        raw = b"legacy\n"
        encoded = encode_bytes(raw, magic=MAGIC_V1)
        self.assertTrue(encoded.startswith(MAGIC_V1))
        decoded = decode_bytes(encoded)
        self.assertEqual(raw, decoded)

    def test_v1_verified_is_false(self) -> None:
        raw = b"legacy\n"
        encoded = encode_bytes(raw, magic=MAGIC_V1)
        buf = io.BytesIO(encoded)
        out = io.BytesIO()
        info = decode_stream(buf, out)
        self.assertFalse(info["verified"])

    def test_v1_silent_corruption(self) -> None:
        raw = b"integrity\n"
        encoded = encode_bytes(raw, magic=MAGIC_V1)
        # Insert an extra space into the first nibble run (hi of 'i'=0x69 is 6 spaces).
        # This increments hi from 6 to 7, silently changing 'i' to 'y' (0x79).
        # The nibble pair count stays even so no DecodeError is raised.
        header_len = len(MAGIC_V1)
        corrupted = bytes(encoded[:header_len]) + b" " + bytes(encoded[header_len:])
        buf = io.BytesIO(corrupted)
        out = io.BytesIO()
        info = decode_stream(buf, out)
        self.assertFalse(info["verified"])
        self.assertNotEqual(raw, out.getvalue())

    def test_metadata_mismatch(self) -> None:
        raw = b"abc"
        encoded = encode_bytes(raw, magic=MAGIC_V2)
        tampered = encoded.replace(b"source-bytes: 3", b"source-bytes: 4", 1)
        with self.assertRaises(DecodeError):
            decode_bytes(tampered)

    def test_trailing_data_after_metadata(self) -> None:
        raw = b"abc\n"
        encoded = encode_bytes(raw, magic=MAGIC_V2)
        tampered = encoded + b"junk"
        with self.assertRaises(DecodeError):
            decode_bytes(tampered)

        with tempfile.NamedTemporaryFile(suffix=".ds", delete=False) as f:
            path = Path(f.name)
            f.write(tampered)
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        with self.assertRaises(DecodeError):
            inspect_file(path)

    def test_missing_header(self) -> None:
        with self.assertRaises(DecodeError):
            decode_bytes(b"NOTDS\n")

    def test_missing_metadata(self) -> None:
        raw = b"no metadata"
        encoded = encode_bytes(raw, magic=MAGIC_V2, include_metadata=False)
        with self.assertRaises(DecodeError):
            decode_bytes(encoded)

    def test_streaming_max_nibble(self) -> None:
        raw = bytes([0x00, 0x0F, 0xF0, 0xFF]) * 4
        input_fp = io.BytesIO(raw)
        encoded_fp = io.BytesIO()
        encode_stream(input_fp, encoded_fp, magic=MAGIC_V2)

        encoded_fp.seek(0)
        output_fp = io.BytesIO()
        decode_stream(encoded_fp, output_fp)
        self.assertEqual(raw, output_fp.getvalue())

    def test_inspect_v2(self) -> None:
        raw = b"check\n"
        encoded = encode_bytes(raw, magic=MAGIC_V2)
        with tempfile.NamedTemporaryFile(suffix=".ds", delete=False) as f:
            path = Path(f.name)
            f.write(encoded)
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        report = inspect_file(path)
        self.assertEqual(report["format"], "ds2")
        self.assertTrue(report["verified"])
        metadata = report["metadata"]
        self.assertIsInstance(metadata, dict)
        self.assertIn("brand", metadata)

    def test_inspect_v1(self) -> None:
        raw = b"legacy\n"
        encoded = encode_bytes(raw, magic=MAGIC_V1)
        with tempfile.NamedTemporaryFile(suffix=".ds", delete=False) as f:
            path = Path(f.name)
            f.write(encoded)
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        report = inspect_file(path)
        self.assertEqual(report["format"], "ds1")
        self.assertIsNone(report["metadata"])

    def test_cli_blocks_overwrite_of_input(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            tmp = Path(f.name)
            f.write(b"hi\n")
        self.addCleanup(lambda: tmp.unlink(missing_ok=True))

        argv = ["ds-codec", "encode", str(tmp), str(tmp)]
        stderr = io.StringIO()
        old_argv, old_stderr = sys.argv, sys.stderr
        sys.argv, sys.stderr = argv, stderr
        try:
            with self.assertRaises(SystemExit) as ctx:
                cli_main()
        finally:
            sys.argv, sys.stderr = old_argv, old_stderr

        self.assertNotEqual(ctx.exception.code, 0)
        self.assertIn("Input and output paths must differ", stderr.getvalue())

    def test_cli_encode_decode_with_stdio(self) -> None:
        raw = b"stdin stream\n"

        # Encode from stdin to stdout
        enc_stdin = io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8")
        enc_stdout_buffer = io.BytesIO()
        enc_stdout = io.TextIOWrapper(enc_stdout_buffer, encoding="utf-8")
        enc_stderr = io.StringIO()
        old = (sys.argv, sys.stdin, sys.stdout, sys.stderr)
        sys.argv, sys.stdin, sys.stdout, sys.stderr = ["ds-codec", "encode", "-", "-"], enc_stdin, enc_stdout, enc_stderr
        try:
            cli_main()
        finally:
            enc_stdout.flush()
            sys.argv, sys.stdin, sys.stdout, sys.stderr = old
        encoded = enc_stdout_buffer.getvalue()
        self.assertTrue(encoded.startswith(MAGIC_V2))
        self.assertIn("encoded", enc_stderr.getvalue())

        # Decode from stdin to stdout
        dec_stdin = io.TextIOWrapper(io.BytesIO(encoded), encoding="utf-8")
        dec_stdout_buffer = io.BytesIO()
        dec_stdout = io.TextIOWrapper(dec_stdout_buffer, encoding="utf-8")
        dec_stderr = io.StringIO()
        old = (sys.argv, sys.stdin, sys.stdout, sys.stderr)
        sys.argv, sys.stdin, sys.stdout, sys.stderr = ["ds-codec", "decode", "-", "-"], dec_stdin, dec_stdout, dec_stderr
        try:
            cli_main()
        finally:
            dec_stdout.flush()
            sys.argv, sys.stdin, sys.stdout, sys.stderr = old
        self.assertEqual(raw, dec_stdout_buffer.getvalue())
        self.assertIn("decoded", dec_stderr.getvalue())

    def test_inspect_json_output(self) -> None:
        raw = b"json check\n"
        encoded = encode_bytes(raw, magic=MAGIC_V2)
        with tempfile.NamedTemporaryFile(suffix=".ds", delete=False) as f:
            path = Path(f.name)
            f.write(encoded)
        self.addCleanup(lambda: path.unlink(missing_ok=True))

        stdout = io.StringIO()
        stderr = io.StringIO()
        old = (sys.argv, sys.stdout, sys.stderr)
        sys.argv, sys.stdout, sys.stderr = ["ds-codec", "inspect", str(path), "--json"], stdout, stderr
        try:
            cli_main()
        finally:
            sys.argv, sys.stdout, sys.stderr = old

        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["format"], "ds2")
        self.assertIn("metadata", payload)
        self.assertIn("source_bytes", payload["stats"])

        stdout = io.StringIO()
        old = (sys.argv, sys.stdout, sys.stderr)
        sys.argv, sys.stdout, sys.stderr = ["ds-codec", "inspect", str(path), "--json", "--no-metadata"], stdout, stderr
        try:
            cli_main()
        finally:
            sys.argv, sys.stdout, sys.stderr = old
        payload = json.loads(stdout.getvalue())
        self.assertIsNone(payload["metadata"])


if __name__ == "__main__":
    unittest.main()
