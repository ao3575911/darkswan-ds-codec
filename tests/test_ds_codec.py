import hashlib
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
    decode_record,
    decode_bytes,
    decode_stream,
    encode_bytes,
    encode_stream,
    iter_records,
    count_records,
    estimate_capacity,
    analyze_carrier,
    evaluate_survivability,
    embed_payload,
    extract_payload,
    split_payload,
    reconstruct_payload,
    generate_operation_manifest,
    verify_operation_manifest,
    inspect_file,
    read_record,
)


class TestDSCodec(unittest.TestCase):
    def test_split_reconstruct_payload_api(self) -> None:
        secret = b"threshold-secret"
        shards = split_payload(secret, total_shards=5, threshold=3, deterministic=True, seed="abc")
        recovered = reconstruct_payload([shards[0], shards[2], shards[4]])
        self.assertEqual(secret, recovered)

    def test_split_reconstruct_insufficient_shares(self) -> None:
        secret = b"threshold-secret"
        shards = split_payload(secret, total_shards=5, threshold=3, deterministic=True, seed="abc")
        with self.assertRaises(DecodeError):
            reconstruct_payload([shards[0], shards[1]])

    def test_split_reconstruct_tamper_detected(self) -> None:
        secret = b"threshold-secret"
        shards = split_payload(secret, total_shards=4, threshold=2, deterministic=True, seed="xyz")
        bad = bytearray(shards[1])
        bad[-1] ^= 0x01
        with self.assertRaises(DecodeError):
            reconstruct_payload([shards[0], bytes(bad)])

    def test_split_reconstruct_cli(self) -> None:
        secret = b"secret-via-cli"
        with tempfile.TemporaryDirectory() as td:
            secret_path = Path(td) / "secret.bin"
            out_prefix = Path(td) / "out" / "shard"
            out_prefix.parent.mkdir(parents=True, exist_ok=True)
            recovered_path = Path(td) / "recovered.bin"
            secret_path.write_bytes(secret)

            stdout = io.StringIO()
            stderr = io.StringIO()
            old = (sys.argv, sys.stdout, sys.stderr)
            sys.argv, sys.stdout, sys.stderr = [
                "ds-codec",
                "split-payload",
                str(secret_path),
                str(out_prefix),
                "--total-shards",
                "5",
                "--threshold",
                "3",
                "--deterministic",
                "--seed",
                "cli",
                "--json",
            ], stdout, stderr
            try:
                cli_main()
            finally:
                sys.argv, sys.stdout, sys.stderr = old
            report = json.loads(stdout.getvalue())
            self.assertEqual(report["total_shards"], 5)
            self.assertEqual(len(report["written_shards"]), 5)

            shard_paths = report["written_shards"][:3]
            stdout = io.StringIO()
            stderr = io.StringIO()
            old = (sys.argv, sys.stdout, sys.stderr)
            sys.argv, sys.stdout, sys.stderr = [
                "ds-codec",
                "reconstruct-payload",
                str(recovered_path),
                shard_paths[0],
                shard_paths[1],
                shard_paths[2],
                "--json",
            ], stdout, stderr
            try:
                cli_main()
            finally:
                sys.argv, sys.stdout, sys.stderr = old
            recon_report = json.loads(stdout.getvalue())
            self.assertEqual(recon_report["secret_sha256"], hashlib.sha256(secret).hexdigest())
            self.assertEqual(recovered_path.read_bytes(), secret)

    def test_evaluate_survivability_api(self) -> None:
        cover = b"line1\nline2\nline3\nline4\nline5\n"
        secret = b"payload"
        report = evaluate_survivability(cover, secret, deterministic=True, seed="s1")
        self.assertIn("pass_rate", report)
        self.assertEqual(report["transform_count"], 5)
        identity = [row for row in report["results"] if row["transform"] == "identity"]
        self.assertEqual(len(identity), 1)
        self.assertTrue(identity[0]["ok"])

    def test_evaluate_survivability_cli_json(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as cover_file:
            cover_path = Path(cover_file.name)
            cover_file.write(b"a\nb\nc\nd\ne\n")
        self.addCleanup(lambda: cover_path.unlink(missing_ok=True))
        with tempfile.NamedTemporaryFile(delete=False) as secret_file:
            secret_path = Path(secret_file.name)
            secret_file.write(b"hidden")
        self.addCleanup(lambda: secret_path.unlink(missing_ok=True))

        stdout = io.StringIO()
        stderr = io.StringIO()
        old = (sys.argv, sys.stdout, sys.stderr)
        sys.argv, sys.stdout, sys.stderr = [
            "ds-codec",
            "evaluate-survivability",
            str(cover_path),
            str(secret_path),
            "--transforms",
            "identity,normalize_lf",
            "--deterministic",
            "--seed",
            "case1",
            "--json",
        ], stdout, stderr
        try:
            cli_main()
        finally:
            sys.argv, sys.stdout, sys.stderr = old
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["transform_count"], 2)
        self.assertGreaterEqual(report["pass_rate"], 0.0)

    def test_policy_requires_ack(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as cover_file:
            cover_path = Path(cover_file.name)
            cover_file.write(b"a\nb\nc\n")
        self.addCleanup(lambda: cover_path.unlink(missing_ok=True))
        with tempfile.NamedTemporaryFile(delete=False) as policy_file:
            policy_path = Path(policy_file.name)
            policy_file.write(json.dumps({"require_authorization_ack": True}).encode("utf-8"))
        self.addCleanup(lambda: policy_path.unlink(missing_ok=True))

        stdout = io.StringIO()
        stderr = io.StringIO()
        old = (sys.argv, sys.stdout, sys.stderr)
        sys.argv, sys.stdout, sys.stderr = [
            "ds-codec",
            "capacity",
            str(cover_path),
            "--policy",
            str(policy_path),
            "--json",
        ], stdout, stderr
        try:
            with self.assertRaises(SystemExit):
                cli_main()
        finally:
            sys.argv, sys.stdout, sys.stderr = old
        self.assertIn("requires --ack-authorized-use", stderr.getvalue())

    def test_policy_ack_allows_operation(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as cover_file:
            cover_path = Path(cover_file.name)
            cover_file.write(b"a\nb\nc\n")
        self.addCleanup(lambda: cover_path.unlink(missing_ok=True))
        with tempfile.NamedTemporaryFile(delete=False) as policy_file:
            policy_path = Path(policy_file.name)
            policy_file.write(json.dumps({"require_authorization_ack": True}).encode("utf-8"))
        self.addCleanup(lambda: policy_path.unlink(missing_ok=True))

        stdout = io.StringIO()
        stderr = io.StringIO()
        old = (sys.argv, sys.stdout, sys.stderr)
        sys.argv, sys.stdout, sys.stderr = [
            "ds-codec",
            "capacity",
            str(cover_path),
            "--policy",
            str(policy_path),
            "--ack-authorized-use",
            "--json",
        ], stdout, stderr
        try:
            cli_main()
        finally:
            sys.argv, sys.stdout, sys.stderr = old
        report = json.loads(stdout.getvalue())
        self.assertIn("max_payload_bytes", report)

    def test_analyze_carrier_api(self) -> None:
        cover = b"line1 \nline2\r\nline3\r"
        report = analyze_carrier(cover)
        self.assertEqual(report["carrier_lines"], 3)
        self.assertTrue(report["mixed_newlines"])
        self.assertGreaterEqual(report["risk_score"], 34)

    def test_analyze_carrier_cli_json(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as cover_file:
            cover_path = Path(cover_file.name)
            cover_file.write(b"a\nb\nc\n")
        self.addCleanup(lambda: cover_path.unlink(missing_ok=True))

        stdout = io.StringIO()
        stderr = io.StringIO()
        old = (sys.argv, sys.stdout, sys.stderr)
        sys.argv, sys.stdout, sys.stderr = ["ds-codec", "analyze-carrier", str(cover_path), "--json"], stdout, stderr
        try:
            cli_main()
        finally:
            sys.argv, sys.stdout, sys.stderr = old
        report = json.loads(stdout.getvalue())
        self.assertIn("risk_level", report)
        self.assertIn("newline_counts", report)

    def test_manifest_sign_and_verify_api(self) -> None:
        manifest = generate_operation_manifest("hide", {"x": 1}, signing_key="mk1")
        self.assertTrue(verify_operation_manifest(manifest, "mk1"))
        self.assertFalse(verify_operation_manifest(manifest, "wrong"))

    def test_manifest_verify_cli(self) -> None:
        manifest = generate_operation_manifest("hide", {"x": 1}, signing_key="mk2")
        with tempfile.NamedTemporaryFile(delete=False) as mf:
            manifest_path = Path(mf.name)
            mf.write(json.dumps(manifest).encode("utf-8"))
        self.addCleanup(lambda: manifest_path.unlink(missing_ok=True))

        stdout = io.StringIO()
        stderr = io.StringIO()
        old = (sys.argv, sys.stdout, sys.stderr)
        sys.argv, sys.stdout, sys.stderr = [
            "ds-codec",
            "verify-manifest",
            str(manifest_path),
            "--manifest-key",
            "mk2",
            "--json",
        ], stdout, stderr
        try:
            cli_main()
        finally:
            sys.argv, sys.stdout, sys.stderr = old
        report = json.loads(stdout.getvalue())
        self.assertTrue(report["verified"])

    def test_hide_writes_manifest(self) -> None:
        cover = b"cover-1\ncover-2\ncover-3\ncover-4\n"
        secret = b"top-secret"

        with tempfile.NamedTemporaryFile(delete=False) as secret_file:
            secret_path = Path(secret_file.name)
            secret_file.write(secret)
        self.addCleanup(lambda: secret_path.unlink(missing_ok=True))
        with tempfile.NamedTemporaryFile(delete=False) as output_file:
            output_path = Path(output_file.name)
        self.addCleanup(lambda: output_path.unlink(missing_ok=True))
        with tempfile.NamedTemporaryFile(delete=False) as manifest_file:
            manifest_path = Path(manifest_file.name)
        self.addCleanup(lambda: manifest_path.unlink(missing_ok=True))

        stdin = io.TextIOWrapper(io.BytesIO(cover), encoding="utf-8")
        stderr = io.StringIO()
        old = (sys.argv, sys.stdin, sys.stderr)
        sys.argv, sys.stdin, sys.stderr = [
            "ds-codec",
            "hide",
            "-",
            str(secret_path),
            str(output_path),
            "--manifest-out",
            str(manifest_path),
            "--manifest-key",
            "mk3",
        ], stdin, stderr
        try:
            cli_main()
        finally:
            sys.argv, sys.stdin, sys.stderr = old

        manifest_obj = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest_obj["operation"], "hide")
        self.assertIn("signature", manifest_obj)
        self.assertTrue(verify_operation_manifest(manifest_obj, "mk3"))

    def test_stego_encrypted_round_trip_api(self) -> None:
        cover = b"c1\nc2\nc3\nc4\nc5\n"
        secret = b"super secret payload"
        stego = embed_payload(cover, secret, profile="balanced", passphrase="hunter2")
        recovered = extract_payload(stego, passphrase="hunter2")
        self.assertEqual(secret, recovered)

    def test_stego_encrypted_wrong_passphrase(self) -> None:
        cover = b"c1\nc2\nc3\nc4\nc5\n"
        secret = b"super secret payload"
        stego = embed_payload(cover, secret, profile="balanced", passphrase="correct-pass")
        with self.assertRaises(DecodeError):
            extract_payload(stego, passphrase="wrong-pass")

    def test_stego_profile_low_noise_deterministic(self) -> None:
        cover = b"l1\nl2\nl3\nl4\nl5\nl6\nl7\n"
        secret = b"deterministic"
        stego_a = embed_payload(cover, secret, profile="low-noise", deterministic=True, seed="seed-1")
        stego_b = embed_payload(cover, secret, profile="low-noise", deterministic=True, seed="seed-1")
        self.assertEqual(stego_a, stego_b)
        self.assertEqual(secret, extract_payload(stego_a))

    def test_estimate_capacity(self) -> None:
        cover = b"l1\nl2\nl3\nl4\n"
        self.assertEqual(estimate_capacity(cover, chunk_size=8), 24)

    def test_estimate_capacity_empty_or_small_cover(self) -> None:
        self.assertEqual(estimate_capacity(b"", chunk_size=8), 0)
        self.assertEqual(estimate_capacity(b"single\n", chunk_size=8), 0)
        with self.assertRaises(ValueError):
            estimate_capacity(b"line\nline\n", chunk_size=0)

    def test_capacity_cli_json(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as cover_file:
            cover_path = Path(cover_file.name)
            cover_file.write(b"a\nb\nc\n")
        self.addCleanup(lambda: cover_path.unlink(missing_ok=True))

        with tempfile.NamedTemporaryFile(delete=False) as secret_small_file:
            secret_small_path = Path(secret_small_file.name)
            secret_small_file.write(b"123456")
        self.addCleanup(lambda: secret_small_path.unlink(missing_ok=True))

        with tempfile.NamedTemporaryFile(delete=False) as secret_large_file:
            secret_large_path = Path(secret_large_file.name)
            secret_large_file.write(b"123456789")
        self.addCleanup(lambda: secret_large_path.unlink(missing_ok=True))

        stdout = io.StringIO()
        stderr = io.StringIO()
        old = (sys.argv, sys.stdout, sys.stderr)
        sys.argv, sys.stdout, sys.stderr = [
            "ds-codec",
            "capacity",
            str(cover_path),
            "--secret",
            str(secret_small_path),
            "--chunk-size",
            "4",
            "--json",
        ], stdout, stderr
        try:
            cli_main()
        finally:
            sys.argv, sys.stdout, sys.stderr = old
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["max_payload_bytes"], 8)
        self.assertEqual(report["carrier_lines"], 3)
        self.assertTrue(report["fits"])

        stdout = io.StringIO()
        old = (sys.argv, sys.stdout, sys.stderr)
        sys.argv, sys.stdout, sys.stderr = [
            "ds-codec",
            "capacity",
            str(cover_path),
            "--secret",
            str(secret_large_path),
            "--chunk-size",
            "4",
            "--json",
        ], stdout, stderr
        try:
            cli_main()
        finally:
            sys.argv, sys.stdout, sys.stderr = old
        report = json.loads(stdout.getvalue())
        self.assertFalse(report["fits"])

    def test_capacity_cli_profile_low_noise(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as cover_file:
            cover_path = Path(cover_file.name)
            cover_file.write(b"a\nb\nc\nd\ne\nf\n")
        self.addCleanup(lambda: cover_path.unlink(missing_ok=True))

        stdout = io.StringIO()
        stderr = io.StringIO()
        old = (sys.argv, sys.stdout, sys.stderr)
        sys.argv, sys.stdout, sys.stderr = [
            "ds-codec",
            "capacity",
            str(cover_path),
            "--profile",
            "low-noise",
            "--json",
        ], stdout, stderr
        try:
            cli_main()
        finally:
            sys.argv, sys.stdout, sys.stderr = old
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["profile"], "low-noise")
        self.assertGreater(report["max_payload_bytes"], 0)

    def test_stego_round_trip_api(self) -> None:
        cover = b"line 1\nline 2\nline 3\nline 4\n"
        secret = b"\x00\x01hidden-bytes\xff"
        stego = embed_payload(cover, secret, chunk_size=8)
        recovered = extract_payload(stego)
        self.assertEqual(secret, recovered)

    def test_stego_capacity_error(self) -> None:
        cover = b"a\n"
        secret = b"too much data for one carrier line"
        with self.assertRaises(ValueError):
            embed_payload(cover, secret, chunk_size=4)

    def test_stego_tamper_detected(self) -> None:
        cover = b"line 1\nline 2\nline 3\nline 4\n"
        secret = b"attack at dawn"
        stego = embed_payload(cover, secret, chunk_size=16)
        marker = b"\t \t  \t"
        marker_idx = stego.find(marker)
        self.assertNotEqual(marker_idx, -1)
        tampered_arr = bytearray(stego)
        payload_idx = marker_idx + len(marker)
        tampered_arr[payload_idx] = 0x09 if tampered_arr[payload_idx] == 0x20 else 0x20
        tampered = bytes(tampered_arr)
        with self.assertRaises(DecodeError):
            extract_payload(tampered)

    def test_stego_cli_hide_reveal(self) -> None:
        cover = b"cover-1\ncover-2\ncover-3\ncover-4\n"
        secret = b"top-secret"

        hide_stdin = io.TextIOWrapper(io.BytesIO(cover), encoding="utf-8")
        hide_stdout_buffer = io.BytesIO()
        hide_stdout = io.TextIOWrapper(hide_stdout_buffer, encoding="utf-8")
        hide_stderr = io.StringIO()
        old = (sys.argv, sys.stdin, sys.stdout, sys.stderr)
        sys.argv, sys.stdin, sys.stdout, sys.stderr = [
            "ds-codec",
            "hide",
            "-",
            str(Path(__file__).resolve()),
            "-",
            "--chunk-size",
            "8",
        ], hide_stdin, hide_stdout, hide_stderr
        try:
            with tempfile.NamedTemporaryFile(delete=False) as secret_file:
                secret_path = Path(secret_file.name)
                secret_file.write(secret)
            self.addCleanup(lambda: secret_path.unlink(missing_ok=True))
            sys.argv[3] = str(secret_path)
            cli_main()
        finally:
            hide_stdout.flush()
            sys.argv, sys.stdin, sys.stdout, sys.stderr = old
        stego = hide_stdout_buffer.getvalue()
        self.assertIn("hidden payload", hide_stderr.getvalue())

        reveal_stdin = io.TextIOWrapper(io.BytesIO(stego), encoding="utf-8")
        reveal_stdout_buffer = io.BytesIO()
        reveal_stdout = io.TextIOWrapper(reveal_stdout_buffer, encoding="utf-8")
        reveal_stderr = io.StringIO()
        old = (sys.argv, sys.stdin, sys.stdout, sys.stderr)
        sys.argv, sys.stdin, sys.stdout, sys.stderr = ["ds-codec", "reveal", "-", "-"], reveal_stdin, reveal_stdout, reveal_stderr
        try:
            cli_main()
        finally:
            reveal_stdout.flush()
            sys.argv, sys.stdin, sys.stdout, sys.stderr = old
        self.assertEqual(secret, reveal_stdout_buffer.getvalue())
        self.assertIn("revealed payload", reveal_stderr.getvalue())

    def test_stego_cli_hide_reveal_with_passphrase(self) -> None:
        cover = b"cover-1\ncover-2\ncover-3\ncover-4\ncover-5\n"
        secret = b"encrypted-secret"

        hide_stdin = io.TextIOWrapper(io.BytesIO(cover), encoding="utf-8")
        hide_stdout_buffer = io.BytesIO()
        hide_stdout = io.TextIOWrapper(hide_stdout_buffer, encoding="utf-8")
        hide_stderr = io.StringIO()
        old = (sys.argv, sys.stdin, sys.stdout, sys.stderr)
        sys.argv, sys.stdin, sys.stdout, sys.stderr = [
            "ds-codec",
            "hide",
            "-",
            str(Path(__file__).resolve()),
            "-",
            "--profile",
            "balanced",
            "--passphrase",
            "pw1",
            "--deterministic",
            "--seed",
            "demo",
        ], hide_stdin, hide_stdout, hide_stderr
        try:
            with tempfile.NamedTemporaryFile(delete=False) as secret_file:
                secret_path = Path(secret_file.name)
                secret_file.write(secret)
            self.addCleanup(lambda: secret_path.unlink(missing_ok=True))
            sys.argv[3] = str(secret_path)
            cli_main()
        finally:
            hide_stdout.flush()
            sys.argv, sys.stdin, sys.stdout, sys.stderr = old
        stego = hide_stdout_buffer.getvalue()

        reveal_stdin = io.TextIOWrapper(io.BytesIO(stego), encoding="utf-8")
        reveal_stdout_buffer = io.BytesIO()
        reveal_stdout = io.TextIOWrapper(reveal_stdout_buffer, encoding="utf-8")
        reveal_stderr = io.StringIO()
        old = (sys.argv, sys.stdin, sys.stdout, sys.stderr)
        sys.argv, sys.stdin, sys.stdout, sys.stderr = [
            "ds-codec",
            "reveal",
            "-",
            "-",
            "--passphrase",
            "pw1",
        ], reveal_stdin, reveal_stdout, reveal_stderr
        try:
            cli_main()
        finally:
            reveal_stdout.flush()
            sys.argv, sys.stdin, sys.stdout, sys.stderr = old
        self.assertEqual(secret, reveal_stdout_buffer.getvalue())

    def test_iter_records_v2(self) -> None:
        raw = b"zero\none\ntwo\n"
        encoded = encode_bytes(raw, magic=MAGIC_V2)
        self.assertEqual(list(iter_records(io.BytesIO(encoded))), raw.splitlines(keepends=True))

    def test_iter_records_v1(self) -> None:
        raw = b"a\nb\n"
        encoded = encode_bytes(raw, magic=MAGIC_V1)
        self.assertEqual(list(iter_records(io.BytesIO(encoded))), raw.splitlines(keepends=True))

    def test_iter_records_missing_header(self) -> None:
        with self.assertRaises(DecodeError):
            list(iter_records(io.BytesIO(b"NOTDS\n")))

    def test_count_records_v2(self) -> None:
        raw = b"alpha\nbeta\ngamma\n"
        encoded = encode_bytes(raw, magic=MAGIC_V2)
        self.assertEqual(count_records(io.BytesIO(encoded)), 3)

    def test_count_records_v1(self) -> None:
        raw = b"alpha\nbeta\ngamma\n"
        encoded = encode_bytes(raw, magic=MAGIC_V1)
        self.assertEqual(count_records(io.BytesIO(encoded)), 3)

    def test_decode_record_public(self) -> None:
        raw = b"first\nsecond\n"
        encoded = encode_bytes(raw, magic=MAGIC_V2)
        lines = encoded.splitlines(keepends=True)
        self.assertEqual(decode_record(lines[2]), b"second\n")

    def test_decode_record_strips_newline(self) -> None:
        raw = b"value\n"
        encoded = encode_bytes(raw, magic=MAGIC_V1)
        line = encoded.splitlines(keepends=True)[1]
        self.assertEqual(decode_record(line), decode_record(line.rstrip(b"\n")))

    def test_read_record_v2(self) -> None:
        raw = b"zero\none\ntwo\n"
        encoded = encode_bytes(raw, magic=MAGIC_V2)
        expected_lines = raw.splitlines(keepends=True)
        for idx, expected in enumerate(expected_lines):
            self.assertEqual(read_record(io.BytesIO(encoded), idx), expected)

    def test_read_record_v1(self) -> None:
        raw = b"alpha\nbeta\ngamma\n"
        encoded = encode_bytes(raw, magic=MAGIC_V1)
        expected_lines = raw.splitlines(keepends=True)
        for idx, expected in enumerate(expected_lines):
            self.assertEqual(read_record(io.BytesIO(encoded), idx), expected)

    def test_read_record_out_of_bounds(self) -> None:
        raw = b"only\n"
        encoded = encode_bytes(raw, magic=MAGIC_V2)
        with self.assertRaises(IndexError):
            read_record(io.BytesIO(encoded), 1)

    def test_read_record_negative(self) -> None:
        raw = b"only\n"
        encoded = encode_bytes(raw, magic=MAGIC_V1)
        with self.assertRaises(ValueError):
            read_record(io.BytesIO(encoded), -1)

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
