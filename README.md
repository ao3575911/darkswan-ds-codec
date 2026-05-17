# DarkSwan DS Codec

DS1/DS2 whitespace codec and steganography toolkit with policy controls, manifest verification, and survivability testing.

`darkswan` (file extension `.ds`) is a line-addressable, whitespace container. Every source line is encoded independently, and the bytes are recovered by replaying how a cursor stepped across blank space. The payload lives entirely in how far the cursor moved horizontally (spaces and tabs) and which line it stopped on (newlines).

## Quick start

- Install: `pip install .` (or `pip install -e .` for development).
- Encode: `ds-codec encode plain.txt archive.ds`
- Decode: `ds-codec decode archive.ds restored.txt`
- Inspect/verify: `ds-codec inspect archive.ds` or `ds-codec inspect --json archive.ds`
- Hide payload in text carrier: `ds-codec hide cover.txt secret.bin stego.txt`
- Reveal payload from stego text: `ds-codec reveal stego.txt recovered.bin`
- Preflight capacity: `ds-codec capacity cover.txt --secret secret.bin --json`
- Encrypted hide/reveal: `ds-codec hide cover.txt secret.bin stego.txt --passphrase "<pw>"` then `ds-codec reveal stego.txt recovered.bin --passphrase "<pw>"`
- Profiled embedding: `--profile balanced|low-noise|high-capacity`
- Deterministic reproducibility: `--deterministic --seed <value>`
- Carrier risk analysis: `ds-codec analyze-carrier cover.txt --json`
- Signed manifest output: add `--manifest-out op-manifest.json --manifest-key "<key>"` to `hide|reveal|capacity|analyze-carrier`
- Manifest verification: `ds-codec verify-manifest op-manifest.json --manifest-key "<key>" --json`
- Survivability harness: `ds-codec evaluate-survivability cover.txt secret.bin --json`
- Policy guardrails: add `--policy policy.json --ack-authorized-use --engagement ENG-123 --classification internal` to stego operations
- Split payload into threshold shards: `ds-codec split-payload secret.bin shards/out --total-shards 5 --threshold 3 --json`
- Reconstruct from shards: `ds-codec reconstruct-payload recovered.bin shards/out.part-01.dsshard shards/out.part-02.dsshard shards/out.part-03.dsshard --json`
- Stream: use `-` for stdin/stdout on encode/decode (e.g., `cat plain.txt | ds-codec encode - - > archive.ds`).
- Legacy: `ds-codec encode --format ds1 plain.txt legacy.ds` for header-only output without metadata.

## File layout (DS2, default)

- Header: literal bytes `DARKSWAN-DS2\n`.
- Records: one encoded record per source line in order (see nibble encoding below). Each record ends with a single `\n`, independent of whether the original line had one; the original newline byte is preserved inside the record data.
- Metadata trailer (ASCII, sentinel guarded):
  ```
  ##META
  format-version: 2
  brand: DarkSwan DS Codec
  tool: ds-codec/<version>
  hash: sha256:<digest>      # checksum of the original raw bytes
  source-bytes: <int>        # total input bytes seen by encoder
  source-lines: <int>        # total records written
  encoded-records: <int>     # mirrors source-lines
  ##ENDMETA
  ```
- No bytes are allowed after `##ENDMETA`; trailing data is treated as tampering.

### Legacy DS1

- Header: literal bytes `DARKSWAN-DS1\n`.
- Records only, no metadata, no checksum. The decoder auto-detects DS1/DS2 from the header.

## Nibble encoding (record anatomy)

- Each source line (the bytes returned by `readline`, newline included if present) becomes one record.
- A byte splits into two 4-bit nibbles: `hi = byte >> 4`, `lo = byte & 0x0F`.
- Emit `hi` spaces followed by a tab, then `lo` spaces followed by a tab. Each nibble run is 0–15 spaces; a value of 0 is just the tab.
- Repeat for every byte in the line, then finish the record with `\n`. Record newlines are separators only; they are not data-bearing.
- On decode, runs are split by tabs, counted, sanity-checked to be spaces only, grouped in pairs, and reassembled into bytes. An odd number of runs, spaces outside 0–15, or stray characters trigger `DecodeError`.

Example: encoding ASCII `"A\n"` (`0x41 0x0a`):
- `0x41` → hi `4` → `"    \t"`; lo `1` → `" \t"`; byte emits `"    \t \t"`.
- `0x0a` → hi `0` → `"\t"`; lo `10` → `"          \t"` (ten spaces); byte emits `"\t          \t"`.
- Record separator: `\n`.
- Full record bytes: `"    \t \t\t          \t\n"`.

Think of the number of spaces before each tab as the nibble’s score; tabs mark nibble boundaries, and the record newline marks the end of the line’s cursor path.

## Manually encoding a line (by hand)

1. Start at column 0 with a blank line. Decide which exact bytes to encode (include the newline byte if you want the original line ending back on decode).
2. For each byte, convert to hex or binary and extract `hi` (upper 4 bits) and `lo` (lower 4 bits).
3. Type `hi` spaces, then a tab; type `lo` spaces, then a tab. Keep counts strict—`15` is the maximum for any nibble.
4. Repeat step 3 for every byte in the line.
5. Press Enter once to append the record separator `\n` and move to the next record.
6. Repeat the process for every original line to build the full file.

Worked example: `"OK\n"` (`0x4f 0x4b 0x0a`):
- `0x4f` → hi `4` (`"    \t"`), lo `15` (`"               \t"` = fifteen spaces), emits `"    \t               \t"`.
- `0x4b` → hi `4` (`"    \t"`), lo `11` (`"           \t"` = eleven spaces), emits `"    \t           \t"`.
- `0x0a` → hi `0` (`"\t"`), lo `10` (`"          \t"` = ten spaces), emits `"\t          \t"`.
- Append record newline: resulting record is `"    \t               \t    \t           \t\t          \t\n"`.


<img width="865" height="454" alt="image" src="https://github.com/user-attachments/assets/95e99948-33ed-4a8f-835a-fab1de6ae46d" />


Tips:
- Counting helps: write the space counts next to each nibble while you type to avoid slipping past 15.
- After hand-building a record, `ds-codec decode - -` can validate your work by reading from stdin and surfacing `DecodeError` messages if something is off.

## CLI usage (expanded)

- Encode with defaults (DS2 + metadata):
  ```bash
  ds-codec encode samples/official.txt samples/official.ds
  ```
- Decode to stdout for quick inspection:
  ```bash
  ds-codec decode samples/official.ds -
  ```
- Pipe through the encoder (stdin to stdout):
  ```bash
  cat notes.txt | ds-codec encode - - > notes.ds
  ```
- Emit legacy DS1 (no checksum):
  ```bash
  ds-codec encode --format ds1 notes.txt notes.ds1
  ```
- Inspect and verify an existing file (text or JSON):
  ```bash
  ds-codec inspect samples/official.ds
  ds-codec inspect --json samples/official.ds | jq .
  ```
  The report includes format, verification status, and the same size/count fields stored in metadata.
- Safety guard: the CLI refuses identical input/output paths to avoid overwriting the source.

## Library API (Python)

- `encode_bytes(raw: bytes, magic=MAGIC_V2, include_metadata=True) -> bytes`: encode a blob, returning the full DS payload.
- `decode_bytes(encoded: bytes) -> bytes`: decode a DS payload, verifying DS2 metadata and checksum.
- `decode_record(encoded_line: bytes) -> bytes`: decode one encoded DS record line, with or without trailing `\n`.
- `read_record(in_fp, n: int) -> bytes`: consume a DS header, then decode the `n`th record (0-based) from the current stream position.
- `iter_records(in_fp) -> Iterator[bytes]`: iterate decoded records from a DS stream from current position.
- `count_records(in_fp) -> int`: count DS records from current position without materializing full decoded payload.
- `estimate_capacity(cover: bytes, chunk_size=64) -> int`: estimate max payload bytes for a given carrier and chunk size.
- `analyze_carrier(cover: bytes) -> dict`: compute carrier transformation risk metrics and score.
- `evaluate_survivability(cover: bytes, payload: bytes, ...) -> dict`: embed then test extraction after common text transformations.
- `embed_payload(cover: bytes, payload: bytes, chunk_size=64, profile="balanced", passphrase=None, deterministic=False, seed=None) -> bytes`: hide payload bytes with profile-driven placement and optional encrypted envelope.
- `extract_payload(stego: bytes, passphrase=None) -> bytes`: recover hidden payload bytes, verify integrity, and decrypt when encrypted mode is used.
- `generate_operation_manifest(operation: str, details: dict, signing_key=None) -> dict`: create chain-of-custody manifest with optional HMAC signature.
- `verify_operation_manifest(manifest: dict, signing_key: str) -> bool`: verify signed manifest integrity.
- `load_policy(path: Optional[str]) -> dict`: load operational guardrail policy for authorization and classification controls.
- `split_payload(payload: bytes, total_shards: int, threshold: int, ...) -> List[bytes]`: split payload into threshold shards.
- `reconstruct_payload(shards: List[bytes]) -> bytes`: reconstruct payload from compatible shard subset.
- `encode_stream(input_fp, output_fp, magic=MAGIC_V2, include_metadata=True) -> dict`: stream line by line, write the header/records/trailer, and return stats.
- `decode_stream(input_fp, output_fp, verify=True) -> dict`: stream decode, returning `{format, verified, metadata, stats}`; raises `DecodeError` on corruption.
- `inspect_file(path, verify=True) -> dict`: inspect/verify without materializing output (uses a null sink).

## Integrity and debugging

- DS2 decoding validates: header, nibble shapes (even number of runs, only spaces before tabs, 0–15 range), SHA-256 hash, record counts, and rejects any trailing bytes after `##ENDMETA`.
- DS1 decoding validates header and nibble shapes but has no checksum; it is intentionally fragile.
- Errors surface as `DecodeError`. Use `ds-codec inspect` to debug without writing output, or pipe into `ds-codec decode - -` to get messages while experimenting.

## Samples and tests

- Samples: `samples/official.txt` (plaintext) and `samples/official.ds` (DS2 with trailer).
- Tests: `python -m unittest discover -s tests`

## Repository operations

- CI workflow: `.github/workflows/ci.yml`
- Label sync workflow: `.github/workflows/labels-sync.yml`
- Issue templates: `.github/ISSUE_TEMPLATE/`
- Discussion templates: `.github/DISCUSSION_TEMPLATE/`
- PR template: `.github/PULL_REQUEST_TEMPLATE.md`
- Repo profile and metadata guide: `docs/REPOSITORY_PROFILE.md`
- Version tracking: `pyproject.toml`, `ds_codec.py` (`TOOL_VERSION`), `VERSION`, and `CHANGELOG.md`

## Design notes

- The format is intentionally whitespace-only and sensitive to edits: any stray character, extra space, or missing tab corrupts data.
- Compression is not the goal; the value is in a transparent, line-by-line cursor trace that is easy to inspect, diff, and blame.
