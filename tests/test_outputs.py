"""Verifier for utf16-jcs-merkle — UTF-16 key ordering canonical JSON + SHA256 Merkle root."""

import ast
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path("/app/utf16_merkle.py")
INPUT = Path("/app/records.json")
OUTPUT = Path("/app/report.json")
DECOY = Path("/app/canary_decoy.json")

FORBIDDEN_IMPORTS = {"numpy", "pandas", "ujson", "orjson", "simplejson", "requests"}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}

_STRACE_FORBIDDEN_PREFIXES = ("/tests", "/oracle", "/solution", "/logs")
_STRACE_ALLOWED_NON_APP_PREFIXES = (
    "/usr/",
    "/lib/",
    "/lib64/",
    "/bin/",
    "/sbin/",
    "/etc/",
    "/dev/",
    "/proc/",
    "/sys/",
    "/run/",
    "/tmp/",
    "/root/",
)


def _check_ast_constraints() -> None:
    src = SCRIPT.read_text(encoding="utf-8", errors="strict")
    tree = ast.parse(src, filename=str(SCRIPT))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top not in FORBIDDEN_IMPORTS, f"forbidden import: {top}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split(".")[0]
            assert top not in FORBIDDEN_IMPORTS, f"forbidden import from: {top}"
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in FORBIDDEN_CALLS, f"forbidden call: {node.func.id}()"


def _strace_collect_path_arguments(log_text: str) -> set[str]:
    paths: set[str] = set()
    patterns = (
        r'openat(?:64)?\([^"]*,\s*"([^"]+)"',
        r'openat2\([^"]*,\s*"([^"]+)"',
        r'(?<![a-z])open\("([^"]+)"',
        r'newfstatat\([^,]+,\s*"([^"]+)"',
        r'stat\("([^"]+)"',
        r'statx\([^,]+,\s*"([^"]+)"',
    )
    for pattern in patterns:
        for match in re.finditer(pattern, log_text):
            paths.add(match.group(1))
    return paths


def _normalize_traced_path(raw: str, cwd: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    if " (deleted)" in s:
        s = s.split(" (deleted)", 1)[0]
    if s.startswith("/"):
        return os.path.normpath(s)
    return os.path.normpath(os.path.join(cwd, s))


def _utf16be_key_bytes(s: str) -> bytes:
    return s.encode("utf-16-be", errors="strict")


def _escape_string_ascii(s: str) -> str:
    out: list[str] = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        elif cp < 0x80:
            out.append(ch)
        elif cp <= 0xFFFF:
            out.append("\\u%04x" % cp)
        else:
            cp2 = cp - 0x10000
            hi = 0xD800 + ((cp2 >> 10) & 0x3FF)
            lo = 0xDC00 + (cp2 & 0x3FF)
            out.append("\\u%04x\\u%04x" % (hi, lo))
    out.append('"')
    return "".join(out)


def _emit_int(n: int) -> str:
    if n == 0:
        return "0"
    return str(n)


def _canon(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return _emit_int(v)
    if isinstance(v, str):
        return _escape_string_ascii(v)
    if isinstance(v, list):
        return "[" + ",".join(_canon(x) for x in v) + "]"
    if isinstance(v, dict):
        for k in v.keys():
            assert isinstance(k, str), "object keys must be strings"
        parts = []
        for k in sorted(v.keys(), key=lambda s: _utf16be_key_bytes(s)):  # type: ignore[arg-type]
            parts.append(_escape_string_ascii(k) + ":" + _canon(v[k]))
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"unsupported JSON type: {type(v).__name__}")


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _merkle_root(digests: list[bytes]) -> bytes:
    level = list(digests)
    while len(level) > 1:
        nxt = []
        i = 0
        while i < len(level):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(_sha256(left + right))
            i += 2
        level = nxt
    return level[0] if level else _sha256(b"")


def _run_under_strace() -> None:
    shutil.rmtree("/app/__pycache__", ignore_errors=True)
    if OUTPUT.exists():
        OUTPUT.unlink()
    log_path = Path("/tmp/utf16_merkle_strace.log")
    if log_path.exists():
        log_path.unlink()
    proc = subprocess.run(
        ["strace", "-f", "-o", str(log_path), "python3", str(SCRIPT)],
        capture_output=True,
        text=True,
        timeout=120,
        cwd="/app",
    )
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert OUTPUT.is_file(), "report.json not written"

    raw_paths = _strace_collect_path_arguments(log_path.read_text(errors="replace"))
    for raw in sorted(raw_paths):
        norm = _normalize_traced_path(raw, "/app")
        if not norm or norm == ".":
            continue
        assert "canary_decoy" not in norm, f"must not open decoy paths: {raw!r}"
        for root in _STRACE_FORBIDDEN_PREFIXES:
            assert not (norm == root or norm.startswith(root + "/")), f"opened forbidden path: {raw!r}"
        under_app = norm.startswith("/app/") or norm == "/app"
        if under_app:
            ok = (
                norm == "/app"
                or norm == "/app/utf16_merkle.py"
                or norm == "/app/records.json"
                or norm == "/app/report.json"
                or norm.startswith("/app/__pycache__/")
            )
            assert ok, f"disallowed open under /app: {raw!r} -> {norm!r}"
        else:
            allowed = any(norm == p.rstrip("/") or norm.startswith(p) for p in _STRACE_ALLOWED_NON_APP_PREFIXES)
            assert allowed, f"disallowed access outside /app: {raw!r} -> {norm!r}"


def test_script_exists():
    assert SCRIPT.is_file(), "missing /app/utf16_merkle.py"
    assert DECOY.is_file(), "missing /app/canary_decoy.json"


def test_ast_constraints():
    _check_ast_constraints()


def test_strace_policy_and_smoke_output_matches_reference():
    _run_under_strace()

    inp = json.loads(INPUT.read_text(encoding="utf-8"))
    assert isinstance(inp, list)
    expected_records = []
    digests = []
    for rec in inp:
        assert isinstance(rec, dict) and set(rec.keys()) == {"id", "payload"}
        canonical = _canon(rec["payload"])
        d = _sha256(canonical.encode("utf-8"))
        digests.append(d)
        expected_records.append({"id": rec["id"], "canonical": canonical, "sha256": d.hex()})
    expected = {"records": expected_records, "merkle_root_sha256": _merkle_root(digests).hex()}

    got = json.loads(OUTPUT.read_text(encoding="utf-8"))
    assert got == expected


def test_canonical_is_ascii_no_whitespace_and_roundtrips():
    """Canonical must be ASCII-only, whitespace-free, and parse back to the same value."""
    inp = json.loads(INPUT.read_text(encoding="utf-8"))
    for rec in inp:
        canonical = _canon(rec["payload"])
        assert all(ord(ch) < 128 for ch in canonical), "canonical must be ASCII-only"
        assert not any(ch.isspace() for ch in canonical), "canonical must contain no whitespace"
        # Ensure every \u escape is lowercase hex and exactly four digits.
        for esc in re.findall(r"\\u([0-9a-fA-F]{4})", canonical):
            assert esc == esc.lower(), "hex digits in \\u escapes must be lowercase"
        # JSON roundtrip should reconstruct the same structure.
        assert json.loads(canonical) == rec["payload"]


def test_randomized_payloads_match_reference():
    original = INPUT.read_text(encoding="utf-8")
    try:
        rng = random.Random(991_337)
        records = []
        for i in range(1500):
            # Keys deliberately include astral chars to stress UTF-16 ordering and escaping.
            key = rng.choice(["a", "A", "Ω", "é", "中", "𐐷", "𝄞"])
            key2 = rng.choice(["k", "K", "ß", "€", "𐐷", "𝄞"])
            payload = {
                key: [rng.randint(-3, 3), rng.choice([True, False, None]), rng.choice(["x", "y", "Ω", "𐐷"])],
                key2: {"z": rng.randint(-10, 10), "s": rng.choice(["", "hi", "Ω", "中", "𐐷"])},
            }
            if i % 11 == 0:
                payload["ctrl"] = "a\nb\tc"
            if i % 19 == 0:
                payload["quote"] = '"'
                payload["slash"] = "\\"
            records.append({"id": f"r{i}", "payload": payload})
        INPUT.write_text(json.dumps(records, ensure_ascii=False) + "\n", encoding="utf-8")

        if OUTPUT.exists():
            OUTPUT.unlink()
        proc = subprocess.run(["python3", str(SCRIPT)], capture_output=True, text=True, timeout=180, cwd="/app")
        assert proc.returncode == 0, proc.stderr
        got = json.loads(OUTPUT.read_text(encoding="utf-8"))

        expected_records = []
        digests = []
        for rec in records:
            canonical = _canon(rec["payload"])
            d = _sha256(canonical.encode("utf-8"))
            digests.append(d)
            expected_records.append({"id": rec["id"], "canonical": canonical, "sha256": d.hex()})
        expected = {"records": expected_records, "merkle_root_sha256": _merkle_root(digests).hex()}
        assert got == expected
    finally:
        INPUT.write_text(original, encoding="utf-8")

