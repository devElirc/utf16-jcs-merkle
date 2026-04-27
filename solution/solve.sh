#!/bin/bash
set -euo pipefail

cat > /app/utf16_merkle.py <<'PY'
#!/usr/bin/env python3

import hashlib
import json
from pathlib import Path

INPUT = Path("/app/records.json")
OUTPUT = Path("/app/report.json")


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
        items = []
        for k in v.keys():
            if not isinstance(k, str):
                raise TypeError("object keys must be strings")
        for k in sorted(v.keys(), key=lambda s: _utf16be_key_bytes(s)):  # type: ignore[arg-type]
            items.append(_escape_string_ascii(k) + ":" + _canon(v[k]))
        return "{" + ",".join(items) + "}"
    raise TypeError(f"unsupported JSON type: {type(v).__name__}")


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _merkle_root(digests: list[bytes]) -> bytes:
    level = list(digests)
    while len(level) > 1:
        nxt: list[bytes] = []
        i = 0
        while i < len(level):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(_sha256(left + right))
            i += 2
        level = nxt
    return level[0] if level else _sha256(b"")


def main() -> None:
    records = json.loads(INPUT.read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise SystemExit("records.json must be a JSON array")
    out_records = []
    digests: list[bytes] = []
    for rec in records:
        if not isinstance(rec, dict) or set(rec.keys()) != {"id", "payload"}:
            raise SystemExit("each record must be an object with id and payload")
        rid = rec["id"]
        if not isinstance(rid, str):
            raise SystemExit("id must be a string")
        payload = rec["payload"]
        canonical = _canon(payload)
        d = _sha256(canonical.encode("utf-8"))
        digests.append(d)
        out_records.append({"id": rid, "canonical": canonical, "sha256": d.hex()})
    root = _merkle_root(digests).hex()
    OUTPUT.write_text(json.dumps({"records": out_records, "merkle_root_sha256": root}) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
PY

chmod +x /app/utf16_merkle.py
python3 /app/utf16_merkle.py

