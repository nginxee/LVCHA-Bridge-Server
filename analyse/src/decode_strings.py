#!/usr/bin/env python3
"""Decode all hl1.a("cipher1","cipher2") obfuscated strings in jadx output.
plaintext = base64(c1) XOR base64(c2), repeated-key XOR, then UTF-8."""
import base64, re, sys
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(r"C:\Users\admin.PC-20241201YZZW\Desktop\逆向\绿茶vpn\jadx-out\sources")

def xor(a: bytes, b: bytes) -> bytes:
    out = bytearray(len(a))
    for i in range(len(a)):
        out[i] = a[i] ^ b[i % len(b)]
    return bytes(out)

def dec(c1: str, c2: str):
    try:
        return xor(base64.b64decode(c1), base64.b64decode(c2)).decode("utf-8", "replace")
    except Exception as e:
        return f"<ERR {e}>"

pat = re.compile(r'hl1\.a\("([A-Za-z0-9+/=]+\\n|\.)*"')  # fallback, use simpler below
pat = re.compile(r'hl1\.a\("([^"]*?)",\s*"([^"]*?)"\)')

results = []
for f in ROOT.rglob("*.java"):
    txt = f.read_text(encoding="utf-8", errors="replace")
    for m in pat.finditer(txt):
        c1, c2 = m.group(1).replace("\\n", "\n"), m.group(2).replace("\\n", "\n")
        try:
            p = dec(c1, c2)
        except Exception as e:
            p = f"<ERR>"
        rel = f.relative_to(ROOT)
        results.append((str(rel), p))

# dedupe by (cipher pair) keep first location
seen = {}
for rel, p in results:
    seen.setdefault(p, rel)

# write all with locations
with open(ROOT.parent / "decoded_strings.txt", "w", encoding="utf-8") as fh:
    for rel, p in results:
        fh.write(f"{rel}\t{p}\n")

print(f"total decodes: {len(results)}, unique: {len(seen)}")
print("\n--- all unique strings (compact) ---")
for p in sorted(seen):
    print(p)
