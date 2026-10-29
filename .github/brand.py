"""Keeps the public repo unreadable: only the files that unlock the rest are plain text.

The laptop keeps the real code. `strip` makes the public copy: the channel name becomes
placeholders, then every file outside PLAIN is encrypted with STATE_KEY (src/vault.py). Every cloud
run calls `apply` right after writing .env: it decrypts the files and puts the names back, so the
code that runs is byte-for-byte the laptop's.

  python3 .github/brand.py apply [dir]
  python3 .github/brand.py strip <dir>
"""
import json
import os
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE / "src"))
import vault  # noqa: E402

KEYS = ["BRAND_UPPER", "BRAND", "BRAND_TAG", "BRAND_LOWER", "BRAND_SLUG"]   # strip order matters
PLAIN = {".github/brand.py", ".github/mask_secrets.py", ".github/workflows/tick.yml",
         ".github/workflows/daily.yml", ".github/workflows/test.yml", ".gitignore", "src/vault.py"}


def values():
    raw = os.environ.get("BRAND_JSON") or (HERE / ".brand.json").read_text()
    return json.loads(raw)


def _files(root):
    root = pathlib.Path(root)
    for p in root.rglob("*"):
        if p.is_file() and ".git" not in p.relative_to(root).parts:
            yield p, str(p.relative_to(root))


def _text(p):
    try:
        return p.read_text(encoding="utf-8")
    except (UnicodeDecodeError, ValueError):
        return None


def apply(root="."):
    v = values()
    for p, rel in _files(root):
        blob = p.read_bytes()
        if blob.startswith(vault.MAGIC):
            p.write_bytes(vault.decrypt(blob))
        if rel in PLAIN:
            continue
        text = _text(p)
        if text is None:
            continue
        new = text
        for k in KEYS:
            new = new.replace(f"__{k}__", v[k])
        if new != text:
            p.write_text(new, encoding="utf-8")


def strip(root):
    v = values()
    if not vault.key():
        sys.exit("STATE_KEY missing in .env - refusing to export unencrypted")
    for p, rel in _files(root):
        text = _text(p)
        if text is not None and rel not in PLAIN:
            new = text
            for k in KEYS:
                new = new.replace(v[k], f"__{k}__")
            if new != text:
                p.write_text(new, encoding="utf-8")
    for p, rel in _files(root):
        text = _text(p)
        if rel in PLAIN and text is not None and re.search(v["PATTERN"], text, re.I):
            sys.exit(f"the name is in a plain file: {rel}")
        if rel not in PLAIN:
            data = p.read_bytes()
            old = _committed(root, rel)
            # an unchanged file keeps its committed ciphertext: encryption is randomised, so
            # re-encrypting everything made every export re-upload the whole repo (2026-10-29)
            p.write_bytes(old if old and _decrypts_to(old, data) else vault.encrypt(data))


def _committed(root, rel):
    """The file's bytes at HEAD of the export checkout, or None."""
    import subprocess
    r = subprocess.run(["git", "show", f"HEAD:{rel}"], cwd=root, capture_output=True)
    return r.stdout if r.returncode == 0 else None


def _decrypts_to(blob, plain):
    try:
        return vault.decrypt(blob) == plain
    except Exception:
        return False


if __name__ == "__main__":
    {"apply": apply, "strip": strip}[sys.argv[1]](*sys.argv[2:])
