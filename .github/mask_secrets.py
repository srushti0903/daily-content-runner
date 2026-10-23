"""Registers every credential value with GitHub's log masking (the repo is public, so are its logs).

DOTENV is one multi-line secret, and GitHub only masks a secret where its whole value appears -
a single token from it inside an error message or URL would print in clear. So each value in .env
and every string inside the YouTube JSON files is masked one by one. Standard library only.
"""
import json
import pathlib
import re


def strings(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from strings(v)
    elif isinstance(obj, str):
        yield obj


values = set()
env = pathlib.Path(".env")
if env.exists():
    for line in env.read_text().splitlines():
        m = re.match(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*(.+?)\s*$", line)
        if m:
            values.add(m.group(1).strip("'\""))
for name in ["token.json", *map(str, pathlib.Path(".").glob("client_secret_*.json"))]:
    p = pathlib.Path(name)
    if p.exists():
        try:
            values.update(strings(json.loads(p.read_text())))
        except ValueError:
            pass
try:   # the channel name too: titles and captions in the logs must not reveal it
    import os
    brand = json.loads(os.environ.get("BRAND_JSON") or "{}")
    values.update(v for k, v in brand.items() if k != "PATTERN")
except ValueError:
    pass
for v in sorted(values):
    if len(v) >= 6 and not v.startswith(("http://", "https://")) and v not in ("true", "false"):
        print(f"::add-mask::{v}")
print(f"masked {len([v for v in values if len(v) >= 6])} credential values")
