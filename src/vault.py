"""Encrypts what the public repo stores (the state branch and the run logs), standard library only.

SHA-256 in counter mode as the keystream, HMAC-SHA256 over nonce+ciphertext, key from STATE_KEY
(in .env, so also inside the DOTENV secret). Without the key the state branch is opaque bytes.

  python src/vault.py show tick        # read the last run logs of a job (laptop: needs .env)
"""
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAGIC = b"LTV1"
LOGS = ROOT / "data" / "logs"
KEEP_RUNS = 15
MAX_LOG = 60_000


def key():
    k = os.environ.get("STATE_KEY")
    if not k and (ROOT / ".env").exists():
        m = re.search(r"^STATE_KEY=(\S+)", (ROOT / ".env").read_text(), re.M)
        k = m.group(1) if m else None
    return hashlib.sha256(k.encode()).digest() if k else None


def _stream(k, nonce, n):
    prefix = k + nonce
    return b"".join(hashlib.sha256(prefix + i.to_bytes(8, "big")).digest()
                    for i in range((n + 31) // 32))[:n]


def _xor(a: bytes, b: bytes) -> bytes:
    if not a:
        return b""
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def encrypt(data: bytes, k=None) -> bytes:
    k = k or key()
    if not k:
        return data
    nonce = os.urandom(16)
    ct = _xor(data, _stream(k, nonce, len(data)))
    mac = hmac.new(k, nonce + ct, hashlib.sha256).digest()
    return MAGIC + nonce + mac + ct


def decrypt(blob: bytes, k=None) -> bytes:
    if not blob.startswith(MAGIC):
        return blob            # written before encryption existed
    k = k or key()
    if not k:
        raise RuntimeError("STATE_KEY is missing - cannot read the encrypted state")
    nonce, mac, ct = blob[4:20], blob[20:52], blob[52:]
    if not hmac.compare_digest(mac, hmac.new(k, nonce + ct, hashlib.sha256).digest()):
        raise RuntimeError("state file failed its integrity check (wrong STATE_KEY?)")
    return _xor(ct, _stream(k, nonce, len(ct)))


def run_logged(name, cmd):
    """Runs cmd, keeps its full output only in the encrypted state (data/logs/<name>.json), and
    prints nothing but the outcome - the repo's Actions logs are public."""
    import subprocess
    start = time.time()
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    text = (proc.stdout + ("\n--- stderr ---\n" + proc.stderr if proc.stderr.strip() else ""))[-MAX_LOG:]
    print(f"{name}: exit {proc.returncode} after {round(time.time() - start)}s")
    if proc.returncode == 0 and not text.strip():
        return 0               # nothing to keep: no state commit for a quiet, healthy run
    LOGS.mkdir(parents=True, exist_ok=True)
    path = LOGS / f"{name}.json"
    runs = json.loads(path.read_text()) if path.exists() else []
    runs.append({"at": time.strftime("%Y-%m-%d %H:%M:%S"), "exit": proc.returncode,
                 "seconds": round(time.time() - start), "log": text})
    path.write_text(json.dumps(runs[-KEEP_RUNS:], ensure_ascii=False))
    return proc.returncode


def show(name, runs=3):
    import subprocess
    blob = subprocess.run(["git", "show", f"origin/state:data/logs/{name}.json"], cwd=ROOT,
                          capture_output=True).stdout
    for r in json.loads(decrypt(blob))[-runs:]:
        print(f"===== {r['at']} exit {r['exit']} ({r['seconds']}s)\n{r['log']}")


if __name__ == "__main__":
    if sys.argv[1] == "run":            # python src/vault.py run <name> -- <command...>
        sys.exit(run_logged(sys.argv[2], sys.argv[sys.argv.index("--") + 1:]))
    elif sys.argv[1] == "show":
        show(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 3)
    else:
        print(base64.b64encode(os.urandom(32)).decode())   # "new": a fresh key
