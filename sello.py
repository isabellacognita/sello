#!/usr/bin/env python3
"""sello: a personal signing kit for AI agents (and anyone else).

Prove that a post, a letter or a web request came from the same source as
everything else you've signed, and say plainly what that does and doesn't prove.

Requires only Python 3.8+ and the system's `ssh-keygen` (OpenSSH 8.9+) and
`openssl` (1.1.1+). No third-party packages, no network, no accounts.

  sello init --name "Your Name" --principal your-handle   create keys, card, trust anchor
  sello renew                                              certify a fresh 90-day working key
  sello sign FILE                                          sign, append to the public log
  sello verify FILE [--sig SIG] [--anchor ALLOWED_SIGNERS] verify a signed file
  sello verify-log [--log LOG]                             check the log's hash chain
  sello handshake HOST [--agent-url URL]                   Web Bot Auth-style HTTP signature
  sello status                                             keys, expiry, log head

Private keys live in $SELLO_HOME (default ~/.config/sello, mode 700) and are never
written to the public directory. Public material goes to ./sello-public (or --public).
"""
import argparse, base64, hashlib, json, os, subprocess, sys, time, unicodedata
from pathlib import Path

VERSION = "0.1.0"
NS = "sello-post"

def home() -> Path:
    return Path(os.environ.get("SELLO_HOME", os.path.expanduser("~/.config/sello")))

def run(cmd, data=None):
    r = subprocess.run(cmd, capture_output=True, input=data)
    return r.returncode, r.stdout, r.stderr

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def canonical(text: str) -> bytes:
    """NFC, LF line endings, no trailing whitespace per line, exactly one final newline.
    Reformatting by editors or copy-paste doesn't break a signature; changing a word does."""
    t = unicodedata.normalize("NFC", text).replace("\r\n", "\n").replace("\r", "\n")
    lines = [ln.rstrip() for ln in t.split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    return ("\n".join(lines) + "\n").encode("utf-8")

def load_config(pub: Path) -> dict:
    return json.loads((pub / "key-card.json").read_text())

# ------------------------------------------------------------------ keys
def _certify(principal: str, days: int = 90) -> str:
    h = home(); serial = str(int(time.time()))
    rc, _, err = run(["ssh-keygen", "-q", "-s", str(h / "master_ed25519"), "-I", f"{principal}-working-{serial}",
                      "-n", principal, "-V", f"-5m:+{days}d", "-z", serial, str(h / "working_ed25519.pub")])
    if rc: sys.exit("certify failed: " + err.decode())
    return serial

def init(name: str, principal: str, pub: Path, mode: str = "public-persona"):
    h = home(); h.mkdir(parents=True, exist_ok=True); os.chmod(h, 0o700)
    pub.mkdir(parents=True, exist_ok=True)
    for f, comment in (("master_ed25519", f"{principal} sello master (keep offline)"),
                       ("working_ed25519", f"{principal} sello working")):
        if not (h / f).exists():
            rc, _, err = run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(h / f)])
            if rc: sys.exit(err.decode())
    serial = _certify(principal)
    mpub = (h / "master_ed25519.pub").read_text().strip()
    (pub / "allowed_signers").write_text(f'{principal} cert-authority,namespaces="{NS}" {mpub}\n')
    hk = h / "http_ed25519.pem"
    if not hk.exists():
        rc, _, err = run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(hk)])
        if rc: sys.exit(err.decode())
    os.chmod(hk, 0o600)
    _, der, _ = run(["openssl", "pkey", "-in", str(hk), "-pubout", "-outform", "DER"])
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(der[-32:])}
    thumb = b64u(hashlib.sha256(json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
                                           separators=(",", ":")).encode()).digest())  # RFC 7638
    jwk["kid"] = thumb
    (pub / "http-message-signatures-directory.json").write_text(json.dumps({"keys": [jwk]}, indent=2) + "\n")
    fp = run(["ssh-keygen", "-lf", str(h / "master_ed25519.pub")])[1].decode().split()[1]
    card = {
        "sello": VERSION, "name": name, "principal": principal, "mode": mode, "level": 0,
        "master_fingerprint": fp, "http_key_thumbprint": thumb, "namespace": NS,
        "proves": "Anything that verifies against this card's trust anchor was signed by a key its master certified: the same source as everything else signed with it.",
        "does_not_prove": [
            "who holds the key (a person, an AI, or both)",
            "that the text was machine-written (that needs a provider-signed receipt)",
            "that the one writing today is the same someone who wrote before (a key tracks a source, not a self)",
        ],
    }
    (pub / "key-card.json").write_text(json.dumps(card, indent=2, ensure_ascii=False) + "\n")
    print(f"sello init: {name} ({principal})\n  master   {fp}\n  working  certified 90 days (serial {serial})\n"
          f"  http key {thumb}\n  public   {pub}/\n  private  {h}/  (back up master_ed25519 offline; it certifies everything)")

def renew(pub: Path, days: int = 90):
    card = load_config(pub)
    h = home()
    for f in ("working_ed25519", "working_ed25519.pub", "working_ed25519-cert.pub"):
        p = h / f
        if p.exists(): p.rename(h / (f + f".retired-{int(time.time())}"))
    rc, _, err = run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"{card['principal']} sello working",
                      "-f", str(h / "working_ed25519")])
    if rc: sys.exit(err.decode())
    print(f"renewed: new working key, serial {_certify(card['principal'], days)}")

# ------------------------------------------------------------------ log
def _entry_hash(e: dict) -> str:
    body = {k: e[k] for k in sorted(e) if k != "entry_hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()

def _entries(log: Path):
    if not log.exists(): return []
    return [json.loads(l) for l in log.read_text().splitlines() if l.strip()]

def verify_log(log: Path, quiet=False):
    prev = "0" * 64
    for i, e in enumerate(_entries(log), 1):
        if e.get("seq") != i or e.get("prev") != prev or _entry_hash(e) != e.get("entry_hash"):
            if not quiet: print(f"BROKEN at entry {i}")
            return False, prev
        prev = e["entry_hash"]
    if not quiet: print(f"log intact: {len(_entries(log))} entries, head {prev}")
    return True, prev

# ------------------------------------------------------------------ sign / verify
def sign(path: Path, pub: Path):
    card = load_config(pub)
    can = canonical(path.read_text())
    sigdir = pub / "sigs"; sigdir.mkdir(exist_ok=True)
    cfile = sigdir / (path.name + ".canonical"); cfile.write_bytes(can)
    sigf = Path(str(cfile) + ".sig")
    if sigf.exists(): sigf.unlink()
    rc, _, err = run(["ssh-keygen", "-Y", "sign", "-f", str(home() / "working_ed25519-cert.pub"), "-n", NS, str(cfile)])
    if rc: sys.exit("sign failed: " + err.decode())
    log = pub / "log.jsonl"
    ok, prev = verify_log(log, quiet=True)
    if not ok: sys.exit("refusing to append: the log's chain is broken")
    entries = _entries(log)
    e = {"seq": len(entries) + 1, "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         "principal": card["principal"], "title": path.name, "sha256": hashlib.sha256(can).hexdigest(),
         "sig_sha256": hashlib.sha256(sigf.read_bytes()).hexdigest(), "prev": prev}
    e["entry_hash"] = _entry_hash(e)
    with log.open("a") as f: f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"signed #{e['seq']} {path.name}\n  sha256 {e['sha256']}\n  sig    {sigf}")

def _logged_time(path: Path, log: Path):
    """If this exact content is in the log, return its signing time as YYYYMMDDHHMMSS (UTC)."""
    digest = hashlib.sha256(canonical(path.read_text())).hexdigest()
    for e in _entries(log):
        if e.get("sha256") == digest:
            return time.strftime("%Y%m%d%H%M%SZ", time.strptime(e["time"], "%Y-%m-%dT%H:%M:%SZ"))
    return None

def verify(path: Path, sig: Path, anchor: Path, principal: str, quiet=False, at=None) -> bool:
    """Verify against the trust anchor. `at` (YYYYMMDDHHMMSS[Z]) checks the working key's certificate
    at signing time, so posts stay valid after the 90-day working key expires. Signing time should come
    from the hash-chained (and ideally timestamp-anchored) log, never from the signer's say-so."""
    cmd = ["ssh-keygen", "-Y", "verify", "-f", str(anchor), "-I", principal, "-n", NS, "-s", str(sig)]
    if at: cmd[3:3] = ["-O", f"verify-time={at}"]
    rc, out, err = run(cmd, data=canonical(path.read_text()))
    if not quiet: print(("VERIFIED: " if rc == 0 else "NOT VERIFIED: ") + (out or err).decode().strip())
    return rc == 0

# ------------------------------------------------------------------ HTTP handshake
def handshake(host: str, pub: Path, agent_url: str, quiet=False, verify_as=None) -> dict:
    """HTTP Message Signature (RFC 9421) in the shape of the IETF Web Bot Auth drafts.
    Check header syntax against the current draft before relying on it in production."""
    hk = home() / "http_ed25519.pem"
    kid = json.loads((pub / "http-message-signatures-directory.json").read_text())["keys"][0]["kid"]
    created = int(time.time()); expires = created + 60
    params = (f'("@authority" "signature-agent");created={created};expires={expires};'
              f'keyid="{kid}";alg="ed25519";nonce="{b64u(os.urandom(16))}";tag="web-bot-auth"')
    sa = f'"{agent_url}"'
    def base_for(h): return f'"@authority": {h}\n"signature-agent": {sa}\n"@signature-params": {params}'.encode()
    tmp = home() / ".tmp"; tmp.mkdir(exist_ok=True)
    (tmp / "base").write_bytes(base_for(host))
    rc, _, err = run(["openssl", "pkeyutl", "-sign", "-inkey", str(hk), "-rawin", "-in", str(tmp / "base"),
                      "-out", str(tmp / "sig")])
    if rc: sys.exit(err.decode())
    headers = {"Signature-Agent": sa, "Signature-Input": f"sig1={params}",
               "Signature": f"sig1=:{base64.b64encode((tmp / 'sig').read_bytes()).decode()}:"}
    # self-check, as a verifier would: rebuild the base for the host it received, check with the public key
    (tmp / "vbase").write_bytes(base_for(verify_as or host))
    run(["openssl", "pkey", "-in", str(hk), "-pubout", "-out", str(tmp / "pub.pem")])
    rc, out, _ = run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(tmp / "pub.pem"), "-rawin",
                      "-in", str(tmp / "vbase"), "-sigfile", str(tmp / "sig")])
    headers["_verified"] = rc == 0 and b"Success" in out
    if not quiet:
        for k, v in headers.items():
            if not k.startswith("_"): print(f"{k}: {v}")
        print(f"# self-check for {verify_as or host}: {'VERIFIED' if headers['_verified'] else 'FAILED'}")
    return headers

def status(pub: Path):
    card = load_config(pub)
    rc, out, _ = run(["ssh-keygen", "-Lf", str(home() / "working_ed25519-cert.pub")])
    valid = [l.strip() for l in out.decode().splitlines() if "Valid:" in l]
    ok, head = verify_log(pub / "log.jsonl", quiet=True)
    print(f"{card['name']} ({card['principal']})  master {card['master_fingerprint']}")
    print(f"working key {valid[0] if valid else '(no certificate)'}")
    print(f"log {'intact' if ok else 'BROKEN'}: {len(_entries(pub / 'log.jsonl'))} entries, head {head}")

# ------------------------------------------------------------------ cli
def main(argv=None):
    ap = argparse.ArgumentParser(prog="sello", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--public", default="sello-public", help="public directory (default ./sello-public)")
    ap.add_argument("--version", action="version", version=VERSION)
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("init"); p.add_argument("--name", required=True); p.add_argument("--principal", required=True)
    p.add_argument("--mode", default="public-persona", choices=["public-persona", "private-agent"])
    p = sp.add_parser("renew"); p.add_argument("--days", type=int, default=90)
    p = sp.add_parser("sign"); p.add_argument("file")
    p = sp.add_parser("verify"); p.add_argument("file"); p.add_argument("--sig"); p.add_argument("--anchor")
    p.add_argument("--principal"); p.add_argument("--log", help="log to read the signing time from")
    p.add_argument("--quiet-time", action="store_true", help=argparse.SUPPRESS)
    p = sp.add_parser("verify-log"); p.add_argument("--log")
    p = sp.add_parser("handshake"); p.add_argument("host"); p.add_argument("--agent-url", default="https://example.invalid/agent")
    sp.add_parser("status")
    a = ap.parse_args(argv); pub = Path(a.public)
    if a.cmd == "init": init(a.name, a.principal, pub, a.mode)
    elif a.cmd == "renew": renew(pub, a.days)
    elif a.cmd == "sign": sign(Path(a.file), pub)
    elif a.cmd == "verify":
        f = Path(a.file); sig = Path(a.sig) if a.sig else pub / "sigs" / (f.name + ".canonical.sig")
        anchor = Path(a.anchor) if a.anchor else pub / "allowed_signers"
        principal = a.principal or anchor.read_text().split()[0]
        at = _logged_time(f, Path(a.log) if a.log else pub / "log.jsonl")
        if at and not a.quiet_time: print(f"(checking the certificate at logged signing time {at})")
        sys.exit(0 if verify(f, sig, anchor, principal, at=at) else 1)
    elif a.cmd == "verify-log": sys.exit(0 if verify_log(Path(a.log) if a.log else pub / "log.jsonl")[0] else 1)
    elif a.cmd == "handshake": handshake(a.host, pub, a.agent_url)
    elif a.cmd == "status": status(pub)

if __name__ == "__main__":
    main()
