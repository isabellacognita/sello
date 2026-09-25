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
  sello id                                                 print your fixed Sello ID
  sello note --about N "TEXT"                              signed, chained note on entry N (corrections live in the log)
  sello seal FILE [--footer]                               sign + print a seal (or a 3-line signature block) for a post
  sello check FILE ["SEAL"]                                paste the whole post; is it exactly what this Sello ID sealed?

Private keys live in $SELLO_HOME (default ~/.config/sello, mode 700) and are never
written to the public directory. Public material goes to ./sello-public (or --public).
"""
import argparse, base64, hashlib, json, os, re, subprocess, sys, time, unicodedata
from pathlib import Path

VERSION = "0.1.3"
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

def init(name: str, principal: str, pub: Path, mode: str = "public-persona", verify_url: str = ""):
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
        "verify_url": verify_url,
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
    """Check the hash chain and that times never go backwards. The times are still the signer's own
    record: an external timestamp anchor bounds them, the chain alone cannot."""
    prev, last = "0" * 64, ""
    for i, e in enumerate(_entries(log), 1):
        if e.get("seq") != i or e.get("prev") != prev or _entry_hash(e) != e.get("entry_hash"):
            if not quiet: print(f"BROKEN at entry {i}")
            return False, prev
        if e.get("time", "") < last:
            if not quiet: print(f"BROKEN at entry {i}: its time is earlier than the entry before it")
            return False, prev
        prev, last = e["entry_hash"], e.get("time", "")
    if not quiet: print(f"log intact: {len(_entries(log))} entries, head {prev}")
    return True, prev

# ------------------------------------------------------------------ sign / verify
def sig_paths(pub: Path, e: dict):
    """Where an entry's canonical text and signature live. New entries are stored by sequence number
    (0007-post.md.canonical), so two posts with the same filename can never overwrite each other.
    Entries signed by sello 0.1.0 were stored by filename alone; fall back to that."""
    d = pub / "sigs"
    new = d / f"{e['seq']:04d}-{e['title']}.canonical"
    base = new if new.exists() or not (d / f"{e['title']}.canonical").exists() else d / f"{e['title']}.canonical"
    return base, Path(str(base) + ".sig")

def sign(path: Path, pub: Path):
    card = load_config(pub)
    can = canonical(path.read_text())
    log = pub / "log.jsonl"
    ok, prev = verify_log(log, quiet=True)
    if not ok: sys.exit("refusing to sign: the log's chain is broken")
    seq = len(_entries(log)) + 1
    sigdir = pub / "sigs"; sigdir.mkdir(exist_ok=True)
    cfile = sigdir / f"{seq:04d}-{path.name}.canonical"
    sigf = Path(str(cfile) + ".sig")
    if cfile.exists() or sigf.exists(): sys.exit(f"refusing to overwrite {cfile.name}: a signature is never replaced")
    cfile.write_bytes(can)
    rc, _, err = run(["ssh-keygen", "-Y", "sign", "-f", str(home() / "working_ed25519-cert.pub"), "-n", NS, str(cfile)])
    if rc: cfile.unlink(); sys.exit("sign failed: " + err.decode())
    e = {"seq": seq, "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         "principal": card["principal"], "title": path.name, "sha256": hashlib.sha256(can).hexdigest(), "bytes": len(can),
         "sig_sha256": hashlib.sha256(sigf.read_bytes()).hexdigest(), "prev": prev}
    e["entry_hash"] = _entry_hash(e)
    with log.open("a") as f: f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"signed #{e['seq']} {path.name}\n  sha256 {e['sha256']}\n  sig    {sigf}")

def _logged_entry(path: Path, log: Path):
    """The log entry for this exact content, if any (the latest, if it was signed more than once)."""
    digest = hashlib.sha256(canonical(path.read_text())).hexdigest()
    found = [e for e in _entries(log) if e.get("sha256") == digest]
    return found[-1] if found else None

def _stamp(e: dict) -> str:
    return time.strftime("%Y%m%d%H%M%SZ", time.strptime(e["time"], "%Y-%m-%dT%H:%M:%SZ"))

def verify(path: Path, sig: Path, anchor: Path, principal: str, quiet=False, at=None) -> bool:
    """Verify against the trust anchor. `at` (YYYYMMDDHHMMSS[Z]) checks the working key's certificate
    at signing time, so posts stay valid after the 90-day working key expires. Signing time should come
    from the hash-chained (and ideally timestamp-anchored) log, never from the signer's say-so."""
    return _verify_bytes(canonical(path.read_text()), sig, anchor, principal, quiet, at)

def _verify_bytes(can: bytes, sig: Path, anchor: Path, principal: str, quiet=False, at=None) -> bool:
    cmd = ["ssh-keygen", "-Y", "verify", "-f", str(anchor), "-I", principal, "-n", NS, "-s", str(sig)]
    if at: cmd[3:3] = ["-O", f"verify-time={at}"]
    rc, out, err = run(cmd, data=can)
    if not quiet: print(("VERIFIED: " if rc == 0 else "NOT VERIFIED: ") + (out or err).decode().strip())
    return rc == 0

def note(text: str, about: int, pub: Path):
    """Append a signed note about an earlier log entry (a correction, a void, a retraction).
    Notes live in the log itself, signed and chained like everything else, so they can't be
    quietly edited or deleted. The log is append-only: you never fix an entry, you annotate it."""
    entries = _entries(pub / "log.jsonl")
    if not 0 < about <= len(entries): sys.exit(f"no entry #{about} to annotate")
    tmp = home() / ".tmp"; tmp.mkdir(parents=True, exist_ok=True)
    f = tmp / f"note-on-{about}.md"
    f.write_text(f"Note on #{about} ({entries[about - 1]['title']}):\n\n{text}\n")
    sign(f, pub)

def sello_id(pub: Path) -> str:
    """The agent's fixed, public Sello ID: handle plus a short form of the master key fingerprint."""
    card = load_config(pub)
    return f"{card['principal']}:{card['master_fingerprint'].split(':', 1)[1][:16]}"

def seal(path: Path, pub: Path, footer: bool = False) -> str:
    """Sign FILE and return a one-line seal to paste under a post (Commons, Reddit, Substack, anywhere).
    With footer=True, return a short signature block: name, seal line, where to verify."""
    sign(path, pub)
    e = _entries(pub / "log.jsonl")[-1]
    line = f"Sello ID {sello_id(pub)} · seal #{e['seq']} {e['entry_hash'][:12]}"
    if footer:
        card = load_config(pub)
        where = card.get("verify_url") or "the signer's public sello directory"
        line = f"{card['name']}\n{line}\nSigned text and how to check it: {where}"
    print(line)
    return line

SEAL_RE = re.compile(r"Sello ID\s+(\S+)\s+·\s+seal\s+#(\d+)\s+([0-9a-f]{8,64})")

def _plain(text: str) -> str:
    """Text as a reader sees it rendered: Markdown marks, list and quote markers, link targets and
    line breaks removed, whitespace collapsed. Used only for the weaker "matches up to formatting" status."""
    t = unicodedata.normalize("NFC", text)
    t = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", t)
    t = re.sub(r"(?m)^\s*(?:#{1,6}\s+|>\s?|[-*+•]\s+|\d+[.)]\s+)", "", t)
    t = t.replace("*", "").replace("`", "")
    return " ".join(t.split())

def _uncovered(before, after, card: dict):
    """Lines outside the signed text that the reader should be told about. A signature block
    after the text (the signer's name, the seal line, the 'Signed text and how to check it' line)
    is expected and not reported; everything else is, including anything above the text."""
    def block_line(l): return l == card["name"] or SEAL_RE.search(l) or l.startswith("Signed text and how to check it:")
    before = [l.strip() for l in before if l.strip()]; after = [l.strip() for l in after if l.strip()]
    if any(SEAL_RE.search(l) for l in after): after = [l for l in after if not block_line(l)]
    return before + after

def examine(path: Path, seal_line, pub: Path, anchor: Path = None) -> dict:
    """Check a post as a reader copied it, and keep the claims separate (after Sable Blackrose):
    is the signature valid for the signed text, and does what the reader copied match it?
    The signed text is found inside the copy by its hash in the log (after june's report that the
    signature block under a post isn't covered), so nothing has to be trimmed by hand."""
    text = path.read_text()
    r = {"sig": False, "display": "no", "outside": [], "reasons": [], "entry": None}
    m = SEAL_RE.search(seal_line) if seal_line else None
    if not m:
        found = SEAL_RE.findall(text)
        if found and not seal_line: m = list(SEAL_RE.finditer(text))[-1]
    if not m:
        m2 = re.search(r"#(\d+)\s+([0-9a-f]{8,64})", seal_line or "")
        if not m2: r["reasons"].append("no sello seal line found"); return r
        sid, seq, prefix = None, int(m2.group(1)), m2.group(2)
    else:
        sid, seq, prefix = m.group(1), int(m.group(2)), m.group(3)
    card = load_config(pub)
    if sid and sid != sello_id(pub): r["reasons"].append(f"the seal names {sid}, but this directory belongs to {sello_id(pub)}")
    entries = _entries(pub / "log.jsonl")
    if not verify_log(pub / "log.jsonl", quiet=True)[0]: r["reasons"].append("the public log's chain is broken")
    e = entries[seq - 1] if 0 < seq <= len(entries) else None
    if not e or not e["entry_hash"].startswith(prefix): r["reasons"].append("no such seal in the log")
    if r["reasons"]: return r
    r["entry"] = e
    signed_file, sig = sig_paths(pub, e)
    if not sig.exists() or hashlib.sha256(sig.read_bytes()).hexdigest() != e["sig_sha256"]:
        r["reasons"].append("the signature file is missing or is not the one the log recorded"); return r
    # 1. find the signed text inside what the reader copied, exactly, at line boundaries
    lines = canonical(text).decode().split("\n")
    region = None
    for i in range(len(lines)):
        if not lines[i].strip(): continue
        for j in range(len(lines), i, -1):
            if not lines[j - 1].strip(): continue
            if hashlib.sha256(canonical("\n".join(lines[i:j]))).hexdigest() == e["sha256"]:
                region = (i, j); break
        if region: break
    if region:
        can = canonical("\n".join(lines[region[0]:region[1]]))
        r["outside"] = _uncovered(lines[:region[0]], lines[region[1]:], card)
        r["display"] = "exact" if not r["outside"] else "extra"
    else:
        # 2. weaker: the same words once rendering is set aside (Markdown marks, line breaks)
        if not signed_file.exists() or hashlib.sha256(signed_file.read_bytes()).hexdigest() != e["sha256"]:
            r["reasons"].append("the text differs from what was sealed"); return r
        can = signed_file.read_bytes()
        ps, pp = _plain(can.decode()), _plain(text)
        k = pp.find(ps) if ps else -1
        if k < 0:
            r["reasons"].append("the text differs from what was sealed")
        else:
            before, after = pp[:k].strip(), pp[k + len(ps):].strip()
            split = lambda x: re.split(r"(?=Sello ID )|(?=Signed text and how)", x)
            after_parts = split(after)
            if card["name"] and after_parts and after_parts[0].strip().endswith(card["name"]):
                head = after_parts[0].strip()[: -len(card["name"])]
                after_parts = [head, card["name"]] + after_parts[1:]
            r["outside"] = _uncovered([before], after_parts, card)
            r["display"] = "formatting" if not r["outside"] else "extra"
    # the signature itself, checked at the logged signing time
    anchor = anchor or pub / "allowed_signers"
    r["sig"] = _verify_bytes(can if region else signed_file.read_bytes(), sig, anchor, e["principal"], quiet=True, at=_stamp(e))
    if not r["sig"]: r["reasons"].append("the signature does not verify against the master key")
    return r

def check(path: Path, seal_line=None, pub: Path = None, anchor: Path = None, quiet=False) -> bool:
    """Yes/no: is what you copied exactly the text this Sello ID sealed? Paste the whole post,
    signature block and all. Prints four separate statuses; returns True only when the signature
    is valid AND everything you copied, apart from the signature block, is covered by it."""
    pub = pub or Path("sello-public")
    r = examine(path, seal_line, pub, anchor)
    e = r["entry"]
    ok = r["sig"] and r["display"] == "exact"
    if not quiet:
        if not e or (r["reasons"] and not r["sig"] and r["display"] == "no"):
            print("NO: " + "; ".join(r["reasons"])); return False
        n = e.get("bytes") or len(canonical(sig_paths(pub, e)[0].read_text())) if sig_paths(pub, e)[0].exists() else "?"
        print(f"Seal #{e['seq']} by {sello_id(pub)}, logged {e['time']}, signed text {n} bytes")
        print("  Signature valid for the signed text:  " + ("NO" if not r["sig"] else "YES" if r["display"] != "no"
              else "YES, for the published signed text in sigs/, which is not what you copied"))
        disp = {"exact": "YES, exactly (apart from the signature block)",
                "formatting": "SAME WORDS, not exact: formatting or line breaks differ (e.g. copied from a rendered page); link targets were not compared",
                "extra": "PARTLY: the signed text is there, but these lines are NOT covered by the signature:",
                "no": "NO: " + "; ".join(r["reasons"])}[r["display"]]
        print("  What you copied matches it:           " + disp)
        for l in r["outside"]: print("      | " + l)
        print("  Who holds the key:                    not established by a signature (see key-card.json)")
        print("  Same self as before:                  not established by a signature")
    return ok

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
    p.add_argument("--verify-url", default="", help="public URL of your sello directory (shown in footers)")
    p.add_argument("--mode", default="public-persona", choices=["public-persona", "private-agent"])
    p = sp.add_parser("renew"); p.add_argument("--days", type=int, default=90)
    p = sp.add_parser("sign"); p.add_argument("file")
    p = sp.add_parser("verify"); p.add_argument("file"); p.add_argument("--sig"); p.add_argument("--anchor")
    p.add_argument("--principal"); p.add_argument("--log", help="log to read the signing time from")
    p.add_argument("--quiet-time", action="store_true", help=argparse.SUPPRESS)
    p = sp.add_parser("verify-log"); p.add_argument("--log")
    p = sp.add_parser("handshake"); p.add_argument("host"); p.add_argument("--agent-url", default="https://example.invalid/agent")
    sp.add_parser("status")
    p = sp.add_parser("seal"); p.add_argument("file"); p.add_argument("--footer", action="store_true")
    p = sp.add_parser("check"); p.add_argument("file"); p.add_argument("seal_line", nargs="?")
    sp.add_parser("id")
    p = sp.add_parser("note"); p.add_argument("--about", type=int, required=True); p.add_argument("text")
    a = ap.parse_args(argv); pub = Path(a.public)
    if a.cmd == "init": init(a.name, a.principal, pub, a.mode, a.verify_url)
    elif a.cmd == "renew": renew(pub, a.days)
    elif a.cmd == "sign": sign(Path(a.file), pub)
    elif a.cmd == "verify":
        f = Path(a.file)
        e = _logged_entry(f, Path(a.log) if a.log else pub / "log.jsonl")
        if a.sig: sig = Path(a.sig)
        elif e: sig = sig_paths(pub, e)[1]
        else: sys.exit("NOT VERIFIED: this text is not in the log (pass --sig to check a signature directly)")
        anchor = Path(a.anchor) if a.anchor else pub / "allowed_signers"
        principal = a.principal or anchor.read_text().split()[0]
        at = _stamp(e) if e else None
        if at and not a.quiet_time: print(f"(checking the certificate at logged signing time {at})")
        sys.exit(0 if verify(f, sig, anchor, principal, at=at) else 1)
    elif a.cmd == "verify-log": sys.exit(0 if verify_log(Path(a.log) if a.log else pub / "log.jsonl")[0] else 1)
    elif a.cmd == "handshake": handshake(a.host, pub, a.agent_url)
    elif a.cmd == "status": status(pub)
    elif a.cmd == "seal": seal(Path(a.file), pub, a.footer)
    elif a.cmd == "check":
        ok = check(Path(a.file), a.seal_line, pub)
        sys.exit(0 if ok else 2 if examine(Path(a.file), a.seal_line, pub)["display"] == "formatting" else 1)
    elif a.cmd == "id": print(sello_id(pub))
    elif a.cmd == "note": note(a.text, a.about, pub)

if __name__ == "__main__":
    main()
