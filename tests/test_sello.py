"""Run with: python3 -m unittest discover -s tests -v   (stdlib only; needs ssh-keygen and openssl)."""
import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import sello  # noqa: E402


class SelloTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        os.environ["SELLO_HOME"] = str(root / "private")
        cls.pub = root / "public"
        sello.init("Test Agent", "test-agent", cls.pub)
        cls.doc = root / "post.md"
        cls.doc.write_text("One plant, and its reflection.\n")
        sello.sign(cls.doc, cls.pub)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _sig(self, seq=1):
        return sello.sig_paths(self.pub, sello._entries(self.pub / "log.jsonl")[seq - 1])[1]

    def _verify(self, path, sig=None):
        sig = sig or self._sig()
        return sello.verify(Path(path), sig, self.pub / "allowed_signers", "test-agent", quiet=True)

    def test_signed_file_verifies(self):
        self.assertTrue(self._verify(self.doc))

    def test_reformatting_still_verifies(self):
        copy = self.doc.with_name("post-copy.md")
        copy.write_text("One plant, and its reflection.   \r\n\r\n")
        self.assertTrue(self._verify(copy, self._sig()))

    def test_changed_word_fails(self):
        copy = self.doc.with_name("post-edit.md")
        copy.write_text("Two plants, and their reflection.\n")
        self.assertFalse(self._verify(copy, self._sig()))

    def test_private_keys_never_public(self):
        names = {p.name for p in self.pub.rglob("*")}
        self.assertFalse(any("ed25519" in n and not n.endswith(".sig") for n in names), names)
        self.assertFalse(any(n.endswith(".pem") for n in names), names)

    def test_log_chain_and_tamper(self):
        log = self.pub / "log.jsonl"
        self.assertTrue(sello.verify_log(log, quiet=True)[0])
        original = log.read_text()
        e = json.loads(original.splitlines()[0]); e["title"] = "something-else.md"
        log.write_text(json.dumps(e) + "\n")
        try:
            self.assertFalse(sello.verify_log(log, quiet=True)[0])
        finally:
            log.write_text(original)

    def test_uncertified_key_rejected(self):
        home = Path(os.environ["SELLO_HOME"])
        k = home / "impostor"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(k)], check=True)
        f = self.doc.with_name("impostor.canonical"); f.write_bytes(sello.canonical("I am Test Agent.\n"))
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(k), "-n", sello.NS, str(f)], check=True,
                       capture_output=True)
        src = self.doc.with_name("impostor.md"); src.write_text("I am Test Agent.\n")
        self.assertFalse(self._verify(src, Path(str(f) + ".sig")))

    def test_expired_certificate_rejected(self):
        home = Path(os.environ["SELLO_HOME"])
        k = home / "expired"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(k)], check=True)
        subprocess.run(["ssh-keygen", "-q", "-s", str(home / "master_ed25519"), "-I", "expired", "-n", "test-agent",
                        "-V", "20200101:20200102", str(k) + ".pub"], check=True)
        f = self.doc.with_name("expired.canonical"); f.write_bytes(sello.canonical("Old words.\n"))
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(k) + "-cert.pub", "-n", sello.NS, str(f)], check=True,
                       capture_output=True)
        src = self.doc.with_name("expired.md"); src.write_text("Old words.\n")
        self.assertFalse(self._verify(src, Path(str(f) + ".sig")))

    def test_handshake_verifies_and_resists_replay(self):
        self.assertTrue(sello.handshake("example.com", self.pub, "https://example.invalid/a", quiet=True)["_verified"])
        self.assertFalse(sello.handshake("example.com", self.pub, "https://example.invalid/a", quiet=True,
                                         verify_as="other.example")["_verified"])

    def test_card_states_limits(self):
        card = json.loads((self.pub / "key-card.json").read_text())
        self.assertEqual(len(card["does_not_prove"]), 3)
        self.assertEqual(card["level"], 0)

    def test_old_signature_valid_at_signing_time(self):
        """A post signed while its working key was valid must still verify after that key expires."""
        home = Path(os.environ["SELLO_HOME"])
        k = home / "past"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(k)], check=True)
        subprocess.run(["ssh-keygen", "-q", "-s", str(home / "master_ed25519"), "-I", "past", "-n", "test-agent",
                        "-V", "20200101:20200201", str(k) + ".pub"], check=True)
        f = self.doc.with_name("past.canonical"); f.write_bytes(sello.canonical("Written in January.\n"))
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(k) + "-cert.pub", "-n", sello.NS, str(f)], check=True,
                       capture_output=True)
        src = self.doc.with_name("past.md"); src.write_text("Written in January.\n")
        sig = Path(str(f) + ".sig")
        self.assertFalse(sello.verify(src, sig, self.pub / "allowed_signers", "test-agent", quiet=True))
        self.assertTrue(sello.verify(src, sig, self.pub / "allowed_signers", "test-agent", quiet=True,
                                     at="20200115120000"))
        self.assertFalse(sello.verify(src, sig, self.pub / "allowed_signers", "test-agent", quiet=True,
                                      at="20200301120000"))

    def test_seal_and_check(self):
        post = self.doc.with_name("reddit-comment.md")
        post.write_text("A key tracks a source, not a self.\n")
        line = sello.seal(post, self.pub)
        self.assertTrue(line.startswith("Sello ID test-agent:"))
        self.assertTrue(sello.check(post, line, self.pub, quiet=True))
        # same seal pasted under different words: NO
        other = self.doc.with_name("forged.md"); other.write_text("A key tracks a self.\n")
        self.assertFalse(sello.check(other, line, self.pub, quiet=True))
        # made-up seal: NO
        self.assertFalse(sello.check(post, "Sello ID test-agent:x · seal #999 deadbeefdead", self.pub, quiet=True))

    def test_footer_block(self):
        post = self.doc.with_name("footer-post.md"); post.write_text("Signed with a footer.\n")
        block = sello.seal(post, self.pub, footer=True)
        lines = block.splitlines()
        self.assertEqual(lines[0], "Test Agent")
        self.assertTrue(lines[1].startswith("Sello ID test-agent:"))
        self.assertTrue(sello.check(post, lines[1], self.pub, quiet=True))

    def test_note_is_signed_and_chained(self):
        n_before = len(sello._entries(self.pub / "log.jsonl"))
        sello.note("Entry 1 was a test.", 1, self.pub)
        entries = sello._entries(self.pub / "log.jsonl")
        self.assertEqual(len(entries), n_before + 1)
        self.assertEqual(entries[-1]["title"], "note-on-1.md")
        self.assertTrue(sello.verify_log(self.pub / "log.jsonl", quiet=True)[0])


    def test_same_filename_never_overwrites(self):
        """Found by a reviewer on Reddit: two different posts both named post.md must both stay checkable."""
        a = Path(self.tmp.name) / "a"; b = Path(self.tmp.name) / "b"; a.mkdir(); b.mkdir()
        (a / "same.md").write_text("The first post.\n"); (b / "same.md").write_text("The second post.\n")
        first = sello.seal(a / "same.md", self.pub)
        second = sello.seal(b / "same.md", self.pub)
        self.assertTrue(sello.check(a / "same.md", first, self.pub, quiet=True))
        self.assertTrue(sello.check(b / "same.md", second, self.pub, quiet=True))

    def test_two_notes_on_one_entry(self):
        sello.note("First note.", 1, self.pub); first = sello._entries(self.pub / "log.jsonl")[-1]
        sello.note("Second note.", 1, self.pub); second = sello._entries(self.pub / "log.jsonl")[-1]
        for e in (first, second):
            _, sig = sello.sig_paths(self.pub, e)
            self.assertEqual(sello.hashlib.sha256(sig.read_bytes()).hexdigest(), e["sig_sha256"])

    def test_replaced_signature_file_is_caught(self):
        post = self.doc.with_name("swap.md"); post.write_text("Swap test.\n")
        line = sello.seal(post, self.pub)
        _, sig = sello.sig_paths(self.pub, sello._entries(self.pub / "log.jsonl")[-1])
        good = sig.read_bytes(); sig.write_bytes(self._sig().read_bytes())
        try:
            self.assertFalse(sello.check(post, line, self.pub, quiet=True))
        finally:
            sig.write_bytes(good)
        self.assertTrue(sello.check(post, line, self.pub, quiet=True))

    def test_legacy_filename_layout_still_checks(self):
        """Signatures made by 0.1.0 (stored as sigs/<title>.canonical.sig) keep verifying."""
        post = self.doc.with_name("legacy.md"); post.write_text("Signed by an older sello.\n")
        line = sello.seal(post, self.pub)
        e = sello._entries(self.pub / "log.jsonl")[-1]
        c, sig = sello.sig_paths(self.pub, e)
        c.rename(self.pub / "sigs" / "legacy.md.canonical"); sig.rename(self.pub / "sigs" / "legacy.md.canonical.sig")
        self.assertTrue(sello.check(post, line, self.pub, quiet=True))

    def test_backwards_time_breaks_log(self):
        later = self.doc.with_name("later.md"); later.write_text("Signed after the first post.\n")
        sello.sign(later, self.pub)
        log = self.pub / "log.jsonl"; original = log.read_text()
        lines = original.splitlines(); e = json.loads(lines[-1])
        e["time"] = "2020-01-01T00:00:00Z"; e["entry_hash"] = sello._entry_hash(e)
        log.write_text("\n".join(lines[:-1] + [json.dumps(e)]) + "\n")
        try:
            self.assertFalse(sello.verify_log(log, quiet=True)[0])
        finally:
            log.write_text(original)


if __name__ == "__main__":
    unittest.main()
