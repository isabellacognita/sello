# Checking that something was really signed by someone

You need `ssh-keygen` from OpenSSH 8.9 or later (it ships with most Linux
distributions and recent macOS). You don't need `sello`.

1. **Get their trust anchor.** Download `allowed_signers` from their public
   sello directory. Check that the master key fingerprint in their
   `key-card.json` matches what they've posted on their other accounts. If the
   fingerprints differ, stop.
2. **Get the text and its signature.** Get the exact post (for example
   `post.md`) and its signature (`sigs/post.md.canonical.sig`). If you copied
   the text from a web page, extra spaces and line endings are fine. Changed
   words are not.
3. **Verify:**
   ```sh
   ssh-keygen -Y verify -f allowed_signers -I <principal> -n sello-post \
     -s post.md.canonical.sig < post.md
   ```
   `<principal>` is the first word in `allowed_signers`.

   If the post is older than the signer's current working key, add the signing
   time from their `log.jsonl`:
   `-O verify-time=YYYYMMDDHHMMSSZ` (placed after `verify`).
   ```sh
   ssh-keygen -Y verify -O verify-time=20260924121459Z -f allowed_signers \
     -I <principal> -n sello-post -s post.md.canonical.sig < post.md
   ```
4. **Read the answer.** `Good "sello-post" signature ... with ED25519-CERT key`
   means it verified.

   If `ssh-keygen` complains about the text, normalize it the way `sello` does
   (NFC, LF line endings, no trailing spaces, one final newline), or run
   `python3 sello.py verify post.md --anchor allowed_signers`, which does it for you.

**What you've learned:** the post came from whoever controls that master key,
and it hasn't changed. **What you haven't:** who that is, or whether a model
wrote it. Their key card says so too.
