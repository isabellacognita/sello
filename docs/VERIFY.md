# Checking that something was really signed by someone

You need `ssh-keygen` from OpenSSH 8.9 or later (it ships with most Linux
distributions and recent macOS). You don't need `sello`.

1. **Get their trust anchor.** Download `allowed_signers` from their public
   sello directory. Check that the master key fingerprint in their
   `key-card.json` matches what they've posted on their other accounts. If the
   fingerprints differ, stop.
2. **Get the text and its signature.** The signature covers only the text of the
   post. The signature block underneath it (the signer's name, the seal line and
   the link) was added after signing and is not covered, and neither is anything
   a platform shows around the post, such as a title or a byline.
   - **With sello:** copy the whole post from the page, signature block and all,
     into a file and run `python3 sello.py --public <their directory> check post.txt`.
     It finds the seal line, finds the signed text inside what you copied by its
     hash in the log, and reports separately whether the signature is valid,
     whether what you copied matches the signed text (and which lines, if any,
     aren't covered), and the two things a signature never establishes. If you
     copied from a rendered page, Markdown marks and line breaks may be gone; it
     then says *same words, not exact*, which is weaker, and it can't compare
     link targets.
   - **With ssh-keygen alone:** find the post's entry in their `log.jsonl` by its
     seal number. The signed text is published in `sigs/`, named with the seal
     number and the entry's title, for example `sigs/0007-post.md.canonical`, with
     its signature next to it (`.canonical.sig`). Seals made with sello 0.1.0 have
     no number: `sigs/post.md.canonical`. Verify that file in step 3, then compare
     it with the post on the page yourself. The entry's `bytes` field (from 0.1.3)
     says how long the signed text is. You can also check that the signature
     file's SHA-256 matches the entry's `sig_sha256`.

3. **Verify:**
   ```sh
   ssh-keygen -Y verify -f allowed_signers -I <principal> -n sello-post \
     -s sigs/0007-post.md.canonical.sig < sigs/0007-post.md.canonical
   ```
   `<principal>` is the first word in `allowed_signers`.

   If the post is older than the signer's current working key, add the signing
   time from their `log.jsonl`:
   `-O verify-time=YYYYMMDDHHMMSSZ` (placed after `verify`).
   ```sh
   ssh-keygen -Y verify -O verify-time=20260924121459Z -f allowed_signers \
     -I <principal> -n sello-post -s sigs/0007-post.md.canonical.sig < sigs/0007-post.md.canonical
   ```
4. **Read the answer.** `Good "sello-post" signature ... with ED25519-CERT key`
   means it verified.

   The published `.canonical` file is already normalized. If you verify your own
   copy instead, normalize it the way `sello` does (NFC, LF line endings, no
   trailing spaces, one final newline) and remove the signature block first.

**What you've learned:** the signed text came from whoever controls that master
key and hasn't changed (up to the normalization above). Whether the *page* still
shows that text is a separate question: the page is a copy the author can edit
at any time, and nothing watches it for you. Checking what you copied, as in
step 2, answers it for the moment you copied. **What the log's
time tells you:** when the signer says they signed it. A timestamp anchor, if
they use one, proves it existed no later than that; nothing proves how early. **What you haven't:** who that is, or whether a model
wrote it. Their key card says so too.
