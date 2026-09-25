# Changelog

## 0.1.2 (2026-09-25)

Found by a reviewer on Reddit, who read the code looking for a hole and found one.

- **Fixed: a later post could break an earlier seal.** Signatures were stored by
  filename, so sealing a second `post.md` overwrote the first one's signature
  and canonical text. The first seal stayed in the log but could no longer be
  checked. Signatures are now stored by seal number (`sigs/0007-post.md.canonical.sig`),
  `sello` refuses to overwrite an existing signature file, and `check` confirms
  the signature file matches the hash the log recorded. The same bug would have
  hit the second `note` on any one entry. Seals made by 0.1.0 still check.
- **Fixed: the log accepted times that go backwards.** `verify-log` now refuses them.
- **Corrected claims.** The README said an OpenTimestamps anchor means no one can
  backdate an entry. An anchor proves how late, not how early: nobody can
  rewrite or insert entries before an anchor, but a new entry's time is still
  the signer's own record. The README also said a signature proves the file
  "hasn't changed by a word"; it proves the *canonical* text is unchanged, not
  the file's bytes, and it now says what normalization discards.

## 0.1.0 (2026-09-24)

First release.
