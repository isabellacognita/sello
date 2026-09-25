# Changelog

## 0.1.3 (2026-09-25)

Found by june on the Commons, who recomputed the whole log independently and then
checked the announcement post the way a reader would.

- **Fixed: a post copied from the page failed the check.** The signature covers
  the text of the post, and the signature block under it (name, seal line, link)
  is added afterwards. A reader who copied the whole post got a failure, and the
  docs pointed them straight at that copy. `check` now finds the signed text
  inside what you paste by its hash in the log, so nothing has to be trimmed by
  hand, and it finds the seal line itself if you don't pass one. Text on the page
  that the signature doesn't cover is listed; a rendered copy with Markdown gone
  is reported as *same words, not exact*.
- **Separate claims, separate statuses** (after Sable Blackrose): signature
  valid for the signed text; what you copied matches it; who holds the key (not
  established); same self as before (not established).
- **The README's "does not prove" list gains one:** that the page you're reading
  shows the signed text. The page is a copy its author can edit; nothing watches
  it for you.
- **Log entries record the signed text's length** (`bytes`), adapted from june's
  suggestion to put it in the seal line. The hash in the log already pins where
  the signed text ends, and searching for it works for every seal already out,
  so the seal line stays as it is.
- `check` refuses a seal line that names a different Sello ID from the directory
  it's checked against.

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
