# 5. Extract the SHA-1 from the FileId by stripping its leading padding

Date: 2026-07-24
Status: Accepted

## Context

Amcache's headline forensic value is a **file hash to pivot on**. Both schemas
store it, but not as a bare digest: the modern `FileId` value (and the legacy `101`
value) is the 40-hex-character SHA-1 prefixed with a `0000` pad, i.e. a 44-character
string. A naive read that returned the whole `FileId` would emit a hash that
matches no other tool's output and no VirusTotal/threat-intel lookup — the exact
"produces plausible-but-wrong output" failure the fleet guards against. The
encoding is documented in libyal's `dtformats` "AMCache.hve format" reference and
confirmed against two independent oracles.

Evidence: `core/src/lib.rs` `sha1_from_file_id` — takes the last 40 chars
(`id[id.len() - 40..]`), lower-cased, guarded by `id.len() >= 40`; the module doc
("the `FileId` value with its leading `0000` padding removed (its last 40 hex
chars)"); `docs/validation.md` byte-for-byte matches against Eric Zimmerman's
`AmcacheParser` and `regipy` (`7z.exe` →
`1189cebeb8ffed7316f98b895ff949a726f4026f`).

## Decision

1. **Derive the digest from structure, not a fixed offset into fixed input**: take
   the trailing 40 characters of the trimmed `FileId`, so the rule holds regardless
   of pad length or surrounding whitespace, and works identically for the modern
   `FileId` and the legacy `101` value.
2. **Return `None` when there is no usable hash** (`id.len() < 40`) — common for
   Store/AppX binaries — rather than emitting a truncated or fabricated value.
3. **Normalize to lower-case hex** so hashes compare and dedupe cleanly across
   entries and against oracles.
4. **Validate against independent oracles on real hives** (ADR is backed by the
   Tier-1 table in `docs/validation.md`), not a self-authored round-trip — this is
   a value-producing path where a wrong impl and a wrong fixture would otherwise
   agree.

## Consequences

- The SHA-1 the tool prints is the same digest AmcacheParser and regipy print, so
  it drops straight into threat-intel and cross-artifact correlation.
- The hash surfaces as a first-class `SubjectRef { scheme: "hash", kind: "sha1" }`
  on every finding (see ADR 0006).
- No spurious hash on hash-less entries.
