# contributing

prs and issues welcome. this is a small, focused project, all three
`ROADMAP.md` milestones are done (Qt-free sender, mDNS discovery, and the
`airplay-send` CLI demo). the fastest way in now is the README recipe +
`ROADMAP.md`'s "later / maybe" list, or just: run `airplay-send` against your
own receiver and file an issue if something's off, real-device reports are
the highest-value thing right now.

## the one rule that actually matters: stay clean-room

this project reconstructs a reverse-engineered protocol. its license story only
holds if we are careful about where code comes from:

- the **crypto/wire-format core** (`src/airplay_crypto.*`) is **clean-room**,
  written from public reverse-engineering work read *as documentation only*.
  **do not paste code into it** from owntone, shairport-sync, pyatv, pair_ap, or
  any other implementation. byte formats and constants (the facts on the wire)
  are fine; their *source code* is not.
- the **RAOP transport** (`src/raop_sender.cpp`) is openly credited as a C++
  **port of pyatv** (MIT) in `licenses/THIRD-PARTY-NOTICES.txt`. if you extend
  it with logic derived from another project, say so in the PR and bring the
  matching license + attribution with it. **never** copy from a GPL/AGPL source
  (owntone's daapd lineage, RAOP-Player, etc.), that would poison the
  Apache-2.0 license for everyone.
- `src/mdns_browser.*` is a different case: it implements open IETF standards
  (RFC 6762 mDNS, RFC 6763 DNS-SD), not a reverse-engineered Apple protocol, so
  there's no clean-room concern for the wire-format parsing itself. The one
  place Apple-specific guesswork creeps back in is `deriveAuth()` (mapping a
  device's TXT record to a `RaopSender::Auth` starting guess); treat that
  function with the same care as the crypto core, documentation only, no
  pasted code, and be honest in comments about what's verified vs. guessed.

- `example/` (the `airplay-send` CLI, the wav reader, the credential cache) has
  no clean-room concern either, it's plumbing + an open file format (RIFF/WAVE),
  not protocol reconstruction. Normal code-review standards apply there.

when in doubt, describe the protocol behaviour in your own words and implement
from that. if you're unsure whether something is OK to bring in, open an issue
first and ask.

## practical bits

- build the crypto core: `cmake -B build && cmake --build build --target airplay_crypto`.
- build the sender: `cmake --build build --target raop_sender posix_transport`.
- build the mDNS browser: `cmake --build build --target mdns_browser`.
- build the CLI demo: `cmake --build build --target airplay-send`.
- keep the prose voice as-is (lowercase, plain). no em-dashes in comments/docs.
- authorship: commits are by their author; no AI-attribution / `Co-Authored-By`
  trailers, please.
- a good bug report (see the issue template) names the **receiver model**, the
  **`sf=` feature flag**, and the **symptom** ("connects but silent", "drops at
  ~30 s", "refused at SETUP"), that's usually enough to locate it in the recipe.

## security

see `SECURITY.md`. the headline open item (fail-closed receiver authentication)
is a genuinely good, well-scoped first contribution.
