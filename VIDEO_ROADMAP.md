# adding AirPlay Video (remote-URL playback) to airplay2-sender-cpp

## 0. scope check first — this is the "cast a URL" protocol, not mirroring

AirPlay is really three unrelated wire protocols wearing one marketing name:

| | RAOP (what this repo does today) | **AirPlay Video** (this plan) | AirPlay Mirroring |
|---|---|---|---|
| what moves over the wire | your PCM, ALAC-encoded, pushed continuously | **nothing but control messages** — a URL, play/pause/seek commands | your screen, H.264-encoded, pushed continuously |
| who fetches the media | n/a, you're pushing it | **the receiver** — it HTTP-GETs the URL itself | n/a, you're pushing it |
| sender-side heavy lifting | audio pacing, RTP, retransmit | **serving byte-ranges of a file**, if it's local | live encoder, NAL packetizer, capture |
| relationship to RAOP code | — | shares only pairing + the encrypted-request framing | shares only pairing + the encrypted-request framing |

Good news: what you picked is the cheap one. There's no encoder, no RTP, no
pacing thread, no A/V sync problem. The whole job is: get a URL in front of
the receiver, and answer its status queries. If the video is already
somewhere fetchable (an HTTP link, a file on a server), a working sender is
maybe 300–500 lines. Fully-local-file support (embedding a byte-range HTTP
server so you can hand the TV a `file:` on your laptop) is the one genuinely
new subsystem, and it's most of the effort below.

---

## 1. what's directly reusable from the current codebase

- **`airplay_crypto.*` — 100%, unchanged.** SRP-6a, X25519, Ed25519, HKDF,
  ChaCha20-Poly1305, TLV8, and the `bplist00` codec are protocol-agnostic;
  video needs every one of them.
- **the HAP pair-setup / pair-verify state machine** — reusable *as a
  concept*, but it currently lives welded inside `RaopSender` (`PairStage`,
  `beginAuthChain_`, `onPairingResponse_`, the SRP scratch fields). See §3,
  this should be pulled out into its own class regardless of the video work,
  because video needs to run the identical HAP dance against a **second,
  separate TCP connection** (the AirPlay HTTP service is a different port
  than RAOP — see §2). Same long-term Ed25519 identity, same stored
  `credsJson`, new pair-verify per connection.
- **the encrypted-request framing** — `writeRtsp_`, `onRtspReadyRead_`, the
  `pendingMethods_` FIFO, and the ChaCha20-Poly1305 frame format
  (`[2B LE len][cipher][16B tag]`, per-direction counters). This is
  generic "encrypted request/response pipe," not RAOP-specific — video's
  `POST /play`, `GET /playback-info`, etc. are just different verbs/URIs down
  the same pipe once pair-verify has run.
- **`bplist` encode/decode** for building request bodies and parsing replies.

## 2. what has to be reconstructed (apple never documented this either)

This is unpublished the same way the RAOP realtime recipe was — the same
"packet-watch + read prior clean-room work as a spec" approach the README
describes for RAOP applies here. The building blocks, from public
clean-room prior art (old `nto/airplay`, various node/python AirPlay-video
implementations, and pyatv's video-adjacent modules — same category of
source this repo already cites for RAOP):

- **transport**: a second TCP connection to the receiver's **AirPlay HTTP
  service** (historically port 7000, discovered the same way `_raop._tcp`
  is — a sibling `_airplay._tcp` mDNS record; since this repo doesn't do
  discovery yet, plan to accept an already-resolved host+port here too,
  same as `RaopSender::start()` does). Requests are real HTTP/1.1 verbs
  (not RTSP/1.0), but once pair-verify succeeds they ride the *same*
  ChaCha20-Poly1305 request framing as the RAOP control channel.
- **`POST /play`** — body is a plist (or classic `text/parameters`
  `key: value` lines, older receivers) with, at minimum:
  - `Content-Location` — the URL the receiver should fetch
  - `Start-Position` — 0.0–1.0 fractional start point
- **`GET /playback-info`** — polled or pushed; plist reply with
  `duration`, `position`, `rate`, `readyToPlay`, `playbackBufferEmpty`.
- **`POST /rate`** — body `{ value: 0.0 | 1.0 }`, pause/resume.
- **`POST /scrub`** — body `{ position: <seconds> }`, seek.
- **`POST /stop`** — end the session.
- **`GET /event`** — a long-lived HTTP connection the receiver uses to push
  state-change plists (structurally the same "decrypt a pushed request off
  a long-lived socket, answer 200 OK" pattern already implemented for the
  RAOP event channel — different plist schema, reusable plumbing).

Treat every field name/shape above as the **hypothesis to verify against
real hardware**, not a spec — flag this explicitly in code comments the way
`raop_sender.cpp` already does (`// #150, verified against ...`), and budget
real Apple TV / receiver time for it. This is the part of this plan most
likely to need correction once you're packet-watching.

## 3. architecture changes

### 3a. extract `Ap2PairingSession` out of `RaopSender`

Right now pairing state (`PairStage`, the SRP scratch, `pairSetupSessionKey_`,
`credsJson_`, the transient-retry flag, the derived Control/Events keys) is
private to `RaopSender`. Pull it into a standalone class with roughly:

```cpp
class Ap2PairingSession {
public:
    void begin(RaopDeviceInfo::Auth auth, const QString& credsJson);
    // drives HAP pair-setup/pair-verify over a caller-supplied
    // send/receive pipe (so it doesn't own the socket)
    bool onPinNeeded(...);        // -> pinRequired-style callback
    void submitPin(const QString&);
    // on completion: shared secret + derived channel keys, ready to
    // hand to whichever encrypted-request layer wants them
    struct Result { Bytes controlIn, controlOut, sharedSecret; QString credsJson; };
};
```

Both `RaopSender` and the new video sender construct one of these against
their own TCP connection. This is a strict subset of the Qt-free transport
refactor already on `ROADMAP.md` (m1) — worth doing together, since both
land on "pairing talks through a small send/recv interface" either way.

### 3b. extract the encrypted-request pipe

`writeRtsp_` / `onRtspReadyRead_` / `pendingMethods_` become a small
`EncryptedRequestChannel` (wraps a socket + the two ChaCha20-Poly1305
counters + the pending-method FIFO), reusable for both RTSP-style and
plain-HTTP-style request lines.

### 3c. new class: `AirPlayVideoSender`

```cpp
class AirPlayVideoSender : public QObject {
public:
    void setAuth(RaopDeviceInfo::Auth, const QString& credsJson);
    void connectTo(const QString& host, quint16 port);   // the _airplay._tcp port

    void play(const QUrl& mediaUrl, double startPosition = 0.0);
    void playLocalFile(const QString& path);   // see §3d — spins up the
                                                 // embedded server, then
                                                 // calls play() with the
                                                 // resulting local URL
    void pause();
    void resume();
    void seek(double seconds);
    void stop();

signals:
    void playbackStateChanged(PlaybackState);   // idle/loading/playing/paused/finished
    void durationKnown(double seconds);
    void positionChanged(double seconds);
    void error(const QString&);
};
```

Deliberately **not** a subclass or sibling state machine bolted onto
`RaopSender` — the two share only §3a/§3b, and forcing one `State` enum to
cover "RTP pacer ticking" and "waiting on a receiver-pull HTTP GET" produces
exactly the kind of tangled class the Qt-removal roadmap item is trying to
get away from.

### 3d. the new subsystem: a minimal byte-range HTTP server

The one thing with no RAOP analogue. Needed whenever the source is a local
file rather than an already-hosted URL — the receiver does the fetching, so
something has to serve it. Requirements, roughly in order of "the receiver
will actually break without it":

1. **`Range:` request support is not optional.** Apple TV/receivers seek by
   issuing byte-range GETs; a server that ignores `Range` and always
   returns the whole body from offset 0 will look like it works for
   playback but seeking will silently fail or restart from zero.
2. Correct `Content-Length` / `206 Partial Content` / `Content-Range`
   response semantics, and `Accept-Ranges: bytes` on the initial response.
3. `HEAD` support (receivers probe duration/size before committing to a
   fetch).
4. Correct `Content-Type` (receiver may refuse to play an unrecognized MIME
   type — derive from extension, keep a small allow-list: mp4/mov/m4v →
   `video/mp4`, etc.).
5. Serve on an address+port reachable from the receiver's subnet, and use
   that in the `Content-Location` URL handed to `/play`. On multi-homed
   machines, pick the interface facing the same subnet as the receiver's
   IP, not just "first non-loopback".
6. Concurrent range requests: some receivers open more than one connection
   for the same fetch (prefetch + playback). The server needs to be at
   least modestly concurrent, not one-request-at-a-time.
7. Bind lifetime tied to the playback session — tear it down on `stop()` /
   `playbackStateChanged(Finished)`, not left listening forever.

This is standard, well-trodden territory (it's a static file server with
range support) — no protocol reverse-engineering needed here, just correct
HTTP/1.1. Consider a small header-only implementation or a lightweight
existing library rather than hand-rolling HTTP parsing; this is the one
piece of the video work that isn't AirPlay-specific at all.

## 4. milestones

Mirrors the existing `ROADMAP.md` style — smallest slice that's actually
useful first.

- **v1 — remote-URL only.** `AirPlayVideoSender::play(QUrl)` against an
  already-hosted video (e.g. an mp4 on a LAN web server, or a public HTTPS
  URL). Exercises pairing-reuse, `/play`, `/playback-info` polling,
  `/rate`, `/scrub`, `/stop`. No new HTTP server, so this validates the
  protocol reconstruction from §2 in isolation before adding the file-server
  complexity of §3d.
- **v2 — local-file playback.** Add the range-serving HTTP server; wire
  `playLocalFile()` through it. This is the version people actually want
  ("cast this file off my machine").
- **v3 — push events instead of polling `/playback-info`.** Implement
  `GET /event` long-poll so `positionChanged`/`playbackStateChanged` are
  receiver-driven rather than timer-polled — nicer UX (accurate scrubber),
  optional.
- **later / maybe**: photo casting (`/photo`, `/photo-caching`) shares
  almost the entire same pairing + request plumbing if it's ever wanted;
  worth a footnote in the roadmap once video v1/v2 land.

## 5. open questions to resolve against real hardware before v1 is "done"

- Exact plist key set / body content-type per receiver generation (older
  AirPlay 1–era boxes used `text/parameters`, not a binary plist — may need
  to detect and speak both, the same way `RaopSender` already branches on
  AP1 vs AP2).
- Whether the AirPlay-video port is *always* discoverable the same way as
  `_raop._tcp`, or needs its own mDNS record/TXT key inspection.
- Whether unauthenticated-video is still possible on any current receiver,
  or whether pair-verify is now mandatory across the board (matters for the
  "point this at a TV with default settings" first-run experience).
- Behavior on `/play` while a session is already active — replace,
  reject, or queue.

## 6. testing

Same honest note as the existing `README.md`'s security section: this is
interoperability research against real devices, not something you can
fully validate from a spec. Plan on:
- a real receiver (Apple TV is the reference target, same as RAOP today),
- a packet-level view of the *unencrypted* pre-pair-verify exchange to
  confirm port/service discovery, since the payload afterward is opaque,
- cross-checking observed behavior against the public clean-room prior art
  in §2 rather than trusting any single source, exactly the methodology
  `raop_sender.cpp`'s attribution comments already model.
