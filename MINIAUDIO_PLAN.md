# Plan: optional miniaudio support (read more than WAV)

Status: proposed. Date: 2026-08-06.

## Goal

Add an optional CMake flag, `ENABLE_MINIAUDIO` (default **OFF**), that lets the
`airplay-send` demo decode more than WAV — MP3, FLAC, OGG/Vorbis, Opus — via
[miniaudio](https://miniaudio.com) (mackron, single-header C, built-in
decoders, no runtime dependencies beyond libc/libm).

Decisions locked in (from discussion):

1. Flag default: **OFF** — the default build stays wav-only and dependency-free
   (`git clone && cmake && run`), matching the README/ROADMAP pitch.
2. Dispatch when ON: **wav_reader first, miniaudio fallback** — both readers
   are compiled when the flag is ON; `airplay-send` tries the fuzz-tested
   `loadWavAsStereo16` first and only asks miniaudio when it fails. The
   default build (flag OFF) contains zero miniaudio references.
3. Acquisition: **FetchContent, pinned tag** `0.11.25` (2026-03-03), shallow
   clone, `SYSTEM` include — same pattern as mbedtls.

## Background

Today the pipeline is: `airplay-send <file.wav>` → `loadWavAsStereo16`
(`example/wav_reader.{h,cpp}`, hand-rolled RIFF/WAVE parser, 8/16/24/32-bit
PCM + float) → interleaved stereo int16 PCM → `RingBuffer` → `RaopSender`
(resamples to 44.1 kHz internally). The reader is demo-scoped: whole file in
memory, errors on stderr, and it only knows RIFF/WAVE.

miniaudio's `ma_decoder` replaces only the *file → PCM* step. It ships
self-contained decoders for WAV (dr_wav), MP3 (dr_mp3), FLAC (dr_flac),
OGG/Vorbis (stb_vorbis) and Opus (dr_opus). AAC is **not** built in (needs an
external backend) — documented limitation, not part of this plan.

## Design

### Dispatch (airplay_send.cpp, only when flag ON)

```cpp
#ifdef WITH_MINIAUDIO
#include "miniaudio_reader.h"
#endif
...
AudioData audio = loadWavAsStereo16(o.wavPath);
#ifdef WITH_MINIAUDIO
if (!audio.ok) audio = loadWithMiniAudio(o.wavPath);  // its error replaces wav's
#endif
```

No extension sniffing: pure fallback on failure. The wav reader's error
("not a RIFF/WAVE file") is replaced by miniaudio's error when both fail, so
the final message is accurate for any input. One `#ifdef` in main; when the
flag is OFF the file compiles exactly as today.

### Shared struct rename

`WavAudio` becomes `AudioData` and moves from `wav_reader.h` into a new tiny
`example/audio_data.h`, so both readers share one output type without one
including the other:

```cpp
struct AudioData {
    std::vector<int16_t> pcm;   // interleaved stereo
    uint32_t sampleRate = 0;
    bool ok = false;
    std::string error;          // set when ok == false
    size_t frames() const { return pcm.size() / 2; }
};
```

`loadWavAsStereo16` keeps its name (it is wav-specific); the new entry point
is `loadWithMiniAudio` (name chosen to make clear it is the fallback, not the
primary path).

## File-by-file changes

| File | Change |
|---|---|
| `CMakeLists.txt` | `option(ENABLE_MINIAUDIO ... OFF)`; `FetchContent_Declare(miniaudio ... GIT_TAG 0.11.25)` + `MakeAvailable` inside the flag block; add `example/miniaudio_reader.cpp` to `airplay-send`, link `miniaudio` target, define `WITH_MINIAUDIO`, and silence miniaudio's own examples/tests (`MINIAUDIO_BUILD_EXAMPLES/TESTS OFF` before `MakeAvailable`). Force decoding-only compile defs on the `miniaudio` target (`MA_NO_DEVICE_IO`, `MA_NO_ENCODING`, `MA_NO_GENERATION`) so it needs no platform audio libs. |
| `example/audio_data.h` | **new** — `AudioData` struct (moved/renamed from `wav_reader.h`), SPDX header, scope note. |
| `example/wav_reader.h` | include `audio_data.h`; drop the struct; signature becomes `AudioData loadWavAsStereo16(const std::string&)`. |
| `example/wav_reader.cpp` | mechanical `WavAudio` → `AudioData` renames only. |
| `example/miniaudio_reader.h` | **new** — `AudioData loadWithMiniAudio(const std::string& path);` + scope note (fallback reader, only built with flag). |
| `example/miniaudio_reader.cpp` | **new** — the decoder (below). |
| `example/airplay_send.cpp` | guarded include + fallback call; usage text `<file.wav>` → `<file>` when the flag is ON (guarded); `wav` locals → `audio` where cheap. |
| `README.md`, `example/README.md` | build instructions for `-DENABLE_MINIAUDIO=ON`, supported-format matrix per config. |
| `ROADMAP.md` | move "more formats" off the wishlist; note the optional flag under done/notes. |
| `CHANGELOG.md` | entry for the flag. |
| `licenses/THIRD-PARTY-NOTICES.txt` | add miniaudio entry under BUILD-TIME deps (FetchContent, pinned 0.11.25) with its actual license text (confirm at implementation: mackron releases under CC0/MIT-0; copy whatever the tag's LICENSE says) and the notice convention used for mbedtls. |

## miniaudio_reader.cpp sketch

```cpp
// decoding-only: strip device/record/encoding subsystems
#define MA_NO_DEVICE_IO
#define MA_NO_ENCODING
#define MA_NO_GENERATION
#include "miniaudio.h"          // link against the FetchContent `miniaudio`
                                // target, which compiles the implementation

AudioData loadWithMiniAudio(const std::string& path) {
    AudioData out;
    ma_decoder_config cfg = ma_decoder_config_init(ma_format_s16, 2, 0);
    //                                          ^ s16 output   ^stereo  ^native rate
    ma_decoder d;
    if (ma_decoder_init_file(path.c_str(), &cfg, &d) != MA_SUCCESS) {
        out.error = "could not decode '" + path + "' (miniaudio)";
        return out;
    }
    const ma_uint64 total = ma_decoder_get_length_in_pcm_frames(&d);
    if (total == 0 || total > kMaxFrames) {   // ~1 GB cap, mirroring wav_reader
        out.error = total == 0 ? "file contains no audio"
                               : "file is implausibly large, refusing to load";
        ma_decoder_uninit(&d);
        return out;
    }
    out.sampleRate = d.outputSampleRate;      // native; RaopSender resamples
    out.pcm.resize(size_t(total) * 2);        // s16 stereo == 2 frames/sample
    if (ma_decoder_read_pcm_frames(&d, out.pcm.data(), total, nullptr) != MA_SUCCESS) {
        out.error = "decode failed partway through the file";
        ma_decoder_uninit(&d);
        return out;
    }
    ma_decoder_uninit(&d);
    out.ok = true;
    return out;
}
```

Notes:

- miniaudio's converter handles mono→stereo duplication and >2ch→stereo
  downmix; output is always interleaved s16 stereo, exactly what the ring
  wants, so `airplay_send.cpp`'s feed loop is untouched.
- Whole-file decode, like the wav reader — consistent with the demo-scoped
  "load into memory" stance. Streaming decode (`ma_decoder` chunked reads in
  the feed loop) is a possible follow-up, noted in ROADMAP's wishlist.
- Error strings follow `wav_reader.cpp` style ("clear error beats crash").
- The FetchContent `miniaudio` target already compiles the implementation in
  its own TU; `miniaudio_reader.cpp` includes the header only. No double
  `MINIAUDIO_IMPLEMENTATION`.

## Verification

- **Both configs build clean**: `cmake -B build -DENABLE_MINIAUDIO=OFF`
  (must be byte-for-byte the old code path) and `cmake -B build-ma
  -DENABLE_MINIAUDIO=ON`, both with existing warning-as-error settings;
  confirm the default build has no miniaudio symbols (`nm` on
  `build/airplay-send`).
- **WAV regression**: decode one of the repo's `Vaporwave Dave - Hacker Music
  - NN ... .wav` files with flag ON — must take the wav_reader path (fallback
  untouched) and produce identical PCM/behavior to the flag-OFF build.
- **Format smoke tests**: convert a wav to mp3/flac/ogg via `ffmpeg`
  (available in env), then `airplay-send --no-discover --host 127.0.0.1
  /tmp/t.flac` etc. — decode happens before the connect attempt, so a bogus
  host still proves the loader: expect `loaded '...': N frames @ rate Hz`
  then the expected connect error.
- **Malformed inputs**: truncated mp3/flac, empty file, random bytes — clean
  error, no crash (miniaudio is battle-tested; this is a smoke check).
- **Opus**: spot-check an `.opus` file if ffmpeg can encode it, else note
  dr_opus support as untested-on-this-machine.
- Docs pass: grep the tree for stale "wav only" claims in README/example
  README/usage text.

## Risks / open items

- Configure-time network fetch for miniaudio — same tradeoff mbedtls already
  makes; `GIT_SHALLOW` + pinned tag keeps it reproducible. Offline builds use
  the flag OFF.
- `miniaudio.h` is ~1 MB and its implementation TU is slow to compile; only
  the flag-ON build pays for it.
- AAC, WMA, and other exotic containers are not covered by miniaudio's
  built-in decoders — document, don't solve.
- `MA_NO_*` defines must be set consistently (the FetchContent target is
  compiled as C; verify the defines propagate before `MA_IMPLEMENTATION` is
  first seen, else the header errors).
