// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// miniaudio_reader.h -- ROADMAP.md m5: fallback reader for mp3/flac/ogg/opus,
// only built when ENABLE_MINIAUDIO is ON.
// ----------------------------------------------------------------------------
// This is the second audio-loading path, tried only when the fuzz-tested
// wav_reader fails (see the dispatch in airplay_send.cpp). It wraps
// miniaudio's ma_decoder into the same AudioData the wav reader produces,
// so the rest of the pipeline (ring buffer → RaopSender) is untouched.
//
// Whole-file decode, consistent with the demo-scoped "load into memory"
// stance (a streaming decode pass is noted in ROADMAP.md's wishlist).

#include "audio_data.h"

namespace fxchain {

// Decodes `path` via miniaudio (mp3, flac, ogg/vorbis, opus, and wav as a
// last resort) into interleaved stereo 16-bit PCM at the file's native
// sample rate. Returns AudioData with ok==false and a clear error string
// on any failure. Mirrors the ~1 GB size cap from wav_reader.
AudioData loadWithMiniAudio(const std::string& path);

} // namespace fxchain
