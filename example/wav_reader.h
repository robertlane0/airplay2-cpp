// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// wav_reader.h -- ROADMAP.md m3: read a .wav file into the interleaved
// stereo int16 PCM that RaopSender::attachRing()'s ring expects.
// ----------------------------------------------------------------------------
// Demo-scoped, not a general media library: loads the whole file into memory
// (fine for the kind of short clips this demo is for; a real app would stream
// from disk instead), and only handles the RIFF/WAVE chunk layout every
// encoder in practice produces (fmt ' + 'data', in either order, with or
// without a WAVE_FORMAT_EXTENSIBLE fmt chunk). No RIFF64/BWF/ADPCM support.
//
// Bounds-checked against a truncated/malformed file (this is a user-supplied
// file, not untrusted network input, but "corrupt wav -> clear error" beats
// "corrupt wav -> crash" for a CLI tool either way).

#include "audio_data.h"

namespace fxchain {

// Reads `path`, converts to interleaved stereo 16-bit PCM at the file's
// native sample rate (RaopSender resamples to 44.1 kHz internally, see
// RaopSender::setInputFormat, so this does NOT resample). Mono is
// duplicated to both channels; more than 2 channels keeps only the first 2.
// Supports 8/16/24/32-bit integer PCM and 32-bit IEEE float, including a
// WAVE_FORMAT_EXTENSIBLE fmt chunk.
AudioData loadWavAsStereo16(const std::string& path);

} // namespace fxchain
