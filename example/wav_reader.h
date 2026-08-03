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

#include <cstdint>
#include <string>
#include <vector>

namespace fxchain {

struct WavAudio {
    std::vector<int16_t> pcm;   // interleaved stereo (frame = pcm[i*2], pcm[i*2+1])
    uint32_t sampleRate = 0;
    bool ok = false;
    std::string error;          // set when ok == false

    size_t frames() const { return pcm.size() / 2; }
};

// Reads `path`, converts to interleaved stereo 16-bit PCM at the file's
// native sample rate (RaopSender resamples to 44.1 kHz internally, see
// RaopSender::setInputFormat, so this does NOT resample). Mono is
// duplicated to both channels; more than 2 channels keeps only the first 2.
// Supports 8/16/24/32-bit integer PCM and 32-bit IEEE float, including a
// WAVE_FORMAT_EXTENSIBLE fmt chunk.
WavAudio loadWavAsStereo16(const std::string& path);

} // namespace fxchain
