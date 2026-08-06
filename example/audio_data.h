// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// audio_data.h -- ROADMAP.md m4: the shared audio type that both
// wav_reader and (when ENABLE_MINIAUDIO is ON) miniaudio_reader produce.
// ----------------------------------------------------------------------------
// Moved out of wav_reader.h so the miniaudio reader can include it without
// pulling in the wav parser. This is the one struct that every audio-loading
// path returns; airplay_send.cpp consumes it generically.

#include <cstdint>
#include <string>
#include <vector>

namespace fxchain {

struct AudioData {
    std::vector<int16_t> pcm;   // interleaved stereo (frame = pcm[i*2], pcm[i*2+1])
    uint32_t sampleRate = 0;
    bool ok = false;
    std::string error;          // set when ok == false

    size_t frames() const { return pcm.size() / 2; }
};

} // namespace fxchain
