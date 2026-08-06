// SPDX-License-Identifier: Apache-2.0
//
// miniaudio_reader.cpp -- see miniaudio_reader.h for scope notes.
//
// This file includes miniaudio.h for declarations only; the implementation
// (MINIAUDIO_IMPLEMENTATION) is compiled in its own TU via CMake's generated
// miniaudio_impl.c, so there's no double-implementation risk here.

#include "miniaudio_reader.h"
#include "miniaudio.h"

namespace fxchain {

namespace {

// Mirror the ~1 GB cap from wav_reader.cpp; at stereo s16 (4 bytes/frame)
// this is 268 M frames, generous headroom for anything reasonable.
constexpr size_t kMaxFrames = 1024ULL * 1024 * 1024 / 4;

} // namespace

AudioData loadWithMiniAudio(const std::string& path) {
    AudioData out;

    // Ask miniaudio to convert to interleaved s16 stereo at the file's
    // native sample rate (0 = don't resample; RaopSender does that).
    ma_decoder_config cfg = ma_decoder_config_init(ma_format_s16, 2, 0);
    ma_decoder d;
    if (ma_decoder_init_file(path.c_str(), &cfg, &d) != MA_SUCCESS) {
        out.error = "could not decode '" + path + "' (miniaudio)";
        return out;
    }

    ma_uint64 total = 0;
    if (ma_decoder_get_length_in_pcm_frames(&d, &total) != MA_SUCCESS || total == 0) {
        out.error = (total == 0) ? "file contains no audio"
                                 : "could not determine audio length";
        ma_decoder_uninit(&d);
        return out;
    }
    if (total > kMaxFrames) {
        out.error = "file is implausibly large, refusing to load";
        ma_decoder_uninit(&d);
        return out;
    }

    out.sampleRate = d.outputSampleRate;    // native; RaopSender resamples
    out.pcm.resize(size_t(total) * 2);      // s16 stereo == 2 samples/frame

    ma_uint64 framesRead = 0;
    ma_result result = ma_decoder_read_pcm_frames(&d, out.pcm.data(), total, &framesRead);
    if (result != MA_SUCCESS && result != MA_AT_END) {
        out.error = "decode failed partway through the file";
        ma_decoder_uninit(&d);
        return out;
    }

    // If the decoder returned fewer frames than advertised (can happen with
    // some VBR formats), shrink the buffer to match what was actually read.
    if (framesRead < total)
        out.pcm.resize(size_t(framesRead) * 2);

    ma_decoder_uninit(&d);
    out.ok = true;
    return out;
}

} // namespace fxchain
