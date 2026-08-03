// SPDX-License-Identifier: Apache-2.0
//
// wav_reader.cpp -- see wav_reader.h for scope notes.

#include "wav_reader.h"

#include <algorithm>
#include <cstring>
#include <fstream>

namespace fxchain {

namespace {

// A file this large is almost certainly a mistake (or not actually a short
// demo clip); fail with a clear message rather than trying to load it all
// into memory. ~1 GB is generous headroom for anything reasonable.
constexpr size_t kMaxFileBytes = 1024ULL * 1024 * 1024;

uint16_t rdU16(const uint8_t* p) { return uint16_t(p[0] | (uint16_t(p[1]) << 8)); }
uint32_t rdU32(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

// Decode one sample (at `p`, `bytesPerSample` wide) to int16, given the wav's
// format tag (1 = PCM integer, 3 = IEEE float).
int16_t decodeSample(const uint8_t* p, int bytesPerSample, uint16_t formatTag) {
    if (formatTag == 3 && bytesPerSample == 4) {
        float f;
        std::memcpy(&f, p, 4);
        f = std::clamp(f, -1.0f, 1.0f);
        return int16_t(f * 32767.0f);
    }
    switch (bytesPerSample) {
    case 1: {
        // WAV 8-bit PCM is unsigned, centered at 128.
        const int v = int(p[0]) - 128;
        return int16_t(v * 256);
    }
    case 2: {
        int16_t v;
        std::memcpy(&v, p, 2);
        return v;
    }
    case 3: {
        uint32_t u = uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16);
        if (u & 0x00800000u) u |= 0xFF000000u;   // sign-extend 24 -> 32 bits
        const int32_t v = static_cast<int32_t>(u);
        return int16_t(v >> 8);
    }
    case 4: {
        int32_t v;
        std::memcpy(&v, p, 4);
        return int16_t(v >> 16);
    }
    default:
        return 0;
    }
}

}  // namespace

WavAudio loadWavAsStereo16(const std::string& path) {
    WavAudio out;

    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) { out.error = "could not open '" + path + "'"; return out; }
    const std::streamoff sizeOff = f.tellg();
    if (sizeOff < 0) { out.error = "could not determine file size"; return out; }
    const size_t fileSize = size_t(sizeOff);
    if (fileSize > kMaxFileBytes) { out.error = "file is implausibly large, refusing to load"; return out; }
    if (fileSize < 44) { out.error = "file is too small to be a wav"; return out; }
    f.seekg(0);

    std::vector<uint8_t> buf(fileSize);
    if (!f.read(reinterpret_cast<char*>(buf.data()), std::streamsize(fileSize))) {
        out.error = "short read while loading the file";
        return out;
    }

    if (std::memcmp(buf.data(), "RIFF", 4) != 0 || std::memcmp(buf.data() + 8, "WAVE", 4) != 0) {
        out.error = "not a RIFF/WAVE file (missing 'RIFF'/'WAVE' magic)";
        return out;
    }

    uint16_t formatTag = 0, numChannels = 0, bitsPerSample = 0, blockAlign = 0;
    uint32_t sampleRate = 0;
    bool haveFmt = false;
    const uint8_t* dataPtr = nullptr;
    size_t dataLen = 0;

    size_t pos = 12;   // past "RIFF"+size+"WAVE"
    while (pos + 8 <= buf.size()) {
        const uint8_t* chunkId = buf.data() + pos;
        const uint32_t chunkSize = rdU32(buf.data() + pos + 4);
        const size_t chunkDataOff = pos + 8;
        if (chunkDataOff + size_t(chunkSize) > buf.size()) {
            // A truncated/malformed final chunk; stop, use whatever chunks
            // were already fully parsed (matches how most players are
            // forgiving of a slightly-broken trailing chunk).
            break;
        }
        if (std::memcmp(chunkId, "fmt ", 4) == 0 && chunkSize >= 16) {
            const uint8_t* p = buf.data() + chunkDataOff;
            formatTag     = rdU16(p + 0);
            numChannels   = rdU16(p + 2);
            sampleRate    = rdU32(p + 4);
            blockAlign    = rdU16(p + 12);
            bitsPerSample = rdU16(p + 14);
            // WAVE_FORMAT_EXTENSIBLE (0xFFFE): the real format lives in the
            // first 2 bytes of the 16-byte SubFormat GUID, after a 2-byte
            // cbSize + 2-byte validBitsPerSample + 4-byte channelMask.
            if (formatTag == 0xFFFE && chunkSize >= 18 + 16) {
                const uint8_t* ext = p + 18;   // cbSize(2) validBits(2) mask(4) = 8, then SubFormat GUID(16)
                if (chunkSize >= 16 + 8 + 16)
                    formatTag = rdU16(ext + 8);
            }
            haveFmt = true;
        } else if (std::memcmp(chunkId, "data", 4) == 0) {
            dataPtr = buf.data() + chunkDataOff;
            dataLen = chunkSize;
        }
        // Chunks are word-aligned: an odd chunkSize has one pad byte after it.
        pos = chunkDataOff + size_t(chunkSize) + (chunkSize & 1);
    }

    if (!haveFmt) { out.error = "no 'fmt ' chunk found"; return out; }
    if (!dataPtr) { out.error = "no 'data' chunk found"; return out; }
    if (formatTag != 1 && formatTag != 3) {
        out.error = "unsupported wav format tag " + std::to_string(formatTag)
                  + " (only PCM integer and IEEE float are supported)";
        return out;
    }
    if (numChannels == 0) { out.error = "wav declares 0 channels"; return out; }
    if (bitsPerSample != 8 && bitsPerSample != 16 && bitsPerSample != 24 && bitsPerSample != 32) {
        out.error = "unsupported bits-per-sample " + std::to_string(bitsPerSample);
        return out;
    }
    const int bytesPerSample = bitsPerSample / 8;
    if (blockAlign == 0) blockAlign = uint16_t(bytesPerSample * numChannels);
    if (blockAlign < bytesPerSample * numChannels) {
        out.error = "wav 'fmt ' chunk has an inconsistent blockAlign";
        return out;
    }

    const size_t frameCount = dataLen / blockAlign;
    out.pcm.resize(frameCount * 2);
    for (size_t i = 0; i < frameCount; ++i) {
        const uint8_t* frame = dataPtr + i * blockAlign;
        const int16_t l = decodeSample(frame, bytesPerSample, formatTag);
        const int16_t r = (numChannels >= 2)
            ? decodeSample(frame + bytesPerSample, bytesPerSample, formatTag)
            : l;   // mono -> duplicate to both channels
        out.pcm[i * 2 + 0] = l;
        out.pcm[i * 2 + 1] = r;
    }

    out.sampleRate = sampleRate;
    out.ok = true;
    return out;
}

} // namespace fxchain
