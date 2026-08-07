# airplay 2 sender, build the Qt-free crypto + wire-format core, the Qt-free
# sender + receiver discovery, and (as of ROADMAP.md m3) the CLI demo.
#
# `airplay_crypto` builds standalone. `raop_sender` is the sender state
# machine; it talks to the network only through `ITransport` (src/transport.h)
# -- no Qt. `posix_transport` is the default (poll()/BSD sockets) adapter.
# `mdns_browser` discovers receivers on the LAN (no Qt, no avahi/dns-sd/
# Bonjour.h dependency). `airplay-send` (example/) wires all three together
# into `airplay-send <host> <file.wav>`.
cmake_minimum_required(VERSION 3.16)
project(airplay2_sender LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# --- Mbed TLS 3.6 (Apache-2.0): bignum, sha512, hkdf, chachapoly, drbg ---
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING  OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v3.6.0
    GIT_SHALLOW    TRUE
    SYSTEM
)
FetchContent_MakeAvailable(mbedtls)

if(TARGET mbedcrypto)
    target_compile_options(mbedcrypto PRIVATE
        $<$<C_COMPILER_ID:GNU>:-Wno-unterminated-string-initialization>
    )
endif()

# --- orlp/ed25519 (zlib, vendored): the one primitive Mbed TLS lacks ---
# Drop seed.c and define ED25519_NO_SEED: ed25519_create_seed() is never called
# (all seeds come from Mbed TLS CTR-DRBG), so we don't pull in seed.c's
# CryptGenRandom/getrandom entropy path. Matches third_party/ed25519/SOURCE.md.
file(GLOB ED25519_SRC ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ed25519/src/*.c)
list(FILTER ED25519_SRC EXCLUDE REGEX "/seed\\.c$")
add_library(ed25519 STATIC ${ED25519_SRC})
target_compile_definitions(ed25519 PRIVATE ED25519_NO_SEED)
target_include_directories(ed25519 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ed25519/src)

# --- the Qt-free AirPlay 2 crypto + wire-format core (the reusable part) ---
add_library(airplay_crypto STATIC src/airplay_crypto.cpp)
target_include_directories(airplay_crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ed25519/src)
target_link_libraries(airplay_crypto PUBLIC mbedcrypto ed25519)
target_compile_features(airplay_crypto PUBLIC cxx_std_20)

# --- the default Qt-free transport (poll()/BSD sockets); Linux/macOS/BSD ---
add_library(posix_transport STATIC src/posix_transport.cpp)
target_include_directories(posix_transport PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_features(posix_transport PUBLIC cxx_std_20)

# --- the sender itself: plain C++ + ITransport + airplay_crypto, no Qt ---
add_library(raop_sender STATIC src/raop_sender.cpp)
target_include_directories(raop_sender PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(raop_sender PUBLIC airplay_crypto)
target_compile_features(raop_sender PUBLIC cxx_std_20)

# --- receiver discovery: a tiny dependency-free mDNS/DNS-SD browser ---
add_library(mdns_browser STATIC src/mdns_browser.cpp)
target_include_directories(mdns_browser PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(mdns_browser PUBLIC raop_sender)   # RaopSender::Auth
target_compile_features(mdns_browser PUBLIC cxx_std_20)

# --- the CLI demo: raop_sender + posix_transport + mdns_browser + a wav
# reader + a tiny per-device credential cache, wired into one binary ---
add_executable(airplay-send
    example/airplay_send.cpp
    example/wav_reader.cpp
    example/creds_store.cpp)
target_link_libraries(airplay-send PRIVATE raop_sender posix_transport mdns_browser)
target_compile_definitions(airplay-send PRIVATE
    HEADLESS_DEFAULT=$<BOOL:${HEADLESS_DEFAULT}>)
target_compile_features(airplay-send PRIVATE cxx_std_20)

# --- headless default: how airplay-send responds when cached credentials are
# stale (a receiver that reset its pairing). OFF = prompt for a PIN
# re-authentication; ON = fail immediately. The CLI's --headless/--interactive
# flags override it at runtime; --version reports the build-time value.
option(HEADLESS_DEFAULT "Fail on stale cached credentials without prompting (overridable with --interactive)" OFF)

# --- optional: miniaudio (decoding-only) for mp3/flac/ogg/opus support ---
# Default OFF: the default build stays wav-only and dependency-free.
# When ON: tries the fuzz-tested wav_reader first, miniaudio fallback.
option(ENABLE_MINIAUDIO "Build with miniaudio for mp3/flac/ogg/opus decoding" OFF)
if(ENABLE_MINIAUDIO)
    # Suppress miniaudio's own examples/tests; strip the device/record/
    # encoding/generation subsystems so it needs no platform audio libs.
    set(MINIAUDIO_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(MINIAUDIO_BUILD_TESTS   OFF CACHE BOOL "" FORCE)
    set(MINIAUDIO_EXTRAS        OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(miniaudio
        GIT_REPOSITORY https://github.com/mackron/miniaudio.git
        GIT_TAG        0.11.25
        GIT_SHALLOW    TRUE
        SYSTEM
    )
    FetchContent_MakeAvailable(miniaudio)

    file(WRITE "${CMAKE_BINARY_DIR}/miniaudio_impl.c"
        "#define STB_VORBIS_HEADER_ONLY\n"
        "#include \"extras/stb_vorbis.c\"\n"
        "#define MINIAUDIO_IMPLEMENTATION\n"
        "#define MA_NO_DEVICE_IO\n"
        "#define MA_NO_ENCODING\n"
        "#define MA_NO_GENERATION\n"
        "#include \"miniaudio.h\"\n"
        "#undef STB_VORBIS_HEADER_ONLY\n"
        "#include \"extras/stb_vorbis.c\"\n"
    )
    set_target_properties(miniaudio PROPERTIES SOURCES "${CMAKE_BINARY_DIR}/miniaudio_impl.c")
    target_include_directories(miniaudio PRIVATE "${miniaudio_SOURCE_DIR}")

    # Decoding-only: strip everything the demo doesn't need.
    target_compile_definitions(miniaudio PUBLIC
        MA_NO_DEVICE_IO
        MA_NO_ENCODING
        MA_NO_GENERATION
    )

    target_sources(airplay-send PRIVATE example/miniaudio_reader.cpp)
    target_compile_definitions(airplay-send PRIVATE WITH_MINIAUDIO)

    # --- Opus decode support: two pieces miniaudio leaves external ---
    # miniaudio has NO built-in Opus decoder; Ogg support in the stock build is
    # Vorbis-only (stb_vorbis). The reference way to decode Ogg Opus with
    # miniaudio is the extra "libopus" decoding backend in
    # extras/decoders/libopus/, which sits on top of xiph's libopus + libopusfile.
    # Wire both in so .opus streams actually decode.

    # libopusfile (xiph/opusfile) only ships an autotools build in the v0.12
    # release -- no CMakeLists.txt, and the CMakeLists on 'master' requires a
    # system Opus CMake config that isn't available here. So consume the tagged
    # sources directly and compile the four codec translation units ourselves,
    # which means populating without add_subdirectory().
    if(POLICY CMP0169)
        cmake_policy(SET CMP0169 OLD)
    endif()
    FetchContent_Declare(opusfile
        GIT_REPOSITORY https://github.com/xiph/opusfile.git
        GIT_TAG        v0.12
        GIT_SHALLOW    TRUE
        SYSTEM
    )
    FetchContent_GetProperties(opusfile)
    if(NOT opusfile_POPULATED)
        FetchContent_Populate(opusfile)
    endif()

    find_package(PkgConfig REQUIRED)
    pkg_check_modules(OPUSFILE_DEPS REQUIRED opus ogg)

    # config.h is normally produced by autotools' configure step; opusfile's
    # sources include it and only read OP_HAVE_LRINTF (float rounding on glibc).
    file(WRITE "${CMAKE_BINARY_DIR}/opusfile_config.h"
        "#ifndef OP_CONFIG_H\n"
        "#define OP_CONFIG_H\n"
        "#define OP_HAVE_LRINTF 1\n"
        "#endif\n"
    )

    add_library(opencode_opusfile STATIC
        "${opusfile_SOURCE_DIR}/src/opusfile.c"
        "${opusfile_SOURCE_DIR}/src/info.c"
        "${opusfile_SOURCE_DIR}/src/stream.c"
        "${opusfile_SOURCE_DIR}/src/internal.c"
    )
    target_include_directories(opencode_opusfile PUBLIC
        "${opusfile_SOURCE_DIR}/include"
        ${OPUSFILE_DEPS_INCLUDE_DIRS}
    )
    target_include_directories(opencode_opusfile PRIVATE
        "${CMAKE_BINARY_DIR}"
    )
    target_link_libraries(opencode_opusfile PUBLIC
        ${OPUSFILE_DEPS_LIBRARIES}
        m
    )

    # The miniaudio "libopus" decoding backend: registerable via
    # ma_decoding_backend_libopus. Compiled as its own TU so it only pulls the
    # ma_* symbols it needs out of libminiaudio at final link, matching how
    # miniaudio itself builds extras/decoders today.
    add_library(opencode_ma_opus STATIC
        "${miniaudio_SOURCE_DIR}/extras/decoders/libopus/miniaudio_libopus.c"
    )
    target_include_directories(opencode_ma_opus PRIVATE "${miniaudio_SOURCE_DIR}")
    target_link_libraries(opencode_ma_opus PUBLIC opencode_opusfile)

    target_link_libraries(airplay-send PRIVATE miniaudio opencode_ma_opus opencode_opusfile)
endif()

