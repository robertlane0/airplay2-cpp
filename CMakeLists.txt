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
FetchContent_Declare(mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v3.6.0
    GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(mbedtls)

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
target_compile_features(airplay-send PRIVATE cxx_std_20)
