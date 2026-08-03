// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// creds_store.h -- ROADMAP.md m3: a tiny file-per-device cache for the
// long-term HAP credentials RaopSender::onCredentialsObtained hands back,
// so re-running the demo against a device you've already paired with skips
// the PIN prompt (the reconnect story the README describes).
// ----------------------------------------------------------------------------
// One flat, opaque credsJson string per device id, one file each, under
// $XDG_CACHE_HOME/airplay-send/ (falling back to $HOME/.cache/airplay-send/,
// then /tmp/airplay-send-creds/ if neither is set). Filenames use the
// `.credentials` extension the repo's own .gitignore already excludes.
//
// This is deliberately as small as it looks: no encryption at rest, no
// permissions hardening beyond relying on the directory's default mode.
// Treat it the way you'd treat an ssh known_hosts-adjacent file: fine for a
// demo/dev machine, not something to point at a shared/multi-user box
// without tightening it first.

#include <string>

namespace fxchain {

// "" if nothing is cached for this device (or the cache can't be read).
std::string loadCachedCreds(const std::string& deviceId);

// Best-effort; a failure to persist (e.g. a read-only filesystem) is not
// fatal to the caller, it just means the next run re-prompts for a PIN.
void saveCachedCreds(const std::string& deviceId, const std::string& credsJson);

} // namespace fxchain
