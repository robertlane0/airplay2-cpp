// SPDX-License-Identifier: Apache-2.0
//!
//! A tiny file-per-device cache for the long-term HAP credentials
//! `Session::on_credentials_obtained` hands back, so re-running the demo
//! against a device you've already paired with skips the PIN prompt (port
//! of `example/creds_store.{h,cpp}`).
//!
//! One flat, opaque creds-JSON string per device id, one file each, under
//! `$XDG_CACHE_HOME/airplay-send/` (falling back to
//! `$HOME/.cache/airplay-send/`, then `/tmp/airplay-send-creds/` if
//! neither is set). Filenames use the `.credentials` extension.
//!
//! Deliberately as small as it looks: no encryption at rest, no
//! permissions hardening beyond the directory mode. Treat it the way
//! you'd treat an ssh known_hosts-adjacent file: fine for a demo/dev
//! machine, not something to point at a shared/multi-user box without
//! tightening it first.

use std::path::{Path, PathBuf};

fn cache_dir() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("airplay-send");
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".cache").join("airplay-send");
        }
    }
    PathBuf::from("/tmp/airplay-send-creds")
}

/// deviceId is typically a MAC ("AA:BB:CC:DD:EE:FF"); keep only
/// characters that are safe in a filename on every platform we care
/// about, mapping everything else (colons included) to '_'. Defends
/// against a deviceId containing a path separator or similar, however
/// that string was sourced.
fn sanitize(device_id: &str) -> String {
    let s: String = device_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() {
        "unknown".to_string()
    } else {
        s
    }
}

fn path_for(dir: &Path, device_id: &str) -> PathBuf {
    dir.join(format!("{}.credentials", sanitize(device_id)))
}

/// `mkdir -p`: create every missing path segment, not just the final
/// one, with the C++ mode 0700.
fn ensure_dir(dir: &Path) {
    use std::os::unix::fs::DirBuilderExt;
    let mut b = std::fs::DirBuilder::new();
    b.mode(0o700);
    let _ = b.recursive(true).create(dir); // ignore EEXIST and other errors
}

/// "" if nothing is cached for this device (or the cache can't be read).
pub fn load_cached_creds(device_id: &str) -> String {
    if device_id.is_empty() {
        return String::new();
    }
    std::fs::read(path_for(&cache_dir(), device_id))
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

/// Best-effort; a failure to persist (e.g. a read-only filesystem) is
/// not fatal to the caller, it just means the next run re-prompts for a
/// PIN.
pub fn save_cached_creds(device_id: &str, creds_json: &str) {
    if device_id.is_empty() || creds_json.is_empty() {
        return;
    }
    let dir = cache_dir();
    ensure_dir(&dir);
    let _ = std::fs::write(path_for(&dir, device_id), creds_json);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_root(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "airplay-send-creds-test-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn sanitize_maps_hostile_characters() {
        assert_eq!(sanitize("AA:BB:CC:DD:EE:FF"), "AA_BB_CC_DD_EE_FF");
        // '.' is legal in a filename and kept; only '/' is mapped.
        assert_eq!(sanitize("../etc/passwd"), ".._etc_passwd");
        assert_eq!(sanitize("a b"), "a_b");
        assert_eq!(sanitize(""), "unknown");
        assert_eq!(sanitize("---..."), "---...");
    }

    #[test]
    fn save_then_load_roundtrip_under_root() {
        let root = scratch_root("roundtrip");
        let id = "00:11:22:33:44:55";
        save_into(&root, id, r#"{"ltsk":"x"}"#);
        assert_eq!(load_from(&root, id), r#"{"ltsk":"x"}"#);
        assert!(path_for(&root, id).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_file_loads_empty() {
        let root = scratch_root("missing");
        assert_eq!(load_from(&root, "ff:ee:dd:cc:bb:aa"), "");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_id_or_creds_is_a_noop() {
        let root = scratch_root("noop");
        save_into(&root, "", "x");
        save_into(&root, "id", "");
        assert!(!root.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn nested_missing_directories_are_created() {
        let root = scratch_root("nested");
        let deep = root.join("a").join("b").join("c");
        save_into(&deep, "id", "creds");
        assert_eq!(load_from(&deep, "id"), "creds");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Test-only: the same file layout as [`save_cached_creds`] but with
    /// an explicit root (env mutation is `unsafe` in Rust 2024, and the
    /// real cache dir is process-global). Mirrors the real function's
    /// no-op boundary: empty id or empty creds never touch the disk.
    fn save_into(root: &Path, id: &str, json: &str) {
        if id.is_empty() || json.is_empty() {
            return;
        }
        ensure_dir(root);
        let _ = std::fs::write(path_for(root, id), json);
    }

    fn load_from(root: &Path, id: &str) -> String {
        std::fs::read(path_for(root, id))
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    }
}
