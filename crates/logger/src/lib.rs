// SPDX-License-Identifier: Apache-2.0
//! The smallest logging sink that could work.
//!
//! Rust 2024 migration of [`src/logger.h`](../../src/logger.h) (C++ original
//! in this repository). Behavior contract inherited from the C++:
//!
//! * A single pluggable global sink; defaults to printing `[info] msg` /
//!   `[warn] msg` to stderr.
//! * `Log::setSink` replaces the sink. There is no way back to the default
//!   sink (same as C++).
//! * Messages are `"{}"`-placeholder formatted (see [`format`]).
//!
//! Deliberate, documented differences from the C++:
//!
//! * Variadic `Log::info(fmt, args...)` becomes the [`info!`] / [`warn!`]
//!   macros, which delegate to [`std::format!`]. An arity mismatch is a
//!   compile-time error in Rust instead of silently ignoring extra arguments
//!   or leaving the placeholder in place. For dynamically built format
//!   strings, [`format`] keeps the exact C++ behavior (replace successive
//!   `{}` left to right; missing placeholder returns the string unchanged).
//! * The C++ sink is an unsynchronized function-local static; in Rust the
//!   sink lives behind a `Mutex` so `set_sink` and logging are thread-safe
//!   (the C++ version was a data race if both happened concurrently).
//! * A sink must not recursively log through [`info`]/[`warn`] (documented
//!   divergence; pathological in the C++ too).
//!
//! ```
//! use logger::{info, warn};
//! info!("{} frames @ {} Hz", 44100, 96000);   // -> "[info] 44100 frames @ 96000 Hz"
//! warn!("dry run");                            // -> "[warn] dry run"
//! ```

use std::sync::{Arc, Mutex, OnceLock};

/// The severity a message is logged at (C++ `LogLevel { Info, Warn }`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
}

/// A pluggable sink: called with the severity and the fully formatted
/// message. `Send + Sync` so the global sink can be shared safely (the
/// default sink only writes to stderr).
pub type Sink = Arc<dyn Fn(LogLevel, &str) + Send + Sync>;

static SINK: Mutex<Option<Sink>> = Mutex::new(None);

static DEFAULT_SINK: OnceLock<Sink> = OnceLock::new();

fn default_sink_arc() -> Sink {
    DEFAULT_SINK.get_or_init(|| Arc::new(default_sink)).clone()
}

fn emit(level: LogLevel, msg: &str) {
    // Clone the Arc and drop the guard before calling the sink, so a sink
    // may itself log (recursively) without deadlocking, and a panicking
    // sink cannot leave the mutex poisoned.
    let sink = match SINK.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
        Some(s) => s.clone(),
        None => default_sink_arc(),
    };
    sink(level, msg);
}

fn default_sink(level: LogLevel, msg: &str) {
    let tag = match level {
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
    };
    eprintln!("[{tag}] {msg}");
}

/// Replace the global log sink. The previous sink is dropped.
///
/// `set_sink(logger::Sink::new(&my_sink))`:
pub fn set_sink(sink: Sink) {
    *SINK.lock().unwrap_or_else(|p| p.into_inner()) = Some(sink);
}

/// Log an already-formatted message at Info level.
pub fn info(msg: &str) {
    emit(LogLevel::Info, msg);
}

/// Log an already-formatted message at Warn level.
pub fn warn(msg: &str) {
    emit(LogLevel::Warn, msg);
}

/// Route a formatted message to the sink (used by [`info!`]/[`warn!`]).
#[doc(hidden)]
pub fn log_with(level: LogLevel, msg: String) {
    emit(level, &msg);
}

/// C++-compatible `"{}"` placeholder substitution.
///
/// Replaces successive `{}` placeholders in `fmt`, left to right, with
/// `args`. Exactly matches the C++ `Log::format`:
///
/// * a missing `{}` leaves the string unchanged;
/// * extra arguments beyond the placeholders are ignored;
/// * `{}` inside the replacement text is not re-scanned (replacement is
///   left-to-right on the original template).
pub fn format(fmt: &str, args: &[String]) -> String {
    let mut out = fmt.to_owned();
    for arg in args {
        let Some(pos) = out.find("{}") else {
            break; // C++: no placeholder -> return the (partially) built string unchanged
        };
        out.replace_range(pos..pos + 2, arg);
    }
    out
}

/// Format and log at Info level: [`logger::info!`](crate::info!).
#[macro_export]
macro_rules! info {
    ($($arg:tt)+) => {
        $crate::log_with($crate::LogLevel::Info, format!($($arg)+))
    };
}

/// Format and log at Warn level: [`logger::warn!`](crate::warn!).
#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => {
        $crate::log_with($crate::LogLevel::Warn, format!($($arg)+))
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    type Captured = std::sync::Mutex<Vec<(LogLevel, String)>>;

    // Tests that replace the global SINK must run exclusively: otherwise
    // two tests can each set their own sink and capture the other's
    // messages. Serialize them with a global test lock.
    static SINK_GUARD: Mutex<()> = Mutex::new(());

    fn capturing_sink() -> (Sink, Arc<Captured>) {
        let log: Arc<Captured> = Arc::new(Mutex::new(Vec::new()));
        let captured = log.clone();
        let sink: Sink = Arc::new(move |level, msg| {
            captured.lock().unwrap().push((level, msg.to_owned()));
        });
        (sink, log)
    }

    #[test]
    fn set_sink_routes_everything() {
        let _guard = SINK_GUARD.lock().unwrap();
        let (sink, log) = capturing_sink();
        set_sink(sink);
        info("plain message");
        warn("warning message");
        let entries = log.lock().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], (LogLevel::Info, "plain message".into()));
        assert_eq!(entries[1], (LogLevel::Warn, "warning message".into()));
    }

    #[test]
    fn macros_format_and_route() {
        let _guard = SINK_GUARD.lock().unwrap();
        let (sink, log) = capturing_sink();
        set_sink(sink);
        info!("{} frames @ {} Hz", 44100, 96000);
        warn!("dry run at {}", "noon");
        let entries = log.lock().unwrap();
        assert_eq!(entries[0].1, "44100 frames @ 96000 Hz");
        assert_eq!(entries[1].1, "dry run at noon");
    }

    #[test]
    fn format_matches_cpp_semantics() {
        // Left-to-right replacement of the original template.
        assert_eq!(format("{} {}", &["a".into(), "b".into()]), "a b");
        // No placeholder -> unchanged, extras ignored.
        assert_eq!(format("hello", &["x".into()]), "hello");
        // Extra args ignored once no placeholder remains.
        assert_eq!(format("{} done", &["a".into(), "b".into()]), "a done");
        // Replacement text is not rescanned.
        assert_eq!(format("{}!", &["{}".into()]), "{}!");
        // Empty template.
        assert_eq!(format("", &["x".into()]), "");
    }

    #[test]
    fn sink_replaced_not_accumulated() {
        let _guard = SINK_GUARD.lock().unwrap();
        let (sink1, log1) = capturing_sink();
        let (sink2, log2) = capturing_sink();
        set_sink(sink1);
        set_sink(sink2);
        info("once");
        assert!(log1.lock().unwrap().is_empty());
        assert_eq!(log2.lock().unwrap().len(), 1);
    }
}
