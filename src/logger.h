// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// logger.h -- the smallest logging sink that could work.
// ----------------------------------------------------------------------------
// raop_sender.cpp calls Log::info(fmt, args...) / Log::warn(fmt, args...)
// with "{}"-style positional placeholders. This header used to be
// `../common/logger.h`, host glue that lived in FXChainPlayer and wasn't part
// of this repo. ROADMAP.md m2 already describes exactly what it should
// become ("a one-line std::function<void(level, msg)> sink") -- that's
// small enough to just do now, rather than leave raop_sender unable to
// build standalone until m2 lands.
//
// default sink prints to stderr; call Log::setSink() to route it anywhere
// (your own logger, a UI console, /dev/null).

#include <cstdio>
#include <functional>
#include <sstream>
#include <string>
#include <utility>

namespace fxchain {

enum class LogLevel { Info, Warn };

class Log {
public:
    using Sink = std::function<void(LogLevel, const std::string&)>;

    static void setSink(Sink sink) { sink_() = std::move(sink); }

    template <typename... Args>
    static void info(const std::string& fmt, Args&&... args) {
        sink_()(LogLevel::Info, format(fmt, std::forward<Args>(args)...));
    }
    template <typename... Args>
    static void warn(const std::string& fmt, Args&&... args) {
        sink_()(LogLevel::Warn, format(fmt, std::forward<Args>(args)...));
    }

    // Replace successive "{}" placeholders in `fmt`, left to right, with
    // `args` streamed through operator<<. Exposed publicly since raop_sender
    // also uses it to build a couple of user-facing error strings.
    static std::string format(const std::string& fmt) { return fmt; }
    template <typename T, typename... Rest>
    static std::string format(const std::string& fmt, T&& v, Rest&&... rest) {
        const auto pos = fmt.find("{}");
        if (pos == std::string::npos) return fmt;
        std::ostringstream os;
        os << v;
        return format(fmt.substr(0, pos) + os.str() + fmt.substr(pos + 2),
                      std::forward<Rest>(rest)...);
    }

private:
    static Sink& sink_() {
        static Sink s = [](LogLevel lvl, const std::string& msg) {
            std::fprintf(stderr, "[%s] %s\n", lvl == LogLevel::Warn ? "warn" : "info",
                        msg.c_str());
        };
        return s;
    }
};

} // namespace fxchain
