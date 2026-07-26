# AirPlay Video Sender (Fork)

> **This repository is a fork of Akustikrausch's AirPlay 2 Sender project.**
>
> The upstream project is a clean-room implementation of the modern AirPlay 2 **realtime audio (RAOP)** sender protocol. It documents and implements pairing, encrypted RTSP, ALAC streaming, and the protocol required to send realtime audio to modern Apple devices.
>
> **This fork has a different goal.**
>
> It is focused exclusively on implementing **AirPlay Video**, specifically remote-URL playback ("cast this URL") and eventually local-file playback by serving media over HTTP. While both protocols share the same pairing and encrypted transport, AirPlay Video is a fundamentally different protocol from RAOP and deserves its own direction. 

## Why this fork exists

The upstream project already solved the hardest part of modern AirPlay:

* HomeKit pairing
* encrypted request channels
* authentication
* binary plist support
* protocol documentation

That work provides an excellent foundation.

My interest isn't realtime audio, however. I'm interested in understanding and implementing the **AirPlay Video** protocol.

Rather than expanding the upstream project in a direction it wasn't primarily designed for, this fork is free to reorganize the codebase around video-first architecture while continuing to reuse as much of the underlying protocol work as possible. 

## Project goals

This repository has one primary objective:

* ✅ AirPlay Video remote-URL playback

Once that's working:

* local-file playback via an embedded HTTP byte-range server
* playback control (play, pause, seek, stop)
* playback state reporting
* documentation of the protocol as it is reverse engineered against real hardware

## Non-goals

This fork is **not** trying to become a comprehensive AirPlay implementation.

Current non-goals include:

* new realtime audio features
* additional audio codecs
* RAOP improvements unrelated to video
* generalized sender APIs
* feature parity with upstream

Architectural refactoring will happen only where it directly benefits AirPlay Video.

## Roadmap

Development follows a deliberately incremental plan:

**v1 — Remote URL playback**

* pair with receiver
* implement `/play`
* playback controls
* playback status

**v2 — Local file playback**

* embedded HTTP server
* byte-range support
* `playLocalFile()`

**v3 — Receiver-driven events**

* long-lived `/event` connection
* push-based playback updates instead of polling

Photo casting and other AirPlay features are considered future possibilities, but are outside the immediate scope. 

## Relationship to upstream

This repository would not exist without the work of **Akustikrausch**.

The original project remains the reference implementation for modern AirPlay 2 realtime audio and the authoritative source for its protocol documentation. This fork intends to periodically merge fixes from upstream where practical while pursuing a different architectural direction centered on AirPlay Video.

If your goal is AirPlay 2 audio streaming, you should use the upstream project. If your goal is understanding or implementing AirPlay Video, this fork is where that work happens. 

