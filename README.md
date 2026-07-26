# AirPlay Video Sender (Fork)

> **This is a fork of Akustikrausch's excellent AirPlay 2 Sender project.**
>
> The original repository focuses on implementing a modern AirPlay 2 realtime audio sender and documenting the protocol in exceptional detail. This fork has a different goal: **adding AirPlay Video support**, specifically playback of remote media URLs on Apple TV and other AirPlay receivers. 

## Why this fork exists

First, full credit where it's due.

The original project solved a huge amount of difficult reverse engineering around modern AirPlay pairing, authentication, encrypted RTSP, and session management. None of that work is being replaced here—it forms the foundation this fork builds upon.

My interests, however, are much narrower.

### My goal

This repository exists for **one purpose**:

> **Implement AirPlay Video by supporting remote URL playback.**

That means:

* launching remote HTTP(S) media URLs on Apple TV
* understanding and implementing the required AirPlay video control protocol
* experimenting with video-specific RTSP/HTTP requests
* documenting everything necessary to make video playback work

## Non-goals

Unlike the upstream project, this fork is **not** intended to become a general-purpose AirPlay implementation.

I'm **not** currently interested in:

* improving realtime audio
* adding additional codecs
* polishing the sender library
* removing Qt
* CLI tooling
* general infrastructure work
* feature parity with upstream

If those are your goals, you should probably use the original repository instead.

## Relationship to upstream

This repository will periodically merge useful fixes from upstream where practical.

However, architectural decisions made here will prioritize video support over maintaining compatibility with upstream's roadmap.

## Upstream project

If you're interested in:

* AirPlay 2 realtime audio
* RAOP
* protocol documentation
* pairing and encryption details
* a reusable AirPlay sender

please see the original project by **Akustikrausch**. It remains the authoritative implementation for those goals. 

## Current status

Current focus:

* ☐ Discover the AirPlay video session flow
* ☐ Implement remote URL playback
* ☐ Document the protocol as it is reverse engineered
* ☐ Refactor only when required to support video

Everything else is considered secondary.

