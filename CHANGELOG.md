# Changelog

All notable changes to Flux and `common` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims at
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.

Before 1.0 the wire format and the API may change between any two versions, and a
security fix is allowed to change either.

## [Unreleased]

### Added
- Session key rotation. The key is now a chain: each rotation derives the next
  link one-way from the current one and wipes the old, so a key stolen today
  cannot read traffic recorded before the last rotation. Rotation is silent on
  the wire, runs on a per-peer byte threshold (`Config::rotateAfterBytes`) or
  on `RotateKeys`, and the peer discovers it by trial decryption.
- A 0-RTT opener. A send to a peer whose certificate is loaded, named through
  `Connect(addr, tag)`, carries application data in its first packet, under an
  interim key the sender derives alone, while the ordinary handshake completes
  behind it and replaces that key. Flows run across the handover. Off by
  default (`Config::knock`), with a per-tick validation budget, a clock
  window, an unproven-peer cap and a per-peer packet allowance.
  `MaxPayload` reports the payload the next packet to a target can carry, and
  a send past it is refused with `TooLarge` rather than truncated or silently
  dropped. An opener honours the security level the caller picked, so a
  mac-only send inside the window travels readable and unpadded rather than
  being quietly upgraded to encrypted.
- `RemoveCertificate` revokes a pinned identity at runtime. The tag's entry
  is kept with its key wiped and version cleared, so every later check
  against it fails hard rather than falling open.
- Identity rotation. `RotateIdentity` replaces the keypair a socket proves its
  tag with, under live traffic, without changing the tag, so running sessions
  and peer relationships are untouched. Previous keypairs are kept as
  `Config::identityHistory` allows, and a first-flight opener naming one is
  still opened, so its data arrives while the sender's certificate catches up.
  The opener names the key it was aimed at in four bytes, so a receiver holding
  several picks one rather than trying each. Two events carry the news:
  `PEER_STALE_IDENTITY` on the receiver, and `PEER_CERT_MISMATCH` on a sender
  whose pinned certificate no longer matches, which is its cue to fetch a fresh
  one. `ForgetPreviousIdentities` wipes the retained keys outright, for a leak.

## [0.4.0] - 2026-08-11

### Added
- A C API, so other languages can drive the transport. One exported symbol hands
  back a table of function pointers. Handles are 64-bit numbers (a slot, its
  generation, and a kind tag) rather than pointers, so a binding can copy, zero
  or move a value without touching a live object, and a stale or wrong-kind
  number is refused. A layout check lets a binding confirm its own structs before
  it trusts them.
- Pool slots carry a generation. An index on its own names whichever tenant holds
  the slot now, so a release advances the generation and an index paired with an
  old one is refused.
- The first transfer tests: the codes each refusal owes, a run arriving byte for
  byte at the offsets it belongs at, and recovery across six damaged links.

### Fixed
- A transfer no longer deadlocks when the reply to its first announcement is lost.
  A repeated announcement used to be met with silence, leaving the sender holding
  every data packet behind it until the peer timed out.
- A packet builder whose flow was never declared no longer faults on a put.
- A congestion floor set above the ceiling is refused at `Init` rather than
  tripping an assert on the first acknowledgement.

## [0.3.5] - 2026-08-09

### Added
- Transfers. A transfer moves one run of bytes whose length is agreed up front,
  between buffers the application owns. Nothing is staged per packet and the
  sender never chunks, so a gigabyte and a kilobyte cost the same tracking state.
- Flow message batching, so several messages leave as one datagram under one seal.
- An event hook, so a socket reports what happened to a peer or a flow rather than
  waiting to be asked.
- Per-peer receive grants, so one peer cannot occupy the buffer the others need.
- A mac-only security level that authenticates a packet without encrypting it.

### Changed
- Congestion control reads delay as well as loss, so it settles on a short queue
  rather than a full one. A sender starved by a neighbour that keeps the queue
  full stops treating the queue as its own and holds its share. Loss recovery runs
  off the acknowledgements rather than a clock, and sends are paced at the rate the
  path takes.

## [0.3.0] - 2026-07-31

### Added
- Recovery is tested against ten damaged links carrying loss, burst loss,
  reordering, duplication, corruption and handshake loss.

### Fixed
- A flow id closed and reopened is a new generation on the wire, so reusing an id
  no longer delivers the previous generation's packets as though they belonged to
  the current one.
- Acks and refusals name the generation they answer, so one still in flight when
  an id reopens cannot resolve packets that were never delivered.
- A corrupted handshake response no longer binds a peer to an identity nobody
  holds, which used to leave that address unreachable for good.

## [0.2.0] - 2026-07-29

### Added
- Replies build directly from the received packet, with no address named.
- CI covers Linux, macOS, Windows, Debian and Rocky, with Android and iOS
  cross-builds.

### Changed
- Flows no longer need an opening exchange. A flow is opened locally, serves any
  number of peers with independent per-target state, and closes locally.
- Unreliable delivery is newest only.
- `common` is vendored in `external/` as its own library with its own tests.

## [0.1.0] - 2026-07-27

### Added
- First public release of `flux` and `common`. Verified on macOS/arm64: builds
  and tests clean under ASan/UBSan and TSan. Windows and Linux are written for but
  had not yet been compiled or run at this release. The wire format and API may
  still change before 1.0.

[Unreleased]: https://github.com/Binarii-Games/bcp-flux/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/Binarii-Games/bcp-flux/compare/v0.3.5...v0.4.0
[0.3.5]: https://github.com/Binarii-Games/bcp-flux/compare/v0.3.0...v0.3.5
[0.3.0]: https://github.com/Binarii-Games/bcp-flux/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Binarii-Games/bcp-flux/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Binarii-Games/bcp-flux/releases/tag/v0.1.0
