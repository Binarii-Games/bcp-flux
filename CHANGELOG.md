# Changelog

All notable changes to Flux and `common` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims at
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.

Before 1.0 the wire format and the API may change between any two versions, and a
security fix is allowed to change either.

## [0.5.0] - 2026-08-17

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
  `MaxPayload` reports the payload the next packet to a target can carry, and a
  send past it returns `TooLarge` and leaves the payload alone. An opener
  honours the security level the caller picked, so a
  mac-only send inside the window travels readable and unpadded.
  `SAFE_PAYLOAD_BYTES` is 968: any opener
  may carry a resume note, and a figure that always fits has to account for
  one.
- `RemoveCertificate` revokes a pinned identity at runtime. The tag's entry
  is kept with its key wiped and version cleared, so every later check against
  it fails hard.
- Session resumption. A process that dies and restarts brings its session back
  with no handshake at all. Before this it waited up to thirty seconds for the
  far side to evict the entry it still holds. Each side seals a note for its
  peer
  once a session confirms, sealed for the issuer's own future self so the
  holder stores bytes it cannot read and the issuer stores nothing. Presenting
  one at `Connect` puts it inside the first packet: opening that packet proves
  the sender holds the key the note names, so the two together are what the
  exchange would have established. The tag inside is re-checked against the
  trust store on arrival, so a revoked certificate stops a resumption too.
  Nothing secret is in a note, so the bytes are handed to the application
  and loaded back exactly as certificates are, and a note that will not open
  leaves an ordinary first contact behind it. Notes are kept only when
  `Config::keepResumeNotes` asks, and last 48 hours by default.
- Identity rotation. `RotateIdentity` replaces the keypair a socket proves its
  tag with, under live traffic, without changing the tag, so running sessions
  and peer relationships are untouched. Previous keypairs are kept as
  `Config::identityHistory` allows, and a first-flight opener naming one is
  still opened, so its data arrives while the sender's certificate catches up.
  The opener names the key it was aimed at in four bytes, so a receiver holding
  several picks the right one directly. Two events carry the news:
  `PEER_STALE_IDENTITY` on the receiver, and `PEER_CERT_MISMATCH` on a sender
  whose pinned certificate no longer matches, which is its cue to fetch a fresh
  one. `ForgetPreviousIdentities` wipes the retained keys outright, for a leak.

- The C API reaches everything above. Certificates and identity cross as
  fixed-size byte buffers, because a server has to persist
  its identity and a handle could never leave the process, and the private form
  is byte for byte the identity file. Added: identity generation and the
  certificate derived from it, loading and revoking a certificate, rotating an
  identity and forgetting the previous ones, rotating a session key, naming the
  identity expected at an address so a first send can carry data, asking what
  the next packet to a peer may carry, reading whether a delivered packet rode a
  first flight, and collecting and presenting a resume note. `LayoutCheck`
  reports the knock config block so a binding can still prove its own structs,
  and three event bits the enum was missing are there. `FLUX_SAFE_PAYLOAD_BYTES`
  and `FLUX_RESUME_NOTE_BYTES` are checked against the C++ constants at build
  time, so the two cannot drift apart unnoticed. The `flux_c` target builds
  the whole library as one standalone shared file exporting only
  `flux_get_api`, which is the file a binding loads. Addresses cross as
  `FLUX_ADDRESS_SIZE` canonical bytes through `AddressResolve`,
  `PeerAddress` and `PeerAt`, so a binding's address is data it can hold,
  store and compare, and a stored one opens a session with nothing
  resolved.

## [0.4.0] - 2026-08-11

### Added
- A C API, so other languages can drive the transport. One exported symbol hands
  back a table of function pointers. Handles are 64-bit numbers holding a slot,
  its generation and a kind tag, so a binding can copy, zero
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
- A congestion floor set above the ceiling is refused at `Init`. It used to
  trip an assert on the first acknowledgement.

## [0.3.5] - 2026-08-09

### Added
- Transfers. A transfer moves one run of bytes whose length is agreed up front,
  between buffers the application owns. Nothing is staged per packet and the
  sender never chunks, so a gigabyte and a kilobyte cost the same tracking state.
- Flow message batching, so several messages leave as one datagram under one seal.
- An event hook, so a socket reports what happened to a peer or a flow without
  being asked.
- Per-peer receive grants, so one peer cannot occupy the buffer the others need.
- A mac-only security level that authenticates a packet without encrypting it.

### Changed
- Congestion control reads delay as well as loss, so it settles on a short
  queue. A sender starved by a neighbour that keeps the queue
  full stops treating the queue as its own and holds its share. Loss recovery
  runs off the acknowledgements, and sends are paced at the rate the
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

[0.5.0]: https://github.com/Binarii-Games/bcp-flux/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Binarii-Games/bcp-flux/compare/v0.3.5...v0.4.0
[0.3.5]: https://github.com/Binarii-Games/bcp-flux/compare/v0.3.0...v0.3.5
[0.3.0]: https://github.com/Binarii-Games/bcp-flux/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Binarii-Games/bcp-flux/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Binarii-Games/bcp-flux/releases/tag/v0.1.0
