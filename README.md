# openbcp

The open networking libraries of BCP (Binarii Core Primitives). Independent
C++20 libraries, each usable on its own — two today, more as the project grows:

- **`flux`** — the transport. A connectionless, zero-alloc, encrypted UDP
  protocol: handshake, secure packets, address migration, and reliable-ordered,
  reliable-unordered and unreliable flows over one socket.
- **`common`** — the systems primitives it is written with: error and result
  types, lock-free collections, byte cursors, crypto, platform glue, logging,
  math. Transport-agnostic by rule, so nothing in it knows what a packet is.

Cross-platform (Windows / Linux / macOS, x86-64 and arm64), no exceptions, no
heap allocation on the packet path. The crypto dependency (Monocypher) is
vendored — a plain clone is everything you need, no submodules to fetch.

It is aimed at low-latency traffic where per-packet cost matters — games,
real-time systems, anything that would otherwise reach for raw UDP and rebuild
reliability, encryption and connection handling by hand.

> Status: pre-1.0. The wire format and API may still change.

## What flux does

- **No connect step.** The first send to an unknown address runs the handshake
  and holds the message until the session is up. There is no connection object
  to manage, and no callback to wait on.
- **Encrypted by default.** XChaCha20-Poly1305 on every packet, with the nonce
  counter masked so an observer cannot follow a peer by its packet sequence.
  Plaintext is available as an explicit opt-out when you want it.
- **Three delivery modes on one socket.** Reliable-ordered, reliable-unordered,
  and unreliable — all numbered and acknowledged, so loss is visible to
  congestion control even when nothing is retransmitted.
- **Survives address changes.** A peer that moves keeps its session: no
  re-handshake, and the rotating tag that identifies it is derived at both ends
  rather than sent, so a move is not linkable on the wire.
- **Identity by pinned certificate.** Trust comes from how a certificate was
  delivered, not from a signature chain, and the handshake proves the peer owns
  the matching key.
- **Owns no thread.** `Poll` and `Update` run on threads you choose, as often as
  you choose. Both are safe to call concurrently.
- **Stateless until proven.** The responder holds no state through the
  handshake challenge, so an unverified peer costs it nothing to ignore.

Not there yet, and worth knowing before you adopt it: path MTU discovery
(packets are a conservative 1200 bytes), NAT traversal, 0-RTT resumption after
a session is gone, and congestion control beyond plain AIMD.

## Requirements

- **CMake** ≥ 3.25
- **A C++20 compiler**: MSVC, GCC, or Clang
- **Ninja** (used below; any CMake generator works)

## Build

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

## Test

The suite is split into three categories, one executable per file:

| Directory            | Runs                              | CTest label   |
|----------------------|-----------------------------------|---------------|
| `tests/unit/`        | data-structure integrity          | `unit`        |
| `tests/integration/` | full processes and edge cases     | `integration` |
| `tests/bench/`       | performance against a baseline    | `bench`       |

```sh
# Fast suite — unit + integration, the commit gate:
ctest --test-dir build -LE bench --output-on-failure

# Benchmarks — heavier; run on demand (build Release for meaningful numbers):
ctest --test-dir build -L bench --output-on-failure
```

Non-release builds are instrumented with **AddressSanitizer + UndefinedBehaviorSanitizer**
by default. To run the concurrency tests under **ThreadSanitizer** instead
(mutually exclusive with ASan), configure a separate build:

```sh
cmake -S . -B build-tsan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBCP_SANITIZE=thread
cmake --build build-tsan
ctest --test-dir build-tsan --output-on-failure
```

Disable sanitizers with `-DBCP_SANITIZE=""`. Some toolchains (notably Apple's
Command Line Tools clang) ship a broken ASan/TSan runtime; the build probes for
this at configure time and falls back to UBSan-only rather than produce binaries
that fail to start.

## Layout

```
common/    include/ + src/     systems primitives
flux/      include/ + src/     the transport
examples/  runnable programs written against the public API
external/  monocypher/         vendored crypto (BSD-2-Clause OR CC0-1.0)
tests/     unit/ integration/ bench/ + shared harnesses
```

[ARCHITECTURE.md](ARCHITECTURE.md) covers the entities, the ownership rules, the
wire format, and how many ways there are to do each thing.

## Try it

Each example is one file running two sockets in one process, built with
everything else:

```sh
./build/send_and_respond          # A sends, B answers
./build/simultaneous_handshake    # both send first; the handshake collision resolves itself
./build/reliable_flow             # RELIABLE_ORDERED flow, numbered burst
./build/unreliable_flow           # the same burst on an UNRELIABLE flow
```

There is no connect step: the first send to an address Flux has not seen starts
the handshake and holds the message until the session is up. See
[examples/](examples/).

## Benchmarks

What one packet costs, measured on an Apple M3 Max, Release, clang 22. Loopback,
so treat absolute times as machine-specific; the deltas are the useful part.

**Send path** — Flux against the bare `sendto()` syscall underneath it, median
of 30,000 sends per variant, interleaved so all three see the same machine
state:

| payload | bare `sendto` | + Flux framing | + AEAD seal |
|---|---|---|---|
| 64 B | 2792 ns | **+125 ns** | +583 ns |
| 1024 B | 2875 ns | **+167 ns** | +2875 ns |

Framing costs about 5% over the raw syscall. Everything else is the encryption,
which scales with payload and is the same cost any encrypted transport pays.

**Encryption alone**, no sockets involved — XChaCha20-Poly1305 through vendored
Monocypher:

| payload | encrypt | decrypt + verify |
|---|---|---|
| 64 B | 372 ns | 352 ns |
| 256 B | 661 ns | 668 ns |
| 1200 B | 2254 ns | 2252 ns |

Portable C, so roughly 0.5 GB/s. That is the ceiling on a full-size packet
today, and swapping in a SIMD implementation is the lever if it ever needs
lifting.

Run them yourself with `ctest --test-dir build -L bench` on a Release build.
They always exit 0 — they are measurements, not a pass/fail gate.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

`flux` and `common` stay Apache-2.0. Binarii Games sells products built on these
libraries; a paid tier means extra code in that tier, not features taken out of
here.

Contributions stay yours: no CLA, no copyright assignment, just a Developer
Certificate of Origin sign-off. See [CONTRIBUTING.md](CONTRIBUTING.md).

Report security problems privately through [SECURITY.md](SECURITY.md), not an
issue. [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) covers the rest.
