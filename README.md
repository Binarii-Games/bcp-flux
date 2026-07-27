# openbcp

Open primitives from the BCP (Binarii Core Primitives) project. Two independent
libraries, each usable on its own:

- **`common`** — general-purpose systems primitives: error and result types,
  lock-free collections, byte cursors, crypto, platform glue, logging, math.
  Nothing in it knows what a packet or a peer is.
- **`flux`** — a connectionless, zero-alloc, encrypted transport protocol built
  with `common`. Handshake, secure packets, address migration, reliable and
  unreliable flows.

C++20, cross-platform (Windows / Linux / macOS, x86-64 and arm64), no exceptions,
no heap allocation on the packet path. The crypto dependency (Monocypher) is
vendored — a plain clone is everything you need, no submodules to fetch.

> Status: pre-1.0. The wire format and API may still change.

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

## Try it

The examples build with everything else:

Each is one file, two sockets in one process, and runs on its own:

```sh
./build/send_and_respond          # A sends, B answers
./build/simultaneous_handshake    # both send first; the handshake collision resolves itself
./build/reliable_flow             # RELIABLE_ORDERED flow, numbered burst
./build/unreliable_flow           # the same burst on an UNRELIABLE flow
```

There is no connect step: the first send to an address Flux has not seen starts
the handshake and holds the message until the session is up. See
[examples/](examples/).

## Licensing and commitment

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

`flux` and `common` are Apache-2.0 and will stay that way. Binarii Games Inc.
sells products built on top of these libraries, and a paid tier means new code in
that tier. It does not mean capabilities withheld from this repository, and it
does not mean capabilities moved out of it later to be sold.

Two things make that checkable instead of merely stated. Nothing published here
gets taken back out to sell, which the commit history shows or fails to show. And
the architecture rules out the arrangement that would make hollowing this out
worthwhile: nothing in `flux` may reference a layer above it, and `flux` plus
`common` have to be complete and useful to someone who never touches anything
else we make. That constraint is described in [ARCHITECTURE.md](ARCHITECTURE.md)
and it is why the open libraries cannot quietly become a funnel.

Contributions stay yours. There is no CLA and no copyright assignment — just a
Developer Certificate of Origin sign-off, so you keep the copyright in your work
and we gain no right to relicense it. See [CONTRIBUTING.md](CONTRIBUTING.md).

Found a security problem? Please report it privately rather than in an issue —
[SECURITY.md](SECURITY.md) has the two ways to do that. Community expectations
are in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
