# Contributing to openbcp

Thanks for your interest. This is a systems library where correctness and
clarity matter more than surface area, so the bar for a change is high and the
conventions are deliberate.

## Building and testing

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build -LE bench --output-on-failure
```

Everything must configure, build, and test on Windows (MSVC), Linux (GCC/Clang),
and macOS (Clang) from the same `CMakeLists.txt`. A change that only works on one
OS is a bug — whether it's an `#ifdef` gap, a shell script, or a test that
hard-codes a backend.

A change is not done until its tests have run **clean under sanitizers**, not
merely compiled and passed. ASan + UBSan is the default; anything touching the
lock-free code (`SlotPool`, `FifoQueue`, the peer-table seqlock,
atomics) must also run clean under TSan (`-DBCP_SANITIZE=thread`, a separate
configure). A green suite over lock-free code without TSan is not evidence of
race-freedom.

## Tests

Three categories, one executable per file (drop a file in, CMake globs it):

- `tests/unit/` — one data structure's integrity, in isolation.
- `tests/integration/` — a full process end to end, with its edge cases.
- `tests/bench/` — a hand-built structure against the standard-library baseline
  a competent engineer would reach for; measurement, not a pass/fail gate.

Tests use a tiny hand-rolled harness (`tests/harness.h`) — a test reads top to
bottom with no framework to learn.

**A test encodes intended behaviour, never the current code.** It asserts what
the code is *supposed* to do — its contract — not what the implementation happens
to do today. A test that fails because of a design gap is the test doing its job:
the fix goes to the code, not the assertion. Endianness tests assert the literal
bytes on the wire, not just a round-trip.

## Conventions

- **No exceptions**; fallible functions return `common::Error` or
  `common::Result<T>`, and `[[nodiscard]]` marks anything that must be checked.
- **No heap allocation on the packet path.** Allocation happens in `Init`, never
  on a hot path or in a destructor. Fixed arrays and pools, not `std::vector` /
  `std::unordered_map` / `std::string` on the wire path.
- **The wire is little-endian**, encoded by explicit shifts through the byte
  cursors. Never `memcpy` a multi-byte scalar to the wire, never overlay a struct
  on wire bytes, never assume host byte order.
- **Ownership is explicit and in the type system** (see `PacketSlotHandle` /
  `PeerHandle`): one owner per resource, move-only where ownership is unique, RAII
  release on the destructor edge.
- **Fixed-width integer types** (`uint8_t` … `uint64_t`) for anything on the
  wire, any size, or any count — never bare `int`/`long`.
- **Comments explain *why*.** They are sparse and load-bearing; naming and
  structure carry the *what*.

Match the surrounding code: brace style and idiom vary by directory, and the
existing file wins.

## Submitting

Contributions are accepted under the Apache License 2.0, the same terms the
libraries themselves carry (see `LICENSE`).

**Your work stays yours.** There is no CLA and no copyright assignment. You keep
the copyright in what you write, and Binarii Games Inc. gets no right to
relicense it. See [the commitment in README.md](README.md#licensing-and-commitment).

What we do ask for is a sign-off, so the provenance of every line is on record.
Add `-s` when you commit:

```sh
git commit -s -m "your message"
```

which appends a line to the message:

```
Signed-off-by: Your Name <your.email@example.com>
```

That line certifies the [Developer Certificate of Origin
1.1](https://developercertificate.org): that you wrote the change or otherwise
have the right to submit it under Apache-2.0, and that you understand the
contribution and the sign-off are public and permanently recorded. Use a real
name and a working address. A commit without a sign-off cannot be merged.

If your employer owns the copyright in your work, get their permission before
signing off.
