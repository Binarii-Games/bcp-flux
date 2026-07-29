# Contributing to Flux

This is a systems library, so correctness and clarity come before surface area.
The conventions below are what the existing code already does.

## Building and testing

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build -LE bench --output-on-failure
```

Everything must configure, build, and test on Windows (MSVC), Linux (GCC/Clang),
and macOS (Clang) from the same `CMakeLists.txt`. A change that only works on one
OS is a bug, whether it is an `#ifdef` gap, a shell script, or a test that
hard-codes a backend.

A change is not done until its tests have run clean under sanitizers, not merely
compiled and passed. ASan and UBSan are the default. Anything touching the
lock-free code (`SlotPool`, `FifoQueue`, the peer-table seqlock, atomics) must
also run clean under TSan (`-DBCP_SANITIZE=thread`, a separate configure). A
green suite over lock-free code without TSan is not evidence of race-freedom.

## Tests

Three categories, one executable per file (drop a file in, CMake globs it):

- `tests/unit/` covers one data structure's integrity, in isolation.
- `tests/integration/` covers a full process end to end, with its edge cases.
- `tests/bench/` measures a hand-built structure against the standard-library
  baseline a competent engineer would reach for. Measurement, not a pass/fail
  gate.

Those cover Flux. The vendored `common` keeps its own under
`external/common/tests/` in the same three categories, and they link `common`
without Flux. A change to `common` is tested there.

Tests use a tiny hand-rolled harness (`harness.h`, one per test tree) so a test
reads top to bottom with no framework to learn.

A test encodes intended behaviour, never the current code. It asserts what the
code is supposed to do, its contract, rather than what the implementation
happens to do today. A test that fails because of a design gap is the test doing
its job, and the fix goes to the code rather than the assertion. Endianness
tests assert the literal bytes on the wire, not just a round trip.

## Conventions

- No exceptions. Fallible functions return `common::Error` or
  `common::Result<T>`, and `[[nodiscard]]` marks anything that must be checked.
- No heap allocation on the packet path. Allocation happens in `Init`, never on
  a hot path or in a destructor. Fixed arrays and pools, not `std::vector` or
  `std::unordered_map` or `std::string` on the wire path.
- The wire is little-endian, encoded by explicit shifts through the byte
  cursors. Never `memcpy` a multi-byte scalar to the wire, never overlay a struct
  on wire bytes, never assume host byte order.
- Ownership is explicit and in the type system (see `PacketSlotHandle` and
  `PeerHandle`): one owner per resource, move-only where ownership is unique,
  RAII release on the destructor edge.
- Fixed-width integer types (`uint8_t` through `uint64_t`) for anything on the
  wire, any size, or any count. Never bare `int` or `long`.
- Comments explain why. They are sparse and load-bearing, because naming and
  structure carry what the code does.

Match the surrounding code. Brace style and idiom vary by directory, and the
existing file wins.

## Submitting

Contributions are accepted under the Apache License 2.0, the same terms the
libraries themselves carry (see `LICENSE`).

Your work stays yours. There is no CLA and no copyright assignment. You keep the
copyright in what you write, and Binarii Games Inc. gets no right to relicense
it. See [the commitment in README.md](README.md#license).

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

## Using AI tools

Use whatever tools you like. There is no restriction, no disclosure requirement,
and nobody will ask in review.

What is required is that you understand what you submit. Expect to explain any
line of it, justify the design, and answer questions about edge cases nobody
warned you about. If a change cannot survive that, whatever produced it is
beside the point. It is not ready.

Two places where this bites hardest, and where a patch that merely looks correct
will be turned down:

- Concurrency. Anything touching `SlotPool`, `FifoQueue`, the per-slot RW locks,
  the peer-table seqlock, atomics or memory ordering. Confident and subtly wrong
  is the characteristic failure of generated concurrency code, and a wrong
  memory ordering passes review and a green test suite alike. Bring the
  reasoning with the patch: which loads and stores are relaxed against
  acquire/release, what a racing reader can and cannot observe, and worked
  interleavings for the happy path and the adversarial one. Run it under
  ThreadSanitizer and say so.
- Cryptography. Do not write new crypto, and do not have anything write it for
  you. Compose what is already in `common/crypto`. If a change genuinely needs a
  primitive that is not there, raise it first.

The legal half is already covered by the sign-off. It says you have the right to
submit the work under Apache-2.0, whatever helped you write it, and that does
not change.
