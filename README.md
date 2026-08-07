# Flux

[![ci](https://github.com/Binarii-Games/bcp-flux/actions/workflows/ci.yml/badge.svg)](https://github.com/Binarii-Games/bcp-flux/actions/workflows/ci.yml)

A connectionless, encrypted UDP transport in C++20. There is no connection
object, nothing allocates on the packet path, and one socket carries reliable
and unreliable traffic at the same time.

Flux builds on `common`, a standalone systems library that knows nothing about
transports, vendored in `external/common` at a pinned version. Monocypher is
vendored the same way. Both are Apache-2.0.

Windows, Linux and macOS, on x86-64 and arm64. No exceptions.

## Build

CMake 3.25 or newer and a C++20 compiler (MSVC, GCC, or Clang). Ninja is used
below, any generator works.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

## Guide

Everything below is running code, and the same steps live as full programs in
[examples/](examples/).

```cpp
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>

namespace flux   = bcp::flux;
namespace common = bcp::common;
```

### Create a socket

Configure, then `Init`. Nothing allocates after this call.

```cpp
flux::Socket socket;

flux::Socket::Config config;
config.type = flux::Socket::BackendType::STD_UNX;   // STD_WIN on Windows, after WSAStartup
config.port = 9500;

if (socket.Init(config) != common::Error::Ok)
    return 1;
```

### Run it

Flux owns no thread, so the socket only works when you call it. `Update` runs
the timers (acks, retransmits, handshake retries), `Poll` hands you what
arrived, and `Flush` puts what you sent on the wire. Call them from any threads,
at any cadence, all three are safe concurrently.

Polling from more than one thread needs one more step, because an ordered flow
is only ordered to a single reader. Set `config.pollLanes` to the number of
threads that will poll, and hand each thread's lane back to its next `Poll`:

```cpp
flux::ThreadIdentity me{};
for (;;)
{
    flux::PollCursor cursor = socket.Poll(inbox, 8, me);
    me.lane = cursor.Lane();           // come back to this lane next time
    while (cursor.Next()) { /* ... */ }  // the lane is yours until the cursor dies
}
```

`Poll` takes whichever lane is free, preferring the one you pass, and holds it
until the cursor goes out of scope. So a peer's packets reach one thread at a
time and arrive in sequence, a thread that keeps passing its lane back stays on
it, and a lane whose thread stops calling is picked up by another instead of
filling. Left at the default of one lane, `Poll` behaves exactly as above and
the identity can be left off.

`Flush` matters: a send on a flow is packed together with others going the same
way, so several small messages leave as one datagram. They wait until you flush,
which means the moment your bytes go out is yours to pick rather than a timer's.
Miss it and they sit there.

```cpp
flux::PacketSlotHandle inbox[8];

for (;;)
{
    socket.Flush();    // send what this round produced
    socket.Update();

    flux::PollCursor cursor = socket.Poll(inbox, 8);
    while (cursor.Next())
    {
        const uint8_t* payload = cursor.Message().Content();
        const uint16_t length  = cursor.Message().ContentLength();
        // read the payload here, the handles free their slots when they die
    }
}
```

`Poll` fills the array with packets and hands back a cursor over the messages
inside them. One datagram can carry several, so the loop runs once per message
rather than once per packet, and a caller never has to know which arrived
together. `cursor.Packet()` reaches the packet a message came in when you want
its address or its flow.

The payload is never copied out. A handle points into the socket's receive
pool and returns its slot when it goes out of scope.

### Send

There is no connect call. The first send to an address Flux has not seen runs
the handshake and parks the message until the session is up, which costs two
round trips. Everything after goes straight out, encrypted.

```cpp
const flux::Address addr = flux::Address::From("::1", 9501).Take();

const uint8_t msg[] = "hello";
socket.BuildPacket().NoFlow().PutBytes(msg, sizeof(msg) - 1).Send(addr);
```

`NoFlow` is fire-and-forget: no sequence, no ack, no retransmission, the
cheapest thing Flux sends. Delivery guarantees come from flows, below.

### Reply

A received packet builds its own response, aimed at its sender. No address
needed.

```cpp
inbox[i].PrepareResponse().NoFlow().PutBytes(msg, sizeof(msg) - 1).Respond();
```

### Open a flow

A flow is a numbered channel with a delivery guarantee. Give the socket flow
pools at `Init`:

```cpp
config.flows.outCount = 16;   // sending associations, socket-wide
config.flows.inCount  = 16;   // receiving associations, socket-wide
```

`OpenFlow` is local. It puts nothing on the wire, and the flow is sendable the
moment it returns, even before any handshake. The receiver needs no setup
either, it registers the flow from the first packet that arrives.

```cpp
flux::FlowHandle flow = socket.OpenFlow(7, flux::FlowMode::RELIABLE_ORDERED);

socket.BuildPacket().WithFlow(flow).PutU32(value).Send(addr);
```

Four modes:

| Mode | Retransmitted | Delivered | In flight |
|---|---|---|---|
| `RELIABLE_ORDERED` | yes | in sequence, gaps held back until filled | 256 |
| `RELIABLE_UNORDERED` | yes | on arrival | 256 |
| `UNRELIABLE` | no | newest only, stale packets dropped | 256 |
| `RELIABLE_ORDERED_BULK` | yes | in sequence | 1024 |

All four number and acknowledge every packet, so loss feeds congestion
control even when nothing is resent.

Bulk is the same contract as `RELIABLE_ORDERED` with four times the window, for
traffic that fills a pipe rather than tracking a clock. It costs more memory per
target and stalls longer behind a lost packet, so it draws from a pool you size
yourself with `flows.bulkOutCount`, which is zero by default.

### One flow, many peers

A flow is not bound to a peer. The same handle serves every address you send
it to, and each target gets its own sequence, its own retransmits and its own
failures, so a dead peer never affects the others.

```cpp
socket.BuildPacket().WithFlow(flow).PutU32(value).Send(addrB);
socket.BuildPacket().WithFlow(flow).PutU32(value).Send(addrC);   // independent sequence
```

Closing is local too. It frees the flow and everything it held, and sends
nothing:

```cpp
socket.CloseFlow(flow);
```

### Authenticated and plaintext sends

`Send` is best-effort: encrypted always, authenticated when the peer is.
`SendSecured` refuses any peer not authenticated against a pinned certificate,
loaded with `socket.LoadCertificate(cert)`. `Unsecured` is the explicit opt-out
that skips encryption entirely.

```cpp
socket.BuildPacket().NoFlow().PutBytes(msg, len).SendSecured(addr);
socket.BuildPacket().Unsecured().NoFlow().PutBytes(msg, len).Send(addr);
```

## Underneath

A session belongs to the peer, not its address. When a peer moves (NAT rebind,
VPN reconnect, network handoff) the session continues with no re-handshake:
secure packets carry a small rotating tag both ends derive from the session
key, so a mover is recognised without any exchange. Rotating it unlinks a
deliberate address change from everything sent before. Peers are named by
`blake2b(publicKey)`, so proving the key proves the name and no registry is
involved.

Packets are little-endian and capped at 1200 bytes, under the IPv6 minimum MTU
with margin for tunnels. Every secure packet is sealed with XChaCha20-Poly1305,
and the nonce counter is masked so an observer cannot follow a peer by watching
a serial number climb. Control packets are indistinguishable from data on the
wire. The full layout is in [ARCHITECTURE.md](ARCHITECTURE.md), along with the
entities, the ownership rules, and how many ways there are to do each thing.

The wire format is not frozen before 1.0. It can change between versions, and a
security fix is allowed to change it.

Not there yet: path MTU discovery, NAT traversal, and session resumption. There is no 0-RTT. A certificate authenticates
a peer, it does not shorten the handshake.

## Test

Three categories, one executable per file:

| Directory            | Runs                              | CTest label   |
|----------------------|-----------------------------------|---------------|
| `tests/unit/`        | data-structure integrity          | `unit`        |
| `tests/integration/` | full processes and edge cases     | `integration` |
| `tests/bench/`       | performance against a baseline    | `bench`       |

Those cover Flux. The vendored `common` keeps its own under
`external/common/tests/`, and they link `common` alone, so it is tested
without the transport.

```sh
# Fast suite, unit plus integration. This is the commit gate:
ctest --test-dir build -LE bench --output-on-failure

# Benchmarks. Heavier, run on demand, build Release for meaningful numbers:
ctest --test-dir build -L bench --output-on-failure
```

Non-release builds are instrumented with AddressSanitizer and
UndefinedBehaviorSanitizer by default. To run the concurrency tests under
ThreadSanitizer instead (mutually exclusive with ASan), configure a separate
build:

```sh
cmake -S . -B build-tsan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBCP_SANITIZE=thread
cmake --build build-tsan
ctest --test-dir build-tsan --output-on-failure
```

Disable sanitizers with `-DBCP_SANITIZE=""`. Some toolchains, notably Apple's
Command Line Tools clang, ship a broken ASan/TSan runtime. The build probes for
that at configure time and falls back to UBSan only, rather than producing
binaries that fail to start.

## Layout

```
flux/      include/ + src/     the transport
tests/     unit/ integration/ bench/ + shared harnesses
examples/  runnable programs written against the public API
external/  common/             standalone systems library, vendored, own tests
           monocypher/         vendored crypto (BSD-2-Clause OR CC0-1.0)
```

## Examples

One file each, running several sockets in one process, built with everything
else:

```sh
./build/send_and_respond          # A sends, B answers
./build/respond                   # B answers through the packet itself, no address named
./build/simultaneous_handshake    # both send first, the handshake collision resolves itself
./build/reliable_flow             # one RELIABLE_ORDERED flow, numbered burst to two peers
./build/unreliable_flow           # the same burst on an UNRELIABLE flow
```

## Benchmarks

What one packet costs, measured on an Apple M3 Max, Release, clang 22. These run
over loopback, so treat the absolute times as machine-specific. The deltas are
the useful part.

Send path, Flux against the bare `sendto()` syscall underneath it, median of
30,000 sends per variant, interleaved so all three see the same machine state:

| payload | bare `sendto` | + Flux framing | + AEAD seal |
|---|---|---|---|
| 64 B | 2792 ns | +125 ns | +583 ns |
| 1024 B | 2875 ns | +167 ns | +2875 ns |

Framing costs about 5% over the raw syscall. Everything else is the encryption,
which scales with payload and is the same cost any encrypted transport pays.

Encryption alone, no sockets involved. XChaCha20-Poly1305 through vendored
Monocypher:

| payload | encrypt | decrypt + verify |
|---|---|---|
| 64 B | 372 ns | 352 ns |
| 256 B | 661 ns | 668 ns |
| 1200 B | 2254 ns | 2252 ns |

Monocypher is portable C with no SIMD, so encryption tops out around 0.5 GB/s.
A SIMD implementation would raise that if it ever matters.

Run them on a Release build with `ctest --test-dir build -L bench`. They print
numbers and always exit 0.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Flux and `common` stay Apache-2.0. Binarii Games sells products built on these
libraries. A paid tier means extra code in that tier, not features taken out of
here.

Contributions stay yours: no CLA, no copyright assignment, just a Developer
Certificate of Origin sign-off. See [CONTRIBUTING.md](CONTRIBUTING.md).

Report security problems privately through [SECURITY.md](SECURITY.md) rather
than an issue. [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) covers the rest.
