# Flux

[![linux](https://github.com/Binarii-Games/bcp-flux/actions/workflows/linux.yml/badge.svg)](https://github.com/Binarii-Games/bcp-flux/actions/workflows/linux.yml)
[![windows](https://github.com/Binarii-Games/bcp-flux/actions/workflows/windows.yml/badge.svg)](https://github.com/Binarii-Games/bcp-flux/actions/workflows/windows.yml)
[![macos](https://github.com/Binarii-Games/bcp-flux/actions/workflows/macos.yml/badge.svg)](https://github.com/Binarii-Games/bcp-flux/actions/workflows/macos.yml)
[![android](https://github.com/Binarii-Games/bcp-flux/actions/workflows/android.yml/badge.svg)](https://github.com/Binarii-Games/bcp-flux/actions/workflows/android.yml)
[![ios](https://github.com/Binarii-Games/bcp-flux/actions/workflows/ios.yml/badge.svg)](https://github.com/Binarii-Games/bcp-flux/actions/workflows/ios.yml)
[![release](https://img.shields.io/github/v/release/Binarii-Games/bcp-flux?sort=semver)](https://github.com/Binarii-Games/bcp-flux/releases)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

A connectionless, encrypted UDP transport in C++20. There is no connection
object, nothing allocates on the packet path, and one socket carries reliable
flows, unreliable flows and whole-buffer transfers at the same time.

Flux builds on `common`, a standalone systems library that knows nothing about
transports, vendored in `external/common` at a pinned version. Monocypher is
vendored the same way. Both are Apache-2.0.

## Features

- **Connectionless.** No connection object. The first send to a new address runs
  the handshake and parks the message until the session is up. Everything after
  goes straight out.
- **Zero allocation on the packet path.** Every buffer is pooled and sized at
  `Init`. Nothing heap-allocates between socket receive and the handler callback.
- **Mixed reliability on one socket.** Reliable ordered, reliable unordered,
  unreliable, and bulk flows, each numbered and acknowledged, all at once.
- **Whole-buffer transfers.** Move a run of bytes whose length is known up front
  with no per-packet staging, so a gigabyte and a kilobyte cost the same state.
- **Encrypted by default.** XChaCha20-Poly1305, X25519, and BLAKE2b, with a
  mac-only level for public traffic and an explicit plaintext opt-out.
- **0-RTT to a known identity.** Hold a peer's certificate and the first packet
  to it already carries application data, encrypted toward that identity, while
  the handshake completes behind it. See [0-RTT](#0-rtt).
- **Session resumption.** A process that restarts picks its session back up
  immediately, with no handshake and no wait for the far side to drop the entry
  it still holds.
- **Rotating identities.** Replace the keypair a socket proves its name with,
  under live traffic, without changing the name or disturbing a session.
- **Survives address changes.** A session follows the peer, not its address, so a
  NAT rebind or a VPN reconnect continues with no re-handshake.
- **Delay-aware congestion control.** It reads queue growth as well as loss, so it
  holds its share beside BBR and leaves CUBIC the larger half almost without a
  drop.
- **Drivable from other languages.** A numbers-based C API hands out 64-bit
  handles, so a binding never holds a pointer. See [C API](#c-api).

## Table of contents

- [0-RTT](#0-rtt)
- [Requirements](#requirements)
- [Building](#building)
- [Integrating](#integrating)
- [Quick start](#quick-start)
- [Usage](#usage)
- [C API](#c-api)
- [Architecture](#architecture)
- [Benchmarks](#benchmarks)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## 0-RTT

The first packet to a peer can carry application data, even on first contact.
It takes the peer's certificate (a public key and an identity tag), obtained
out of band like an SSH host key. Load it, point `Connect(addr, tag)` at the
address, and the next send leaves immediately, sealed toward that key. The
ordinary handshake completes behind it, and the first flight belongs to the
same session as everything after. Sending this way is off until
`config.knock.enable` turns it on.

The trade-offs:

- **Replay.** A captured first flight is re-accepted only inside a 30 second
  clock window, and only by a receiver that lost its peers to a restart in the
  meantime. `IsKnock` marks every message that rode one, so anything
  non-idempotent can be kept off them.
- **Forward secrecy.** The first packet is sealed toward the receiver's
  long-term key, so a later theft of that key opens a recording of it.
  `RotateIdentity` caps the exposure at one rotation period. Everything after
  the handshake mixes both ephemerals and is unaffected.
- **Unproven sender address.** The transport answers a knock with one
  stateless challenge no larger than the knock itself, key agreements are
  budgeted per tick (32), and unproven peers are capped (64) with a per-peer
  packet allowance (256).
- **Less room.** An opener carries 968 bytes (`SAFE_PAYLOAD_BYTES`) against
  1200 established. `MaxPayload(addr)` reports the live figure.

A knock the receiver declines for any reason falls back to the ordinary
handshake, one pass later, with no error to handle. A resume note rides inside
a knock and brings a previous session back with no handshake at all. See
[Resume after a restart](#resume-after-a-restart).

## Requirements

CMake 3.25 or newer and a C++20 compiler (MSVC, GCC, or Clang).

Supported platforms are Windows, Linux, and macOS, on x86-64 and arm64. iOS and
Android are cross-compiled in CI to keep the code portable, but they are
build-checked only and not yet exercised as runtime targets.

## Building

Ninja is used below, any generator works.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

## Integrating

Flux is a CMake project with two library targets, `flux` and `common`. Linking
`flux` pulls in `common` and the vendored Monocypher automatically.

Pull it in at configure time with FetchContent:

```cmake
include(FetchContent)
FetchContent_Declare(
  flux
  GIT_REPOSITORY https://github.com/Binarii-Games/bcp-flux.git
  GIT_TAG        v0.5.0
)
FetchContent_MakeAvailable(flux)

target_link_libraries(your_target PRIVATE flux)
```

Or vendor the tree and add it directly:

```cmake
add_subdirectory(third_party/flux)
target_link_libraries(your_target PRIVATE flux)
```

There is no `find_package` or system install before 1.0. Pin a tag, because the
API and the wire format can still change between versions.

## Quick start

```cpp
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>

namespace flux   = bcp::flux;
namespace common = bcp::common;

flux::Socket socket;

flux::Socket::Config config;
config.type = flux::Socket::BackendType::STD_UNX;   // STD_WIN on Windows
config.port = 9500;
socket.Init(config);

// Send. The first packet to a new address runs the handshake underneath.
const flux::Address addr = flux::Address::From("::1", 9501).Take();
const uint8_t msg[] = "hello";
socket.BuildPacket().NoFlow().PutBytes(msg, sizeof(msg) - 1).Send(addr);

// Drive the socket and read what arrived.
flux::PacketSlotHandle inbox[8];
for (;;)
{
    socket.Flush();
    socket.Update();

    flux::PollCursor cursor = socket.Poll(inbox, 8);
    while (cursor.Next())
    {
        const uint8_t* payload = cursor.Message().Content();
        const uint16_t length  = cursor.Message().ContentLength();
        // read the payload here
    }
}
```

The [Usage](#usage) section below walks each step, and the same programs live in
full under [examples/](examples/).

## Usage

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
it, and a lane whose thread stops calling is picked up by another before it
fills. Left at the default of one lane, `Poll` behaves exactly as above and the
identity can be left off.

`Flush` matters: a send on a flow is packed together with others going the same
way, so several small messages leave as one datagram. They wait until you
flush, so you pick the moment your bytes go out. Miss it and they sit there.

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
inside them. One datagram can carry several, so the loop runs once per message,
and a caller never has to know which arrived together. `cursor.Packet()`
reaches the packet a message came in when you want its address or its flow.

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
traffic whose job is to fill a pipe. It costs more memory per target and stalls
longer behind a lost packet, so it draws from a pool you size yourself with
`flows.bulkOutCount`, which is zero by default.

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

### Events

State is always readable: ask a flow its lifecycle or a peer its flow count
and you get the truth. Events cover the other kind of question, the things
that happen between two polls: a handshake completed, a peer vanished or
moved, a flow was refused, lost or reopened by the far side, a transfer was
offered. Subscribe to the ones you want and `Poll` hands them to your hook
with nothing locked, so the handler can call straight back into the socket.

```cpp
void OnEvent(void* context, const flux::EventInfo& info)
{
    if (info.Has(flux::SocketEvent::PEER_LOST)) { /* info.Peer() names it */ }
}

config.events.hook       = OnEvent;
config.events.context    = &myState;
config.events.subscribed = flux::ToBits(flux::SocketEvent::PEER_LOST)
                         | flux::ToBits(flux::SocketEvent::OUTGOING_FLOW_LOST);
```

An event names the entity and carries nothing else. Everything it could carry
is already readable through the ordinary calls, so the handler reads the
state and gets the truth even when the moment it describes has passed. The
full list lives in `socket_events.h` with a doc comment each, and a socket
with no hook registered works exactly the same.

### Move a whole buffer

A flow carries messages. A transfer carries one run of bytes whose length is
known up front, and it skips the chunking: hand the socket a pointer and a
length, keep the memory alive, and get told when it is done. Nothing is
staged per packet. Data is read straight from your buffer, retransmits
re-read it, and delivery on the far side writes straight into the receiver's,
so a gigabyte and a kilobyte cost the same state.

```cpp
config.flows.transferOutCount = 2;
config.flows.transferInCount  = 2;
```

```cpp
socket.SendTransfer(1, addr, payload.data(), payload.size());
```

The receiver hears about the offer as an event and answers with memory or
with a refusal, and answering from inside the handler is legal:

```cpp
void OnTransfer(void* context, const flux::EventInfo& info)
{
    if (!info.Has(flux::SocketEvent::TRANSFER_INCOMING)) return;
    flux::TransferRequest request = socket.PendingTransfer(info.Flow(), info.Peer());
    buffer.resize(request.Length());
    request.Allow(buffer.data());          // or request.Reject()
}
```

Completion surfaces on both ends through `PollTransfers`, as a view naming
the buffer, the length and the outcome:

```cpp
flux::TransferView done[4];
for (size_t i = 0, n = socket.PollTransfers(done, 4); i < n; ++i)
    socket.CompleteTransfer(done[i].Flow(), done[i].Peer());
```

`TransferProgress` reports how far along a running transfer is, and a
transfer shares the peer's congestion state with every flow beside it, so
the two never fight over one link.

### Authenticated and plaintext sends

`Send` is best-effort: encrypted always, authenticated when the peer is.
`SendSecured` refuses any peer not authenticated against a pinned certificate,
loaded with `socket.LoadCertificate(cert)`. `Unsecured` is the explicit opt-out
that skips encryption entirely.

```cpp
socket.BuildPacket().NoFlow().PutBytes(msg, len).SendSecured(addr);
socket.BuildPacket().Unsecured().NoFlow().PutBytes(msg, len).Send(addr);
```

Authentication runs one way: only the side that dialled out learns the peer's
tag, so a server can never authenticate a client through the handshake, and
`SendSecured` toward one always refuses. Authenticate clients at the
application level. `RemoveCertificate(tag)` revokes a tag at runtime, and every
later check against it fails hard.

### First contact with data

Carrying data in the first packet needs three things at `Init`: this socket's
own identity, a store to keep the other side's certificate in, and the switch.

```cpp
config.identity         = &identity;   // flux::Identity::Generate(tag).Take()
config.trustedCertCount = 4;
config.knock.enable     = true;
```

Then load the certificate of whoever you are about to talk to, name it at the
address, and send:

```cpp
socket.LoadCertificate(serverCert);
socket.Connect(addr, serverCert.identityTag);

const uint32_t room = socket.MaxPayload(addr);   // 968 while the first packet opens
socket.BuildPacket().NoFlow().PutBytes(msg, len).Send(addr);
```

That send leaves immediately carrying the payload, and the handshake follows
behind it. Without the `Connect` call, or with knocking off, the same send
takes the plain handshake and the message waits.

On the receiving side, first-flight messages are marked:

```cpp
const flux::PacketSlot* packet = cursor.Packet().Read();
if (packet && packet->IsKnock())
{
    // replayable, so idempotent work only
}
```

### Resume after a restart

Once a session confirms, each side seals a note for the other and raises
`RESUME_NOTE_RECEIVED`. Ask for the bytes and persist them:

```cpp
config.keepResumeNotes = true;                 // off by default

uint8_t note[flux::Socket::RESUME_NOTE_BYTES];
const uint32_t len = socket.ResumeNoteFor(addr, note, sizeof(note));
```

Nothing secret is in a note. Hand it back after a restart:

```cpp
socket.Connect(addr, serverCert.identityTag, note, len);
```

The next send carries it in the first packet and the session comes back,
authenticated, with no handshake. A stale or revoked note just leaves an
ordinary first contact. Notes last 48 hours by default.

### Rotate an identity

`RotateIdentity` replaces the keypair a socket proves its tag with. The tag
does not change, so running sessions and every peer relationship carry on
untouched.

```cpp
config.identityHistory = 2;      // previous keypairs kept openable

const flux::Identity next = flux::Identity::Generate(socket.IdentityTag()).Take();
socket.RotateIdentity(next);
```

A first flight aimed at a retained key still opens, so a sender one rotation
behind still gets through. `PEER_STALE_IDENTITY` and `PEER_CERT_MISMATCH`
report the two ends of that, and the mismatch is a sender's cue to fetch a
fresh certificate. `ForgetPreviousIdentities` wipes the retained secrets at
once, for a leaked key.

## C API

The C API is one shared library, `flux_c.dll` on Windows, `libflux_c.dylib`
on macOS, `libflux_c.so` on Linux, and one header,
[flux_api_v1.h](flux/include/flux/c/flux_api_v1.h). The library exports a
single function:

```c
const void* flux_get_api(uint32_t version);
```

Call it with the version you were written against and cast the result to that
version's table, a struct holding `version` and one function pointer per
operation. Every flux call is an entry in that table, and everything a socket
hands out, peers, flows, packets, is a plain 64-bit number, so a stale number
gets an error code back and never touches freed memory.

Loading it from C#:

```csharp
[DllImport("flux_c")]
static extern unsafe FluxApiV1* flux_get_api(uint version);

struct FluxSocket { }   // opaque, only ever behind a pointer

[StructLayout(LayoutKind.Sequential)]
unsafe struct FluxApiV1
{
    public uint version;
    public delegate* unmanaged[Cdecl]<FluxLayout*, void> LayoutCheck;
    public delegate* unmanaged[Cdecl]<FluxConfig*, void> DefaultConfig;
    public delegate* unmanaged[Cdecl]<FluxSocket*> CreateSocket;
    public delegate* unmanaged[Cdecl]<FluxSocket*, FluxConfig*, int> InitSocket;
    // ... one field per entry, in the header's order
}
```

```csharp
unsafe
{
    FluxApiV1* api = flux_get_api(1);

    FluxConfig config = default;
    api->DefaultConfig(&config);
    config.port = 9500;

    FluxSocket* socket = api->CreateSocket();
    api->InitSocket(socket, &config);
}
```

The structs are retyped by hand, so call `LayoutCheck` once at startup and
refuse to run on any disagreement. That turns a field out of place from
silent corruption into a message. The header carries the full contract,
including the threading rules and the lifetime of every number.

## Architecture

A session belongs to the peer, not its address. When a peer moves (NAT rebind,
VPN reconnect, network handoff) the session continues with no re-handshake:
secure packets carry a small rotating tag both ends derive from the session
key, so a mover is recognised without any exchange. Rotating it unlinks a
deliberate address change from everything sent before. Peers are named by
`blake2b(publicKey)`, so proving the key proves the name and no registry is
involved.

Congestion control reads delay as well as loss, so its resting state is a short
queue. When a neighbour keeps the queue full anyway, Flux notices it is being
starved and stops treating that queue as its own. So it holds its share beside
BBR and leaves CUBIC the larger half almost without a drop.

Packets are little-endian and capped at 1200 bytes, under the IPv6 minimum MTU
with margin for tunnels. Every secure packet is sealed with XChaCha20-Poly1305,
and the nonce counter is masked so an observer cannot follow a peer by watching
a serial number climb. Control packets are indistinguishable from data on the
wire.

The full layout is in [ARCHITECTURE.md](ARCHITECTURE.md): the entities, the
ownership rules, the wire format, and the sanctioned number of ways to perform
each operation.

## Benchmarks

Every number below comes from a bench that ships in this repo, and each
command sits above the table it produced on this machine (Apple M3 Max,
Release, clang 22). Absolute times are machine-specific, the deltas and the
shares are the signal. Build Release first:

```sh
cmake -S . -B build-rel -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-rel
```

`ctest --test-dir build-rel -L bench` runs the whole set. Benches print
numbers and always exit 0.

Every bench builds from this repo alone except one. The sharing bench races
Flux against QUIC, and msquic is not vendored here, so it has to be installed
before that bench exists. See [Sharing one queue with QUIC](#sharing-one-queue-with-quic).

### Send path

Flux against the bare `sendto()` syscall underneath it, median of 30,000
sends per variant, interleaved so all three see the same machine state:

```sh
./build-rel/socket_send_bench
```

| payload | bare `sendto` | + Flux framing | + AEAD seal |
|---|---|---|---|
| 64 B | 2708 ns | +208 ns | +958 ns |
| 1024 B | 2667 ns | +292 ns | +2958 ns |

Framing adds a couple hundred nanoseconds over the raw syscall. Everything else
is the encryption, which scales with payload and is the same cost any encrypted
transport pays.

### Encryption

XChaCha20-Poly1305 through vendored Monocypher, no sockets involved:

```sh
./build-rel/crypto_bench
```

| payload | encrypt | decrypt + verify |
|---|---|---|
| 64 B | 372 ns | 352 ns |
| 256 B | 661 ns | 668 ns |
| 1200 B | 2254 ns | 2252 ns |

Monocypher is portable C with no SIMD, so encryption tops out around
0.5 GB/s. A SIMD implementation would raise that if it ever matters.

### A transfer across a lossy link

An in-process relay models 50 Mbit with a 40 ms round trip and a 250 KB
tail-drop queue, one bandwidth-delay product. One 100 MiB transfer crosses it
per row. Independent loss matches thermal noise, and the burst rows lose
everything for stretches averaging twenty packets, the shape a fade or a
handover produces, and the shape that defeats recovery tuned for independent
loss alone. The floor at the link rate is 16.8 s.

```sh
./build-rel/link_transfer_bench
```

| loss | time | rate | of the link |
|---|---|---|---|
| clean | 17.5 s | 48.1 Mbit | 96% |
| 1% independent | 18.5 s | 45.3 Mbit | 91% |
| 2% independent | 19.1 s | 43.8 Mbit | 88% |
| 5% independent | 19.9 s | 42.1 Mbit | 84% |
| 1% bursts of 20 | 18.8 s | 44.7 Mbit | 89% |
| 2% bursts of 20 | 26.1 s | 32.1 Mbit | 64% |
| 5% bursts of 20 | 60.4 s | 13.9 Mbit | 28% |

The acknowledgement names every hole in the window, so repair keeps pace with a
loss rate the congestion controller attributes to the link. Burst rows move a
few seconds between runs, since where a burst lands against the window decides
how much serialises behind repair. A first argument changes the payload and a
second filters the rows, so `link_transfer_bench 200 independent` runs the
three independent rows at 200 MiB.

### One gigabyte at line rate

```sh
./build-rel/link_transfer_bench 1024 clean
```

| payload | time | rate | of the link |
|---|---|---|---|
| 1 GiB | 177.3 s | 48.5 Mbit | 97% |

The floor is 171.8 s. The same payload through msquic BBR on the same link
model measured 255.7 s at 33.6 Mbit, a third slower on a clean link.

### Sharing one queue with QUIC

Both senders move 100 MiB through ONE shared tail-drop queue, started together,
so they interact: whoever keeps more in flight occupies more of the queue and
pushes the other toward the drop tail.

This is the one bench with an outside dependency. msquic is not vendored,
because it is a large production stack with its own build and its own release
cadence, and pinning a copy here would mean maintaining it. Install it first
and reconfigure:

```sh
# macOS
brew install libmsquic

# Debian and Ubuntu, from Microsoft's package feed
curl -sSL https://packages.microsoft.com/keys/microsoft.asc \
  | sudo tee /etc/apt/trusted.gpg.d/microsoft.asc >/dev/null
sudo apt-add-repository https://packages.microsoft.com/ubuntu/$(lsb_release -rs)/prod
sudo apt update && sudo apt install libmsquic

# Windows, or anywhere the above does not reach
# build from source: https://github.com/microsoft/msquic
```

```sh
cmake -S . -B build-rel -G Ninja -DCMAKE_BUILD_TYPE=Release
```

CMake looks for msquic at configure time and prints which way it went. Without
it every other bench still builds and runs, and only this one is absent, so
missing it costs you one table.

The numbers below came from msquic 2.5.9.

```sh
./build-rel/link_share_bench bbr
```

| sender | time | goodput | share while contended |
|---|---|---|---|
| Flux transfer | 45.0 s | 18.7 Mbit | 42.5% |
| QUIC BBR | 45.2 s | 18.6 Mbit | 57.5% |

Jain 0.978, 34 ms standing queue, heavy drops on both sides.

```sh
./build-rel/link_share_bench cubic
```

| sender | time | goodput | share while contended |
|---|---|---|---|
| Flux transfer | 34.6 s | 24.2 Mbit | 45.8% |
| QUIC CUBIC | 31.3 s | 26.8 Mbit | 54.2% |

Jain 0.993, and 421 drops in total against the BBR pairing's quarter
million: beside a loss-sensitive neighbour Flux backs off before the queue
overflows, and both finish sooner than either does beside BBR. For scale,
msquic BBR beside msquic CUBIC on this link measured 64/36: BBR takes more
from CUBIC by force than Flux takes from anyone.

## Testing

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

Disable sanitizers with `-DBCP_SANITIZE=""`. Some toolchains, Apple's Command
Line Tools clang among them, ship a broken ASan/TSan runtime. The build probes
for that at configure time and falls back to UBSan only, so the binaries still
start.

### Layout

```
flux/      include/ + src/     the transport
tests/     unit/ integration/ bench/ + shared harnesses
examples/  runnable programs written against the public API
external/  common/             standalone systems library, vendored, own tests
           monocypher/         vendored crypto (BSD-2-Clause OR CC0-1.0)
```

### Examples

One file each, running several sockets in one process, built with everything
else:

```sh
./build/send_and_respond          # A sends, B answers
./build/respond                   # B answers through the packet itself, no address named
./build/simultaneous_handshake    # both send first, the handshake collision resolves itself
./build/reliable_flow             # one RELIABLE_ORDERED flow, numbered burst to two peers
./build/unreliable_flow           # the same burst on an UNRELIABLE flow
./build/events                    # told what happened instead of asking every tick
./build/mac_only                  # readable on the wire, not alterable
./build/unsecured                 # the cheapest packet Flux sends
./build/big_message               # a message bigger than a packet, as a run on one flow
./build/bulk_transfer             # something large, chunked by hand over a bulk flow
./build/transfer_flow             # the same job handed over as one transfer, no chunking
```

## Roadmap

Not there yet: path MTU discovery and NAT traversal.

The wire format is not frozen before 1.0. It can change between versions, and a
security fix is allowed to change it.

Released versions are recorded in [CHANGELOG.md](CHANGELOG.md).

## Contributing

Contributions are welcome under the Apache License 2.0. There is no CLA and no
copyright assignment, only a Developer Certificate of Origin sign-off (`git
commit -s`). Everything must build and test on Windows, Linux, and macOS from
the same `CMakeLists.txt`, and a change is not done until its tests run clean
under sanitizers. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities privately through GitHub's "Report a vulnerability"
button or the email in [SECURITY.md](SECURITY.md), not through a public issue.
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) covers conduct in the project's spaces.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Flux and `common` stay Apache-2.0. Binarii Games sells products built on these
libraries. A paid tier means extra code in that tier, not features taken out of
here. Contributions stay yours. There is no CLA and no copyright assignment,
only a DCO sign-off.
