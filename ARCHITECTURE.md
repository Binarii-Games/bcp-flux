# Architecture

## Overview

Flux is a connectionless, encrypted UDP transport. It builds on `common`, a
standalone systems library vendored in `external/common` and developed on its
own.

This document describes each library's structure: its entities, its ownership
graph, and the number of sanctioned ways to perform each core operation. Where
a count appears below it is the whole count, and a path not described here does
not exist.

At the top sits the one entity the application holds, `flux::Socket`. It owns the
tables that carry protocol state and a platform backend that does the sending and
receiving:

```
application
    |
flux::Socket
    |  owns
    +-- FlowTable      flows, associations, retained reliable bodies
    +-- PeerTable      peers, keyed by address, id and migration tag
    +-- TransferTable  whole-buffer transfers in flight
    +-- CertStore      pinned certificates
    +-- ISocketKernel  the per-OS UDP backend
    |
operating system UDP
```

For how to build and test, see [README.md](README.md). For the conventions a
change is held to, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Table of contents

- [Goals and non-goals](#goals-and-non-goals)
- [The library set](#the-library-set)
- [The common library](#the-common-library)
- [The flux library](#the-flux-library)
  - [Entities](#entities)
  - [Memory: the pools](#memory-the-pools)
  - [Ownership: the handles](#ownership-the-handles)
  - [Concurrency](#concurrency)
  - [Wire format](#wire-format)
  - [Source layout](#source-layout)
  - [Operation paths](#operation-paths)
  - [Lifecycles](#lifecycles)
  - [Platform backends](#platform-backends)

## Goals and non-goals

Flux is a general-purpose transport in the same class as QUIC. What it commits to:

- Connectionless with a handshake. There is no connection object, and the first
  packet to a new address carries the session up underneath the send.
- No heap allocation on the packet path. Every buffer is pooled and sized at
  `Init`, so behaviour under load is deterministic and no allocator sits on a hot
  path.
- Mixed reliability on one socket. Reliable ordered, reliable unordered,
  unreliable, and bulk flows run side by side, and a whole-buffer transfer runs
  beside them.
- A session that follows the peer rather than its address, so a NAT rebind or a
  VPN reconnect continues with no re-handshake, and nothing on the wire relinks
  the peer across the change.
- Encryption by default, with the same framing whether a packet is encrypted,
  authenticated only, or plaintext.
- The same source building and running on Windows, Linux, and macOS, on x86-64
  and arm64.
- A C API, so a binding in another language can drive the transport.

What it leaves to someone else:

- Naming, routing, and service discovery. Flux knows peers, addresses, and
  endpoints. It has no concept of a node, a route, or a service name, and a layer
  above supplies those.
- The run loop. Flux owns no thread. The application calls `Update`, `Poll`, and
  `Flush` on whatever threads and cadence it chooses.
- Certificate policy. Flux stores an opaque identity tag and proves possession of
  the matching key. It never parses the tag, and where trust comes from is the
  caller's decision.
- A frozen wire format. Before 1.0 the format and the API can change between
  versions.

## The library set

| Library | Namespace | What it is | Depends on |
|---|---|---|---|
| `common` | `bcp::common` | general-purpose systems primitives | monocypher (vendored) |
| `flux` | `bcp::flux` | the transport | `common` |

```
flux  --depends on--->  common  --depends on--->  monocypher
                        (vendored)                (vendored)
```

A library may depend on another library in the set. It may never depend on a
consumer of itself, and it may never carry a concept that only makes sense to
one of its consumers. A type that only makes sense to a transport belongs in
`flux`.

`common` is meant to carry nothing that only makes sense to a transport, and
three places currently break that: the error enum names transport conditions,
`platform.h` pulls in the OS socket headers, and `BytesWriter` carries a pointer
to a packet length field. They are listed here rather than quietly excepted,
because a rule with unlisted exceptions is not a rule. Those exceptions are the
whole list, and nothing new joins it.

### Conventions every library obeys

- No exceptions. A function that yields no value returns `common::Error`, and
  one that yields a value and a status returns `common::Result<T>`. Anything
  that must be checked is `[[nodiscard]]`.
- Two-phase initialisation: a default constructor, then `Init(...)` returning
  `Error`.
- `Shutdown()` and `Close()` are idempotent, destructors call them, and handles
  are invalidated after cleanup.
- Allocation happens in `Init` and nowhere else. In `flux` that covers
  everything between socket receive and the handler callback.
- Fixed-width integer types for anything on a wire, any size, and any count.
  `enum class` with an explicit underlying type.
- Ownership is explicit and in the type system: one owner per resource, RAII
  release on the destructor edge, move-only where ownership is unique, a
  moved-from object left unusable.

## The common library

- **Error and result.** `Error` is an `enum class : uint8_t`, codes grouped by
  numeric range, every code mapped by `ErrorToString`. `Result<T>` pairs an
  `Error` with a value. Callers check `isErr()` before `Take()`.
- **Platform.** `CACHE_LINE` (128 on arm64, 64 elsewhere), `CpuPause()`,
  `MonotonicMicros()`, which is meaningful only as a difference between two
  calls, and `WallClockSeconds()`, which survives reboots and can jump when
  the host clock is adjusted, so it serves coarse validity windows and never
  timeouts or measurement.
- **Collections.** Two structures, and they are the whole set. `SlotPool` is an
  index free-list over one contiguous block plus a per-slot reader/writer lock.
  The free-list is lock-free; the per-slot lock is a blocking spin with no try
  variant and no timeout, so a caller that takes one cannot decline to wait. The free-list is sharded across up to sixteen rings so
  concurrent acquires and releases spread over independent cache lines. Slots
  are fixed-stride and never move, so an index is a stable name for a piece of
  memory. The pool runs no constructors and zeroes only at `Init`, so anything
  stored in one is trivially copyable and whoever leases a slot writes every
  field. `FifoQueue<T>` is a lock-free bounded MPMC queue.
- **Byte cursors.** `BytesWriter` and `BytesReader` are the sanctioned way to
  move a multi-byte value into or out of a buffer. Both bounds-check every
  access, and both encode little-endian by explicit shift, which is what makes
  the encoding independent of host byte order. Never `memcpy` a scalar through
  these buffers, and never overlay a struct on them.
- **Crypto.** X25519 keypairs and Diffie-Hellman, a blake2b KDF and keyed MAC,
  XChaCha20-Poly1305 AEAD, ids as `blake2b(pubkey)`, constant-time comparison,
  secure wipe, and `RandomBytes` over the platform RNG. Every function a caller
  uses is inline in the header, so monocypher and `bcrypt` propagate as `PUBLIC`
  link dependencies.
- **Log.** All diagnostics go through `Log` and `LogF`. The callback type is
  declared but nothing installs one, so today both write to stdout under a mutex.
  Never `printf` directly, never iostreams.

## The flux library

A transport protocol: connectionless with a handshake, zero-allocation on the
packet path, encrypted, endianness-explicit, with mixed-reliability flows and
address migration.

Its entities are peers and sockets. There is no concept of a node, a route, or
a service name, and naming and routing belong to a layer above. The one
exception is `Address::From`, which will resolve a hostname through the
platform's `getaddrinfo` as a convenience for callers that have a name rather
than a literal. That call blocks and allocates, so it belongs to setup and never
to a packet path.

`Socket` also owns five smaller pieces the sections below refer to without
introducing: `SocketListener` and `SocketSender`, thin wrappers over the kernel's
receive and send; `ChallengeGenerator`, the stateless handshake cookie source;
`IdentityTable`, the keypairs this socket answers on; and `ReplayWindow`, one
per peer slot.

| Sub-namespace | Holds |
|---|---|
| `bcp::flux` | `Socket`, `FlowTable`, `Peer`, `PeerTable`, flows, handles |
| `bcp::flux::internal` | wire constants, not public API |
| `bcp::flux::wire` | `PacketBuilder` and its stages |
| `bcp::flux::platform` | per-OS `ISocketKernel` backends |
| `bcp::flux::pending` | the parked-behind-handshake packet list |

### Entities

#### Peer

A remote endpoint this socket has spoken to, living in a `SlotPool` slot inside
`PeerTable`. It holds the session key, the send counter, migration tag state,
handshake progress, liveness stamps, per-peer congestion state, and the head
and tail of its parked-packet list.

Identity comes in three forms, and they are not interchangeable:

- `Address` is a hashable wrapper over `sockaddr_storage`. Where the peer is
  at the moment, and it changes on migration.
- `BcpId` is `blake2b(publicKey)`, derived at handshake and bound to the peer.
  Either side recomputes it from a presented key and checks the peer owns what
  it claims, with no registry involved. It follows the key rather than the
  address, so it is the lookup that survives migration. Its lifetime follows
  the keypair: a socket given an identity in `Config` keeps the same id across
  runs, and one that generates its own keeps it only for that process.
- `PeerTag` is a rotating 4-byte value carried on secure packets, derived
  identically at both ends from the session key and never exchanged. It is the
  migration handle, an address-independent way to recognise a connection whose
  address just changed. All-zero is reserved as the empty marker.

#### Flow and association

A flow is a unidirectional numbered channel, in one of four modes:

| Mode | Retransmit | Delivery | Window |
|---|---|---|---|
| `RELIABLE_ORDERED` | yes | in sequence | 256 |
| `RELIABLE_UNORDERED` | yes | on arrival | 256 |
| `UNRELIABLE` | no | newest only | 256 |
| `RELIABLE_ORDERED_BULK` | yes | in sequence | 1024 |

Every flow packet is numbered and acknowledged whatever the mode, so loss is
observed and feeds congestion control even when nothing is resent. `UNRELIABLE`
drops a packet older than the newest it has delivered, still acknowledged, so
the sender resolves it without waiting out a timeout.

`Flow` is socket-wide, holds no address, and carries id, mode, the encoded wire
byte, and a lifecycle the application controls. Sending on it to an address
creates the per-target state, the association, on first use.

`OutAssociation` is the sending half, one per (flow, target). It holds the peer
identity, the flow link, the sequence, the round-trip estimate, the in-flight
ring (retransmit sources, indexed `seq & (cap-1)`), and the waiting ring (a
strict FIFO of accepted-but-not-yet-admitted sends). `InAssociation` is the
receiving half, built from the first packet to arrive on a remote's flow, and
holds the delivery cursors, the seen bitmap, and the reorder hold-back ring. It
is an order of magnitude smaller, because this is the side a remote can make
this socket allocate. The two live in separate pools, so a hostile peer opening
flows exhausts only the in-association pool, never this socket's capacity to
open its own.

Each association slot is larger than its struct, with its rings following
inline. Caps are powers of two fixed at `Init` and stamped into the slot, so a
slot describes its own layout:

```
[OutAssociation][InFlightEntry × inflightCap][WaitingEntry × waitingCap][open batch]
[InAssociation ][seen bitmap               ][HoldbackEntry × reorderCap]
```

The open batch is the packet a sending association is filling, sized for the
largest one this socket would put on the wire. It is inline rather than a
pooled slot so that the association's own lock covers it: finding a pooled slot
would mean taking the association lock and then the slot's, which is the
reverse of the order the send path takes everywhere else.

#### Transfer

A transfer moves one run of bytes whose length is agreed up front, between two
buffers the application owns. The sender hands `SendTransfer` a pointer and a
length and keeps the memory alive until the outcome comes back. The receiver
learns of the offer through the `TRANSFER_INCOMING` event and answers it with
`Allow` and a buffer of the announced size, or with `Reject`. Packet `s`
belongs at offset `s * stride` and nowhere else, so the interesting work is
arithmetic rather than buffering: nothing is staged per packet, a retransmit
is re-read from the sender's buffer, and delivery writes straight into the
receiver's. That destination is memory the library does not own, which is why
every bound a sender could influence is checked rather than trusted.

A transfer and a bulk flow answer different jobs. A flow carries a stream of
messages that each need framing and delivery as they arrive, and it retains a
staging copy of every reliable body. A transfer carries one known-length run
whose only deliverable is the completed buffer, so it can skip the copies and
the per-message framing entirely.

`OutTransfer` and `InTransfer` are the two halves, in their own pools inside
`TransferTable`, with their window rings (send stamps, acknowledgement bitmap,
resend marks, placement bitmap) in table-owned blocks beside them. The
tracking is window sized rather than transfer sized, so a gigabyte and a
kilobyte need the same state. The window bounds the sequence span above the
progress cursor rather than the count in flight, because the rings index by
`seq & (window - 1)` and a sequence a whole window past the cursor would land
on a live entry belonging to an older one.

A transfer spends the same per-peer congestion budget the flows do, through
the same controller, because everything sent to one peer crosses one link.

#### PacketSlot

A packet as it sits in a pool slot: an address, a size, and the raw wire bytes
as a flexible array. Packet bodies are never copied between slots. They are
written in place and passed by handle.

#### Certificate

A long-term public key pinned to an opaque 32-byte identity tag. A certificate
is trusted because of how it was delivered (embedded in a client, provisioned,
loaded from config), and the handshake proves the peer owns the matching
secret, so no signature is carried. Flux never parses an identity tag. It
stores it, matches it, and surfaces it to the layer above.

#### Identity

The keypair a socket proves its own tag with, and the ones it proved it with
before. The tag is the durable half and never moves: a rotation replaces the
key that currently proves it, so peer relationships survive one and only the
proof is new. A socket that never rotates holds exactly one keypair, which is
what every socket held before rotation existed.

Each keypair is named by a four-byte id derived from its public half, so a
first-flight opener can say which key it was encrypted toward. Anyone holding
the certificate can compute that id, which is exactly who needs to, and it
says nothing about how often the socket rotates because it comes from the key
rather than from a counter.

### Memory: the pools

Nothing on the packet path allocates. There are thirteen pools, each with one
owner:

| Pool | Owner | Holds |
|---|---|---|
| recv | `ISocketKernel` | inbound packets |
| send | `ISocketKernel` | outbound packets |
| pending | `Socket` | packets parked behind an unfinished handshake |
| staging | `FlowTable` | retained reliable bodies, held until the receiver's cursor passes |
| flow | `FlowTable` | `Flow` slots, one per open flow |
| out-association | `FlowTable` | `OutAssociation` slots, standard window |
| out-association, bulk | `FlowTable` | `OutAssociation` slots, deep window |
| in-association | `FlowTable` | `InAssociation` slots, standard window |
| in-association, bulk | `FlowTable` | `InAssociation` slots, deep window |
| out-transfer | `TransferTable` | `OutTransfer` slots, window rings in table-owned blocks beside them |
| in-transfer | `TransferTable` | `InTransfer` slots, likewise |
| peer | `PeerTable` | `Peer` slots |
| certificate | `CertStore` | trusted `Certificate` slots |

Each association pool is really two, a standard one and a deep one for bulk,
behind a single index space. `SplitAssocPool` maps an index below the standard
capacity to the first and the rest into the second, so a slot index stays a
plain integer everywhere it is stored and the rest of the table never learns
there are two. A bulk association's rings are four times as deep, and this is
what stops an ordinary flow paying for that.

`Socket` owns the kernel and borrows its two pools as raw pointers, lending both
to `FlowTable` along with the delivery lanes. Every other pool is owned by
`Socket` or by the component it reaches through.

Four flat arrays are indexed by peer slot. Three of them are guarded by that
peer's slot lock: the replay window state, and the two flow directories
(`FlowDirEntry[]`, one per direction). The fourth is not, and that is the point
of it. `PeerRecvState[]` records how many receive slots a peer currently pins,
counting both packets held behind a gap and packets queued for delivery that
have not been polled, alongside the limit that peer was given. Both are written
where no peer lock is held, on the receive path and again when the application
polls, so both are atomics and every access is relaxed. Neither publishes
anything, they are only ever compared, so a reader may see a count stale by
however many pins and releases are in flight. That costs a packet either side of
a limit and can never over-allocate the pool, because the count decides policy
and never ownership.

Staging is sized apart from the kernel send pool so a
busy reliable flow can never starve handshakes, acks, or unreliable traffic of
send slots. Staging running dry is backpressure.

### Ownership: the handles

| Handle | Owns | Released by |
|---|---|---|
| `PacketSlotHandle` | a slot lease and its lock | destructor, returning the slot to the pool |
| `PeerHandle` | the slot's lock only | destructor, dropping the lock |
| `FlowHandle` | nothing, a `{slot, epoch, flowId, flowData}` key | nothing to release |
| `PollCursor` | the claim on the lane it drained | destructor, freeing the lane |

All four are move-only, and a moved-from handle is left unusable.

`PacketSlotHandle` is the unit of packet ownership. An invalid index yields a
failed handle whose `Read()` and `Write()` return `nullptr`. `Detach()` gives
up ownership and returns the bare index, which is how a reliable body outlives
the send that wrote it. `PacketSlotWriter` wraps a handle with a byte cursor.
`PacketSlotReader` borrows one instead of owning it, and walks the messages a
packet holds one at a time, so it has to be something the packet's owner
outlives.

`PollCursor` is what `Poll` returns. It borrows the array `Poll` filled and
drives one reader across every packet in it, which is what lets a caller read
one flat loop whether the messages arrived one per datagram or packed together.
It owns the claim on the lane it drained and frees that on destruction, which is
what keeps one thread the only reader of a peer's traffic for as long as the
caller is still reading.

`PeerHandle` arrives read-locked with the key verified under that lock.
`RemovePeer` frees a slot only after taking its write lock, so a peer is never
freed under a live handle.

`FlowHandle` holds no lock and keeps nothing alive. Every operation goes
through the socket and is checked against slot and epoch, so a handle that
outlives its flow misses cleanly. Only out-flows have one. The receiving half
of a remote's flow never surfaces to the application.

The lending rule: a handle is a held lock, and nothing may look up a resource
its caller already holds, because the second acquisition self-deadlocks the
moment either side wants to write. A function that needs a resource its caller
holds takes the handle, never an address or slot index:

- Lend (`PeerHandle&`) when the caller still needs the handle afterwards.
  `pending::Push` and `pending::PopFront` are the model.
- Transfer (`PeerHandle` by value) when the callee is the terminal user,
  typically because it must release the lock before ending in a send.
  `FlushPeerAcks` and `UpdateOutFlow` are the model.

### Concurrency

Flux owns no thread. Work happens on a caller's thread. Four entry points carry
the packet path and all of them are safe to call concurrently:

- `Poll` processes inbound packets and drains a lane of ready ones to the
  application.
- `Update` runs the tick: retry handshakes, flush owed acks, retransmit, drain
  waiting sends, evict idle peers, reclaim jammed receiving flows. All
  time-based work lives here. One pass runs at a time: while one is in flight,
  another caller returns immediately instead of running a second pass. The
  pass takes exclusive peer locks as it walks, so concurrent passes would
  serialize against each other and against the receive path, and a thread that
  skips one loses nothing it was not already getting.
- `Flush` puts part-filled batches on the wire, at most `MAX_FLUSH_PER_PEER`
  associations per peer per call, the rest riding the next one.
- Sending, through `PacketBuilder`.

The rest of the public surface is setup and inspection: `Init`, `Shutdown`,
`Connect`, `OpenFlow`, `CloseFlow`, `GetFlowState`, `GetPeer`, `RemovePeer`,
`RotateTags`, `RetryHandshakes`, `NextTimeout`, `LoadCertificate`,
`ReceivingFlowCount`, `BuildPacket`.

A send on a flow is packed into a batch and waits for `Flush`, so a caller
drives all three round its loop and nothing leaves without the last of them.
There is deliberately no automatic flush. One that fired sometimes would make
send timing unpredictable and would hide a forgotten call rather than surfacing
it, and the moment bytes go out is the caller's to choose.

Flow state lives in `FlowTable`, which owns the flow, association and staging
pools and every algorithm that reads only those: sequence numbering, the send
gate, the waiting ring, the seen bitmap, ack ranges, reorder hold-back and
retransmit selection. It never acquires a peer, never touches the kernel and
never encrypts. A peer reaches it only as a reference the socket already
locked, so the ordering below is a property of the split rather than a rule to
remember: a class with no way to reach a peer cannot lock one out of order.

Lock order: packet slot, then peer, then flow. Within the flow level, a flow is
taken before an association, which is how a flow reaches its association list. The wire send happens with
nothing held, so every locked scope gathers what the send needs
(`PeerSendMaterials`), closes, and the packet is sealed and sent afterwards. A
peer lock is never held across a `SendTo` syscall or anything that takes a
staging lock.

`PeerTable` and `CertStore` share one design: entries in a `SlotPool`, Robin
Hood open-addressed indexes mapping keys to slots, removal by backward-shift on the peer side only so
probe distance stays bounded. One table-wide seqlock (`version_`) covers the
indexes. A writer holds it odd across any mutation, a reader validates its
whole probe against it and retries if the version moved, and writers serialize
on a single write lock. Readers never store to the index, so lookups scale
across cores, and a matched slot's key is verified under its read lock, except on the tag index, which verifies none, so a
hash collision never resolves to the wrong peer.

Do not call a table operation while holding a handle from that table. Writers
wait on slot locks, and a handle holder calling back in closes a cycle.
Changes here are validated under ThreadSanitizer. A green suite alone says
nothing about race-freedom.

### Wire format

Little-endian, every multi-byte access through `common`'s byte cursors.
(`htons` in `address.h` is for OS `sockaddr` structures, a separate concern.)
Two layouts, split by the `UNSECURE` bit of the leading controller byte. A `?`
marks a conditional field, and everything after the `‖` is ciphertext:

```
secure    [Controller(1)][NonceCounter(8)][PeerTag(4)]? ‖ [Channel(1)]([FlowId(2)][FlowSeq(4)][FlowData(1)])?[content] [Tag(16)]
unsecured [Controller(1)][content]
```

| Field | Bytes | Present | What it is |
|---|---|---|---|
| Controller | 1 | always | six independent bit flags, listed below |
| NonceCounter | 8 | secure | the sender's counter, masked, the wire half of the nonce |
| PeerTag | 4 | secure, `TAGGED` set | the migration tag |
| Channel | 1 | secure, inside the seal | 0 for application data, otherwise an internal control op |
| FlowId | 2 | `HAS_FLOW` set | the sender's flow id |
| FlowSeq | 4 | `HAS_FLOW` set | the packet's sequence on that flow, starting at 1 |
| FlowData | 1 | `HAS_FLOW` set | mode in bits 0-2, epoch in bits 3-5, more-follows in bit 6, continues in bit 7 |
| content | rest | always | one message, or a list of them when `BATCH` is set |
| Tag | 16 | secure | the AEAD authentication tag, after the content rather than before it |

The tag sits at the end so that everything it covers is one unbroken run of
bytes rather than pieces on either side of it.

Content is one message filling it, or, when `CTRL_BATCH` is set, a list of
messages each behind a two-byte little-endian length. The first message in a
list carries no length of its own, so a packet holding a single message is
byte-identical to an unbatched one and a caller sending one message at a time
pays nothing. The lengths must account for the content exactly, and a chain that
overruns or leaves a tail is refused whole.

The controller bits: `CTRL_INTERNAL` marks session-opening traffic, which is
consumed rather than delivered in every case but one. The knock is the
exception: it opens a session and carries application data in the same packet,
so it is consumed as an opener and what it carried is delivered. `CTRL_HAS_FLOW` says the flow header sits inside the seal.
`CTRL_UNSECURE` marks the plaintext opt-out, which carries no tag, no nonce,
and no integrity. `CTRL_TAGGED` says the peer tag follows the nonce.
`CTRL_MACONLY` marks a packet authenticated but not encrypted, framed exactly
like an encrypted one so every offset is identical and only the transform
differs. `CTRL_BATCH` says the content is that list. The controller byte and
peer tag are authenticated associated data: readable on the wire, not
alterable.

The nonce counter must travel, but in the clear it is a serial number that
would link a peer across a migration. So the field carries the counter XORed
with a mask derived from a per-peer header key and this packet's own AEAD tag,
unique per packet. Both ends recompute it, and an observer sees eight bytes
that never form a sequence.

The channel byte sits inside the seal, so the receiver learns whether it holds
control or data only after a successful decrypt. The cleartext `CTRL_HAS_FLOW`
bit still says whether a packet carries a flow, which packet size gives away
anyway.

Handshake packets are the only cleartext opcodes (`HS_INIT`, `HS_CHLG`,
`HS_RES`, `HS_FINISH`), carried on unsecured internal packets because no key
exists yet.

Most wire constants are named in `flux/internal/constants.h`. The exceptions
live where the thing they describe is decoded: the flow framing bits and the
epoch width in `flow.h`, and the controller bits in `socket.h`. `CTRL_BATCH` is
the one controller bit taking its value from `constants.h`, because the batch
packer sets it and has no business reaching into the socket's headers.

### Source layout

Six pieces sit in their own files rather than inside `Socket` or `FlowTable`,
because each is one job and neither of those is:

| File | Holds |
|---|---|
| `crypto/packet_seal.cpp` | one seal and one open per framing, at whichever security level the caller picked, and nothing that reaches a peer, a flow or a pool |
| `flow/flow_batching.cpp` | the open batch on a sending association: what may join it and what its bytes cost |
| `flow/assoc_directory.cpp` | flow id to slot index, per peer, per direction |
| `peer/congestion.cpp` | the budget, loss and delay signals both, which belongs to the peer and not to any one flow |
| `internal/congestion_curve.h` | the growth arithmetic that policy consults: the queue a path tolerates, CUBIC's window over time, the straight line under it |
| `transfer/transfer_table.cpp` | every transfer this socket runs: the window rings, the placement arithmetic, the overdue scan |
| `socket/socket_transfer.cpp` | the transfer entry points and the tick's transfer pass, which reach most of the socket's sending machinery but none of the flow tables |
| `socket/socket_knock.cpp` | the first-flight opener: arming a window, the receiver pipeline, and the caps that bound what an unproven peer costs |
| `crypto/identity_table.cpp` | the keypairs this socket answers on, and the lock that lets one be replaced under live traffic |

The split is by job, not by size. The handshake and the migration receive path
are both larger than any of these and both stay where they are: each reaches
most of `Socket`, so moving either would trade one large file for a large file
plus a wide interface.

### Operation paths

#### Reaching a peer: four keys, one sweep, one raw index

| Route | Call | When |
|---|---|---|
| by address | `PeerTable::GetPeer(const Address&)` | the ordinary receive and send path |
| by id | `PeerTable::GetPeer(const BcpId&)` | after a peer proves an id, survives migration |
| by tag | `PeerTable::GetPeersByTag(...)` | migration only, multi-valued |

A fourth exists for naming a peer outside this library, where an address is
too large to hand over and a bare slot index is unsafe: `GetPeer(slot,
generation)`, which proves the slot has not been recycled since the pair was
handed out. The C API is its only caller.

All four return a read-locked `PeerHandle`. The tag route is multi-valued
because one peer holds several tags at once (its rotation window, capped at
`MAX_TAGS_PER_PEER`) and two peers may derive the same tag by chance. A clash
resolves by trial decryption.

Two further routes yield no handle at all. `CollectAddresses` copies out
every live address so the tick and `Flush` can walk peers without holding the
table, and it takes the writer lock, which is the opposite profile from the three
lookups above. And a bare slot index, handed out by `RegisterPeer`, is what the
handshake carries between its steps: every binding call (`BindId`, `BindTag`,
`UnbindTags`, `UpdateAddress`) is keyed on that index rather than on a handle.
Reads go through a verified key; those mutations do not.

#### Opening a session: two triggers, one handshake, one resume

| Trigger | When | What it carries |
|---|---|---|
| `HS_INIT` | nothing is known about the target | nothing, it only asks to be challenged |
| `HS_KNOCK` | a certificate is named for the target | an interim key and application data |
| `HS_KNOCK` with a resume note | a note that target issued before is presented | the above, and proof of a prior session |

The first two end in the same place: the receiver answers with the ordinary
stateless challenge, and the `HS_CHLG` / `HS_RES` / `HS_FINISH` exchange that
follows is one path with no knowledge of which trigger started it. The cookie
echo in `HS_RES` proves the address either way, and the session it derives is
the same session. There is no second handshake and no second way to prove an
address.

The third runs none of that. Opening the packet proves the sender holds the key
it presents, and the note proves that key held a session with this socket, so
between them they have already established what the exchange would have. The
peer is installed confirmed, with whatever authentication the trust store gives
its tag now, and no challenge is sent because nothing is owed. A note that will
not open leaves an ordinary first contact behind it, so the path is additive:
nothing that worked before behaves differently.

A returning peer usually arrives holding a stale entry from the session it
lost, which is why an opener whose stored keys cannot open it falls through to
the key agreement rather than being refused. That fall-through is what makes a
peer which has lost its keys recognisable at all.

#### Three security levels

A packet is encrypted, authenticated but readable, or neither. `PacketBuilder`
picks with `MacOnly()` and `Unsecured()`, and encrypted is the default. Mac-only
carries the same framing and the same tag as encrypted and costs roughly half the
crypto, for traffic that is public anyway and sent often. Unsecured carries no
tag at all and cannot carry a flow, because a forged packet could otherwise name
any sequence it liked.

The choice holds inside a first-flight opener as well. An opener carries the
level in its controller byte, so the two share every byte of framing and differ
only in the transform over the interior, the same relationship the two ordinary
seals have. An encrypted opener pads its interior to the full wire size, so no
observer learns how much rode the first flight. A mac-only one does not, since a
readable payload announces its own length and padding would buy nothing but
bandwidth. The level is visible either way, which costs nothing: a readable
payload is self-evidently readable.

#### Sending: two seals, seven origins

An outbound packet is sealed one of two ways. `SealSecurePacket` encrypts the
payload and covers it with a tag. `SealMacOnlyPacket` leaves the payload readable
and covers it with the same tag, for traffic that is public anyway and sent
often. Framing is identical either way, so every offset matches and only the
seal and the open differ. The receive side mirrors them with `OpenSecurePacket`
and `OpenMacOnlyPacket`.

Seven things originate a send:

1. Application, non-flow: `BuildPacket().NoFlow()...Send()` or `.SendSecured()`
2. Application, on a flow: `BuildPacket().WithFlow(flow)...Send()` or `.SendSecured()`
3. Handshake: `BuildInternal(op)`, unsecured because no key exists yet
4. Secure control: `SendSecureControl(...)`, wire-identical to data
5. Retransmit: `ResendStaging(...)` into `SealStagingToWire`
6. The waiting-ring drain: reliable entries go through `SealStagingToWire` like
   a retransmit, unreliable ones are sealed and sent where they sit, because
   nothing retains them and there is no staging copy to seal from
7. The tick's transfer pass: announcements, data and repairs for every
   transfer a peer is running, read straight from the application's buffer
   and framed as secure control, so a retransmit costs a ring entry rather
   than a retained copy

The builder requires the packet's kind declared before any payload, because the
kind decides the pool: a reliable flow body is its own retransmit source and
goes to a retained staging slot, everything else goes to a kernel send slot and
is released once on the wire.

A send on a flow does not usually reach the wire by itself. It is packed into
that flow's open batch and waits for `Flush`, so several small messages leave as
one datagram, under one seal, holding one staging slot. A batch that fills goes
out immediately rather than waiting, since there is no room for the next message
either way. Nothing else is
batched: handshake traffic, secure control, retransmits and the waiting-ring
drain all go straight out, and so does a message the caller framed itself as
part of a larger one, since the framing bits describe a packet's first and last
message and hand-framed pieces cannot share one.

The batch is a wire packet on its flow and takes that flow's next sequence
number, which is what leaves acknowledgement, retransmission, duplicate
detection, ordering and the windows untouched. They still see one packet per
sequence and never learn how many messages rode inside it.

Because a batched send answers the caller the moment it is packed, the
admission gate is consulted before the message is accepted rather than when the
batch is flushed. A flow that cannot take another packet refuses at the `Send`
that asked, exactly as it did before batching. A flush whose send is refused
leaves the batch in place, since nothing reached the wire.

`Flush` seals every batch a peer is holding before it sends any of them, then
hands that whole round to the backend in one call. Sealing and sending are
separate steps for this reason: the seal needs the peer's session material and
the send needs none of it, so the material is gathered once per batch and the
datagrams then leave together. The backend reports how many reached the wire,
counting from the first, and every batch behind that point stays with its flow
for the next flush.

Closing a flow flushes first. The batch lives on the association and would
otherwise be torn down with it, losing messages the caller was told had been
accepted.

Replying starts from the received packet: `PacketSlotHandle::PrepareResponse()`
returns the same builder aimed at that packet's source, and the chain ends in
`Respond()` or `RespondSecured()`. `Poll` stamps its socket into every handle
it delivers, which is what lets the handle mint the builder.

`Send` is best-effort. `SendSecured` delivers only to a peer authenticated
against a trusted certificate.

#### Admitting a flow packet: one gate, five outcomes

`CanSend` is a pure predicate over the already-locked flow and peer: ring slot
free, `unresolved < inflightCap` (reliable only), congestion budget covers the
packet. `StampFlowPacket` assumes it passed and only mutates.
`FlowTable::AdmitOut` sequences the two under the peer lock the caller lends.

| Outcome | Meaning | Slot owner afterwards |
|---|---|---|
| `Sent` | stamped and in flight | proceeds to seal and wire |
| `Queued` | window or budget full | the flow's waiting ring |
| `Dropped` | unreliable, no buffer configured | released, not an error |
| `Rejected` | reliable waiting ring full | released, `TooManyPending` to the app |
| `Dead` | no such flow, or not `OPEN` | released, a real failure |

When the waiting buffer fills, a reliable flow rejects the newest send, so
nothing accepted is ever dropped, and an unreliable flow evicts its oldest to
seat the newest, so an unreliable send is never refused for capacity. The ring
is strict FIFO: while anything waits, a new packet joins the back, otherwise
its sequence would outrun older data.

#### Receiving: one gate, three sinks, two bypasses, two passes

Session-opening traffic goes to `ProcessInternal` before the gate runs at all.
The handshake messages are unauthenticated by construction, so a known-peer
check, a decrypt and a replay window have nothing to apply to them. The bypass
is narrow: a packet claiming to be internal and secure at once is forged or
corrupt, and is dropped.

A knock takes the same bypass and then does the gate's work itself, because
what it needs is not what the gate does: the key it opens under is derived from
the packet's own header rather than looked up on a peer, and there may be no
peer yet. Having opened, it applies the same replay window and hands what it
carried to the same three sinks below, so a knock's payload reaches the
application through exactly the path any other packet's does.

Everything else runs through `PreProcessIn` (known-peer check for unsecured
traffic, decryption for secure, then replay and liveness), which routes what it
admits to one of three sinks. The decryption tries the current key first and
then the links a rotation could have put in play, which is how a silent
rotation is discovered (see Key rotation under Lifecycles):

1. `ProcessSecureControl`: path validation, flow reject, flow ack, transfer
   data, transfer ack, transfer reject
2. `ProcessFlowIn`: flow data
3. `QueueReady`: non-flow application data

Pass 2 drains the ready queue into the caller's buffer. Packets never leave the
receive pool, and the application receives handles into it.

A packet carrying a list of messages is queued whole, as one entry, exactly like
a packet carrying one. Nothing is copied and nothing is expanded, so a datagram
holding sixteen messages costs one slot rather than seventeen. The unpacking
happens where the application reads: `PollCursor` walks the list and hands back
one message at a time, so a caller still sees a flat run of messages and never
has to know which of them travelled together. The length chain is validated
before the first message is handed out, and a chain that overruns or leaves a
tail yields nothing from that packet, because reading an entry the chain does
not account for means trusting bytes chosen by whatever damaged it.

#### Lanes: what keeps an ordered flow ordered on the way out

Packets reach the ready queues in sequence already. `DeliverOrdered` queues only
at the cursor, anything ahead of it waits in the reorder ring, and the drain that
follows a filled gap runs under the same association lock that moved the cursor.
So the order going in is correct whichever thread put them there.

Taking them out is where it can be lost. One queue read by several threads hands
each of them whatever they win, and two threads then walk their own packets at
their own speed, so the application sees sequence four before sequence one even
though the queue held them the right way round.

`ReadyLanes` fixes that by giving each draining thread its own queue. A peer's packets
always take the same lane, chosen by hashing its slot index, so one thread sees
all of them and sees them in order. The slot index is used because it does not
change while the peer lives: a peer that moves to a new address keeps its lane,
and no state is ever handed between threads.

`Config::pollLanes` sets how many, defaulting to one, which is the single queue
this has always been. It must be a power of two and at most sixteen, and `Init`
refuses anything else rather than rounding, because a rounded count would leave a
lane no thread was told to drain. The caller names its lane with a
`ThreadIdentity`, which is nothing but the lane it last held.

A lane is claimed for the life of the `PollCursor`, not merely for the drain.
That span is what the guarantee rests on: the order survives only while one
thread is the only one working a peer's traffic, and the application reads that
traffic after `Poll` has returned. Nothing is registered. `Poll` takes whichever
lane is free, preferring the one the caller passes back, so a thread settles on
one lane while nothing contends and a lane whose usual thread stops calling is
taken by another rather than filling untouched.

Each lane is sized for the whole receive pool rather than a share of it, because
all the traffic can come from peers landing in one lane, and a push that fails is
a packet dropped after its sender was told it arrived. That makes the lanes the
largest memory the socket commits after the pools themselves, and it is why the
lane count is capped.

A packet with no flow carries no sequence and so has no order to keep. It takes
the lane its source address hashes to, which only keeps one sender's traffic
landing together.

#### Delivering an in-flow packet: two deliverers

`ProcessFlowIn` dispatches on mode. `DeliverOrdered` handles
`RELIABLE_ORDERED`: delivery at the cursor, an in-window gap parks the packet
in the hold-back ring, past-window packets are ejected, and `DrainHoldbackRun`
releases the contiguous run when a gap fills. `DeliverUnordered` handles the
other two modes, delivering on arrival, except that `UNRELIABLE` drops a packet
older than the newest it has delivered. Both consult the seen bitmap, because a
retransmit wears a fresh nonce and only the bitmap tells "sequence 6, again"
from "sequence 6, finally".

#### A stalled flow gives up its buffer, not its identity

An ordered flow whose cursor has not moved for the stall timeout is pinning
receive slots for a gap nobody is filling. The tick frees everything it
buffered and clears those sequences from the seen bitmap, so a resend is not
mistaken for a duplicate. The association itself stays, with its cursor, epoch
and identity intact.

Keeping it is the whole point. An association rebuilt from scratch starts at
sequence one while the sender is already hundreds ahead, so every packet after
that lands outside the window and neither side has any way to notice. Holding
the cursor still means the sender resends into the same gap it always had.

That works because an acknowledgement no longer frees the sender's copy. A
sequence is acknowledged when the receiver has it, which is not the same as the
receiver having delivered it: a packet buffered ahead of a gap is acknowledged
and can still be dropped. So the copy is kept until the receiver reports a
cursor past that sequence, which is the point where it can no longer ask for it.

#### The acknowledgement carries a cursor as well as ranges

An entry is `[flowId(2)][epoch(1)][rangeCount(1)][recvNext(4)][ackDelay(2)]`
followed by that many `[first(4)][last(4)]` pairs.

`recvNext` is the receiver's delivery cursor. Everything below it has reached
the application and can never be requested again, so it is what the sender
releases against. It is one fixed field, it only ever climbs, and a report that
is lost costs nothing because the next one carries the same or better.

The ranges are the packets held above that cursor, and they are an optimisation:
they let the sender stop retransmitting something the receiver already holds.
Losing one costs a redundant retransmit and nothing more. That distinction is
why the list may be capped at all. It is built from the newest sequence
downward, so a cap discards the oldest runs, and those are the ones nearest the
cursor. Were the cursor not carried separately, the truncation would be
throwing away exactly the information the send window is waiting on.

A flow that has just given up its buffered packets sends an entry with no ranges
at all. The cursor is then the whole message, and it is the only way the sender
learns that copies it had already released on the strength of an acknowledgement
are owed again.

#### The acknowledgement says how long it was held

A reply waits for a second packet or for the ack timer, so anything up to the
full ack delay passes between an arrival and the reply going out. Measured raw,
that wait looks exactly like a slower path.

The entry carries it instead. `ackDelay` is the microseconds between the newest
sequence in the entry arriving and the reply leaving, and the sender takes it
back out of the round trip. It saturates at about 65 milliseconds, well past any
cadence a receiver runs at, and saturating makes the sender subtract too little,
so an overflow reads as a slow path rather than a fast one.

The sender takes one sample per acknowledgement, from the newest sequence that
acknowledgement resolves for the first time, which is the sequence the hold time
was measured against. A sequence that has been retransmitted is skipped. The
reply cannot say which transmission it answers, and measuring from the most
recent send would give a sample shorter than the path.

### Lifecycles

#### Handshake

```
initiator                                  responder
SendHandshakeInit  --HS_INIT--->           Handshake_Challenge   (stateless)
                   <---HS_CHLG--
Handshake_Respond  --HS_RES---->           Handshake_Validate    (verify, then
                   <---HS_FINISH--          register + key + finish)
Handshake_Complete (key, flush parked packets)
```

The responder holds no state through the challenge and creates a peer only
after verification, so an unverified initiator costs it nothing. Both sides
bind a role-ordered transcript into the session key and a confirmation MAC:

```
initiatorPk ‖ responderPk ‖ initiatorEph ‖ responderEph ‖ saltI ‖ saltR
  ‖ initiatorCaps ‖ responderCaps ‖ initiatorVersion ‖ responderVersion ‖ tag
```

Version and capabilities sit inside the MAC'd transcript, so a downgraded
negotiation fails key confirmation instead of succeeding quietly.

The derivation yields two independent roots, each from the same exchange
under its own label: the session key, and a resume root reserved for session
resumption. Neither reveals the other, and both come from material wiped
before the handshake returns.

Packets sent to a peer mid-handshake are parked in the pending pool as an
intrusive list and flushed when the session completes. The two ends compare
public keys and the lower takes nonce lane 0, so the two send counters under
one shared key occupy distinct nonce spaces and cannot collide.

#### Key rotation

The session key is a chain. Rotating moves one link along it: the next key
is a one-way derivation of the current one, the counter-masking and MAC-only
keys re-derive from the new link, the send counter restarts, and the
migration tags restart with it because they derive from the session. The
resume root is untouched. Nothing about any of this travels on the wire, so
an observer sees no boundary to correlate across an address change.

A rotation happens when a byte threshold crosses or when `RotateKeys` is
called, and the peer is not told. It discovers the change when a packet
refuses to open under the current key and opens under the next link instead.
That discovery is the commit: the discovering side walks its own state one
link, resets the replay window because the sender's counters restarted, and
drops whatever was still sealed under the old link. Reliable traffic loses
nothing to the drop, because a retransmit seals fresh from staging under the
current key.

The initiator cannot drop the old link at once. The peer keeps sealing under
it until a rotated packet crosses, up to a round trip, so the initiator
holds the old keys beside the new ones and opens with either. The first
packet that opens under the new link is the confirmation: the old keys are
wiped and the replay window resets in the same locked step that accepts the
packet. A straggler under the old link is refused from then on, because its
counter belongs to a window that no longer exists and would poison the fresh
one.

One link may be unconfirmed at a time. A second rotation before the first is
confirmed is refused, so the two ends never sit two links apart and the
discovery is always a single derivation away. A corrupt packet costs two
open attempts steady-state and three during the round trip after this
side's own rotation, and never more.

#### Address migration

A connection survives its peer's address changing, with no re-handshake. When a
packet arrives from an unknown address, Flux looks up its peer tag,
trial-decrypts each candidate, and on the genuine mover delivers immediately,
since AEAD has already proved identity. Only the return route waits: a path
challenge is armed, and the old address stands until it is answered, so an
unproven address never tears down a proven session and a spoofed replay cannot
redirect traffic. Unknown-address lookups are budgeted per `Poll` pass, and a
legitimate mover past the budget retries on its next packet.

`RotateTags` advances every established peer's tag together, so a local address
change made for privacy is not linkable by tag either.

#### Flows

Opening is local. `OpenFlow(id, mode)` takes no address, costs nothing on the
wire, and the flow is sendable the instant it returns, including before any
handshake. The receiver builds its half from whichever packet arrives first,
reading the mode off the flow data byte.

An id closed and opened again numbers its packets from one, while the receiver
still holds the old association at whatever sequence it reached, so the two
generations would share one sequence space and the second would read as a run
of duplicates. The epoch in the flow data byte separates them. `OpenFlow`
advances it by one for that id, and a receiver seeing a higher one clears the
association back to sequence one and drops what it was holding. The comparison
walks forward from the epoch the association holds, because the field wraps
after eight opens: a short walk is a generation this side has not caught up
with, a long walk is a straggler from a generation already replaced, and the
straggler is dropped rather than pulling the association back onto a sequence
space nothing will send on again.

A message larger than one packet travels as a run of them on one ordered flow,
and bits 6 and 7 are the whole of the framing. More-follows says the message
continues past this packet, and continues says this packet is not the one that
opened it, so an ordinary send leaves both clear and is a message of one. The
transport carries the two bits and never gathers the run, so a message has no
size limit and the receive path allocates nothing to hold one.

Ordered delivery is what lets two bits do that job, and the other modes refuse
them. An unordered flow could deliver a run in any order, leaving nothing to
append to, and unreliable delivers newest only, which would tear a message apart
by design.

The bit that says a packet opened a message is what makes an abandoned one
recoverable. A flow that fails or is reopened mid-message leaves the receiver
holding a run nothing will finish, and the next opening packet tells it to drop
what it holds rather than appending a fresh message to the remains of the old
one. Without it the receiver would deliver bytes that were never sent, in an
order that looks correct.

The in-flight window is the sender's ring capacity, the receiver's
seen-bitmap width, and the depth of its reorder hold-back, and `WindowFor`
derives all of it from the mode. It is not
configuration, and nothing carries it on the wire: both ends read the same three
mode bits and reach the same number, so they agree by construction. A declared
window was tried and removed because nothing forced the two to match.

Bulk is four times as deep because depth is throughput on a long path, and it
costs a longer stall behind one lost packet, which realtime traffic will not
pay. The deeper ring is inline in the association, 24 KB a slot against 6, so
bulk associations come from a pool of their own and a socket that never opens
one pays nothing. `Config::flows::bulkOutCount` sizes it, and at zero the mode
is refused at `OpenFlow` rather than at the first send.

That agreement is what the seen bitmap rests on. The send gate refuses when the
ring slot for the next sequence is still occupied, so while a sequence is
unresolved the sender can never advance a full window past it, and the
receiver's bitmap floor can never climb above the oldest thing still in flight.

Registration is caps-only: a dry pool or a full per-peer directory yields
`FLOW_REJECT`, and the sender fails that one association rather than
retransmitting into silence. This is the one path where a remote makes
this socket allocate, and it is reachable only after a completed handshake.

How much a remote may make this socket hold is a separate limit, told to that
remote over the secure channel as a `GRANT` op carrying a slot count and a
generation. Each side announces its own receive capacity once its session
commits, so the exchange is symmetric and neither side ever states the other's
allowance. The value is local configuration, so the receiver enforces it from
the peer's first packet rather than from the announcement, and what travels only
saves the sender from overshooting.

Both ends act on it, and the send gate treats it as its own question. What the
path will carry and what the peer will hold are separate limits, tested
separately, and the smaller one decides. Folding a grant into the congestion
budget would let a small grant read as a congested path and shrink a budget the
network never objected to, and would lose the distinction between being
network-limited and being receiver-limited. The sender's count of what a peer is
holding is an estimate, since it cannot see what has been delivered and not yet
polled, so it reads low. The receiver's enforcement is the authoritative one and
the sender's restraint only spares the bandwidth of sending into a refusal.

Reception happens on the tick, not on the poll. `Update` empties the OS receive
buffer into the pool, consuming handshake and control traffic and queueing
application packets, and `Poll` hands over what it brought. That is what puts
the receive rules, the grant among them, at the moment this socket takes
responsibility for a packet, and it keeps the kernel from becoming the queue for
an application that collects at its own pace. How much one tick takes is
configured, defaulting to the pool's own capacity, since nothing more can be
taken while every slot is occupied. Everything on the tick reads its clock from
one place, so passing a fixed time receives without anything aging out.

Enforcement is a refusal to buffer. A peer already holding its grant has further
out-of-order packets ejected rather than held, which is the same path an
out-of-window packet takes: no copy, no pinned slot, and the sequence is left
unseen so the sender resends it. That is what bounds one remote's share of a
pool every remote draws from. It cannot stall a flow, because the packet at the
cursor is delivered rather than buffered, so the one packet that would drain the
buffer is never the one refused. A grant of zero bounds nothing, which is how a
socket that configures none behaves exactly as it did before grants existed.

Under all of the grants sits one floor they cannot collectively spend. Hold-back
across every peer may fill the receive pool only down to a reserve, and no
further. Grants are allowed to overcommit the pool, because most peers are idle
most of the time and sizing for the worst case would mean granting almost
nothing to anyone, so the reserve is what keeps reception possible when they are
not idle. It is the difference between throttling one peer and going deaf to all
of them: a pool consumed entirely by buffered packets leaves the kernel nowhere
to read into. A socket whose pool is smaller than the reserve simply never
buffers, which costs reordering and not reception.

The reserve is configured, defaulting to a sixteenth of the receive pool with a
floor. A fraction rather than a fixed count, because what it has to absorb is
arrivals per tick, and a socket sized for ten thousand peers needs headroom a
socket sized for ten does not. A grant can also be cut without anyone asking. A peer whose buffered packets are
repeatedly thrown away for making no progress is holding what it is not using,
and after enough of those its grant is halved and the new figure announced like
any other. Loss alone never reaches this, because a gap the sender fills costs
nothing: what counts is buffer taken and left to time out, which is the one
thing a well-behaved remote never does however poor its path. Halving rather
than closing, so a peer that recovers can still work, and the strikes reset with
the cut so it is judged on what it does next rather than on a total it can never
work off.

A grant is per peer rather than per socket. Configuration sets what a peer
starts with and `SetRecvGrant` changes one afterwards, in either direction, so a
peer that has proved itself can be given more than one that has not. A reduction
binds immediately on the receiving side, and a peer already past the new figure
is not made to give anything back, it simply stops being buffered for until it
drains under it. A grant may be raised or lowered at any
time, which is why the announcement is a control op rather than a handshake
field: the handshake transcript derives the session key, and a limit that
changes has no business in a key. The generation orders announcements so one
that overtakes an older one cannot be undone by it, compared as a wrapped
difference so the counter can run forever.

Closing is local too. `CloseFlow` walks the flow's association list, releases
what each was holding, and frees the flow, sending nothing. A remote dropping
its receive state can never end the flow, only lose one association. An
association is freed by `CloseFlow` or by its peer going away, and by nothing
else: there is no idle timer on an association.

`FAILED` is terminal, reached when the remote rejects the flow or the target
stops answering it. Stopping answering is judged by a clock, not by a count of
attempts: an association that owes packets and has resolved none of them for
sixteen of the path's own round trips is dead. A count of attempts spends
itself in a burst on a lossy but living link and stretches over minutes on a
slow one, and both are the wrong verdict. The rings drain and the congestion bytes refund
immediately, and the slot stays leased until `CloseFlow` or the peer's teardown
frees it. `GetFlowState` reports the failure and does not clear it.

Mode is copied onto each association at creation, because the send gate, the
drain, and the retransmit scan read it per packet, and reaching back to the flow
would mean a second lock on the packet path. The epoch is copied the same way
and for a different reason. Both control ops name a flow by its id, so an ack
or a refusal that arrives after the id has been closed and reopened would land
on the new association and speak for sequences that now mean something else. An
ack carries the epoch of the association that wrote it and resolves nothing
unless it matches, and a refusal echoes the epoch of the packet it refused and
fails nothing unless it matches. The match is exact rather than the forward walk
the data path uses, because a control op describes one generation and has none
of its own to catch up to. The flow lock is taken once per send, at the builder,
and is never held under a peer or association lock.

Two indexes reach an association, in opposite directions. The per-peer
directories answer peer-to-association, which the packet path and peer removal
need. An intrusive list per flow answers flow-to-associations, which only
closing needs. The per-peer directory is split by direction so "my flow 3 to
you" and "your flow 3 to me" cannot collide: data resolves against the in
directory, `FLOW_REJECT` against the out.

#### Transfers

`SendTransfer` leases the sending half and sends an announcement carrying the
length and the stride. Nothing else moves until the receiver answers, because
data sent at a receiver that has not attached a buffer could only be thrown
away. A lost announcement retries on the retransmit timeout, so it delays a
transfer rather than killing it.

On the receiving side the announcement surfaces as `TRANSFER_INCOMING`. The
application fetches the offer with `PendingTransfer`, then attaches a buffer
of the announced length with `Allow` or declines with `Reject`. A refusal
travels back as its own control message and resolves the sender's half with
`Refused`, and what the refusal releases goes straight back to the budget,
because a refusal is not congestion.

The receiver places each data packet at `seq * stride` and acknowledges every
second arrival with its contiguous cursor and a bitmap of the whole window
above it, so the sender is told outright which packets have landed rather
than inferring it from a cursor. An acknowledged sequence resolves out of
order, and the window slides on the cursor.

A hole is resent once as soon as three sequences above it have landed, or one
has landed and the packet has been out longer than a round trip and an
eighth, the same two rules the flow path declares loss by. After that first
repair the retransmit timeout governs each further attempt, which is what
gives a resend time to arrive. The overdue scan resumes across one pass, so a
pass walks the window once however many packets it offers. Losses are charged
to the controller behind a barrier at the highest sequence yet sent: packets
already on the wire when a loss was charged cannot charge another, which is
the transfer's version of the epoch stamp a flow packet carries.

Completion surfaces through `PollTransfers` on both ends as a `TransferView`
naming the buffer, the length and the outcome, and `CompleteTransfer`
releases the receiving half. Sweeping a peer drops its transfers, so a slot
recycled to a later peer can never inherit one.

#### The knock: an opener that carries data

A send to a peer whose identity this socket holds a certificate for does not
wait for a handshake. The first packet is a knock: an opener carrying the
sender's ephemeral, a salt, a clock stamp and the sender's own public key,
with application data encrypted behind it under an interim key the sender
derives alone. Two exchanges go into that key, the two long-term identities
and the sender's fresh ephemeral, so only the named receiver can open it and
every attempt derives a different one.

The sender's public key is sealed rather than carried in the clear, under a
key derived from its ephemeral against the receiver's certificate key. That
is the one exchange a receiver can run before it knows who is knocking, so it
unseals the name and then runs the second exchange against it. In the clear
the key would identify the sender to anyone on the path, which is the linkage
the rotating peer tags and the masked counter exist to prevent, and nothing
else in the header is stable across two knocks from the same sender. The seal
also gates the work: a forgery fails its tag after one key agreement rather
than two.

The header also names which of the receiver's keys all of that was aimed at,
in four bytes, so a receiver holding more than one picks it directly. Without
that name it would have to attempt an agreement against each key it holds,
which would let one unauthenticated packet cost as much work as the receiver
keeps history. The name comes from the key rather than from a counter, so it
reveals nothing about how often that socket rotates, and a receiver that never
rotates simply always sees the same one.

The receiver rebuilds the same key from the header, and the open is the
identity proof: only the holder of the secret behind the presented public key
produces a packet that opens, so the peer's id is bound rather than claimed.
From that moment the peer carries traffic. Flows open on it, number their
packets, acknowledge and retransmit as they always do, because the peer has a
key. What it does not have is a proven address, and that is a separate
question with its own answer below.

The opener rides on every packet until the far side is known to hold the
interim key, not merely on the first: reordering means any of them could be
the one that arrives before the peer exists. The first packet back that opens
is the proof, because only a side that derived the same key could have sealed
it, and from there the opener stops and its bytes go to payload instead. The
key does not change at that moment and neither does anything else, so the
switch costs nothing to recover from if it never happens: the handshake ends
the framing in any case.

The handshake runs behind all of this, unchanged. The knock replaces HS_INIT
and nothing else: the receiver answers it with the ordinary stateless
challenge, the sender echoes the cookie in HS_RES, and that echo is what
proves the address, exactly as it does for a peer that never knocked. The
session it derives then replaces the interim key through the slots a key
rotation uses, so packets still in flight under the interim key keep opening
while the flows, their sequences and the congestion state carry straight on.
The handshake state machine is untouched, which is why an initiator inside its
knock window still reads as awaiting a challenge: `CanCarryTraffic` answers
whether a key exists, `IsValid` answers where the handshake stands, and only
the knock makes the two disagree.

The interim key is weaker than the session key by construction, and that is
the whole price of speaking first. Nothing in it comes from the receiver, so a
later theft of the receiver's long-term key reopens a recorded first flight.
The session key mixes both ephemerals and both are wiped, so nothing reopens
what follows. The window is one round trip, and every message that rode it is
marked, so an application can hold first-flight data to a different standard
than the rest.

What a refused opener costs the sender follows one rule: whatever is retained
survives, and nothing else does. A reliable body sits in staging until its
sequence resolves, so the retransmit re-seals it under whatever framing the
peer has by then and it arrives late rather than never. Nothing keeps a copy of
an unreliable flow packet, a non-flow packet, or a mac-only one, so a flight
nobody opened is where those end. That is the ordinary contract of each kind
rather than anything the opener introduces.

Every way the receiver declines an opener ends the same way: with the ordinary
challenge. A sender aimed at a key this socket does not hold, one whose clock
has drifted, one that arrives when the budget is spent, one that repeats an
opener already seen, and one that finds the cap full all get the same answer,
and it is the answer that helps: the handshake starts on the next pass rather
than after a retry interval. The challenge holds no state and is never larger
than the opener that provoked it, so answering can neither be made to cost
memory nor turned into amplification. A peer that already has a session gets
silence instead, because a packet that fails to open for it is noise rather
than a sender asking for a way in.

Three limits keep an opener that anyone can send from costing more than it
should. A per-tick budget bounds the key agreements one pass will attempt, so
a flood slows early opening rather than the socket. A cap bounds how many
peers may exist with unproven addresses, and past it a knock creates nothing
and gets the plain handshake instead, which holds no state until its echo
arrives. Under that cap, each unproven peer has a packet allowance, and past
it its packets are dropped unbuffered until the echo lands, which reliable
flows recover from by retransmitting.

Replay is bounded by three things that already exist rather than by anything
the opener path adds. The clock stamp travels inside the authenticated header,
so a captured opener cannot be refreshed and stops being accepted once it
falls outside the window. A peer that exists refuses a repeat through its own
replay window, which is counter-checked like every other packet. And a peer
elsewhere holding the same identity refuses the registration outright, so a
copy sent from a second address cannot land beside the original. What is left
is one case: a copy arriving inside the clock window while no peer anywhere
holds that identity, which is a receiver that restarted or a peer something
removed. A message that rode a first flight answers IsKnock, so an application
that must not act twice can decide for itself what may travel there.

#### Revoking a pinned identity

`RemoveCertificate` stops trusting whatever key a tag names, at runtime, under
live traffic. The certificate entry stays and its version is cleared and its
key wiped, so any key presented against that tag afterwards is a hard
mismatch. The cleared version is what the check reads, and it has to fail
before the key comparison, because the wiped key is all zeros and a forged
handshake could present exactly that. A peer already authenticated keeps its
live session, and everything that consults the store afresh refuses from the
next call on.

#### Rotating this socket's own identity

`RotateIdentity` installs a new keypair under the same tag, under live
traffic. Sessions already running are untouched, because their keys came from
the handshake ephemerals rather than from this one. What changes is what a new
handshake announces and what a new opener can be encrypted toward.

Everything a rotation has to answer follows from one asymmetry. A handshake
carries public keys in band, so it always announces the key held now and needs
nothing. An opener does not: it is encrypted toward a key the sender read out
of a certificate, possibly long ago, and a sender whose copy has not caught up
would otherwise be sending into a key nobody holds.

So the previous keypairs are kept, as many as `Config::identityHistory` allows,
and an opener naming one of them is opened on it. The data it carried arrives,
which is the whole reason for keeping the key. The handshake behind it still
announces the current key, the sender's pinned certificate refuses that, and
the two events between them say what to do about it: `PEER_STALE_IDENTITY` on
the receiver, naming a peer working from an old certificate, and
`PEER_CERT_MISMATCH` on the sender, which is its cue to fetch a fresh one. Once
it has, the handshake completes on its own retry. Distributing certificates is
the application's, exactly as it was for the first one.

An opener naming a key that was never held, or one `ForgetPreviousIdentities`
has wiped, meets the same uniform decline as an opener that cannot be read: the
ordinary challenge, and the plain handshake carries the sender instead. That is
what makes forgetting a real answer to a leaked key rather than a hint.

One thing a rotation must never do is move a running session between nonce
lanes, since the two counters under one key would then collide. The lane is
settled from the two public keys when the session key is installed and stored
on the peer, so it is a property of the session and not a lookup that could
answer differently later.

#### Congestion control

The budget is per peer, in bytes, and flow and transfer packets spend it. It starts at
ten full packets and never drops below a configured floor of at least one full
wire packet, so the gate can always admit a packet once the path drains, nor
rises above what every flow window on that peer could hold at once, past which
the number cannot bind anything and only stores a burst. Feedback crosses locks
in one direction: a `CongestionDelta` accumulates under the flow lock and is
applied to the peer under the peer lock.

Two signals decide how it moves, and they answer different questions. Loss says
the path could not carry what was sent. Delay says a queue is forming, which is
the same news arriving earlier, before anything has had to be thrown away. A
controller with only the first has one resting place and it is a full buffer,
because a full buffer is the only thing that produces a loss.

While the budget is below the slow-start threshold it doubles per round trip
for as long as the path shows no standing queue. The sighting that stops it
comes from the newest round-trip sample, which crosses the moment a queue
forms, where the smoothed average lags a full doubling behind. On a sighting
the ramp holds flat while the smoothed figure is given a couple of round trips
to agree. A sighting that fades on both readings resumes the doubling, and one
that holds ends slow start where it stands, one buffer overflow earlier than a
loss would have ended it. Above the threshold, growth is a function of time
since the last reduction rather than of acknowledged bytes, so a long path
recovers as fast as a short one, with a straight-line estimate underneath so a
short path is not punished for running a curve designed for long ones. Over
the curve sits a governor: whatever it wants, the budget does not grow while a
standing queue already exceeds a fraction of the path's minimum round trip.

A sender that answers a standing queue by not growing can be starved by a
neighbour that answers the same queue by filling it further. Both see the same
delay, one reads it as a reason to hold and the other as headroom, and the
holding side ends at a few packets of budget while the filling side takes the
link. The controller carries a verdict for this. A budget pinned at a handful
of packets with the queue over target for many consecutive round trips, while
acknowledgements keep arriving, is starvation rather than congestion. The
budget is the reading that tells the two apart, because the queue cannot: two
well behaved senders sharing a link also hold the queue above target, but
their budgets sit near their shares, so a verdict keyed on the queue would
fire against a fair neighbour and one keyed on the budget does not. While the
verdict holds, the queue level found at that moment replaces the target. The
budget regrows at slow-start speed while the queue stays at or under that
level and holds when pushing past it, so the recovery competes for queue
space the neighbour already created and never adds to it. The verdict lifts
once the queue holds under the ordinary target for long enough that a
periodic probe drain cannot mimic a departure, which is the sign the
neighbour actually left.

The budget says how much may be outstanding, not how fast it may leave, so a
pacing clock meters departures at the budget over the round trip, with a small
gain and a small burst allowance. Every path that puts a flow packet on the
wire answers to the same clock, retransmits included. A resend released at
tick speed rather than path speed re-overflows the very buffer whose loss it
is answering, and each wave of copies then drowns the wave before it.

Loss only counts as a congestion signal at all once the path is losing more
than a congested path needs to. A flow at its fair share of a busy link loses a
fraction of a percent, because that is all the feedback requires, so a link
dropping whole percentages steadily is describing itself rather than asking
anyone to slow down. Below that tolerance the delay signal is the whole
detector, which is what it was built to be.

A loss trims, and how far depends on whether it was congestion. Two witnesses
answer that. The queue at the moment of the loss, and the size of the bite,
because the queue estimate goes blind in exactly one case, a burst overflowing
a shallow buffer, where the packets that would have carried the deep reading
are the ones the overflow dropped. Interference takes a small fraction of
packets at any send rate while overflow takes the whole excess. A corroborated
loss takes the full cut and re-anchors the curve. An uncorroborated one takes a
few percent and leaves the curve alone. A congestion epoch stamped on each
packet as it is sent bounds the response to one reaction per event, so a burst
losing ten packets is one trim rather than ten.

#### Peer eviction

Always on. A zero timeout selects the default rather than switching it off, so
there is no configuration in which a silent peer is kept forever. A peer from
whom nothing has been received for the
configured timeout is torn down on the tick, bounded per call. This socket's own
sends prove nothing, and forgeable handshake chatter does not refresh the clock.

A second silence ends a peer the same way. One can stay alive on the receive
clock, its data reaching us, while it acknowledges nothing we send.
Retransmission cannot mend a session broken like that, and without a verdict it
limps forever: flows fail, the application reopens them, and the loop never
ends. So a peer that owes acknowledgements and has produced none for the same
timeout is lost, reported through the same event, and the application answers
it by reconnecting, which rebuilds the state fresh. Liveness stamps are
monotonic microseconds shifted to roughly 1 ms units, wrapping in 32 bits about
every 51 days, with wrapped subtraction, so a peer idle past a full wrap can
only be evicted late.

### Platform backends

All platform-specific code lives behind an `ISocketKernel` implementation, and
nothing OS-specific leaks into `Socket` or above. Alongside the real backends
sits `FAULTY`, an in-process kernel that drops, duplicates, reorders and corrupts
on a seeded schedule. It is a `BackendType` like any other so a test drives it
through the ordinary public surface. Adding a backend means
implementing the interface and wiring its `BackendType` case, without editing
callers. Windows, Linux, and macOS are all targets, on x86-64 and arm64, and a
path that compiles everywhere carries no architecture-specific intrinsic
unconditionally.

A backend puts packets on the wire one at a time through `SendTo`, or several
at once through `SendBatch`. The batch form exists because a flush usually has
more than one datagram ready for the same peer, and Linux can hand all of them
over in a single `sendmmsg` call. Where the OS has no equivalent the backend
loops over its own `SendTo`, so the calling code is identical everywhere and
only the syscall count changes.
