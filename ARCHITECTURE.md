# Architecture

Flux is a connectionless encrypted UDP transport. It builds on `common`, a
standalone systems library vendored in `external/common` and developed on its
own. `common` carries nothing that only makes sense to a transport.

This document describes each library's structure: its entities, its ownership
graph, and the number of sanctioned ways to perform each core operation. Where
a count appears below it is the whole count, and a path not described here does
not exist.

For how to build and test, see [README.md](README.md). For the conventions a
change is held to, see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 1. The library set

| Library | Namespace | What it is | Depends on |
|---|---|---|---|
| `common` | `bcp::common` | general-purpose systems primitives | monocypher (vendored) |
| `flux` | `bcp::flux` | the transport | `common` |

```
flux  ──depends on──▶  common  ──depends on──▶  monocypher
                       (vendored)                (vendored)
```

A library may depend on another library in the set. It may never depend on a
consumer of itself, and it may never carry a concept that only makes sense to
one of its consumers. `common` knows nothing about packets, peers, sockets, or
wire formats. A type that only makes sense to a transport belongs in `flux`.

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

---

## 2. `common`

- **Error and result.** `Error` is an `enum class : uint8_t`, codes grouped by
  numeric range, every code mapped by `ErrorToString`. `Result<T>` pairs an
  `Error` with a value. Callers check `isErr()` before `Take()`.
- **Platform.** `CACHE_LINE` (128 on arm64, 64 elsewhere), `CpuPause()`, and
  `MonotonicMicros()`, which is meaningful only as a difference between two
  calls.
- **Collections.** Two lock-free primitives, and they are the whole set.
  `SlotPool` is an index free-list over one contiguous block plus a per-slot
  reader/writer lock. The free-list is sharded across up to sixteen rings so
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
  secure wipe, and `RandomBytes` over the platform RNG. Header-only, so
  monocypher and `bcrypt` propagate as `PUBLIC` link dependencies.
- **Log.** All diagnostics go through `Log` and `LogF`, which route to a
  replaceable callback. Never `printf`, never iostreams.

---

## 3. `flux`

A transport protocol: connectionless with a handshake, zero-allocation on the
packet path, encrypted, endianness-explicit, with mixed-reliability flows and
address migration.

Its entities are peers and sockets. There is no concept of a node, a route, a
resolver, or a service name. Naming and routing belong to a layer above.

| Sub-namespace | Holds |
|---|---|
| `bcp::flux` | `Socket`, `FlowTable`, `Peer`, `PeerTable`, flows, handles |
| `bcp::flux::internal` | wire constants, not public API |
| `bcp::flux::wire` | `PacketBuilder` and its stages |
| `bcp::flux::platform` | per-OS `ISocketKernel` backends |
| `bcp::flux::pending` | the parked-behind-handshake packet list |

### 3.1 Entities

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

A flow is a unidirectional numbered channel, in one of three modes:

| Mode | Retransmit | Delivery |
|---|---|---|
| `RELIABLE_ORDERED` | yes | in sequence |
| `RELIABLE_UNORDERED` | yes | on arrival |
| `UNRELIABLE` | no | newest only |

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
[OutAssociation][InFlightEntry × inflightCap][WaitingEntry × waitingCap]
[InAssociation ][seen bitmap               ][HoldbackEntry × reorderCap]
```

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

### 3.2 Memory: the pools

Nothing on the packet path allocates. There are nine pools, each with one
owner:

| Pool | Owner | Holds |
|---|---|---|
| recv | `ISocketKernel` | inbound packets |
| send | `ISocketKernel` | outbound packets |
| pending | `Socket` | packets parked behind an unfinished handshake |
| staging | `FlowTable` | retained reliable bodies, held send-until-ack |
| flow | `FlowTable` | `Flow` slots, one per open flow |
| out-association | `FlowTable` | `OutAssociation` slots |
| in-association | `FlowTable` | `InAssociation` slots |
| peer | `PeerTable` | `Peer` slots |
| certificate | `CertStore` | trusted `Certificate` slots |

`Socket` borrows the two kernel pools as raw pointers, so it must not outlive
the kernel, and lends both to `FlowTable` along with the ready queue. Every
other pool is owned by `Socket` or by the component it reaches through.

Two flat arrays are indexed by peer slot and guarded by that peer's slot lock:
the replay window state, and the flow directories (`FlowDirEntry[]`, one
segment per direction). Staging is sized apart from the kernel send pool so a
busy reliable flow can never starve handshakes, acks, or unreliable traffic of
send slots. Staging running dry is backpressure.

### 3.3 Ownership: the handles

| Handle | Owns | Released by |
|---|---|---|
| `PacketSlotHandle` | a slot lease and its lock | destructor, returning the slot to the pool |
| `PeerHandle` | the slot's lock only | destructor, dropping the lock |
| `FlowHandle` | nothing, a `{slot, epoch, flowId}` key | nothing to release |

All three are move-only, and a moved-from handle is left unusable.

`PacketSlotHandle` is the unit of packet ownership. An invalid index yields a
failed handle whose `Read()` and `Write()` return `nullptr`. `Detach()` gives
up ownership and returns the bare index, which is how a reliable body outlives
the send that wrote it. `PacketSlotWriter` and `PacketSlotReader` wrap a handle
with a byte cursor.

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

### 3.4 Concurrency

Flux owns no thread. Work happens on a caller's thread through three entry
points, all safe to call concurrently:

- `Poll` processes inbound packets and drains ready ones to the application.
- `Update` runs the tick: flush owed acks, retransmit, drain waiting sends,
  evict idle peers. All time-based work lives here.
- Sending, through `PacketBuilder`.

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
Hood open-addressed indexes mapping keys to slots, removal by backward-shift so
probe distance stays bounded. One table-wide seqlock (`version_`) covers the
indexes. A writer holds it odd across any mutation, a reader validates its
whole probe against it and retries if the version moved, and writers serialize
on a single write lock. Readers never store to the index, so lookups scale
across cores, and a matched slot's key is verified under its read lock, so a
hash collision never resolves to the wrong peer.

Do not call a table operation while holding a handle from that table. Writers
wait on slot locks, and a handle holder calling back in closes a cycle.
Changes here are validated under ThreadSanitizer. A green suite alone says
nothing about race-freedom.

### 3.5 The wire

Little-endian, every multi-byte access through `common`'s byte cursors.
(`htons` in `address.h` is for OS `sockaddr` structures, a separate concern.)
Two layouts, split by the `UNSECURE` bit of the leading controller byte. A `?`
marks a conditional field, and everything after the `‖` is ciphertext:

```
secure    [Controller(1)][Tag(16)][NonceCounter(8)][PeerTag(4)]? ‖ [Channel(1)]([FlowId(2)][FlowSeq(4)][FlowData(1)])?[payload]
unsecured [Controller(1)][payload]
```

| Field | Bytes | Present | What it is |
|---|---|---|---|
| Controller | 1 | always | four independent bit flags, listed below |
| Tag | 16 | secure | the AEAD authentication tag over the packet |
| NonceCounter | 8 | secure | the sender's counter, masked, the wire half of the nonce |
| PeerTag | 4 | secure, `TAGGED` set | the migration tag |
| Channel | 1 | secure, inside the seal | 0 for application data, otherwise an internal control op |
| FlowId | 2 | `HAS_FLOW` set | the sender's flow id |
| FlowSeq | 4 | `HAS_FLOW` set | the packet's sequence on that flow, starting at 1 |
| FlowData | 1 | `HAS_FLOW` set | mode in bits 0-2, bits 3-7 reserved and zero |
| payload | rest | always | application bytes, or the control op's body |

The controller bits: `CTRL_INTERNAL` marks handshake traffic, consumed and
never delivered. `CTRL_HAS_FLOW` says the flow header sits inside the seal.
`CTRL_UNSECURE` marks the plaintext opt-out, which carries no tag, no nonce,
and no integrity. `CTRL_TAGGED` says the peer tag follows the nonce. The
controller byte and peer tag are authenticated associated data: readable on the
wire, not alterable.

The nonce counter must travel, but in the clear it is a serial number that
would link a peer across a migration. So the field carries the counter XORed
with a mask derived from a per-peer header key and this packet's own AEAD tag,
unique per packet. Both ends recompute it, and an observer sees eight bytes
that never form a sequence.

The channel byte sits inside the seal, so a control packet (path validation,
flow reject, flow ack) is byte-for-byte indistinguishable from data to any
observer. The receiver learns which it holds only after a successful decrypt.

Handshake packets are the only cleartext opcodes (`HS_INIT`, `HS_CHLG`,
`HS_RES`, `HS_FINISH`), carried on unsecured internal packets because no key
exists yet.

Every wire constant is named in `flux/internal/constants.h`.

### 3.6 The paths

#### Reaching a peer: three keys, one table

| Route | Call | When |
|---|---|---|
| by address | `PeerTable::GetPeer(const Address&)` | the ordinary receive and send path |
| by id | `PeerTable::GetPeer(const BcpId&)` | after a peer proves an id, survives migration |
| by tag | `PeerTable::GetPeersByTag(...)` | migration only, multi-valued |

All three return a read-locked `PeerHandle`, and nothing outside `PeerTable`
reaches a peer slot directly. The tag route is multi-valued because one peer
holds several tags at once (its rotation window, capped at `MAX_TAGS_PER_PEER`)
and two peers may derive the same tag by chance. A clash resolves by trial
decryption.

#### Sending: one seal, five origins

`Socket::SealSecurePacket` is the only place an outbound packet is encrypted.
Five things originate a send:

1. Application, non-flow: `BuildPacket().NoFlow()...Send()` or `.SendSecured()`
2. Application, on a flow: `BuildPacket().WithFlow(flow)...Send()` or `.SendSecured()`
3. Handshake: `BuildInternal(op)`, unsecured because no key exists yet
4. Secure control: `SendSecureControl(...)`, wire-identical to data
5. Retransmit and waiting-ring drain: `SealStagingToWire(...)`, shared by
   `ResendStaging` and `DrainWaitingSends`

The builder requires the packet's kind declared before any payload, because the
kind decides the pool: a reliable flow body is its own retransmit source and
goes to a retained staging slot, everything else goes to a kernel send slot and
is released once on the wire.

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

#### Receiving: one gate, four sinks, two passes

`Poll` pass 1 runs the kernel batch through `PreProcessIn` (known-peer check
for unsecured traffic, decryption for secure, then replay and liveness), which
routes everything it admits to one of four sinks:

1. `ProcessInternal`: handshake traffic
2. `ProcessSecureControl`: path validation, flow reject, flow ack
3. `ProcessFlowIn`: flow data
4. `QueueReady`: non-flow application data

Pass 2 drains the ready queue into the caller's buffer. Packets never leave the
receive pool, and the application receives handles into it.

#### Delivering an in-flow packet: two deliverers

`ProcessFlowIn` dispatches on mode. `DeliverOrdered` handles
`RELIABLE_ORDERED`: delivery at the cursor, an in-window gap parks the packet
in the hold-back ring, past-window packets are ejected, and `DrainHoldbackRun`
releases the contiguous run when a gap fills. `DeliverUnordered` handles the
other two modes, delivering on arrival, except that `UNRELIABLE` drops a packet
older than the newest it has delivered. Both consult the seen bitmap, because a
retransmit wears a fresh nonce and only the bitmap tells "sequence 6, again"
from "sequence 6, finally".

### 3.7 Lifecycles

#### Handshake

```
initiator                                  responder
SendHandshakeInit  ──HS_INIT──▶            Handshake_Challenge   (stateless)
                   ◀──HS_CHLG──
Handshake_Respond  ──HS_RES───▶            Handshake_Validate    (verify, then
                   ◀──HS_FINISH──           register + key + finish)
Handshake_Complete (key, flush parked packets)
```

The responder holds no state through the challenge and creates a peer only
after verification, so an unverified initiator costs it nothing. Both sides
bind a role-ordered transcript into the session key and a confirmation MAC:

```
initiatorPk ‖ responderPk ‖ saltI ‖ saltR
  ‖ initiatorCaps ‖ responderCaps ‖ initiatorVersion ‖ responderVersion ‖ tag
```

Version and capabilities sit inside the MAC'd transcript, so a downgraded
negotiation fails key confirmation instead of succeeding quietly.

Packets sent to a peer mid-handshake are parked in the pending pool as an
intrusive list and flushed when the session completes. The two ends compare
public keys and the lower takes nonce lane 0, so the two send counters under
one shared key occupy distinct nonce spaces and cannot collide.

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

The in-flight window is `internal::FLOW_WINDOW`, 256 packets: the sender's ring
capacity and the receiver's seen-bitmap width, one number for every flow in both
directions. It is a constant rather than configuration, because nothing carries
it on the wire and nothing negotiates it, so two sockets that disagreed would
have no way to find out. Fixing it makes them agree by construction.

That agreement is what the seen bitmap rests on. The send gate refuses when the
ring slot for the next sequence is still occupied, so while a sequence is
unresolved the sender can never advance a full window past it, and the
receiver's bitmap floor can never climb above the oldest thing still in flight.

Registration is caps-only: a dry pool or a full per-peer directory yields
`FLOW_REJECT`, and the sender fails that one association rather than
retransmitting into silence. This is the one path where a remote makes
this socket allocate, and it is reachable only after a completed handshake.

Closing is local too. `CloseFlow` walks the flow's association list, releases
what each was holding, and frees the flow, sending nothing. A remote dropping
its receive state can never end the flow, only lose one association, and an
unused association idles out on its own.

`FAILED` is terminal, reached when the remote rejects the flow or a packet
exhausts its retransmits. The rings drain and the congestion bytes refund
immediately, but the slot waits for the application to observe the failure
through its handle before recycling.

Mode is copied onto each association at creation, because the send gate, the
drain, and the retransmit scan read it per packet, and reaching back to the flow
would mean a second lock on the packet path. The flow lock is taken once per
send, at the builder, and is never held under a peer or association lock.

Two indexes reach an association, in opposite directions. The per-peer
directories answer peer-to-association, which the packet path and peer removal
need. An intrusive list per flow answers flow-to-associations, which only
closing needs. The per-peer directory is split by direction so "my flow 3 to
you" and "your flow 3 to me" cannot collide: data resolves against the in
directory, `FLOW_REJECT` against the out.

#### Congestion control

The budget is per peer, in bytes, and only flow packets spend it. It starts at
ten full packets, grows on acknowledgement, trims on loss to a percentage of
itself, and never drops below a configured floor of at least one full wire
packet, so the gate can always admit a packet once the path drains. Feedback
crosses locks in one direction: a `CongestionDelta` accumulates under the flow
lock and is applied to the peer under the peer lock.

#### Peer eviction

Optional, off by default. A peer from whom nothing has been received for the
configured timeout is torn down on the tick, bounded per call. Received traffic
is the only signal, because this socket's own sends prove nothing, and
forgeable handshake chatter does not refresh the clock. Liveness stamps are
monotonic microseconds shifted to roughly 1 ms units, wrapping in 32 bits about
every 51 days, with wrapped subtraction, so a peer idle past a full wrap can
only be evicted late.

### 3.8 Platform backends

All platform-specific code lives behind an `ISocketKernel` implementation, and
nothing OS-specific leaks into `Socket` or above. Adding a backend means
implementing the interface and wiring its `BackendType` case, without editing
callers. Windows, Linux, and macOS are all targets, on x86-64 and arm64, and a
path that compiles everywhere carries no architecture-specific intrinsic
unconditionally.
