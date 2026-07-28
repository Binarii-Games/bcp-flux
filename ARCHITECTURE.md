# Architecture

openbcp is a set of independent C++20 libraries. Two exist today, `common` and
`flux`, and others may join. Each is a library in its own right, with its own
public surface and its own reasons to exist; none is a support layer for
another.

This document describes the set, the rules every library in it obeys, and then
each library's structure: its entities, its ownership graph, and the number of
sanctioned ways to perform each core operation. Where a count appears below it
is the whole count, and a path not described here does not exist.

For how to build and test, see [README.md](README.md). For the conventions a
change is held to, see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 1. The library set

| Library | Namespace | What it is | Depends on |
|---|---|---|---|
| `common` | `bcp::common` | general-purpose systems primitives: error handling, lock-free collections, byte cursors, crypto, platform glue | monocypher (vendored) |
| `flux` | `bcp::flux` | a connectionless, encrypted, zero-allocation transport protocol | `common` |

```
flux  ──depends on──▶  common  ──depends on──▶  monocypher (vendored)
```

### The dependency rule

A library may depend on another library in the set. It may never depend on a
consumer of itself, and it may never carry a concept that only makes sense to
one of its consumers. Each has to be complete and useful on its own, to someone
who will never touch the others.

Applied to the pair that exists today: `common` knows nothing about packets,
peers, sockets, or wire formats, and a type that only makes sense to a transport
belongs in `flux`. The same test governs any library added later, in both
directions.

A new library joins by taking a section here of the same shape as sections 2 and
3, declaring what it depends on, and inheriting everything in this section.

### Conventions every library obeys

- No exceptions. A function that yields no value returns `common::Error`; one
  that yields a value and a status returns `common::Result<T>`. Anything that
  must be checked is `[[nodiscard]]`.
- Two-phase initialisation: a default constructor, then `Init(...)` returning
  `Error`. Constructors cannot fail when there are no exceptions.
- `Shutdown()` and `Close()` are idempotent, destructors call them, and handles
  are invalidated after cleanup.
- Allocation happens in `Init`. Nothing allocates in a destructor, and `flux`
  narrows this further to forbid allocation anywhere on the packet path.
- Fixed-width integer types for anything on a wire, any size, and any count.
  `enum class` with an explicit underlying type.
- Ownership is explicit and encoded in the type system: one owner per resource,
  RAII release on the destructor edge, move-only where ownership is unique, and
  a moved-from object left unusable.

---

## 2. `common`

General-purpose systems primitives. Everything here is usable by any C++20
program; nothing in it refers to a transport, a packet, or a peer.

### Error and result

`Error` is an `enum class : uint8_t` with codes grouped by numeric range —
general, socket, memory, protocol, peer, handshake, retransmit, transport,
serialization. `ErrorToString` maps every code to a string, and a new code is
added to both in the same edit.

`Result<T>` pairs an `Error` with an optional value, for functions that produce
both. Callers check `isErr()` before `Take()`.

### Platform

`CACHE_LINE` is 128 on arm64 and 64 elsewhere, and every alignment in the
collections is expressed in terms of it. `CpuPause()` emits the architecture's
spin hint (`_mm_pause` on x86, `yield` on arm64). `MonotonicMicros()` returns
process-relative monotonic microseconds that never run backwards, meaningful
only as a difference between two calls.

### Collections

Two lock-free primitives, and they are the whole set. Anything in openbcp
needing concurrent structure composes these rather than introducing
synchronization machinery of its own.

`SlotPool` is a lock-free index free-list plus one contiguous block plus a
per-slot reader/writer lock. The free-list is sharded across up to sixteen
small rings, each permanently owning the indices of its residue class, so
concurrent acquires and releases spread over independent cache lines instead
of colliding on one: acquire starts at a ring picked from a per-thread hint (a
hashed stack address, so no thread identity is needed) and hops onward when a
ring runs empty, and release returns an index to its home ring, which can
therefore be exactly full but never over-full. Slots are fixed-stride and
never move, so an index is a stable name for a piece of memory and can travel
anywhere a pointer would be unsafe.

`FifoQueue<T>` is a lock-free MPMC bounded queue, header-only because it is a
template.

`SlotPool` hands back raw bytes and runs no constructor or destructor, which
imposes two rules on anything stored in one. It must be trivially copyable — no
`std::vector`, no `std::atomic` member, no vtable, nothing owning heap memory.
And a recycled slot still holds the previous tenant's bytes, since the pool
zeroes once at `Init`, so whoever leases a slot writes every field.

### Byte cursors

`BytesWriter` and `BytesReader` are the sanctioned way to move a multi-byte
value into or out of a buffer. Both carry a remaining-byte count and check it
before every access, returning `false` rather than running past the end.

Multi-byte values are encoded little-endian by explicit shift:

```cpp
p[0] = static_cast<uint8_t>(in >> 0);
p[1] = static_cast<uint8_t>(in >> 8);
```

This is what makes the encoding independent of host byte order. Never `memcpy` a
multi-byte scalar through these buffers, and never overlay a struct on them.

### Crypto

A single-file wrapper over vendored Monocypher, mapping terse primitive names to
intention-revealing ones and fixed-size types: X25519 keypairs and
Diffie-Hellman, a blake2b KDF and keyed MAC, XChaCha20-Poly1305 AEAD,
self-certifying ids as `blake2b(pubkey)`, constant-time comparison, and secure
wipe. Sizes are fixed by the primitives (32-byte keys, 16-byte tag, 24-byte
nonce).

`RandomBytes` is the platform secure RNG: `BCryptGenRandom` on Windows,
`getentropy` on macOS (chunked, since it refuses requests over 256 bytes),
`getrandom` on Linux. It returns `false` on RNG failure and the caller must
check.

The wrapper is header-only, so its calls into Monocypher and `bcrypt` are
instantiated in every consumer's translation unit. Both dependencies are
therefore `PUBLIC` on the `common` target, and they propagate down the link
graph.

### Log and math

`Log` and `LogF` take a `LogLevel` and route to a replaceable callback.
Diagnostics anywhere in openbcp go through these, never through `printf` or
iostreams. `math.h` holds `NextPowerOfTwo`.

---

## 3. `flux`

A transport protocol: connectionless with a handshake, zero-allocation on the
packet path, encrypted, endianness-explicit, with mixed-reliability flows and
address migration.

Its entities are peers, sockets, and endpoints. There is no concept of a node, a
route, a resolver, or a service name; naming and routing belong to a layer
above, and `flux` is complete without one.

| Sub-namespace | Holds |
|---|---|
| `bcp::flux` | `Socket`, `Peer`, `PeerTable`, flows, handles |
| `bcp::flux::internal` | wire constants; not public API |
| `bcp::flux::wire` | `PacketBuilder` and its stages |
| `bcp::flux::platform` | per-OS `ISocketKernel` backends |
| `bcp::flux::pending` | the parked-behind-handshake packet list |

### 3.1 Entities

#### Peer

A remote endpoint this socket has spoken to, living in a `SlotPool` slot inside
`PeerTable`. It holds the session key, the send counter, migration tag state,
handshake progress, liveness stamps, per-peer congestion state, and the head and
tail of its parked-packet list.

Identity comes in three forms, and they are not interchangeable:

- `Address` — a hashable wrapper over `sockaddr_storage`. Where the peer is at
  the moment; it changes on migration.
- `BcpId` — `blake2b(publicKey)`, self-certifying, so either side recomputes it
  from a presented key and checks that the peer owns what it claims, with no
  registry involved. It stays stable across address changes. It is not
  persistent: the keypair is generated per process, so an id lives only as long
  as that process, and storing one is a mistake.
- `PeerTag` — a rotating 4-byte value derived from the session key at both ends
  and never put on the wire as a secret. It is the migration handle, an
  address-independent way to recognise a connection whose address just changed.
  All-zero is reserved as the empty marker.

#### Flow

A unidirectional numbered channel between two peers, in one of three modes:

| Mode | Retransmit | Delivery |
|---|---|---|
| `RELIABLE_ORDERED` | yes | in sequence |
| `RELIABLE_UNORDERED` | yes | on arrival |
| `UNRELIABLE` | no | on arrival |

Every flow packet is numbered and acknowledged whatever the mode. `UNRELIABLE`
means the packet is never retransmitted; loss is still observed, and it still
feeds congestion control.

Flows are unidirectional, so each side sees a different half, and the two halves
live in separate pools. `OutFlowState` is the sending half, for flows this
socket opened, and carries the in-flight ring (retransmit sources, indexed
`seq & (cap-1)`) and the waiting ring (a strict FIFO of accepted-but-not-yet-
admitted sends). `InFlowState` is the receiving half, for flows a remote opened;
it is an order of magnitude smaller, because this is the side a remote can make
this socket allocate, and it carries the seen bitmap and the reorder hold-back
ring. Both begin with a `FlowCore` at offset 0, enforced by `static_assert`, so
shared lifecycle code addresses either type through one shape.

Separate pools mean a hostile peer opening flows can exhaust the in-flow pool
without touching this socket's capacity to open its own.

Each flow slot is larger than its struct, with its rings following inline:

```
[OutFlowState][InFlightEntry × inflightCap][WaitingEntry × waitingCap]
[InFlowState ][seen bitmap             ][HoldbackEntry × reorderCap]
```

Caps are powers of two fixed at `Init` and stamped into the slot, so a slot
describes its own layout.

#### PacketSlot

A packet as it sits in a pool slot: an address, a size, and the raw wire bytes
as a flexible array. Packet bodies are never copied between slots; they are
written in place and passed by handle.

#### Certificate

A long-term public key pinned to an opaque 32-byte identity tag. A certificate
is trusted because of how it was delivered — embedded in a client, provisioned,
loaded from config — and the handshake proves the peer owns the matching secret,
so no signature is carried. Flux never parses or interprets an identity tag; it
stores it, matches it, and surfaces it to the layer above.

### 3.2 Memory: the pools

Nothing on the packet path allocates. There are eight pools, each with one
owner:

| Pool | Owner | Holds |
|---|---|---|
| recv | `ISocketKernel` | inbound packets |
| send | `ISocketKernel` | outbound packets |
| pending | `Socket` | packets parked behind an unfinished handshake |
| staging | `Socket` | retained reliable bodies, held send-until-ack |
| out-flow | `Socket` | `OutFlowState` slots |
| in-flow | `Socket` | `InFlowState` slots |
| peer | `PeerTable` | `Peer` slots |
| certificate | `CertStore` | trusted `Certificate` slots |

`Socket` borrows the two kernel pools as raw pointers, so it does not own them
and must not outlive the kernel. Every other pool it owns directly or reaches
through the component that owns it.

Two flat arrays are indexed by peer slot and guarded by that peer's slot lock,
which gives each peer a private segment without a per-peer allocation: the
replay window state, and the flow directory (`FlowDirEntry[]`, one segment for
out-flows and one for in-flows).

Staging is sized independently of the kernel send pool so that a busy reliable
flow retaining bodies can never starve handshakes, acknowledgements, or
unreliable traffic of send slots. Staging running dry is backpressure.

### 3.3 Ownership: the handles

There are three handle types and they own three different things; misreading
which is which is how a resource leaks or a thread wedges.

| Handle | Owns | Released by |
|---|---|---|
| `PacketSlotHandle` | a slot lease and its lock | its destructor, returning the slot to the pool |
| `PeerHandle` | the slot's lock only | its destructor, dropping the lock; the peer outlives it |
| `FlowHandle` | nothing — a `{slot, epoch, flowId}` key | nothing to release |

All three are move-only, and a moved-from handle is left unusable rather than
empty-but-valid.

`PacketSlotHandle` is the unit of packet ownership. It is constructed from a
bare `(index, pool)` pair, and an invalid index yields a failed handle whose
`Read()` and `Write()` return `nullptr`, so a wild index cannot become a wild
pointer. `Detach()` gives up ownership and returns the bare index, which is how
a body outlives the send that wrote it: a reliable flow keeps its plaintext as
the retransmit source, and copying it would put an allocation-free path's
payload through a `memcpy`. `PacketSlotWriter` and `PacketSlotReader` wrap a
handle together with a byte cursor.

`PeerHandle` arrives already read-locked, with the key verified under that lock.
`RemovePeer` frees a slot only after taking its write lock, which cannot be
acquired while a read lock is held, so a peer is never freed under a live
handle.

`FlowHandle` is a `{slot, epoch, flowId}` key. It holds no lock and keeps
nothing alive, so it is cheap to hold for a flow's entire life. Every operation
goes through the socket and is checked against slot and epoch, so a handle that
outlives its flow misses cleanly instead of reaching a recycled slot's new
tenant. Only out-flows have one, because the receiving half of a remote's flow
is internal and never surfaces to the application.

#### The lending rule

A handle is a held lock, so nothing may look up a resource its caller already
holds. A second acquisition of a lock the current thread already owns
self-deadlocks the moment either side wants to write, and the RW handles upgrade
silently, so the deadlock is invisible at the call site.

A function that needs a resource its caller already has takes the handle, not an
address or a slot index:

- Lend (`PeerHandle&`) when the caller still needs the handle afterwards.
  `pending::Push` and `pending::PopFront` are the model.
- Transfer (`PeerHandle` by value) when the callee is the handle's terminal
  user, typically because it must release the lock before ending in a send. The
  by-value signature makes the contract physical, since the caller cannot retain
  the lock across the call. `FlushPeerAcks` and `UpdateOutFlow` are the model.

### 3.4 Concurrency

Flux owns no thread. Every piece of work happens on a caller's thread, through
one of three entry points, all safe to call concurrently:

- `Poll` — process inbound packets and drain ready ones to the application.
- `Update` — the tick: flush owed acks, retransmit, retry open and close, drain
  waiting sends, evict idle peers. All time-based work lives here, and the clock
  is read fresh at each decision point, so a deadline coming due mid-pass fires
  this tick rather than the next.
- Sending, through `PacketBuilder`.

#### Lock order

Packet slot, then peer, then flow. Every path takes locks in that order, and the
wire send happens with nothing held.

Two consequences follow. A peer lock is never held across a `SendTo` syscall,
nor across anything that then takes a staging lock, since that would be
peer-then-staging and a lock-order inversion. And the idiom throughout is to
gather under the lock and send after release: a locked scope collects what the
send needs (`PeerSendMaterials`), the scope closes, and the packet is sealed and
sent afterwards.

#### The seqlock tables

`PeerTable` and `CertStore` share one design. Entries live in a `SlotPool` and
never move, and open-addressed Robin Hood indexes map keys to slots: on insert
an entry that has probed further steals the bucket and the loser keeps probing,
so probe lengths even out and no key pays for someone else's collision cluster.
Removal backward-shifts the run rather than leaving a tombstone, which keeps
probe distance bounded over long uptime.

The access pattern is many readers and rare writers, since lookup happens per
packet and registration only on handshake.

- One table-wide seqlock (`version_`) covers the indexes. A writer holds it odd
  across any mutation, and a reader validates its whole probe against it,
  retrying if the version moved. Per-entry versions would not be enough, because
  displacement and backward-shift move entries between buckets, so a probe can
  miss a peer mid-move even when every entry it read was individually
  consistent. The version is monotonic, which keeps a reusable flag's ABA
  problem from arising.
- Readers never store to the index. A probe only loads, so entry cache lines
  stay shared and lookups scale across cores. The one store a successful lookup
  makes is taking the matched slot's read lock, where the key is verified
  against the entity itself, so a hash collision never resolves to the wrong
  peer.
- Writers serialize on a single write lock. Displacement and backward-shift each
  move a run of entries, and one writer makes that trivially correct instead of
  a lock-free problem with no simple answer. Writes are off the hot path.
- A reader that keeps losing races eventually serializes behind the writer lock,
  so progress holds under continuous mutation.

Entries are cache-line aligned so a writer's stores never dirty a neighbour.

#### Caller obligations

Do not call a table operation while holding a handle from that table. Writers
wait on slot locks, and a handle holder calling back in closes a cycle.
`RemovePeer` from a thread still holding a `PeerHandle` to that peer waits on
that thread's own lock, forever.

A green test suite over this code says nothing about race-freedom. Changes here
are validated under ThreadSanitizer.

### 3.5 The wire

The Flux wire format is little-endian, and every multi-byte access goes through
`common`'s byte cursors (section 2). Never assume host byte order. (`htons` and
`ntohs` appear in `address.h` for OS `sockaddr` structures, which is a separate
concern from wire payload.)

Packet layout is driven by independent bits in the leading controller byte:

```
secure    [Controller(1)][Tag(16)][NonceCounter(8)][PeerTag(4)?] ‖ [Channel(1)][FlowId(2)][FlowSeq(4)]?[payload]
unsecured [Controller(1)][payload]
```

Everything after the `‖` is ciphertext. The controller byte and peer tag are
authenticated associated data: readable on the wire, not alterable.

The nonce counter is masked. It has to travel — the receiver cannot otherwise
know which packet it holds — but in the clear it is a serial number, and a
sequence that stops at one address and resumes at the next value from another
links a peer across a migration however the tag rotates. So the field carries
the counter XORed with a mask derived from a per-peer header key and that
packet's own AEAD tag: unique per packet, so the same counter never produces
the same bytes twice. Both ends recompute it from the session; an observer sees
eight bytes that never form a sequence. The header key is split off the session
key at commit rather than reused, since XChaCha20 derives its own internal
subkey the same way.

The channel byte is the first byte of the encrypted plaintext rather than a
header field. Zero is application data and anything else is internal control —
path validation, flow open, close, and ack. A control packet is therefore
byte-for-byte indistinguishable from data to any observer, including one that
knows Flux's format, and the receiver learns which it holds only after a
successful decrypt.

Handshake packets are the only cleartext opcodes (`HS_INIT`, `HS_CHLG`,
`HS_RES`, `HS_FINISH`), carried on unsecured internal packets because no key
exists yet.

Every wire constant is named in `flux/internal/constants.h`.

### 3.6 The paths

Each core operation below has a stated number of sanctioned paths.

#### Reaching a peer: three keys, one table

| Route | Call | When |
|---|---|---|
| by address | `PeerTable::GetPeer(const Address&)` | the ordinary receive and send path |
| by id | `PeerTable::GetPeer(const BcpId&)` | after a peer proves an id; survives migration |
| by tag | `PeerTable::GetPeersByTag(...)` | migration only; multi-valued |

All three return a read-locked `PeerHandle`, and nothing outside `PeerTable`
reaches a peer slot directly.

The tag route is multi-valued on both sides: one peer holds several tags at once
(its migration window, capped at `MAX_TAGS_PER_PEER`), and two peers may derive
the same tag by chance. A clash resolves by trial decryption, since only the
peer whose key authenticates the packet is the real one.

#### Sending: one seal, five origins

`Socket::SealSecurePacket` is the only place an outbound secure packet is
encrypted. Five things originate a send, and every encrypted one funnels through
that seal:

1. Application, non-flow — `BuildPacket().NoFlow().Send()` / `.SendSecured()`
2. Application, on a flow — `BuildPacket().WithFlow(flow).Send()` / `.SendSecured()`
3. Handshake — `BuildInternal(op)`, unsecured because no key exists yet
4. Secure control — `SendSecureControl(...)`, path validation and the flow
   control plane, wire-identical to data
5. Retransmit and waiting-ring drain — `SealStagingToWire(...)`, shared by
   `ResendStaging` and `DrainWaitingSends`

`PacketBuilder` requires the packet's kind to be declared before any payload is
written, because the declaration decides which pool the body goes into and that
cannot change mid-write. A reliable flow's body must survive its own send, since
it is the retransmit source, so it goes to a retained staging slot; everything
else goes to a kernel send slot, is encrypted in place, and is released once it
is on the wire.

Replying starts from the received packet instead of the socket:
`PacketSlotHandle::PrepareResponse()` returns the same `PacketBuilder` as
`BuildPacket`, aimed at that packet's source, and the chain ends with
`Respond()` or `RespondSecured()` in place of `Send(Address)`. The address is
taken from the packet because a reply is the one case where the destination is
already known exactly, so rebuilding the pairing by hand would only add a way
to get it wrong. `Poll` stamps its socket into every handle it delivers, which
is what lets the handle mint the builder; any other handle yields one whose
stages refuse to send. Kind, content and terminal are the unchanged origin 1
and 2 path.

`Send` is best-effort. `SendSecured` delivers only to a peer authenticated
against a trusted certificate.

#### Admitting a flow packet: one gate, five outcomes

The gate is split into a decision and a mutation. `CanSend` is a pure predicate
over the already-locked flow and peer: is a ring slot free, is
`unresolved < grantedWindow` (reliable only), does the peer's congestion budget
cover this packet. `StampFlowPacket` assumes the predicate passed and only
mutates: assign the sequence number, take the ring entry, spend the budget,
write the seq.

`AdmitFlowPacket` sequences the two under the peer lock the caller already
holds. The peer is lent by reference and never re-looked-up, so a send touches
the peer table once. The outcome is one of five, and ownership of the packet
slot moves differently in each:

| Outcome | Meaning | Slot owner afterwards |
|---|---|---|
| `Sent` | stamped and in flight | proceeds to seal and wire |
| `Queued` | window or budget full | the flow's waiting ring |
| `Dropped` | unreliable, no buffer configured | released; not an error |
| `Rejected` | reliable waiting ring full | released; `TooManyPending` to the app |
| `Dead` | no such flow, or not `OPEN` | released; a real failure |

A refused packet is routed by mode, and the two modes diverge when the waiting
buffer fills. A reliable flow rejects the newest send, so nothing already
accepted is dropped and the application gets a backpressure signal. An
unreliable flow evicts its oldest waiting packet to seat the newest, so an
unreliable send is never refused for capacity. The waiting ring is strict FIFO:
while anything waits, a new packet joins the back even if capacity just freed,
because otherwise its sequence number would outrun older data.

#### Receiving: one gate, four sinks, two passes

`Poll` runs two passes. Pass 1 processes the kernel batch through a single
inbound gate, `PreProcessIn`, which handles the known-peer check for unsecured
traffic, decryption for secure traffic, then replay and liveness. Everything it
admits goes to one of four sinks:

1. `ProcessInternal` — handshake traffic, consumed and never delivered
2. `ProcessSecureControl` — path validation and the flow control plane
3. `ProcessFlowIn` — flow data
4. `QueueReady` — non-flow application data

Pass 2 drains the ready queue into the caller's buffer. Packets never leave the
receive pool; the application receives handles into it.

#### Delivering an in-flow packet: two deliverers

`ProcessFlowIn` dispatches on mode to one of two. `DeliverOrdered` handles
`RELIABLE_ORDERED`: an in-window gap parks the packet in the hold-back ring and
past-window packets are ejected, and when the gap fills `DrainHoldbackRun`
releases the newly contiguous run as a continuation of this path.
`DeliverUnordered` handles `RELIABLE_UNORDERED` and `UNRELIABLE`, delivering on
arrival.

Both consult the in-flow's seen bitmap. A retransmitted flow packet wears a
fresh nonce and so passes cleanly through the anti-replay window one layer up,
and only the bitmap can distinguish "sequence 6, again" from "sequence 6,
finally".

### 3.7 Lifecycles

#### Handshake

```
initiator                                  responder
SendHandshakeInit  ──HS_INIT──▶            Handshake_Challenge   (stateless)
Handshake_Respond  ──HS_RES───▶            Handshake_Validate    (verify, then
                   ◀──HS_FINISH──           register + key + finish)
Handshake_Complete (key, flush parked packets)
```

The responder holds no state through the challenge and creates a peer only after
verification, so responder-side peers are born `ESTABLISHED` while the initiator
passes through `AWAITING_CHALLENGE` and `AWAITING_FINISH`. An unverified
initiator costs the responder nothing to ignore.

Both sides bind a role-ordered transcript into the session key and into a
confirmation MAC:

```
initiatorPk ‖ responderPk ‖ saltI ‖ saltR
  ‖ initiatorCaps ‖ responderCaps ‖ initiatorVersion ‖ responderVersion ‖ tag
```

Version and capabilities sit inside the MAC'd transcript, so a tampered or
downgraded negotiation fails key confirmation instead of succeeding quietly.

Packets sent to a peer mid-handshake are parked in the pending pool as an
intrusive list — each slot holds the next index, so a peer stores only head and
tail — and flushed when the session completes.

The two ends compare public keys, and the lower is lane 0 while the other is
lane 1. Each side's send counter therefore occupies a distinct nonce space, so
two independent counters under one shared key cannot collide.

#### Address migration

A connection survives its peer's address changing without a re-handshake. Secure
packets carry a rotating 4-byte tag derived identically at both ends from the
session key and never exchanged.

When a packet arrives from an unknown address, Flux looks up its tag,
trial-decrypts each candidate, and on the genuine mover delivers immediately,
since AEAD has already proved identity. Only the return route waits: a path
challenge is armed, and the old address stands until it is answered. An unproven
address never tears down a proven session, and a spoofed replay cannot redirect
traffic.

Unknown-address tag lookups are budgeted per `Poll` pass. Genuine moves are
rare, a burst beyond the budget looks like a flood, and a legitimate mover past
it retries on its next packet.

`RotateTags` advances every established peer's tag together, so a local address
change is not linkable by tag either. An observer must not be able to re-link a
connection across an address change the user made in order to break that link.

#### Flows

Opening is local and costs nothing on the wire. A flow is born `OPEN` and can
be sent on the instant `OpenFlow` returns, including before the peer handshake
has completed, and the receiver builds its half from whichever packet reaches
it first. Closing is still a wire exchange. `FAILED` is terminal, reached when
the remote rejects the flow or a packet exhausts its retransmits; the rings are
drained and the congestion bytes refunded immediately, but the slot waits for
the application to observe the failure through its handle before being
recycled.

Every flow packet carries a flow data byte alongside the id and sequence: three
bits of mode, five bits of window exponent. It rides every packet rather than
only the first so that a lost or reordered opener costs nothing, and it is what
registration reads. The receiver refuses a flow whose declared window exceeds
its own seen bitmap, because a sender outrunning that bitmap could have a
retransmit arrive older than anything still remembered and be delivered twice.

Registration is caps-only: a dry pool, a full per-peer directory, or a window
too wide yields `FLOW_REJECT`, and the sender fails that one flow rather than
retransmitting into silence. Every other flow to the same peer is unaffected.
This is the one path on which a remote makes this socket allocate, and it is
reachable only after that peer completed a handshake.

The per-peer flow directory is split in two so that "my flow 3 to you" and "your
flow 3 to me" cannot collide. Which directory a message resolves against follows
from who opened the flow: data and `FLOW_CLOSE` name the sender's out-flow and
land in the in directory, while `FLOW_REJECT` and `FLOW_CLOSE_ACK` answer our
own flows and land in the out directory.

A reliable flow's plaintext is its retransmit source and lives in the staging
pool until its sequence resolves. That is why a packet parked behind an
unfinished handshake records which pool it came from: the flush must put a
retained body back into staging, since the in-flight ring releases it there.

#### Congestion control

The budget is per peer and measured in bytes, and only flow packets spend it,
since non-flow traffic is untracked. It starts at ten full packets' worth, grows
on acknowledgement, and trims on loss to a percentage of itself, never below a
configured floor that is itself never less than one full wire packet, so the
gate can always admit a packet once the path drains.

Feedback crosses locks in one direction. A `CongestionDelta` is accumulated
under the flow lock and applied to the peer under the peer lock; the flow side
only accumulates and never reaches for the peer, which keeps the peer-then-flow
ordering acyclic.

#### Peer eviction

Optional and off by default. When enabled, a peer from whom nothing has been
received for the configured timeout is torn down on the tick, bounded per call
so a mass idle-out cannot stall `Update`.

Received traffic is the only signal, because this socket's own sends prove
nothing about whether the remote is still there. A fresh peer gets one full
timeout to complete its handshake, and forgeable handshake chatter does not
refresh the clock.

Liveness stamps are monotonic microseconds right-shifted into roughly 1.024 ms
units, wrapping in 32 bits about every 49.7 days. Elapsed time is computed with
wrapped subtraction and stays exact under one wrap, so a peer idle past a full
wrap can only be evicted late. Stamps refresh lazily on a configured grain,
which bounds stamp writes to one per grain per peer.

### 3.8 Platform backends

All platform-specific code lives behind an `ISocketKernel` implementation, and
nothing OS-specific leaks into `Socket` or above. Adding a backend means
implementing the interface and wiring its `BackendType` case, without editing
callers.

Windows, Linux and macOS are all targets, on x86-64 and arm64. A path that
compiles everywhere carries no architecture-specific intrinsic unconditionally:
the 16-byte compare-and-swap flag in `CMakeLists.txt` is guarded by a processor
check, because arm64 has the capability without asking for it.
