# Architecture

Flux is a connectionless encrypted UDP transport. It builds on `common`, a
standalone systems library vendored in `external/common` and developed on its
own. `common` is meant to carry nothing that only makes sense to a transport,
and three places currently break that: the error enum names transport
conditions, `platform.h` pulls in the OS socket headers, and `BytesWriter`
carries a pointer to a packet length field. They are listed here rather than
quietly excepted, because a rule with unlisted exceptions is not a rule.

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
one of its consumers. A type that only makes sense to a transport belongs in
`flux`. The exceptions named above are the whole list, and nothing new joins it.

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

---

## 3. `flux`

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
`Identity`, this socket's long-term keypair; and `ReplayWindow`, one per peer
slot.

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

Nothing on the packet path allocates. There are eleven pools, each with one
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

### 3.3 Ownership: the handles

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

### 3.4 Concurrency

Flux owns no thread. Work happens on a caller's thread. Four entry points carry
the packet path and all of them are safe to call concurrently:

- `Poll` processes inbound packets and drains a lane of ready ones to the
  application.
- `Update` runs the tick: retry handshakes, flush owed acks, retransmit, drain
  waiting sends, evict idle peers, reclaim jammed receiving flows. All
  time-based work lives here.
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

### 3.5 The wire

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

The controller bits: `CTRL_INTERNAL` marks handshake traffic, consumed and
never delivered. `CTRL_HAS_FLOW` says the flow header sits inside the seal.
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

### 3.5b Where the code lives

Four pieces sit in their own files rather than inside `Socket` or `FlowTable`,
because each is one job and neither of those is:

| File | Holds |
|---|---|
| `crypto/packet_seal.cpp` | the two seals and the two opens, and nothing that reaches a peer, a flow or a pool |
| `flow/flow_batching.cpp` | the open batch on a sending association: what may join it and what its bytes cost |
| `flow/assoc_directory.cpp` | flow id to slot index, per peer, per direction |
| `peer/congestion.cpp` | the AIMD budget, which belongs to the peer and not to any one flow |

The split is by job, not by size. The handshake and the migration receive path
are both larger than any of these and both stay where they are: each reaches
most of `Socket`, so moving either would trade one large file for a large file
plus a wide interface.

### 3.6 The paths

#### Reaching a peer: three keys, one sweep, one raw index

| Route | Call | When |
|---|---|---|
| by address | `PeerTable::GetPeer(const Address&)` | the ordinary receive and send path |
| by id | `PeerTable::GetPeer(const BcpId&)` | after a peer proves an id, survives migration |
| by tag | `PeerTable::GetPeersByTag(...)` | migration only, multi-valued |

All three return a read-locked `PeerHandle`. The tag route is multi-valued
because one peer holds several tags at once (its rotation window, capped at
`MAX_TAGS_PER_PEER`) and two peers may derive the same tag by chance. A clash
resolves by trial decryption.

Two more routes exist and neither yields a handle. `CollectAddresses` copies out
every live address so the tick and `Flush` can walk peers without holding the
table, and it takes the writer lock, which is the opposite profile from the three
lookups above. And a bare slot index, handed out by `RegisterPeer`, is what the
handshake carries between its steps: every binding call (`BindId`, `BindTag`,
`UnbindTags`, `UpdateAddress`) is keyed on that index rather than on a handle.
Reads go through a verified key; those mutations do not.

#### Three security levels

A packet is encrypted, authenticated but readable, or neither. `PacketBuilder`
picks with `MacOnly()` and `Unsecured()`, and encrypted is the default. Mac-only
carries the same framing and the same tag as encrypted and costs roughly half the
crypto, for traffic that is public anyway and sent often. Unsecured carries no
tag at all and cannot carry a flow, because a forged packet could otherwise name
any sequence it liked.

#### Sending: two seals, six origins

An outbound packet is sealed one of two ways. `SealSecurePacket` encrypts the
payload and covers it with a tag. `SealMacOnlyPacket` leaves the payload readable
and covers it with the same tag, for traffic that is public anyway and sent
often. Framing is identical either way, so every offset matches and only the
seal and the open differ. The receive side mirrors them with `OpenSecurePacket`
and `OpenMacOnlyPacket`.

Six things originate a send:

1. Application, non-flow: `BuildPacket().NoFlow()...Send()` or `.SendSecured()`
2. Application, on a flow: `BuildPacket().WithFlow(flow)...Send()` or `.SendSecured()`
3. Handshake: `BuildInternal(op)`, unsecured because no key exists yet
4. Secure control: `SendSecureControl(...)`, wire-identical to data
5. Retransmit: `ResendStaging(...)` into `SealStagingToWire`
6. The waiting-ring drain: reliable entries go through `SealStagingToWire` like
   a retransmit, unreliable ones are sealed and sent where they sit, because
   nothing retains them and there is no staging copy to seal from

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

#### Receiving: one gate, three sinks, one bypass, two passes

Handshake traffic goes to `ProcessInternal` before the gate runs at all. It is
unauthenticated by construction, so a known-peer check, a decrypt and a replay
window have nothing to apply to it. The bypass is narrow: a packet claiming to
be internal and secure at once is forged or corrupt, and is dropped.

Everything else runs through `PreProcessIn` (known-peer check for unsecured
traffic, decryption for secure, then replay and liveness), which routes what it
admits to one of three sinks:

1. `ProcessSecureControl`: path validation, flow reject, flow ack
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

An entry is `[flowId(2)][epoch(1)][rangeCount(1)][recvNext(4)]` followed by that
many `[first(4)][last(4)]` pairs.

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
initiatorPk ‖ responderPk ‖ initiatorEph ‖ responderEph ‖ saltI ‖ saltR
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
socket sized for ten does not. A grant is per peer rather than per socket. Configuration sets what a peer
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

`FAILED` is terminal, reached when the remote rejects the flow or a packet
exhausts its retransmits. The rings drain and the congestion bytes refund
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

#### Congestion control

The budget is per peer, in bytes, and only flow packets spend it. It starts at
ten full packets, grows on acknowledgement, trims on loss to a percentage of
itself, and never drops below a configured floor of at least one full wire
packet, so the gate can always admit a packet once the path drains. Feedback
crosses locks in one direction: a `CongestionDelta` accumulates under the flow
lock and is applied to the peer under the peer lock.

#### Peer eviction

Always on. A zero timeout selects the default rather than switching it off, so
there is no configuration in which a silent peer is kept forever. A peer from
whom nothing has been received for the
configured timeout is torn down on the tick, bounded per call. Received traffic
is the only signal, because this socket's own sends prove nothing, and
forgeable handshake chatter does not refresh the clock. Liveness stamps are
monotonic microseconds shifted to roughly 1 ms units, wrapping in 32 bits about
every 51 days, with wrapped subtraction, so a peer idle past a full wrap can
only be evicted late.

### 3.8 Platform backends

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
