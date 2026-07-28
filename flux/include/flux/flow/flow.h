#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include <flux/address.h>
#include <flux/internal/constants.h>
#include <flux/peer/peer_id.h>

namespace bcp::flux
{
    /** What the flow type controls: whether lost data is retransmitted, and
        whether delivery waits for order. Every flow packet is numbered and
        acknowledged regardless of mode. UNRELIABLE means never retransmitted,
        not invisible to the transport.
    */
    enum class FlowMode : uint8_t
    {
        RELIABLE_ORDERED   = 0,  ///< sequenced byte-stream: retransmit, deliver in order
        RELIABLE_UNORDERED = 1,  ///< independent messages: retransmit, deliver on arrival
        UNRELIABLE         = 2,  ///< numbered + acked for loss visibility, never retransmitted
    };

    /** The flow data byte, after the sequence number in every flow packet:
        bits 0-2 the mode (values 3-7 reserved for modes to come), bits 3-7 the
        window exponent, window = 16 << exponent, so 1 is 32 and 11 is 32768.

        It rides every packet rather than only the first so the receiver can
        register the flow from whichever packet arrives first: a lost or
        reordered opener costs nothing. Encode returns 0, never a valid
        encoding, when the mode or window cannot be expressed; Decode refuses
        the same values coming in, because they arrive from the network. */
    [[nodiscard]] inline uint8_t EncodeFlowData(FlowMode mode, uint32_t window) noexcept
    {
        if (static_cast<uint8_t>(mode) > 2)
            return 0;

        uint8_t exponent = 0;
        for (uint8_t e = 1; e <= 11; ++e)
        {
            if (window == (16u << e))
            {
                exponent = e;
                break;
            }
        }
        if (exponent == 0)
            return 0;

        return static_cast<uint8_t>(static_cast<uint8_t>(mode) | (exponent << 3));
    }

    [[nodiscard]] inline bool DecodeFlowData(uint8_t data, FlowMode& outMode,
                                             uint32_t& outWindow) noexcept
    {
        const uint8_t modeBits = data & 0x07;
        const uint8_t exponent = data >> 3;

        if (modeBits > 2 || exponent < 1 || exponent > 11)
            return false;

        outMode   = static_cast<FlowMode>(modeBits);
        outWindow = 16u << exponent;
        return true;
    }

    /** A flow's lifecycle. A flow is born OPEN and usable immediately: opening
        is local, and the remote registers its receiving side from whichever
        data packet reaches it first. Closing is still a wire exchange. FAILED
        is terminal, entered when the remote rejects the flow or a packet runs
        out of retransmit attempts; the flow stops sending, its rings are
        drained, and the slot waits for the app to observe the failure through
        its handle before CloseFlow recycles it.
    */
    enum class FlowLifecycle : uint8_t
    {
        OPEN    = 0,
        CLOSING = 1,
        CLOSED  = 2,
        FAILED  = 3,
    };

    /** The identity and lifecycle every flow carries regardless of direction,
        embedded as the FIRST member of both flow types so shared machinery
        (open/close retries, epoch checks, the peer-removal sweep) can operate
        on either pool's slots through this one shape.

        How a flow operation finds its peer: peerSlot is the direct route. It
        cannot go stale, because RemovePeer closes and frees every flow a peer
        owns before releasing the peer's slot, so a flow never outlives the peer
        it indexes. peerAddr/peerId are the verified routes for hand-over-hand
        crossings (flow lock released before the peer is approached): by id once
        the peer is established (stable across address migration), by address
        before then, safe because a peer cannot migrate before it has a session.
    */
    struct FlowCore
    {
        uint32_t peerSlot;
        Address  peerAddr;      ///< address at open time, not maintained after
        BcpId    peerId;        ///< all-zero until the peer proves one

        uint32_t epoch;         ///< bumped on every lease; stale handles miss
        uint16_t flowId;
        FlowMode mode;
        FlowLifecycle life;

        uint8_t  attempts;              ///< FLOW_CLOSE retries so far
        uint64_t lastCtrlSentMicros;    ///< last close send, for retry pacing
    };

    /** One packet this side sent and still awaits an ack for. Lives in the
        out-flow's in-flight ring, indexed by seq & (cap - 1): the slot for a
        seq is computed, never searched. Free is seq == 0 (the never-sent
        sentinel; resolution zeroes it). packetSlot cannot mark freedom, because
        an unreliable flow's entries never hold one. An occupied entry under a
        new seq is the ring wrapping onto an unresolved packet: the flow is at
        its window and must not send until something resolves.

        packetSlot is the retained plaintext in the socket's staging pool, the
        retransmit source, released when the seq resolves. INVALID on an
        unreliable flow, whose entries track loss and budget only.
    */
    struct InFlightEntry
    {
        uint64_t sentAtMicros;
        uint32_t seq;
        uint32_t packetSlot;
        uint16_t wireSize;     ///< budget spent on this packet, refunded on resolve
        uint8_t  retries;      ///< retransmits so far; the give-up counter
    };

    /** One packet received ahead of order on a RELIABLE_ORDERED in-flow, held
        until the gap before it fills. Same ring indexing as InFlightEntry.
        packetSlot == INVALID means free.
    */
    struct HoldbackEntry
    {
        uint32_t seq;
        uint32_t packetSlot;
    };

    /** One packet accepted by Send but not yet admitted to the wire (the flow's
        window or the peer's congestion budget was full). Lives in the out-flow's
        waiting ring, a strict FIFO walked head-first (unlike the seq-indexed
        rings above): entries occupy [waitingHead, waitingHead + waitingCount).

        packetSlot is where the still-plaintext body waits: the socket's staging
        pool on a reliable flow (the same retained body the in-flight ring takes
        over once stamped), the kernel's send pool on an unreliable one. wireSize
        is recorded at enqueue so the drain can query the budget without touching
        the slot; a packet slot's lock must never be taken under the peer or flow
        lock. waitingSince orders the drain across a peer's flows, oldest first.
    */
    struct WaitingEntry
    {
        uint64_t waitingSince;
        uint32_t packetSlot;
        uint16_t wireSize;
    };

    /** A contiguous range of received seqs, inclusive on both ends. The wire
        representation inside a FLOW_ACK body. Acks are cumulative state reports
        generated from the in-flow's seen bitmap at flush time, never a stored
        delta: a lost FLOW_ACK is fully covered by the next one.
    */
    struct AckRange
    {
        uint32_t first;
        uint32_t last;
    };

    /** One entry of a peer's flow directory: the per-peer map from wire flowId
        to the flow's slot in the matching pool. Each peer has TWO directory
        segments, out-flows (opened by this socket) and in-flows (opened by the
        remote), in separate socket-owned blocks, each guarded by the peer's slot
        lock. The split lets the remote's opens be bounded and pooled
        independently of our own, and keeps "my flow 3 to you" and "your flow 3
        to me" from colliding: every message type resolves against one side
        (data and FLOW_CLOSE name the sender's out-flow, so they land in the IN
        directory; FLOW_REJECT and FLOW_CLOSE_ACK answer our own flows, so they
        land in the OUT directory). flowSlot == INVALID marks a free entry; pad is the
        alignment gap, named and zeroed rather than implicit.
    */
    struct FlowDirEntry
    {
        uint16_t flowId;
        uint16_t pad;
        uint32_t flowSlot;
    };

    /** A flow this socket opened: the SENDING half. One slot in the out-flow
        pool. The pool hands out raw bytes and never runs constructors, so this
        must stay trivially copyable, and whoever leases a slot writes every
        field except core.epoch, which survives and advances.

        The slot is larger than the struct; the in-flight and waiting rings
        follow it:
          [OutFlowState][InFlightEntry x inflightCap][WaitingEntry x waitingCap]
        Both caps are powers of two fixed at Init (in-flight slots are
        seq & (cap - 1); waiting is a head + count FIFO) and stamped here so
        slots self-describe. waitingCap differs by mode (reliable and unreliable
        flows take their own Config knob), while the pool stride is sized for the
        larger of the two.

        Seqs count packets ("the Nth packet of this flow") starting at 1; 0 is
        the never-sent sentinel, so a zeroed field reads as "nothing yet".

        The flow keeps at most inflightCap packets unresolved, which is also
        the window it declares on the wire: the receiver checks the declared
        width against its own bitmap at registration and rejects a flow it
        could not dedupe, so the window can never outrun the receiver's memory
        whatever either socket's config says.
    */
    struct OutFlowState
    {
        FlowCore core;

        uint32_t nextSeq;

        /** Packets stamped and not yet resolved (acked or declared lost). The
            send gate: a stamp is refused while unresolved == inflightCap,
            which enforces the receiver's grant. The ring's own wrap check bounds
            only inflightCap, which may be larger than what the receiver can
            dedupe.
        */
        uint32_t unresolved;

        /** Smoothed RTT state for this flow's retransmit timeout, in
            microseconds; 0 until the first sample.
        */
        uint32_t srttMicros;
        uint32_t rttvarMicros;

        uint16_t inflightCap;   ///< power of two, from Config; sizes the in-flight ring
        uint16_t waitingCap;    ///< power of two or 0, by mode from Config; sizes the waiting ring

        /** The waiting FIFO's cursors: waitingHead indexes the oldest entry
            (masked by waitingCap - 1; it only ever advances), waitingCount how
            many are queued. The head entry is the only one the drain considers;
            within a flow, packets leave in the order Send accepted them.
        */
        uint32_t waitingHead;
        uint32_t waitingCount;

        InFlightEntry* InFlight()
        {
            return reinterpret_cast<InFlightEntry*>(
                reinterpret_cast<uint8_t*>(this) + sizeof(OutFlowState));
        }
        const InFlightEntry* InFlight() const
        {
            return reinterpret_cast<const InFlightEntry*>(
                reinterpret_cast<const uint8_t*>(this) + sizeof(OutFlowState));
        }
        WaitingEntry* Waiting()
        {
            return reinterpret_cast<WaitingEntry*>(
                reinterpret_cast<uint8_t*>(this) + sizeof(OutFlowState)
                + inflightCap * sizeof(InFlightEntry));
        }
        const WaitingEntry* Waiting() const
        {
            return reinterpret_cast<const WaitingEntry*>(
                reinterpret_cast<const uint8_t*>(this) + sizeof(OutFlowState)
                + inflightCap * sizeof(InFlightEntry));
        }

        static constexpr size_t StrideFor(uint16_t inflightCap, uint16_t waitingCap)
        {
            return sizeof(OutFlowState)
                 + inflightCap * sizeof(InFlightEntry)
                 + waitingCap * sizeof(WaitingEntry);
        }
    };

    /** A flow the remote opened with this socket: the RECEIVING half. One slot
        in the in-flow pool, an order of magnitude smaller than an out slot,
        because this is the side a REMOTE can make us allocate. Same pool rules
        as OutFlowState: trivially copyable, every field written on lease, epoch
        survives.

        The slot layout:
          [InFlowState][seen bitmap][HoldbackEntry x reorderCap]

        The seen bitmap is this side's memory of which seqs arrived: one bit per
        seq in a sliding window below recvHighest, the anti-replay-window shape
        one layer up. It exists because a retransmitted flow packet wears a fresh
        nonce and sails through the replay window; only this can tell "seq 6,
        again" from "seq 6, finally". Its width (windowBits) is what this socket
        granted the opener: the sender clamps its in-flight to the grant, so a
        seq below the window floor is provably resolved and an arrival there can
        only be a stale duplicate. Acks are emitted from this bitmap as
        cumulative reports; nothing is cleared on flush.
    */
    struct InFlowState
    {
        FlowCore core;

        /** recvNext is the ordered-delivery cursor (the seq the app is owed
            next); recvHighest the highest seq seen, so a packet landing above
            recvHighest + 1 is a gap, the loss signal. newSinceFlush counts seqs
            first-seen since the last ack flush: 0 means nothing is owed, and
            crossing the fill threshold forces a flush early.
        */
        uint32_t recvNext;
        uint32_t recvHighest;
        uint32_t newSinceFlush;
        uint64_t ackArmedMicros;  ///< when this flow first owed an ack since the
                                  ///< last flush; the deadline is ackArmedMicros
                                  ///< + Config::flowAckDelay. 0 when none owed.

        uint16_t windowBits;    ///< seen-bitmap width; the window this socket grants
        uint16_t reorderCap;    ///< power of two or 0, from Config

        uint64_t* Seen()
        {
            return reinterpret_cast<uint64_t*>(
                reinterpret_cast<uint8_t*>(this) + sizeof(InFlowState));
        }
        const uint64_t* Seen() const
        {
            return reinterpret_cast<const uint64_t*>(
                reinterpret_cast<const uint8_t*>(this) + sizeof(InFlowState));
        }
        HoldbackEntry* Holdback()
        {
            return reinterpret_cast<HoldbackEntry*>(
                reinterpret_cast<uint8_t*>(this) + sizeof(InFlowState)
                + (windowBits / 8));
        }
        const HoldbackEntry* Holdback() const
        {
            return reinterpret_cast<const HoldbackEntry*>(
                reinterpret_cast<const uint8_t*>(this) + sizeof(InFlowState)
                + (windowBits / 8));
        }

        static constexpr size_t StrideFor(uint16_t windowBits, uint16_t reorderCap)
        {
            return sizeof(InFlowState)
                 + (windowBits / 8)
                 + reorderCap * sizeof(HoldbackEntry);
        }
    };

    static_assert(std::is_trivially_copyable_v<OutFlowState>,
                  "OutFlowState lives in a SlotPool by raw cast, so it must stay trivially copyable");
    static_assert(std::is_trivially_copyable_v<InFlowState>,
                  "InFlowState lives in a SlotPool by raw cast, so it must stay trivially copyable");
    static_assert(offsetof(OutFlowState, core) == 0 && offsetof(InFlowState, core) == 0,
                  "FlowCore must sit at offset 0 so shared lifecycle code can address either type");
}
