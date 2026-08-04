#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include <flux/address.h>
#include <flux/internal/constants.h>
#include <flux/peer/peer_id.h>

// A flow is what the application opens; an association is the state a flow
// keeps with one peer. OpenFlow creates the flow and takes no address, so one
// flow serves every peer it is sent to, and the first packet to each address
// creates that peer's association.
//
// Everything a packet path reads per packet lives on the association. Mode is
// copied there at creation rather than read back from the flow: it never
// changes, and reaching the flow would mean a second lock on the send gate,
// the waiting drain and the retransmit scan.

namespace bcp::flux
{
    /** Whether lost data is retransmitted, and what delivery promises. Every
        flow packet is numbered and acknowledged whatever the mode, so even
        UNRELIABLE traffic feeds congestion control. UNRELIABLE is never resent
        and delivers newest only: it carries current state, so a packet older
        than the newest delivered is dropped as stale. */
    enum class FlowMode : uint8_t
    {
        RELIABLE_ORDERED      = 0,
        RELIABLE_UNORDERED    = 1,
        UNRELIABLE            = 2,
        /** Ordered and reliable like the first, with four times the window.
            For traffic that fills a pipe rather than tracking a clock: the
            depth is throughput on a long path, and the cost is a longer stall
            behind one lost packet, which realtime traffic will not pay. It
            draws its associations from a pool of its own so that cost lands on
            the flows that asked for it. */
        RELIABLE_ORDERED_BULK = 3,
    };

    static constexpr uint8_t FLOW_MODE_COUNT = 4;

    [[nodiscard]] inline bool IsOrdered(FlowMode mode) noexcept
    {
        return mode == FlowMode::RELIABLE_ORDERED
            || mode == FlowMode::RELIABLE_ORDERED_BULK;
    }

    /** Whether a mode keeps sent bodies for retransmission. */
    [[nodiscard]] inline bool IsReliable(FlowMode mode) noexcept
    {
        return mode != FlowMode::UNRELIABLE;
    }

    /** In-flight window, in packets, for a mode. Both ends derive it from the
        three mode bits on the wire, so a sender's ring and a receiver's seen
        bitmap agree by construction with nothing negotiated. A declared window
        was tried and removed for exactly that reason: nothing forced the two
        to match.

        Unreliable is no smaller than the reliable modes. It is never resent,
        but it is still acknowledged for congestion control, and at a high send
        rate a shallow window would stall waiting for that feedback. */
    [[nodiscard]] inline uint16_t WindowFor(FlowMode mode) noexcept
    {
        return mode == FlowMode::RELIABLE_ORDERED_BULK
             ? internal::FLOW_WINDOW_BULK : internal::FLOW_WINDOW;
    }

    /** Reorder hold-back depth, in packets, for a mode. As deep as the window
        so the receiver can hold everything a sender may put in flight past a
        gap. A shallower buffer would eject in-window packets it cannot hold,
        and the sender would resend them into the same gap until it gives up.
        Unordered modes deliver on arrival and never hold back, so zero. */
    [[nodiscard]] inline uint16_t ReorderCapFor(FlowMode mode) noexcept
    {
        return IsOrdered(mode) ? WindowFor(mode) : 0;
    }

    /** Lifecycle, used at both scopes with different meanings. A flow is OPEN
        until the application closes it, and CLOSING only for the span of that
        close, so nothing opens a new association under a flow going away. An
        association is OPEN until that one target rejects it or stops
        answering, and FAILED there leaves the flow open for every other
        peer. */
    enum class FlowLifecycle : uint8_t
    {
        OPEN    = 0,
        CLOSING = 1,
        CLOSED  = 2,
        FAILED  = 3,
    };

    /** How many positions the flow epoch has. A flow id closed and reopened
        numbers its packets from one again, and the receiver still holds the old
        association at whatever sequence it reached, so the two generations
        would share one sequence space and the second would be read as a batch
        of duplicates. The epoch is what separates them.

        Eight positions leave three generations of forward margin, which is what
        lets a receiver that missed one or two generations entirely still
        recognise the current one as newer. */
    static constexpr uint8_t FLOW_EPOCH_COUNT = 8;
    static constexpr uint8_t FLOW_EPOCH_MASK  = FLOW_EPOCH_COUNT - 1;

    /** Where a packet sits in a message that spans several of them. A message
        larger than one packet is sent as a run of them on one flow, and these
        two bits are the whole of the framing: the transport carries them and
        never assembles anything, so a message has no size limit and the receive
        path allocates nothing to hold one.

        Whole is an ordinary packet, which is a message of one, so every send
        that never asks for anything else keeps behaving exactly as before.

        First is what makes a truncated message recoverable. A flow that fails
        or reopens mid-message leaves the receiver holding a run that will never
        be finished, and the next First tells it to drop what it has rather than
        appending a fresh message onto the wreckage of the old one. */
    enum class FlowPart : uint8_t
    {
        Whole  = 0,   ///< a message of one packet
        First  = 1,   ///< opens a message, more to come
        Middle = 2,   ///< neither opens nor closes
        Last   = 3,   ///< closes the message opened by an earlier First
    };

    /** Bit 7 says a packet continues something earlier rather than saying one
        opens a message, so an ordinary packet still encodes both bits as zero
        and nothing about an existing send changes. */
    static constexpr uint8_t FLOW_PART_MORE = 0x40;   ///< bit 6: more follows
    static constexpr uint8_t FLOW_PART_CONT = 0x80;   ///< bit 7: continues an earlier packet

    /** Ordered delivery is what lets two bits carry the whole framing, so the
        other modes have no use for them and must refuse them. On an unordered
        flow the run could arrive in any order and there would be nothing to
        append to, and unreliable delivers newest only, which would tear a
        message apart by design. */
    [[nodiscard]] inline bool FlowPartAllowed(FlowMode mode, FlowPart part) noexcept
    {
        return part == FlowPart::Whole || IsOrdered(mode);
    }

    /** The flow data byte carried after the sequence in every flow packet:
        mode in bits 0-2, epoch in bits 3-5, more-follows in bit 6, and
        message-starts in bit 7. The in-flight window comes from the mode bits
        already here, so nothing about it travels separately.

        The byte rides every packet, not just the first, so a receiver can
        register the flow from whichever packet arrives first, and so a
        generation change is seen on whichever packet of it arrives first rather
        than only on the one that opened it.

        RELIABLE_ORDERED as a whole message encodes as zero, so the byte has no
        spare value to mean failure and both directions report that
        separately. */
    [[nodiscard]] inline bool EncodeFlowData(FlowMode mode, uint8_t epoch,
                                             FlowPart part, uint8_t& outData) noexcept
    {
        if (static_cast<uint8_t>(mode) >= FLOW_MODE_COUNT)
            return false;
        if (epoch > FLOW_EPOCH_MASK)
            return false;
        if (!FlowPartAllowed(mode, part))
            return false;

        uint8_t bits = 0;
        if (part == FlowPart::First || part == FlowPart::Middle) bits |= FLOW_PART_MORE;
        if (part == FlowPart::Middle || part == FlowPart::Last)  bits |= FLOW_PART_CONT;

        outData = static_cast<uint8_t>(static_cast<uint8_t>(mode) | (epoch << 3) | bits);
        return true;
    }

    /** The framing bits out of a flow data byte, without the rest of the
        decode. */
    [[nodiscard]] inline FlowPart FlowDataPart(uint8_t data) noexcept
    {
        const bool more = (data & FLOW_PART_MORE) != 0;
        const bool cont = (data & FLOW_PART_CONT) != 0;
        if (!cont) return more ? FlowPart::First : FlowPart::Whole;
        return more ? FlowPart::Middle : FlowPart::Last;
    }

    /** The epoch out of a flow data byte, without the rest of the decode. The
        control ops echo a generation back and need only this part of it. */
    [[nodiscard]] inline uint8_t FlowDataEpoch(uint8_t data) noexcept
    {
        return static_cast<uint8_t>((data >> 3) & FLOW_EPOCH_MASK);
    }

    /** Reads a flow data byte off the wire. Refuses reserved modes, and refuses
        framing bits on a mode that cannot carry them: this input is
        attacker-chosen, and a receiver that ignored a bit it does not
        understand could not tell a flow it understands from one carrying an
        extension it does not. */
    [[nodiscard]] inline bool DecodeFlowData(uint8_t data, FlowMode& outMode,
                                             uint8_t& outEpoch, FlowPart& outPart) noexcept
    {
        const uint8_t modeBits = data & 0x07u;
        if (modeBits >= FLOW_MODE_COUNT)
            return false;

        const FlowMode mode = static_cast<FlowMode>(modeBits);
        const FlowPart part = FlowDataPart(data);
        if (!FlowPartAllowed(mode, part))
            return false;

        outMode  = mode;
        outEpoch = FlowDataEpoch(data);
        outPart  = part;
        return true;
    }

    /** Where an arriving epoch sits relative to the one an association holds. */
    enum class FlowEpochOrder : uint8_t { Current, Newer, Stale };

    /** Compares by walking forward from what the association holds, because the
        field wraps and equality alone cannot tell a fresh generation from one
        already replaced. A short walk is a generation this side has not caught
        up with. A long walk can only be the field having come round again, so
        the packet is a straggler from a generation that is gone.

        Half the space answers each way, so a straggler arriving after the reset
        is dropped instead of pulling the association back onto a sequence space
        nothing will ever send on again. */
    [[nodiscard]] inline FlowEpochOrder CompareFlowEpoch(uint8_t have, uint8_t seen) noexcept
    {
        const uint8_t forward = static_cast<uint8_t>((seen - have) & FLOW_EPOCH_MASK);
        if (forward == 0)
            return FlowEpochOrder::Current;

        return forward < (FLOW_EPOCH_COUNT / 2) ? FlowEpochOrder::Newer
                                                : FlowEpochOrder::Stale;
    }

    /** Outcome of trying to admit a flow packet to the wire, decided under the
        peer and flow locks. Only Sent proceeds to the seal. Every other outcome
        ends the send here, and who owns the packet slot afterwards differs, so
        the caller's switch must honour it. */
    enum class SendAdmission : uint8_t
    {
        Sent,      ///< stamped and in flight; proceed to seal + wire
        Queued,    ///< held in the flow's waiting ring, which owns the slot now
        Dropped,   ///< unreliable with no buffer configured; discarded, not an error
        Rejected,  ///< reliable waiting ring full; TooManyPending to the app
        Dead,      ///< no such flow, or not OPEN; a real failure
    };

    /** Outcome of registering a remote's flow from the packet that named it.
        Stale means a generation already replaced, which is dropped without an
        answer: nothing is left at the other end to hear one. */
    enum class FlowAdmit : uint8_t { Registered, Existing, Rejected, Stale };

    /** Feedback gathered under a flow lock and applied to the peer under the
        peer lock. The flow side only accumulates, so it never reaches for the
        peer, which is what keeps the peer-then-flow order acyclic. */
    struct CongestionDelta
    {
        uint32_t resolvedBytes   = 0;   ///< in-flight bytes freed (acked or lost)
        uint32_t resolvedPackets = 0;   ///< of those, the count, against the peer's grant
        uint32_t ackedBytes      = 0;   ///< of those, the acked ones; grow the budget
        uint32_t rttSampleMicros = 0;   ///< newest acked round-trip, 0 if none
        bool     sawLoss         = false;
    };

    /** A flow the application opened. Socket-wide, one per flow id, and what a
        FlowHandle points at. Holds no per-peer state and knows no address. */
    struct Flow
    {
        uint32_t epoch;         ///< survives the lease and advances; stale handles miss
        uint32_t firstAssoc;    ///< association list head, INVALID when none
        uint16_t flowId;        ///< INVALID_FLOW_ID marks the slot free
        FlowMode mode;
        uint8_t  flowData;      ///< the wire byte, encoded once at open
        FlowLifecycle life;
    };

    /** One packet sent and not yet acknowledged. Indexed by seq & (cap - 1), so
        an entry is computed rather than searched. seq == 0 marks it free, since
        an unreliable flow's entries never hold a packet slot to mark it with.

        packetSlot is the retained plaintext in the staging pool, this packet's
        retransmit source. INVALID on an unreliable flow, whose entries track
        loss and budget only.

        An acknowledgement frees the window slot but not the copy. A receiver
        that buffered a packet ahead of a gap can be made to drop it again under
        memory pressure, so the copy is held until the receiver reports a
        delivery cursor past this sequence, which is the point past which it can
        no longer ask for it. Only an ordered flow retains: an unordered
        receiver buffers nothing, so its acknowledgement is final. */
    struct InFlightEntry
    {
        uint64_t sentAtMicros;
        uint32_t seq;
        uint32_t packetSlot;
        uint16_t wireSize;     ///< refunded to the congestion budget on resolve
        uint8_t  retries;      ///< give-up counter; the flow fails at the cap
        bool     acked;        ///< resolved, copy retained until the run below it clears
    };

    /** One packet received ahead of order, held until the gap before it fills.
        packetSlot == INVALID means free. */
    struct HoldbackEntry
    {
        uint32_t seq;
        uint32_t packetSlot;
    };

    /** One packet accepted by Send but refused the wire, because the window or
        the peer's congestion budget was full. A strict FIFO over
        [waitingHead, waitingHead + waitingCount), unlike the seq-indexed rings.

        wireSize is recorded at enqueue so the drain can test the budget without
        locking the slot: a packet slot's lock must never be taken under the
        peer or association lock. waitingSince orders the drain across a peer's
        associations, oldest first. */
    struct WaitingEntry
    {
        uint64_t waitingSince;
        uint32_t packetSlot;
        uint16_t wireSize;
    };

    /** A contiguous run of received seqs, inclusive. Acks are generated from the
        seen bitmap at flush time and are cumulative, never a stored delta, so a
        lost ack is fully covered by the next one. */
    struct AckRange
    {
        uint32_t first;
        uint32_t last;
    };

    /** One peer's map from wire flow id to association slot. Each peer owns two
        fixed strips, one per direction, so "my flow 3 to you" and "your flow 3
        to me" cannot collide. Data names the sender's flow and resolves against
        the IN strip; FLOW_REJECT answers our own and resolves against the OUT
        strip.

        flowSlot == INVALID marks a free entry. pad is the alignment gap, named
        so it is zeroed rather than left indeterminate. */
    struct FlowDirEntry
    {
        uint16_t flowId;
        uint16_t pad;
        uint32_t flowSlot;
    };

    /** What a flow keeps with one peer, sending side. Created by the first
        packet sent to that address.

        The slot is larger than the struct; both rings follow it:
          [OutAssociation][InFlightEntry x inflightCap][WaitingEntry x waitingCap]
        Caps are powers of two fixed at Init and stamped here so a slot
        self-describes. waitingCap differs by mode, while the pool stride covers
        the larger.

        Seqs start at 1, so a zeroed field reads as "nothing sent yet".

        The pool hands out raw bytes and runs no constructor, so this must stay
        trivially copyable and a lease writes every field except epoch, which
        survives and advances. */
    struct OutAssociation
    {
        // Which peer. peerSlot is the direct route and cannot go stale, because
        // RemovePeer frees a peer's associations before releasing its slot.
        // peerAddr and peerId are for hand-over-hand crossings, where the
        // association lock is dropped before the peer is approached: by id once
        // the peer is established, since that survives migration, by address
        // before then, when it cannot yet have migrated.
        uint32_t peerSlot;
        Address  peerAddr;
        BcpId    peerId;        ///< all-zero until the peer proves one

        // Which flow, and the next association under it. The directories index
        // peer to association; this list is the only thing that answers the
        // reverse, which is what CloseFlow needs.
        uint32_t flowSlot;
        uint32_t nextInFlow;

        // Copied from the flow at creation, immutable after. mode is read for
        // every packet by the send gate, the drain and the retransmit scan, so
        // it lives here rather than behind a second lock on the flow. flowEpoch
        // is the generation this association belongs to, which is what the ack
        // and reject handlers check before they resolve or fail anything.
        uint16_t flowId;
        FlowMode mode;
        uint8_t  flowEpoch;

        uint32_t epoch;         ///< revalidates the drain's peek against its claim
        FlowLifecycle life;     ///< per target: FAILED here leaves the flow open

        uint32_t nextSeq;
        uint32_t unresolved;    ///< stamped and unacked; the send gate refuses at inflightCap

        /** Lowest sequence whose ring entry may still hold a retained copy.
            Everything below it has been released, so it is the floor a
            receiver can no longer ask about. */
        uint32_t ackBase;

        uint32_t srttMicros;    ///< 0 until the first sample
        uint32_t rttvarMicros;

        uint16_t inflightCap;
        uint16_t waitingCap;

        uint32_t waitingHead;   ///< masked by waitingCap - 1; only advances
        uint32_t waitingCount;

        /** The batch being filled, and the whole of the batching state. Sends
            append into the inline buffer below until it is sealed, by a message
            that will not fit or by Flush, and sealing hands it to the ordinary
            admit path. So the batch takes the flow's next sequence and every
            ack, retransmit and dedupe stays exactly as it was: the reliability
            machinery only ever sees one wire packet per sequence and never
            learns how many messages rode inside it.

            One open batch per flow, never more. Two would let a later message
            seal into an earlier sequence, which is reordering the packer
            invented rather than the network.

            The buffer is inline rather than a pooled slot so this association's
            own lock covers it. Finding a pooled slot would mean taking the
            association lock and then the slot's, which is the reverse of the
            packet-then-flow order the rest of the send path takes.

            used is zero when no batch is open. header is where the packet's own
            framing ends and the message list begins, captured from the first
            message because it already carries exactly the framing this batch
            needs. firstLen exists because that first message is stored with no
            length in front of it, which is what keeps a one-message batch
            identical on the wire to an unbatched packet, and the length has to
            come from somewhere when a second message forces it to grow one. */
        uint16_t openBatchUsed;
        uint16_t openBatchHeader;
        uint16_t openBatchCount;
        uint16_t openBatchFirstLen;

        /** Set while a flush is carrying this batch to the wire, between the
            copy out and the confirmation that it went. An append landing in
            that gap would either be thrown away when the batch is cleared, or
            resent along with messages that already left, so appends are refused
            while it is set and their messages open the next batch instead. */
        bool     openBatchInFlight;

        InFlightEntry* InFlight()
        {
            return reinterpret_cast<InFlightEntry*>(
                reinterpret_cast<uint8_t*>(this) + sizeof(OutAssociation));
        }
        const InFlightEntry* InFlight() const
        {
            return reinterpret_cast<const InFlightEntry*>(
                reinterpret_cast<const uint8_t*>(this) + sizeof(OutAssociation));
        }
        WaitingEntry* Waiting()
        {
            return reinterpret_cast<WaitingEntry*>(
                reinterpret_cast<uint8_t*>(this) + sizeof(OutAssociation)
                + inflightCap * sizeof(InFlightEntry));
        }
        const WaitingEntry* Waiting() const
        {
            return reinterpret_cast<const WaitingEntry*>(
                reinterpret_cast<const uint8_t*>(this) + sizeof(OutAssociation)
                + inflightCap * sizeof(InFlightEntry));
        }

        /** The batch under construction: one whole packet, its own framing then
            the messages packed behind it. Sized for the largest packet this
            socket would ever put on the wire, since that is the most a batch
            can ever hold. */
        uint8_t* OpenBatch()
        {
            return reinterpret_cast<uint8_t*>(this) + sizeof(OutAssociation)
                 + inflightCap * sizeof(InFlightEntry)
                 + waitingCap * sizeof(WaitingEntry);
        }
        const uint8_t* OpenBatch() const
        {
            return reinterpret_cast<const uint8_t*>(this) + sizeof(OutAssociation)
                 + inflightCap * sizeof(InFlightEntry)
                 + waitingCap * sizeof(WaitingEntry);
        }

        static constexpr size_t StrideFor(uint16_t inflightCap, uint16_t waitingCap)
        {
            return sizeof(OutAssociation)
                 + inflightCap * sizeof(InFlightEntry)
                 + waitingCap * sizeof(WaitingEntry)
                 + internal::MAX_WIRE_PACKET_SIZE;
        }
    };

    /** What a remote's flow leaves with this socket, receiving side. Created by
        the first packet that arrives on it, which is the one path where a
        REMOTE makes this socket allocate, so it is an order of magnitude
        smaller than the sending half and capped per peer.

        The slot layout:
          [InAssociation][seen bitmap][HoldbackEntry x reorderCap]

        The seen bitmap is this side's memory of which seqs arrived. It exists
        because a retransmit wears a fresh nonce and passes the replay window
        looking new, so only this can tell "seq 6 again" from "seq 6 finally".
        Its width is the in-flight window for this mode, which both ends derive, so
        a seq below the floor is provably resolved and can only be a stale
        duplicate.

        Same pool rules as the sending half. */
    struct InAssociation
    {
        uint32_t peerSlot;
        Address  peerAddr;
        BcpId    peerId;

        uint16_t flowId;        ///< the REMOTE's flow id, from the wire
        FlowMode mode;          ///< decoded from the flow data byte
        uint8_t  flowEpoch;     ///< same byte: which generation of that id this is
        FlowLifecycle life;

        uint32_t epoch;

        uint32_t recvNext;      ///< ordered delivery cursor: the seq the app is owed
        uint32_t recvHighest;   ///< anything above this + 1 is a gap, the loss signal
        uint32_t newSinceFlush; ///< seqs first seen since the last ack; 0 means none owed

        /** Monotonic micros the delivery cursor last advanced. An ordered flow
            holding a gap whose cursor has not moved for the stall timeout is
            jammed: it is pinning recv slots for a gap the sender is not
            filling, and the tick reclaims it. Set at creation and on every
            cursor advance. */
        uint64_t lastProgressMicros;

        /** When this association first owed an ack. The deadline is this plus
            Config::timers::ackDelayMicros; 0 means nothing is owed. */
        uint64_t ackArmedMicros;

        uint16_t windowBits;    ///< seen-bitmap width, the window for this mode
        uint16_t reorderCap;

        uint64_t* Seen()
        {
            return reinterpret_cast<uint64_t*>(
                reinterpret_cast<uint8_t*>(this) + sizeof(InAssociation));
        }
        const uint64_t* Seen() const
        {
            return reinterpret_cast<const uint64_t*>(
                reinterpret_cast<const uint8_t*>(this) + sizeof(InAssociation));
        }
        HoldbackEntry* Holdback()
        {
            return reinterpret_cast<HoldbackEntry*>(
                reinterpret_cast<uint8_t*>(this) + sizeof(InAssociation)
                + (windowBits / 8));
        }
        const HoldbackEntry* Holdback() const
        {
            return reinterpret_cast<const HoldbackEntry*>(
                reinterpret_cast<const uint8_t*>(this) + sizeof(InAssociation)
                + (windowBits / 8));
        }

        /** How many hold-back entries are occupied. Tells a cursor packet
            whether anything is waiting behind it, which is what decides if it
            may enter past this peer's budget. */
        uint16_t heldCount;

        static constexpr size_t StrideFor(uint16_t windowBits, uint16_t reorderCap)
        {
            return sizeof(InAssociation)
                 + (windowBits / 8)
                 + reorderCap * sizeof(HoldbackEntry);
        }
    };

    static_assert(std::is_trivially_copyable_v<Flow>,
                  "Flow lives in a SlotPool by raw cast");
    static_assert(std::is_trivially_copyable_v<OutAssociation>,
                  "OutAssociation lives in a SlotPool by raw cast");
    static_assert(std::is_trivially_copyable_v<InAssociation>,
                  "InAssociation lives in a SlotPool by raw cast");
}
