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
        RELIABLE_ORDERED   = 0,
        RELIABLE_UNORDERED = 1,
        UNRELIABLE         = 2,
    };

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

    /** The flow data byte carried after the sequence in every flow packet:
        mode in bits 0-2 (3-7 reserved), window exponent in bits 3-7, where
        window = 16 << exponent.

        It rides every packet, not just the first, so a receiver can register
        the flow from whichever packet arrives first.

        @return 0 when the mode or window cannot be encoded. 0 is never a valid
                encoding, so it doubles as the failure value. */
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

    /** Reads a flow data byte off the wire. Refuses reserved modes and window
        exponents out of range, because this input is attacker-chosen. */
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

    /** A flow the application opened. Socket-wide, one per flow id, and what a
        FlowHandle points at. Holds no per-peer state and knows no address. */
    struct Flow
    {
        uint32_t epoch;         ///< survives the lease and advances; stale handles miss
        uint32_t firstAssoc;    ///< association list head, INVALID when none
        uint16_t flowId;        ///< INVALID_FLOW_ID marks the slot free
        uint16_t window;        ///< declared in-flight cap
        FlowMode mode;
        uint8_t  flowData;      ///< the wire byte, encoded once at open
        FlowLifecycle life;
    };

    /** One packet sent and not yet acknowledged. Indexed by seq & (cap - 1), so
        an entry is computed rather than searched. seq == 0 marks it free, since
        an unreliable flow's entries never hold a packet slot to mark it with.

        packetSlot is the retained plaintext in the staging pool, this packet's
        retransmit source, released when the seq resolves. INVALID on an
        unreliable flow, whose entries track loss and budget only. */
    struct InFlightEntry
    {
        uint64_t sentAtMicros;
        uint32_t seq;
        uint32_t packetSlot;
        uint16_t wireSize;     ///< refunded to the congestion budget on resolve
        uint8_t  retries;      ///< give-up counter; the flow fails at the cap
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
        // it lives here rather than behind a second lock on the flow.
        uint16_t flowId;
        FlowMode mode;

        uint32_t epoch;         ///< revalidates the drain's peek against its claim
        FlowLifecycle life;     ///< per target: FAILED here leaves the flow open

        uint32_t nextSeq;
        uint32_t unresolved;    ///< stamped and unacked; the send gate refuses at inflightCap

        uint32_t srttMicros;    ///< 0 until the first sample
        uint32_t rttvarMicros;

        uint16_t inflightCap;
        uint16_t waitingCap;

        uint32_t waitingHead;   ///< masked by waitingCap - 1; only advances
        uint32_t waitingCount;

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

        static constexpr size_t StrideFor(uint16_t inflightCap, uint16_t waitingCap)
        {
            return sizeof(OutAssociation)
                 + inflightCap * sizeof(InFlightEntry)
                 + waitingCap * sizeof(WaitingEntry);
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
        Its width is the window the sender declared, which registration refused
        unless this socket's bitmap could cover it, so a seq below the floor is
        provably resolved and can only be a stale duplicate.

        Same pool rules as the sending half. */
    struct InAssociation
    {
        uint32_t peerSlot;
        Address  peerAddr;
        BcpId    peerId;

        uint16_t flowId;        ///< the REMOTE's flow id, from the wire
        FlowMode mode;          ///< decoded from the flow data byte
        FlowLifecycle life;

        uint32_t epoch;

        uint32_t recvNext;      ///< ordered delivery cursor: the seq the app is owed
        uint32_t recvHighest;   ///< anything above this + 1 is a gap, the loss signal
        uint32_t newSinceFlush; ///< seqs first seen since the last ack; 0 means none owed

        /** When this association first owed an ack. The deadline is this plus
            Config::timers::ackDelayMicros; 0 means nothing is owed. */
        uint64_t ackArmedMicros;

        uint16_t windowBits;    ///< seen-bitmap width, from the declared window
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
