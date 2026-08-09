#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include <common/error.h>
#include <common/collections/slot_pool.h>

#include <flux/address.h>
#include <flux/internal/constants.h>
#include <flux/transfer/transfer.h>

// Every transfer this socket has running, in both directions. It sits beside
// FlowTable rather than inside it, because a transfer shares nothing with an
// association: no staging pool, no reorder ring, no message framing, no mode
// bits. What it has instead is a length agreed up front and a buffer at each
// end that the application owns, which makes a packet's place pure
// arithmetic.
//
// The one thing the two mechanisms do share is the peer's congestion state.
// They must: a transfer and a flow to the same peer cross one link, so they
// spend one budget and one pacing clock. Nothing else crosses between them,
// and this table can never reach a peer, which keeps the packet slot then peer
// then transfer order acyclic exactly as FlowTable's does.

namespace bcp::flux
{
    /** One outgoing transfer: the source buffer and what is still owed on it.

        The buffer belongs to the application and is never copied. A
        retransmit re-reads the bytes at seq * TRANSFER_STRIDE_BYTES, which is
        why the window can be deep enough to fill a fast long path: an
        outstanding packet costs an entry here, not its bytes. */
    struct OutTransfer
    {
        // The per-packet rings are NOT here. A SlotPool runs no constructor
        // and zeroes only at Init, so anything living in one has to be
        // trivially copyable, which an owning pointer is not. The table holds
        // them instead, one contiguous block per direction indexed by slot.

        uint32_t peerSlot;
        Address  peerAddr;
        uint16_t transferId;

        const uint8_t* source;      ///< the application's, alive until finished
        uint64_t       length;
        uint32_t       packetCount; ///< ceil(length / stride), the sequence count

        uint32_t nextSeq;           ///< next data sequence to put on the wire
        uint32_t acked;             ///< data packets resolved, completion at packetCount
        bool     announced;         ///< the announcing packet has been sent
        bool     announceAcked;     ///< and the receiver answered it
        uint64_t announceSentAt;    ///< when, so a lost announcement is repeated

        /** Set when the far side declined. The transfer finishes as Refused
            rather than continuing to send into a receiver with nowhere to put
            it. */
        bool     refused;

        uint32_t inFlight;          ///< data packets outstanding right now
        uint32_t contiguousAcked;   ///< lowest unacked sequence, the progress cursor

        /** Highest sequence the far side has reported holding. Anything sent
            below it and still unacknowledged is missing rather than merely
            late, which is what turns a repair from a timeout into an
            immediate resend. */
        uint32_t highestAcked;

        /** Sequences below this were already on the wire when the controller
            last reacted to loss, so they belong to that event and must not
            charge another.

            The flow path gets this from a congestion epoch stamped on every
            packet. Send order gives a transfer the same thing for free: first
            transmissions go out in sequence, so the next sequence at the
            moment of a reaction is exactly the boundary between what was
            already in flight and what came after. Without it the budget is
            trimmed on every acknowledgement that still mentions an open gap,
            which measured a clean-link transfer at a seventh of its rate. */
        uint32_t lossBarrierSeq;
    };

    /** One incoming transfer: what was announced, what was answered, and where
        the bytes are going.

        Between the announcement and the answer there is nothing to write into,
        so packets that arrive in that window are held. Past the holdback they
        are dropped and the sender retransmits, which throttles it to the speed
        the application answers rather than wasting the link. */
    struct InTransfer
    {
        // As with OutTransfer, the placed-bits ring lives on the table.

        uint32_t peerSlot;
        Address  peerAddr;
        uint16_t transferId;

        uint64_t length;            ///< as announced, and the bound on every write
        uint32_t packetCount;

        uint8_t* destination;       ///< null until the application allows it
        bool     announced;
        bool     complete;          ///< every packet placed, waiting on CompleteTransfer

        uint32_t recvNext;          ///< lowest sequence not yet placed
        uint32_t placed;            ///< how many placed in total, complete at packetCount

        /** Arrivals since the last acknowledgement went out, and whether one
            is owed regardless of the count because the cursor moved or a hole
            opened. */
        uint32_t sinceAck;
        bool     ackOwed;
    };

    /** The table. Owned by Socket beside FlowTable and PeerTable. */
    class TransferTable
    {
    public:
        struct Params
        {
            uint32_t outCount         = 0;
            uint32_t inCount          = 0;
            uint32_t maxPeers         = 0;
            uint64_t maxTransferBytes = 0;   ///< 0 takes TRANSFER_MAX_BYTES_DEFAULT
        };

        TransferTable() = default;
        ~TransferTable();

        TransferTable(const TransferTable&)            = delete;
        TransferTable& operator=(const TransferTable&) = delete;

        /** Allocates both pools and the per-peer directories. Zero counts
            leave the table inert, which is what refuses transfers on a socket
            that never asked for them. */
        [[nodiscard]] common::Error Init(const Params& params) noexcept;
        void Shutdown() noexcept;

        [[nodiscard]] bool SendEnabled() const noexcept { return outCount_ != 0; }
        [[nodiscard]] bool ReceiveEnabled() const noexcept { return inCount_ != 0; }
        [[nodiscard]] uint64_t MaxTransferBytes() const noexcept { return maxTransferBytes_; }

        /** Registers an outgoing transfer and returns its slot, or INVALID.
            Nothing is sent here: the tick and the send pass drive the wire, so
            this only decides that the transfer exists and is legal. */
        [[nodiscard]] common::Error BeginSend(uint32_t peerSlot, const Address& peer,
                                              uint16_t transferId,
                                              const void* buffer, uint64_t length) noexcept;

        /** A peer announced. Creates the incoming transfer and reports whether
            it is new, so the caller raises TRANSFER_INCOMING exactly once for
            it rather than on every retransmitted announcement. */
        [[nodiscard]] common::Error OnAnnounce(uint32_t peerSlot, const Address& peer,
                                               uint16_t transferId, uint64_t length,
                                               uint16_t stride, bool& outIsNew) noexcept;

        /** Places one arrived data packet into the destination buffer.

            The bound is the announced length, checked here rather than
            trusted: a sequence past packetCount or a payload past the stride
            is refused, so the offset multiply can never reach past the buffer
            whatever the sender claims. */
        [[nodiscard]] common::Error OnData(uint32_t peerSlot, uint16_t transferId,
                                           uint32_t seq, const uint8_t* payload,
                                           uint16_t payloadLen) noexcept;

        /** The answer to an announcement. Allow takes the buffer and accepts
            the announced length by doing so. */
        [[nodiscard]] common::Error Allow(uint32_t peerSlot, uint16_t transferId,
                                          void* buffer) noexcept;
        [[nodiscard]] common::Error Reject(uint32_t peerSlot, uint16_t transferId) noexcept;

        /** What a peer announced on this id, or zero when nothing is pending.
            Zero is unambiguous because a zero-length transfer is refused at
            the send. */
        [[nodiscard]] uint64_t PendingLength(uint32_t peerSlot,
                                             uint16_t transferId) const noexcept;

        /** Bytes contiguous from the start, either direction. Contiguous
            rather than counted, so it never reports bytes ready while a hole
            sits behind them. */
        [[nodiscard]] uint64_t Progress(uint32_t peerSlot,
                                        uint16_t transferId) const noexcept;

        /** Releases a completed incoming transfer, freeing the id for the
            next. NotFound when nothing is completed and waiting. */
        [[nodiscard]] common::Error Complete(uint32_t peerSlot,
                                             uint16_t transferId) noexcept;

        /** Drains finished transfers into the caller's array, oldest first.
            An outgoing one reports a null buffer and frees its slot here,
            since the application needs nothing more from it. An incoming one
            reports its buffer and keeps its slot until Complete. */
        [[nodiscard]] size_t DrainFinished(TransferView* out, size_t max) noexcept;

        /** Drops everything belonging to a peer, before its slot can recycle.
            A later peer in the same slot must never inherit a transfer. */
        void SweepPeer(uint32_t peerSlot) noexcept;

        // --- The send pass reaches these under the peer's write lock ---

        /** Runs `fn` over every transfer this peer is sending, each under its
            own write lock. Returning false from `fn` stops the walk, which is
            how the caller stops once its per-pass budget is spent.

            The lock order is peer then transfer, matching the flow path's peer
            then association, so the two can never deadlock against each
            other. */
        template <typename Fn>
        void ForEachSending(uint32_t peerSlot, Fn&& fn) noexcept
        {
            if (!outDir_ || peerSlot >= maxPeers_) return;
            DirEntry* row = &outDir_[static_cast<size_t>(peerSlot) * MAX_PER_PEER];
            for (uint32_t i = 0; i < MAX_PER_PEER; ++i)
            {
                if (row[i].slot == common::collections::SlotPool::INVALID) continue;
                OutTransfer* out =
                    reinterpret_cast<OutTransfer*>(outPool_.WriteLock(row[i].slot));
                bool carryOn = true;
                if (out) carryOn = fn(row[i].slot, *out);
                outPool_.UnlockWrite(row[i].slot);
                if (!carryOn) return;
            }
        }

        /** The lowest overdue sequence at or above `fromSeq`, or UINT32_MAX
            when nothing further is. The caller passes the last answer plus
            one on its next call, so one send pass walks the window once in
            total rather than once per packet it offers. `lossDelay` is the
            deadline for a packet that has been overtaken but not yet resent,
            `rto` the deadline for every attempt after that. */
        [[nodiscard]] uint32_t OldestOverdue(uint32_t slot, const OutTransfer& out,
                                             uint64_t now, uint64_t rto,
                                             uint64_t lossDelay,
                                             uint32_t fromSeq) const noexcept;

        /** Stamps a data sequence as on the wire, which is what makes it
            outstanding and what the deadline is measured from. */
        void MarkSent(uint32_t slot, OutTransfer& out, uint32_t seq, uint64_t now) noexcept;

        /** The announced length of an outgoing transfer, for the announcing
            packet's payload. Zero when there is none. */
        [[nodiscard]] uint64_t SendingLength(uint32_t peerSlot,
                                             uint16_t transferId) noexcept;

        /** How far an incoming transfer's contiguous cursor has reached, and
            which of the 64 sequences above it are already held. Both travel in
            the acknowledgement, so a hole is named rather than waited out.

            @return false when there is no such transfer. */
        [[nodiscard]] bool ReceiveState(uint32_t peerSlot, uint16_t transferId,
                                        uint32_t& outCursor,
                                        uint8_t* outBitmap) noexcept;

        /** Whether this incoming transfer owes an acknowledgement, and clears
            the debt. Acking every packet doubles the packet count on a link
            the reverse path shares, so a cursor that moved, a hole that
            appeared, or a small run of arrivals is what earns one. */
        [[nodiscard]] bool TakeAckDebt(uint32_t peerSlot, uint16_t transferId) noexcept;

        /** Applies a cursor from the far side: everything below it is
            resolved. Reports the wire bytes and packet count freed so the
            caller can give them back to the peer's congestion budget, which is
            the one thing transfers and flows share. */
        /** Applies a cursor plus the selective bitmap that follows it. The
            bitmap covers the 64 sequences above the cursor, which is what
            makes a burst of holes one repair round rather than one repair per
            round trip.

            Reports the wire bytes and packet count freed so the caller can
            return them to the peer's budget, the newest round trip so the
            estimate keeps moving, and the bytes now known missing so the
            controller can react to real loss. */
        void OnAck(uint32_t peerSlot, uint16_t transferId, uint32_t recvNext,
                   const uint8_t* bitmap, uint64_t now,
                   uint32_t& outFreedBytes, uint32_t& outFreedPackets,
                   uint32_t& outRttSample, uint32_t& outLostBytes) noexcept;

        /** The far side declined. Finishes the transfer as Refused and frees
            what it still held on the path. */
        void OnRefused(uint32_t peerSlot, uint16_t transferId,
                       uint32_t& outFreedBytes, uint32_t& outFreedPackets) noexcept;

    private:
        /** Transfer ids one peer may run at once in one direction. A handful,
            because a transfer is a whole buffer rather than a message, and a
            small row keeps the directory scan a cache line. */
        static constexpr uint32_t MAX_PER_PEER = 4;

        /** Directory entry: which transfer id occupies which slot, per peer.
            A small linear row per peer rather than a hash, because the count
            is a handful and the row is one cache line. */
        struct DirEntry
        {
            uint16_t transferId;
            uint32_t slot;
        };

        [[nodiscard]] uint32_t FindOut(uint32_t peerSlot, uint16_t transferId) const noexcept;
        [[nodiscard]] uint32_t FindIn(uint32_t peerSlot, uint16_t transferId) const noexcept;

        common::collections::SlotPool outPool_;
        common::collections::SlotPool inPool_;

        /** The per-packet rings, one contiguous block each, indexed by slot
            times the window. Held here rather than in the slot structs
            because a SlotPool stores trivially copyable bytes and runs no
            constructor over them. */
        std::unique_ptr<uint64_t[]> sentAtRing_;
        std::unique_ptr<uint32_t[]> ackedRing_;
        std::unique_ptr<uint32_t[]> placedRing_;

        /** Which sequences have been sent more than once. Karn's rule: a
            retransmitted packet yields no round-trip sample, because there is
            no way to tell whether the acknowledgement answers the original or
            the resend. Sampling them anyway measured the minimum collapsing
            from 40 ms to 10 microseconds, which made the queue estimate read a
            permanent 40 ms of standing queue and strangled the budget to
            nothing. */
        std::unique_ptr<uint32_t[]> resentRing_;

        static constexpr uint32_t RING_WORDS = internal::TRANSFER_WINDOW / 32u;

        [[nodiscard]] uint64_t* SentAtFor(uint32_t slot) noexcept
        { return sentAtRing_.get() + static_cast<size_t>(slot) * internal::TRANSFER_WINDOW; }
        [[nodiscard]] const uint64_t* SentAtFor(uint32_t slot) const noexcept
        { return sentAtRing_.get() + static_cast<size_t>(slot) * internal::TRANSFER_WINDOW; }
        [[nodiscard]] uint32_t* AckedFor(uint32_t slot) noexcept
        { return ackedRing_.get() + static_cast<size_t>(slot) * RING_WORDS; }
        [[nodiscard]] const uint32_t* AckedFor(uint32_t slot) const noexcept
        { return ackedRing_.get() + static_cast<size_t>(slot) * RING_WORDS; }
        [[nodiscard]] uint32_t* PlacedFor(uint32_t slot) noexcept
        { return placedRing_.get() + static_cast<size_t>(slot) * RING_WORDS; }
        [[nodiscard]] uint32_t* ResentFor(uint32_t slot) noexcept
        { return resentRing_.get() + static_cast<size_t>(slot) * RING_WORDS; }
        [[nodiscard]] const uint32_t* ResentFor(uint32_t slot) const noexcept
        { return resentRing_.get() + static_cast<size_t>(slot) * RING_WORDS; }

        std::unique_ptr<DirEntry[]> outDir_;   ///< maxPeers * maxPerPeer
        std::unique_ptr<DirEntry[]> inDir_;

        uint32_t outCount_  = 0;
        uint32_t inCount_   = 0;
        uint32_t maxPeers_  = 0;
        uint64_t maxTransferBytes_ = 0;

        /** Finished transfers waiting for PollTransfers, as slot indices with
            their direction and outcome. Bounded by the pools, so it can never
            grow past what exists. */
        struct Finished
        {
            uint32_t      slot;
            bool          incoming;
            common::Error outcome;
        };
        std::unique_ptr<Finished[]> finished_;
        uint32_t finishedHead_  = 0;
        uint32_t finishedCount_ = 0;
    };
}
