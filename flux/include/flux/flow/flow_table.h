#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include <common/collections/fifo_queue.h>
#include <common/collections/slot_pool.h>
#include <common/error.h>
#include <common/result.h>

#include <flux/address.h>
#include <flux/flow/flow.h>
#include <flux/flow/flow_handle.h>
#include <flux/peer/peer_id.h>
#include <flux/socket/packet_slot.h>

namespace bcp::flux
{
    struct Peer;

    /** Every flow and every association this socket holds, and the algorithms
        that read only those: sequence numbering, the send gate, the waiting
        ring, the seen bitmap, ack ranges, reorder hold-back, retransmit
        selection.

        It never acquires a peer, never touches the kernel, and never encrypts.
        A peer arrives as a reference the socket already locked, so the flow
        table cannot invert the packet-slot then peer then flow order: it has no
        way to reach a peer to lock one. Everything that ends in a wire send
        gathers here and sends from the socket, after the lock is released.

        Not thread-safe as an object. Safety comes from the pools, which carry a
        lock per slot, and from the caller holding the peer lock where a
        signature says so. */
    class FlowTable
    {
    public:
        /** Retransmits one association contributes to one tick. RetransmitPass
            fills the caller's arrays up to this, and the tick sizes them by it,
            so the two must be one number. */
        static constexpr uint32_t RESENDS_PER_ASSOC_PER_TICK = 16;

        /** What Init needs, filled from Config::Flows and Config::Timers. The
            public Config shape is the socket's and does not change. */
        struct Params
        {
            uint32_t flowCount      = 0;
            uint32_t outCount       = 0;
            uint32_t inCount        = 0;
            uint32_t maxOutPerPeer  = 0;
            uint32_t maxInPerPeer   = 0;
            uint32_t maxPeers       = 0;
            uint32_t reorderCount   = 0;
            uint32_t stagingCount   = 0;
            uint32_t reliableWait   = 0;
            uint32_t unreliableWait = 0;
            uint32_t ackDelayMicros = 0;
            uint32_t retryIntervalMicros = 0;
            uint8_t  maxAttempts    = 0;
        };

        /** One waiting packet the drain may send, peeked under the peer read
            lock and claimed under the write lock. The association's epoch is
            captured with it, so a slot recycled between the two can never be
            mistaken for the one peeked. */
        struct WaitingCandidate
        {
            uint32_t assocSlot  = common::collections::SlotPool::INVALID;
            uint32_t packetSlot = common::collections::SlotPool::INVALID;
            uint32_t epoch      = 0;
            FlowMode mode       = FlowMode::RELIABLE_ORDERED;
        };

        /** Every pool and directory, sized once. recv, send and ready are
            borrowed and must outlive this table: a delivered packet stays in
            the socket's receive pool, and an unreliable body waiting for
            capacity holds a kernel send slot.

            Returns Ok and leaves the table disabled when the params ask for no
            flows at all. */
        [[nodiscard]] common::Error Init(const Params& params,
                                         common::collections::SlotPool* recvPool,
                                         common::collections::SlotPool* sendPool,
                                         common::collections::FifoQueue<uint32_t>* readyQueue) noexcept;

        [[nodiscard]] bool SendEnabled() const noexcept;
        [[nodiscard]] bool ReceiveEnabled() const noexcept;
        [[nodiscard]] uint32_t MaxOutPerPeer() const noexcept;
        /** The configured retry interval, which the peer-side congestion trim
            reads as its fallback when a peer has no round-trip sample yet. */
        [[nodiscard]] uint32_t RetryIntervalMicros() const noexcept;

        // --- Flow lifecycle. No peer involved: a flow knows no address. ---

        /** Leases a flow slot and stamps the wire byte. Fails when the id is
            the reserved sentinel, the mode does not encode, the id is already
            open on this socket, or the pool is dry. */
        [[nodiscard]] FlowHandle Open(uint16_t flowId, FlowMode mode) noexcept;

        /** CLOSED for a stale handle, so a handle outliving its flow reads
            closed rather than reaching the slot's new tenant. */
        [[nodiscard]] FlowLifecycle StateOf(const FlowHandle& flow) noexcept;

        /** Marks the flow CLOSING so nothing opens a new association under it,
            and reports whether this call is the one that did it. */
        [[nodiscard]] bool BeginClose(const FlowHandle& flow) noexcept;

        /** Hands back the next association still on the closing flow's list,
            with the peer identity the caller needs to reach it. False when the
            list is empty and the flow can be freed. */
        [[nodiscard]] bool NextAssocToClose(uint32_t flowSlot, Address& outAddr,
                                            BcpId& outId, uint32_t& outAssoc) noexcept;

        /** Frees the flow slot and returns its id to the free pool. */
        void FinishClose(uint32_t flowSlot) noexcept;

        /** The mode a builder needs before it knows a destination, or false
            when the handle is stale or the flow is not open. Takes and releases
            the flow lock inside, holding nothing else, which is what keeps a
            flow lock off the peer path. */
        [[nodiscard]] bool ModeOf(const FlowHandle& flow, FlowMode& outMode) noexcept;

        // --- Body storage. Reliable bodies outlive their send. ---

        [[nodiscard]] common::Result<PacketSlotWriter> AcquireStagingWriter() noexcept;
        /** Whether this handle's body came from staging, which is what marks a
            packet as its own retransmit source. */
        [[nodiscard]] bool IsRetainedBody(const PacketSlotHandle& handle) const noexcept;
        [[nodiscard]] common::collections::SlotPool* WaitPoolFor(FlowMode mode) noexcept;
        /** Where a retained body lives. The retransmit path holds a staging
            index rather than a handle, and this is what lets it build one. */
        [[nodiscard]] common::collections::SlotPool* StagingPool() noexcept;

        // --- The peer-locked surface. The caller holds the peer lock named in
        //     each comment, and this table never takes one itself. ---

        /** @pre caller holds the peer read lock. */
        [[nodiscard]] FlowLifecycle StateOf(const FlowHandle& flow, uint32_t peerSlot) noexcept;
        /** @pre caller holds the peer read lock. */
        [[nodiscard]] uint32_t FindOutAssoc(uint32_t peerSlot, uint16_t flowId) noexcept;
        /** The association published at one directory index, or INVALID. The
            tick walks a peer's associations by index, one call per index.
            @pre caller holds the peer read lock. */
        [[nodiscard]] uint32_t OutAssocAt(uint32_t peerSlot, uint32_t dirIndex) noexcept;
        /** @pre caller holds the peer read lock. */
        [[nodiscard]] bool AnyAckDue(uint32_t peerSlot, uint64_t now) noexcept;
        /** Soonest deadline across this peer's associations, UINT64_MAX when
            none is armed.
            @pre caller holds the peer read lock. */
        [[nodiscard]] uint64_t NextDeadline(uint32_t peerSlot) noexcept;

        /** Writes the ack body for every association owing one, and clears what
            it acked. The peer is only read here, and the caller upgrades to
            write afterwards to apply what the sweep gathered.
            @pre caller holds the peer read lock. */
        [[nodiscard]] size_t BuildPeerAckBody(uint32_t peerSlot, uint8_t* out, size_t cap) noexcept;

        /** Resolves the acked sequences and accumulates the congestion effect,
            which the caller applies to the peer after upgrading to write. Only
            association state is mutated here, so the read lock is enough.
            @pre caller holds the peer read lock. */
        void ApplyAckRanges(uint32_t peerSlot, uint16_t flowId, const AckRange* ranges,
                            uint8_t count, uint64_t now, CongestionDelta& delta) noexcept;

        /** The send gate: creates the association on first send, then admits,
            queues, drops or refuses. The flow is named by the packet's own flow
            header, which is all the gate has at this point.

            `flying` is false when the peer's handshake has not finished, so the
            packet is admitted but held. It is stamped as never sent, which
            leaves it overdue and puts it on the wire on the first tick after
            the session opens.

            @pre caller holds the packet slot write lock and the peer write lock. */
        [[nodiscard]] SendAdmission AdmitOut(Peer& peer, uint32_t peerSlot,
                                             PacketSlot& packet, uint32_t packetSlot,
                                             uint16_t wireSize, bool flying) noexcept;

        /** Registers a remote's flow from the first packet that names it, and
            reports the association the packet belongs to. outAssoc is INVALID
            on a refusal.
            @pre caller holds the peer write lock. */
        [[nodiscard]] FlowAdmit AdmitIn(uint32_t peerSlot, const Address& from, const BcpId& peerId,
                                        uint16_t flowId, uint8_t flowData,
                                        uint32_t& outAssoc) noexcept;

        /** Fails one target of a flow, draining its rings and refunding what it
            held. The flow stays open for every other peer.
            @pre caller holds the peer write lock. */
        void FailAssoc(uint32_t assocSlot, uint16_t flowId, Peer* refundTo) noexcept;

        /** Unpublishes one association from its peer's outbound directory, so
            no lookup reaches it while it is being torn down.
            @pre caller holds the peer write lock. */
        void UnpublishOut(uint32_t peerSlot, uint32_t assocSlot) noexcept;

        /** Drains an association's rings, refunds what it still held in flight,
            and recycles the slot. refundTo is null when the peer itself is
            going away, which drops the refund with it.
            @pre caller holds the peer write lock when refundTo is not null. */
        void FreeAssoc(uint32_t assocSlot, Peer* refundTo) noexcept;

        /** Frees every association a departing peer held.
            @pre caller holds the peer write lock. */
        void SweepPeer(uint32_t peerSlot) noexcept;

        /** One association's retransmit pass. Entries past their round-trip
            timeout are collected for the caller to resend (reliable) or
            resolved as lost (unreliable), and the flow id they belong to comes
            back in outFlowId. exhausted says a reliable packet ran out of
            attempts, which fails the association. Loss feedback accumulates in
            delta, never on the peer.
            @pre caller holds the peer read lock. */
        void RetransmitPass(uint32_t assocSlot, uint64_t now, CongestionDelta& delta,
                            uint16_t& outFlowId, uint32_t* resendSeqs, uint32_t* resendSlots,
                            uint32_t& resendCount, bool& exhausted) noexcept;

        /** Whether the in-flight ring still owns stagingSlot at expectedSeq. A
            concurrent ack may have resolved it, and recycled the slot, since
            the caller scanned. */
        [[nodiscard]] bool ResendStillValid(uint32_t assocSlot, uint32_t expectedSeq,
                                            uint32_t stagingSlot) noexcept;

        /** The oldest waiting packet across this peer's associations that the
            gate would admit right now. False when nothing waiting can go.
            @pre caller holds the peer read lock. */
        [[nodiscard]] bool PeekWaiting(uint32_t peerSlot, const Peer& peer,
                                       WaitingCandidate& out) noexcept;

        /** Takes the peeked packet off its waiting ring and stamps it, or false
            when the head moved between the peek and now, which leaves the
            packet slot owned by whoever holds it.
            @pre caller holds the packet slot write lock and the peer write lock. */
        [[nodiscard]] bool ClaimWaiting(const WaitingCandidate& candidate, Peer& peer,
                                        PacketSlot& packet) noexcept;

        // --- Delivery. Owns the recv slot for the duration. ---

        /** Orders, dedupes and hands the packet to the ready queue, returning
            how many packets that made deliverable. No peer lock held. */
        [[nodiscard]] uint32_t DeliverIn(uint32_t assocSlot, uint16_t flowId, uint32_t seq,
                                         PacketSlotHandle& incoming) noexcept;

    private:
        common::collections::SlotPool  flowPool_;
        common::collections::SlotPool  outAssocPool_;
        common::collections::SlotPool  inAssocPool_;
        common::collections::SlotPool  stagingPool_;
        std::unique_ptr<FlowDirEntry[]> outAssocDir_;
        std::unique_ptr<FlowDirEntry[]> inAssocDir_;

        common::collections::SlotPool* recvPool_  = nullptr;   ///< borrowed from the kernel
        common::collections::SlotPool* sendPool_  = nullptr;   ///< borrowed from the kernel
        common::collections::FifoQueue<uint32_t>* readyQueue_ = nullptr;   ///< borrowed from the socket

        uint32_t maxOutAssocPerPeer_ = 0;
        uint32_t maxInAssocPerPeer_  = 0;
        uint16_t outInflightCap_     = 0;
        uint16_t inWindowBits_       = 0;
        uint16_t inReorderCap_       = 0;
        uint16_t outReliableWaitCap_   = 0;
        uint16_t outUnreliableWaitCap_ = 0;
        uint32_t ackDelayMicros_       = 0;
        uint32_t retryIntervalMicros_  = 0;
        uint8_t  maxAttempts_          = 0;

        // Directory helpers over the FlowDirEntry[] segment: three scan idioms.
        [[nodiscard]] FlowDirEntry* OutDirFor(uint32_t peerSlot) noexcept;
        [[nodiscard]] FlowDirEntry* InDirFor(uint32_t peerSlot) noexcept;
        [[nodiscard]] static uint32_t FindFlowSlot(const FlowDirEntry* dir, uint32_t width, uint16_t flowId) noexcept;
        [[nodiscard]] static uint32_t InsertFlowSlot(FlowDirEntry* dir, uint32_t width, uint16_t flowId, uint32_t flowSlot) noexcept;
        static void EraseFlowSlot(FlowDirEntry* dir, uint32_t width, uint32_t flowSlot) noexcept;

        /** Scans rather than indexes: the pool is small and opens are rare.

            @return the flow slot, or SlotPool::INVALID. */
        [[nodiscard]] uint32_t FindFlowById(uint16_t flowId) noexcept;

        /** Leases the per-target state on first send, copying the flow's mode
            so later packets read one object under one lock.

            @pre Caller holds the peer's write lock.
            @return INVALID when no such flow is open, the pool is dry, or this
                    peer is at its cap. */
        [[nodiscard]] uint32_t CreateAssociation(const Peer& peer, uint32_t peerSlot,
                                                 uint16_t flowId) noexcept;

        /** Both run under the flow's write lock, which guards the list. Unlink
            happens inside FreeAssoc, so every teardown path is covered. */
        void LinkAssociation(uint32_t flowSlot, uint32_t assocSlot) noexcept;
        void UnlinkAssociation(uint32_t flowSlot, uint32_t assocSlot) noexcept;

        /** Registers a remote's flow on first sight, from a data packet's flow
            header. Refused when the flow data byte does not decode, or on caps:
            a dry pool or a full directory.

            @pre Caller holds the peer's write lock. */
        [[nodiscard]] FlowAdmit AdmitInFlow(uint32_t peerSlot, const Address& from,
                                            const BcpId& peerId, uint16_t flowId,
                                            uint8_t flowData) noexcept;

        [[nodiscard]] uint32_t DrainOutInflight(OutAssociation* flow) noexcept;
        void DrainOutWaiting(OutAssociation* flow) noexcept;
        void DrainInHoldback(InAssociation* flow) noexcept;

        /** Resolve one in-flight entry (acked or lost); accumulate feedback into
            `delta` (never touches the peer). The socket does the peer-side
            arithmetic under the peer's write lock. */
        void ResolveOutEntry(OutAssociation* flow, InFlightEntry& entry,
                             bool acked, uint64_t nowMicros, CongestionDelta& delta) noexcept;

        void RetransmitInflight(OutAssociation& flow, uint64_t now, CongestionDelta& delta,
                                /*out*/ uint32_t* resendSeqs, uint32_t* resendSlots,
                                uint32_t& resendCount, /*out*/ bool& exhausted) noexcept;

        /** Commit one packet to the ready queue (Detaches on success so Poll
            rebuilds the handle). False = queue full, caller must not ack it. */
        [[nodiscard]] bool QueueReady(PacketSlotHandle& handle) noexcept;

        uint32_t DeliverUnordered(InAssociation& flow, PacketSlotHandle& incoming, uint32_t seq) noexcept;
        uint32_t DeliverOrdered(InAssociation& flow, PacketSlotHandle& incoming, uint32_t seq) noexcept;
        uint32_t DrainHoldbackRun(InAssociation& flow) noexcept;
    };
}
