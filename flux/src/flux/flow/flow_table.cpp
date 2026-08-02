#include <flux/flow/flow_table.h>

#include <common/platform.h>
#include <flux/internal/constants.h>
#include <flux/peer/peer.h>
#include <flux/socket/packet_slot.h>
#include <flux/wire/batch.h>

#include <cstring>
#include <new>

namespace bcp::flux
{
    namespace
    {
        /** Rounds up to a multiple of 16 so slot payloads stay aligned. */
        constexpr uint32_t AlignUp16(uint32_t n) noexcept { return (n + 15) & ~15u; }

        /** Rounds a requested window up to a power of two within the flow bounds
            (floor 64 so the seen bitmap is whole 64-bit words). */
        uint32_t RoundUpPow2(uint32_t requested, uint32_t floor, uint32_t ceil) noexcept
        {
            uint32_t v = floor;
            while (v < requested && v < ceil) v <<= 1;
            return v;
        }

        /** Writes every field of a freshly acquired association slot. The pools
            never construct, so a recycled slot holds the previous tenant's bytes
            except epoch, which survives and advances so stale references never
            match again. Born OPEN: opening is local and the remote registers its
            half from the first packet.

            @pre Caller holds the slot write lock. */
        void ResetOutAssoc(OutAssociation* assoc, uint32_t peerSlot, const Address& peerAddr,
                           const BcpId* peerId, uint16_t flowId, FlowMode mode,
                           uint8_t flowEpoch, uint16_t inflightCap, uint16_t waitingCap) noexcept
        {
            assoc->peerSlot   = peerSlot;
            assoc->peerAddr   = peerAddr;
            assoc->peerId     = peerId ? *peerId : BcpId{};
            assoc->flowSlot   = common::collections::SlotPool::INVALID;
            assoc->nextInFlow = common::collections::SlotPool::INVALID;
            assoc->flowId     = flowId;
            assoc->mode       = mode;
            assoc->flowEpoch  = flowEpoch;
            assoc->epoch      = assoc->epoch + 1;
            assoc->life       = FlowLifecycle::OPEN;

            assoc->nextSeq      = 1;
            assoc->unresolved   = 0;
            assoc->srttMicros   = 0;
            assoc->rttvarMicros = 0;
            assoc->inflightCap  = inflightCap;
            assoc->waitingCap   = waitingCap;
            assoc->waitingHead  = 0;
            assoc->waitingCount = 0;

            // No batch is open on a fresh association. A recycled slot carries
            // the previous tenant's bytes, and a non-zero used here would make
            // this flow append into a stranger's half-built packet.
            assoc->openBatchUsed     = 0;
            assoc->openBatchHeader   = 0;
            assoc->openBatchCount    = 0;
            assoc->openBatchFirstLen = 0;

            InFlightEntry* inFlight = assoc->InFlight();
            for (uint32_t i = 0; i < inflightCap; ++i)
                inFlight[i] = InFlightEntry{ 0, 0, common::collections::SlotPool::INVALID, 0, 0 };
            WaitingEntry* waiting = assoc->Waiting();
            for (uint32_t i = 0; i < waitingCap; ++i)
                waiting[i] = WaitingEntry{ 0, common::collections::SlotPool::INVALID, 0 };
        }

        /** Same contract for the receiving half. mode comes off the wire, not
            from a local flow: the sender declares it on every packet. */
        void ResetInAssoc(InAssociation* assoc, uint32_t peerSlot, const Address& peerAddr,
                          const BcpId* peerId, uint16_t flowId, FlowMode mode,
                          uint8_t flowEpoch, uint16_t windowBits, uint16_t reorderCap) noexcept
        {
            assoc->peerSlot   = peerSlot;
            assoc->peerAddr   = peerAddr;
            assoc->peerId     = peerId ? *peerId : BcpId{};
            assoc->flowId     = flowId;
            assoc->mode       = mode;
            assoc->flowEpoch  = flowEpoch;
            assoc->life       = FlowLifecycle::OPEN;
            assoc->epoch      = assoc->epoch + 1;

            assoc->recvNext           = 1;
            assoc->recvHighest        = 0;
            assoc->newSinceFlush      = 0;
            assoc->ackArmedMicros     = 0;
            assoc->lastProgressMicros = common::MonotonicMicros();
            assoc->windowBits         = windowBits;
            assoc->reorderCap         = reorderCap;

            std::memset(assoc->Seen(), 0, windowBits / 8);
            HoldbackEntry* holdback = assoc->Holdback();
            for (uint32_t i = 0; i < reorderCap; ++i)
                holdback[i] = HoldbackEntry{ 0, common::collections::SlotPool::INVALID };
        }

        // --- Flow seen-bitmap + ack + RTT helpers ---

        /** Tests seq's bit in the sliding seen window (the last `windowBits`
            seqs). A seq maps to bit (seq & (windowBits - 1)); the floor is
            recvHighest - windowBits + 1, and below the floor is provably
            resolved. Mirrors the anti-replay window one layer down, in flow-seq
            space. */
        bool SeenTest(const uint64_t* bitmap, uint32_t seq, uint32_t windowBits)
        {
            const uint32_t idx = seq & (windowBits - 1);
            return (bitmap[idx >> 6] >> (idx & 63)) & 1ull;
        }
        void SeenSet(uint64_t* bitmap, uint32_t seq, uint32_t windowBits)
        {
            const uint32_t idx = seq & (windowBits - 1);
            bitmap[idx >> 6] |= (1ull << (idx & 63));
        }
        void SeenClear(uint64_t* bitmap, uint32_t seq, uint32_t windowBits)
        {
            const uint32_t idx = seq & (windowBits - 1);
            bitmap[idx >> 6] &= ~(1ull << (idx & 63));
        }

        /** Advances the seen window to cover seq, clearing bits that fall out as
            it slides so a wrapped seq never reads a stale set-bit, then marks seq
            seen. Called only once a packet is committed (delivered or held). */
        void CommitSeen(InAssociation* flow, uint32_t seq)
        {
            const uint32_t bits = flow->windowBits;
            if (seq > flow->recvHighest)
            {
                if (seq - flow->recvHighest >= bits)
                {
                    // The window slid clear past everything it held, so every
                    // slot is stale. Clearing them one at a time would run for
                    // the whole jump, which a wire sequence makes unbounded.
                    // Wipe the window instead.
                    std::memset(flow->Seen(), 0, bits / 8);
                }
                else
                {
                    const uint32_t oldFloor = flow->recvHighest >= bits
                        ? flow->recvHighest - bits + 1 : 1;
                    const uint32_t newFloor = seq >= bits ? seq - bits + 1 : 1;
                    for (uint32_t s = oldFloor; s < newFloor; ++s)
                        SeenClear(flow->Seen(), s, bits);
                }
                flow->recvHighest = seq;
            }
            SeenSet(flow->Seen(), seq, bits);
        }

        /** Whether seq is a duplicate the window holds, or has fallen below it. */
        bool AlreadySeen(const InAssociation* flow, uint32_t seq)
        {
            const uint32_t bits = flow->windowBits;
            const uint32_t floor = flow->recvHighest >= bits
                ? flow->recvHighest - bits + 1 : 1;
            if (seq < floor) return true;                       // below window
            return SeenTest(flow->Seen(), seq, bits);
        }

        void ArmAck(InAssociation* flow)
        {
            if (flow->newSinceFlush == 0)
                flow->ackArmedMicros = common::MonotonicMicros();   // arm the deadline
            if (flow->newSinceFlush < UINT32_MAX) ++flow->newSinceFlush;
        }

        /** Coalesces the set bits into inclusive [first,last] seq ranges, newest
            first, up to `maxRanges`.

            @return The range count written to `out`. */
        uint8_t BuildAckRanges(const InAssociation* flow, AckRange* out, uint8_t maxRanges)
        {
            const uint32_t bits = flow->windowBits;
            const uint32_t hi   = flow->recvHighest;
            if (hi == 0 || maxRanges == 0) return 0;
            const uint32_t floor = hi >= bits ? hi - bits + 1 : 1;

            uint8_t count = 0;
            uint32_t s = hi;
            for (;;)
            {
                while (s >= floor && !SeenTest(flow->Seen(), s, bits)) --s;
                if (s < floor) break;
                const uint32_t last = s;
                while (s >= floor && SeenTest(flow->Seen(), s, bits)) --s;
                out[count].first = s + 1;
                out[count].last  = last;
                if (++count == maxRanges) break;
                if (s < floor) break;
            }
            return count;
        }

        bool SeqInRanges(uint32_t seq, const AckRange* ranges, uint8_t count)
        {
            for (uint8_t i = 0; i < count; ++i)
                if (seq >= ranges[i].first && seq <= ranges[i].last) return true;
            return false;
        }

        /** RTT smoothing (Jacobson/Karels), microseconds. */
        void SampleRtt(OutAssociation* flow, uint64_t sampleMicros)
        {
            const uint32_t sample = sampleMicros > UINT32_MAX
                ? UINT32_MAX : static_cast<uint32_t>(sampleMicros);
            if (flow->srttMicros == 0)
            {
                flow->srttMicros   = sample;
                flow->rttvarMicros = sample / 2;
                return;
            }
            const uint32_t diff = flow->srttMicros > sample
                ? flow->srttMicros - sample : sample - flow->srttMicros;
            flow->rttvarMicros = (flow->rttvarMicros * 3 + diff) / 4;
            flow->srttMicros   = (flow->srttMicros * 7 + sample) / 8;
        }

        /** The retransmit timeout: RTT-derived once sampled, else the Config
            fallback, clamped to a 1 ms floor. */
        uint64_t RetransmitTimeout(const OutAssociation* flow, uint32_t fallbackMicros)
        {
            uint64_t rto = flow->srttMicros == 0
                ? fallbackMicros
                : static_cast<uint64_t>(flow->srttMicros) + 4ull * flow->rttvarMicros;
            if (rto < 1000) rto = 1000;
            return rto;
        }

        // --- The send gate, as decision then mutation ---
        // CanSend is a pure predicate over the (already-locked) flow and peer:
        // ring slot free, unresolved < inflightCap (reliable only), and the
        // peer's congestion budget covers wireSize. A caller it passes runs to
        // the wire without re-checking. StampFlowPacket assumes it passed and
        // only mutates: assign seq, take the ring entry, spend bytesInFlight,
        // write the seq. AdmitOut takes the FLOW lock and sequences the two
        // under the PEER lock the caller already holds; the peer is lent (by
        // reference), never re-looked-up, so the send path touches the peer
        // table once. A packet the gate refuses is routed by mode: enqueued on
        // the flow's waiting ring (strict FIFO, while anything waits a new
        // packet joins the back even if capacity just freed, or its seq would
        // outrun older data), the oldest waiting unreliable packet evicted to
        // seat the newest, or refused outright. The returned status says which;
        // ownership of packetSlot (staging for reliable, kernel send for
        // unreliable) moves with it. See SendAdmission.

        /** Pure predicate over the already-locked flow and peer, running every check
            a send needs. The window bounds PACKETS per flow (the receiver's dedupe
            guarantee; reliable only), the congestion budget bounds BYTES per peer
            (the path's capacity; both modes), and the ring slot the next seq maps to
            must be free. The budget sum runs in 64 bits so a saturated budget can
            never wrap the comparison.

            @pre Caller holds the flow and peer locks. */
        bool CanSend(const OutAssociation& flow, const Peer& peer,
                     uint16_t wireSize, bool windowed) noexcept
        {
            if (windowed && flow.unresolved >= flow.inflightCap)
                return false;
            if (static_cast<uint64_t>(peer.bytesInFlight) + wireSize > peer.congestionBudget)
                return false;
            const InFlightEntry& entry = flow.InFlight()[flow.nextSeq & (flow.inflightCap - 1)];
            return entry.seq == 0;
        }

        /** Pure mutation: takes the ring entry, spends the congestion budget, and
            writes the seq into the plaintext.

            @pre CanSend passed under the same lock. */
        void StampFlowPacket(OutAssociation& flow, Peer& peer, PacketSlot& packet,
                             uint32_t stagingSlot, uint16_t wireSize,
                             bool flying) noexcept
        {
            const uint32_t seq = flow.nextSeq;
            InFlightEntry& entry = flow.InFlight()[seq & (flow.inflightCap - 1)];
            entry.seq          = seq;
            // A packet held behind a handshake is stamped but not on the wire,
            // and zero reads as overdue against any timeout, so the first tick
            // after the session opens carries it without a special path.
            entry.sentAtMicros = flying ? common::MonotonicMicros() : 0;
            entry.packetSlot   = stagingSlot;   // INVALID for an unreliable flow
            entry.wireSize     = wireSize;
            entry.retries      = 0;

            flow.unresolved += 1;
            peer.bytesInFlight += wireSize;      // congestion spend
            flow.nextSeq = seq + 1;
            if (flow.nextSeq == 0) flow.nextSeq = 1;   // 0 is the never-sent sentinel

            // Forward from the flow header: the sequence is not the last field.
            uint8_t* seqField = packet.data + packet.FlowHeaderOffset()
                              + internal::WIRE_FLOW_ID_SIZE;
            seqField[0] = static_cast<uint8_t>(seq >> 0);
            seqField[1] = static_cast<uint8_t>(seq >> 8);
            seqField[2] = static_cast<uint8_t>(seq >> 16);
            seqField[3] = static_cast<uint8_t>(seq >> 24);
        }

        /** Appends to the waiting FIFO. Ownership of packetSlot passes to the ring.

            @pre Caller holds the flow write lock and has checked there is room. */
        void EnqueueWaiting(OutAssociation& flow, uint32_t packetSlot,
                            uint16_t wireSize) noexcept
        {
            WaitingEntry& tail =
                flow.Waiting()[(flow.waitingHead + flow.waitingCount) & (flow.waitingCap - 1u)];
            tail.waitingSince = common::MonotonicMicros();
            tail.packetSlot   = packetSlot;
            tail.wireSize     = wireSize;
            flow.waitingCount += 1;
        }
    }

    // --- Init ---

    common::Error FlowTable::Init(const Params& params,
                                  common::collections::SlotPool* recvPool,
                                  common::collections::SlotPool* sendPool,
                                  common::collections::FifoQueue<uint32_t>* readyQueue) noexcept
    {
        if (params.outCount == 0 && params.inCount == 0)
            return common::Error::Ok;   // flows disabled entirely

        recvPool_   = recvPool;
        sendPool_   = sendPool;
        readyQueue_ = readyQueue;

        // Fixed, not configured: nothing carries the window on the wire, so two
        // sockets that disagreed could never find out. See internal::FLOW_WINDOW.
        const uint32_t window = internal::FLOW_WINDOW;

        auto initDir = [&](std::unique_ptr<FlowDirEntry[]>& dir, uint32_t width) -> bool
        {
            const size_t entries = static_cast<size_t>(params.maxPeers) * width;
            dir.reset(new (std::nothrow) FlowDirEntry[entries]);
            if (!dir) return false;
            for (size_t i = 0; i < entries; ++i)
                dir[i] = FlowDirEntry{ internal::INVALID_FLOW_ID, 0,
                                       common::collections::SlotPool::INVALID };
            return true;
        };

        if (params.outCount > 0)
        {
            if (params.maxOutPerPeer == 0)
                return common::Error::InvalidParam;
            outInflightCap_ = static_cast<uint16_t>(window);

            // Waiting rings are per-mode: each flow takes the knob its mode
            // names, while every out slot is sized for the larger of the two.
            outReliableWaitCap_ = static_cast<uint16_t>(params.reliableWait > 0
                ? RoundUpPow2(params.reliableWait, 1, internal::FLOW_RING_MAX) : 0);
            outUnreliableWaitCap_ = static_cast<uint16_t>(params.unreliableWait > 0
                ? RoundUpPow2(params.unreliableWait, 1, internal::FLOW_RING_MAX) : 0);
            const uint16_t waitStrideCap = outReliableWaitCap_ > outUnreliableWaitCap_
                ? outReliableWaitCap_ : outUnreliableWaitCap_;

            // Two strides, because the in-flight ring is inline and the bulk
            // window is four times as deep. One pool would make every
            // association pay the deeper ring whether it asked for it or not.
            const uint32_t stride = static_cast<uint32_t>(
                OutAssociation::StrideFor(outInflightCap_, waitStrideCap));
            const uint32_t bulkStride = static_cast<uint32_t>(
                OutAssociation::StrideFor(internal::FLOW_WINDOW_BULK, waitStrideCap));
            if (!outAssocPool_.Init(params.outCount, stride,
                                    params.bulkOutCount, bulkStride))
                return common::Error::NotInitialized;
            bulkEnabled_ = params.bulkOutCount > 0;
            if (!initDir(outAssocDir_, params.maxOutPerPeer))
                return common::Error::NotInitialized;
            maxOutAssocPerPeer_ = params.maxOutPerPeer;

            // Retained reliable bodies: same stride as a wire packet (it IS the
            // packet, kept). Only the sending side needs it.
            if (params.stagingCount > 0)
            {
                const uint32_t stagingStride =
                    AlignUp16(sizeof(PacketSlot) + internal::MAX_WIRE_PACKET_SIZE);
                if (!stagingPool_.Init(params.stagingCount, stagingStride))
                    return common::Error::NotInitialized;
            }
        }

        if (params.outCount > 0)
        {
            // Flows are tiny and few, associations large and many.
            if (params.flowCount == 0)
                return common::Error::InvalidParam;
            if (!flowPool_.Init(params.flowCount, static_cast<uint32_t>(sizeof(Flow))))
                return common::Error::NotInitialized;

            // Zero is a legal flow id, so free has to be stamped explicitly.
            for (uint32_t slot = 0; slot < flowPool_.GetCapacity(); ++slot)
            {
                Flow* flow = reinterpret_cast<Flow*>(flowPool_.WriteLock(slot));
                flow->flowId = internal::INVALID_FLOW_ID;
                flow->life   = FlowLifecycle::CLOSED;
                flowPool_.UnlockWrite(slot);
            }

            lastEpochById_.reset(new (std::nothrow) uint8_t[EPOCH_MEMORY_SIZE]{});
            if (!lastEpochById_)
                return common::Error::NotInitialized;
        }

        if (params.inCount > 0)
        {
            if (params.maxInPerPeer == 0)
                return common::Error::InvalidParam;
            // The reorder hold-back is as deep as the window (ReorderCapFor), so
            // a bulk slot now dwarfs a standard one on the hold-back ring, not
            // just the bitmap. Two strides, like the sending pool, keep an
            // ordered-256 flow from carrying the bulk ring. The remote picks the
            // mode, so a slot is cut for bulk only when the acquire asks for it.
            const uint32_t inStandardStride = static_cast<uint32_t>(
                InAssociation::StrideFor(internal::FLOW_WINDOW, internal::FLOW_WINDOW));
            const uint32_t inBulkStride = static_cast<uint32_t>(
                InAssociation::StrideFor(internal::FLOW_WINDOW_BULK, internal::FLOW_WINDOW_BULK));
            if (!inAssocPool_.Init(params.inCount, inStandardStride,
                                   params.bulkInCount, inBulkStride))
                return common::Error::NotInitialized;
            if (!initDir(inAssocDir_, params.maxInPerPeer))
                return common::Error::NotInitialized;
            maxInAssocPerPeer_ = params.maxInPerPeer;
        }

        ackDelayMicros_      = params.ackDelayMicros;
        retryIntervalMicros_ = params.retryIntervalMicros;
        maxAttempts_         = params.maxAttempts;
        flowStallTimeout_    = params.flowStallTimeoutMicros > 0
            ? params.flowStallTimeoutMicros : internal::FLOW_STALL_TIMEOUT_DEFAULT;
        return common::Error::Ok;
    }

    void FlowTable::Shutdown() noexcept
    {
        // Free what this table owns.
        flowPool_.Shutdown();
        outAssocPool_.Shutdown();
        inAssocPool_.Shutdown();
        stagingPool_.Shutdown();
        outAssocDir_.reset();
        inAssocDir_.reset();
        lastEpochById_.reset();

        // Forget what it borrows, so a stale pointer cannot outlive the kernel
        // that owns the recv and send pools. Nulling the directories also makes
        // SendEnabled and ReceiveEnabled report the table disabled.
        recvPool_   = nullptr;
        sendPool_   = nullptr;
        readyQueue_ = nullptr;
        maxOutAssocPerPeer_ = 0;
        maxInAssocPerPeer_  = 0;
    }

    bool FlowTable::SendEnabled() const noexcept
    {
        return outAssocDir_ != nullptr;
    }

    bool FlowTable::ReceiveEnabled() const noexcept
    {
        return inAssocDir_ != nullptr;
    }

    uint32_t FlowTable::MaxOutPerPeer() const noexcept
    {
        return maxOutAssocPerPeer_;
    }

    uint32_t FlowTable::RetryIntervalMicros() const noexcept
    {
        return retryIntervalMicros_;
    }

    // --- Directory helpers ---

    FlowDirEntry* FlowTable::OutDirFor(uint32_t peerSlot) noexcept
    {
        return outAssocDir_.get() + static_cast<size_t>(peerSlot) * maxOutAssocPerPeer_;
    }

    FlowDirEntry* FlowTable::InDirFor(uint32_t peerSlot) noexcept
    {
        return inAssocDir_.get() + static_cast<size_t>(peerSlot) * maxInAssocPerPeer_;
    }

    /** The directory scan every flow lookup shares.

        @return The entry's flow slot, or INVALID when the id is not published in
        this segment. */
    uint32_t FlowTable::FindFlowSlot(const FlowDirEntry* dir, uint32_t width,
                                     uint16_t flowId) noexcept
    {
        for (uint32_t i = 0; i < width; ++i)
        {
            if (dir[i].flowSlot == common::collections::SlotPool::INVALID) continue;
            if (dir[i].flowId == flowId) return dir[i].flowSlot;
        }
        return common::collections::SlotPool::INVALID;
    }

    /** One scan that both rejects a duplicate id and finds the first free entry,
        publishing the already-leased slot on success.

        @return INVALID when the id is already published (duplicate); `width` when
        there is no free entry (directory full); otherwise the index written.
        @pre Caller holds the peer write lock, the directory's guard. */
    uint32_t FlowTable::InsertFlowSlot(FlowDirEntry* dir, uint32_t width,
                                       uint16_t flowId, uint32_t flowSlot) noexcept
    {
        uint32_t freeAt = width;
        for (uint32_t i = 0; i < width; ++i)
        {
            if (dir[i].flowSlot == common::collections::SlotPool::INVALID)
            {
                if (freeAt == width) freeAt = i;
                continue;
            }
            if (dir[i].flowId == flowId)
                return common::collections::SlotPool::INVALID;   // duplicate
        }
        if (freeAt == width)
            return width;   // directory full
        dir[freeAt] = FlowDirEntry{ flowId, 0, flowSlot };
        return freeAt;
    }

    /** Find-and-clear: unpublish the entry that points at `flowSlot`. The slot is
        unique in the segment, so matching on it alone hits a single entry. */
    void FlowTable::EraseFlowSlot(FlowDirEntry* dir, uint32_t width,
                                  uint32_t flowSlot) noexcept
    {
        for (uint32_t i = 0; i < width; ++i)
        {
            if (dir[i].flowSlot == flowSlot)
            {
                dir[i] = FlowDirEntry{ internal::INVALID_FLOW_ID, 0,
                                       common::collections::SlotPool::INVALID };
                return;
            }
        }
    }

    uint32_t FlowTable::FindFlowById(uint16_t flowId) noexcept
    {
        // A free slot carries INVALID_FLOW_ID, written at Init and restored on
        // close. Zero is a legal flow id, so the sentinel cannot be the pool's
        // zeroing.
        if (flowId == internal::INVALID_FLOW_ID)
            return common::collections::SlotPool::INVALID;

        for (uint32_t slot = 0; slot < flowPool_.GetCapacity(); ++slot)
        {
            const Flow* flow = reinterpret_cast<const Flow*>(flowPool_.ReadLock(slot));
            const bool match = flow->flowId == flowId;
            flowPool_.UnlockRead(slot);
            if (match) return slot;
        }
        return common::collections::SlotPool::INVALID;
    }

    void FlowTable::LinkAssociation(uint32_t flowSlot, uint32_t assocSlot) noexcept
    {
        Flow* flow = reinterpret_cast<Flow*>(flowPool_.WriteLock(flowSlot));
        OutAssociation* assoc = reinterpret_cast<OutAssociation*>(
            outAssocPool_.WriteLock(assocSlot));

        assoc->flowSlot   = flowSlot;
        assoc->nextInFlow = flow->firstAssoc;
        flow->firstAssoc  = assocSlot;

        outAssocPool_.UnlockWrite(assocSlot);
        flowPool_.UnlockWrite(flowSlot);
    }

    void FlowTable::UnlinkAssociation(uint32_t flowSlot, uint32_t assocSlot) noexcept
    {
        if (flowSlot >= flowPool_.GetCapacity())
            return;

        Flow* flow = reinterpret_cast<Flow*>(flowPool_.WriteLock(flowSlot));

        uint32_t prev = common::collections::SlotPool::INVALID;
        uint32_t scan = flow->firstAssoc;
        while (scan != common::collections::SlotPool::INVALID && scan != assocSlot)
        {
            const OutAssociation* node = reinterpret_cast<const OutAssociation*>(
                outAssocPool_.ReadLock(scan));
            const uint32_t next = node->nextInFlow;
            outAssocPool_.UnlockRead(scan);
            prev = scan;
            scan = next;
        }

        if (scan == assocSlot)
        {
            OutAssociation* node = reinterpret_cast<OutAssociation*>(
                outAssocPool_.WriteLock(assocSlot));
            const uint32_t next = node->nextInFlow;
            node->nextInFlow = common::collections::SlotPool::INVALID;
            node->flowSlot   = common::collections::SlotPool::INVALID;
            outAssocPool_.UnlockWrite(assocSlot);

            if (prev == common::collections::SlotPool::INVALID)
            {
                flow->firstAssoc = next;
            }
            else
            {
                OutAssociation* before = reinterpret_cast<OutAssociation*>(
                    outAssocPool_.WriteLock(prev));
                before->nextInFlow = next;
                outAssocPool_.UnlockWrite(prev);
            }
        }

        flowPool_.UnlockWrite(flowSlot);
    }

    // --- Flow lifecycle ---

    FlowHandle FlowTable::Open(uint16_t flowId, FlowMode mode) noexcept
    {
        if (flowId == internal::INVALID_FLOW_ID)
            return FlowHandle{common::Error::InvalidParam};
        if (static_cast<uint8_t>(mode) >= FLOW_MODE_COUNT)
            return FlowHandle{common::Error::InvalidParam};

        // Refused here rather than at the first send. A bulk flow draws from a
        // pool the embedder has to ask for, and a socket that did not ask has
        // no way to serve one, so saying so at the open is the only place the
        // caller can act on it.
        if (mode == FlowMode::RELIABLE_ORDERED_BULK && !bulkEnabled_)
            return FlowHandle{common::Error::InvalidParam};

        // The id is how a remote names the flow, so two sharing one would be
        // indistinguishable on the wire.
        if (FindFlowById(flowId) != common::collections::SlotPool::INVALID)
            return FlowHandle{common::Error::AlreadyInUse};

        const uint32_t flowSlot = flowPool_.Acquire();
        if (flowSlot == common::collections::SlotPool::INVALID)
            return FlowHandle{common::Error::LimitReached};

        const uint8_t flowEpoch = static_cast<uint8_t>(
            (lastEpochById_[flowId] + 1u) & FLOW_EPOCH_MASK);

        // Encoded as a whole message, so the stored byte carries only what is
        // fixed for the flow's lifetime. The framing bits vary per packet and
        // the builder lays them over this.
        uint8_t flowData = 0;
        if (!EncodeFlowData(mode, flowEpoch, FlowPart::Whole, flowData))
        {
            flowPool_.Release(flowSlot);
            return FlowHandle{common::Error::InvalidParam};
        }

        // Kept only once nothing left can fail, so a refused open does not
        // spend one of the eight positions the receiver walks.
        lastEpochById_[flowId] = flowEpoch;

        uint32_t epoch = 0;
        {
            Flow* flow = reinterpret_cast<Flow*>(flowPool_.WriteLock(flowSlot));
            flow->epoch      = flow->epoch + 1;   // survives the lease; stale handles miss
            flow->firstAssoc = common::collections::SlotPool::INVALID;
            flow->flowId     = flowId;
            flow->mode       = mode;
            flow->flowData   = flowData;
            flow->life       = FlowLifecycle::OPEN;
            epoch = flow->epoch;
            flowPool_.UnlockWrite(flowSlot);
        }

        // No peer touched: a flow is not bound to one. The per-target state is
        // created by the first send that names an address.
        return FlowHandle{flowSlot, epoch, flowId, flowData};
    }

    FlowLifecycle FlowTable::StateOf(const FlowHandle& flow) noexcept
    {
        if (flow.Failed() || flow.Slot() >= flowPool_.GetCapacity())
            return FlowLifecycle::CLOSED;

        const Flow* state = reinterpret_cast<const Flow*>(flowPool_.ReadLock(flow.Slot()));
        const FlowLifecycle life = state->epoch == flow.Epoch()
            ? state->life : FlowLifecycle::CLOSED;   // stale handle reads closed
        flowPool_.UnlockRead(flow.Slot());

        return life;
    }

    bool FlowTable::BeginClose(const FlowHandle& flow) noexcept
    {
        if (flow.Failed() || flow.Slot() >= flowPool_.GetCapacity())
            return false;

        // Closed first, so nothing opens a new association under a flow that is
        // going away.
        Flow* state = reinterpret_cast<Flow*>(flowPool_.WriteLock(flow.Slot()));
        const bool began = state->epoch == flow.Epoch()
                        && state->life == FlowLifecycle::OPEN;
        if (began)
            state->life = FlowLifecycle::CLOSING;
        flowPool_.UnlockWrite(flow.Slot());
        return began;   // false means a stale handle, or already closing
    }

    bool FlowTable::NextAssocToClose(uint32_t flowSlot, Address& outAddr,
                                     BcpId& outId, uint32_t& outAssoc) noexcept
    {
        // The list is the only index from a flow to its targets; the
        // directories only answer the reverse.
        uint32_t assocSlot = common::collections::SlotPool::INVALID;
        {
            const Flow* state = reinterpret_cast<const Flow*>(
                flowPool_.ReadLock(flowSlot));
            assocSlot = state->firstAssoc;
            flowPool_.UnlockRead(flowSlot);
        }
        if (assocSlot == common::collections::SlotPool::INVALID)
            return false;

        // Read the identity out, then approach the peer with no association
        // lock held: the refund needs the peer's write lock.
        {
            const OutAssociation* assoc = reinterpret_cast<const OutAssociation*>(
                outAssocPool_.ReadLock(assocSlot));
            outAddr = assoc->peerAddr;
            outId   = assoc->peerId;
            outAssocPool_.UnlockRead(assocSlot);
        }
        outAssoc = assocSlot;
        return true;
    }

    void FlowTable::FinishClose(uint32_t flowSlot) noexcept
    {
        {
            Flow* state = reinterpret_cast<Flow*>(flowPool_.WriteLock(flowSlot));
            state->life   = FlowLifecycle::CLOSED;
            state->flowId = internal::INVALID_FLOW_ID;   // marks the slot free
            flowPool_.UnlockWrite(flowSlot);
        }
        flowPool_.Release(flowSlot);
    }

    bool FlowTable::ModeOf(const FlowHandle& flow, FlowMode& outMode) noexcept
    {
        if (flow.Failed() || flow.Slot() >= flowPool_.GetCapacity())
            return false;

        // Mode comes off the flow, the only thing this needs. No peer yet: the
        // destination is not known until Send names it. Taking and releasing
        // the flow lock here is what keeps it from ever being held across a
        // peer or association lock.
        const Flow* state = reinterpret_cast<const Flow*>(flowPool_.ReadLock(flow.Slot()));
        const bool usable = state->epoch == flow.Epoch()
                         && state->life == FlowLifecycle::OPEN;
        outMode = state->mode;
        flowPool_.UnlockRead(flow.Slot());
        return usable;
    }

    // --- Body storage ---

    common::Result<PacketSlotWriter> FlowTable::AcquireStagingWriter() noexcept
    {
        const uint32_t slot = stagingPool_.Acquire();
        if (slot == common::collections::SlotPool::INVALID)
            return common::Result<PacketSlotWriter>::Fail(common::Error::PoolExhausted);
        return common::Result<PacketSlotWriter>::Success(
            PacketSlotWriter{PacketSlotHandle{slot, &stagingPool_}});
    }

    bool FlowTable::IsRetainedBody(const PacketSlotHandle& handle) const noexcept
    {
        return handle.GetPool() == &stagingPool_;
    }

    common::collections::SlotPool* FlowTable::WaitPoolFor(FlowMode mode) noexcept
    {
        return mode == FlowMode::UNRELIABLE ? sendPool_ : &stagingPool_;
    }

    common::collections::SlotPool* FlowTable::StagingPool() noexcept
    {
        return &stagingPool_;
    }

    // --- The peer-locked surface ---

    FlowLifecycle FlowTable::StateOf(const FlowHandle& flow, uint32_t peerSlot) noexcept
    {
        const uint32_t assocSlot = FindOutAssoc(peerSlot, flow.Id());
        if (assocSlot == common::collections::SlotPool::INVALID)
            return FlowLifecycle::CLOSED;   // never sent to this peer yet

        const OutAssociation* assoc = reinterpret_cast<const OutAssociation*>(
            outAssocPool_.ReadLock(assocSlot));
        const FlowLifecycle life = assoc->life;
        outAssocPool_.UnlockRead(assocSlot);

        return life;
    }

    uint32_t FlowTable::FindOutAssoc(uint32_t peerSlot, uint16_t flowId) noexcept
    {
        return FindFlowSlot(OutDirFor(peerSlot), maxOutAssocPerPeer_, flowId);
    }

    uint32_t FlowTable::OutAssocAt(uint32_t peerSlot, uint32_t dirIndex) noexcept
    {
        return OutDirFor(peerSlot)[dirIndex].flowSlot;
    }

    bool FlowTable::AnyAckDue(uint32_t peerSlot, uint64_t now) noexcept
    {
        bool ackDue = false;
        FlowDirEntry* dir = InDirFor(peerSlot);
        for (uint32_t i = 0; i < maxInAssocPerPeer_ && !ackDue; ++i)
        {
            if (dir[i].flowSlot == common::collections::SlotPool::INVALID)
                continue;
            const InAssociation* flow = reinterpret_cast<const InAssociation*>(
                inAssocPool_.ReadLock(dir[i].flowSlot));
            if (flow->newSinceFlush > 0 &&
                now - flow->ackArmedMicros >= ackDelayMicros_)
                ackDue = true;
            inAssocPool_.UnlockRead(dir[i].flowSlot);
        }
        return ackDue;
    }

    bool FlowTable::InAssocJammed(const InAssociation* flow, uint64_t now) const noexcept
    {
        // Only an ordered flow holds a gap. recvHighest >= recvNext means the
        // cursor sits behind packets already seen, so the hold-back is pinning
        // recv slots. If the cursor has not moved for the timeout, the sender is
        // not filling the gap and never will.
        return flow->reorderCap > 0
            && flow->recvHighest >= flow->recvNext
            && now - flow->lastProgressMicros > flowStallTimeout_;
    }

    bool FlowTable::AnyJammed(uint32_t peerSlot, uint64_t now) noexcept
    {
        bool jammed = false;
        FlowDirEntry* dir = InDirFor(peerSlot);
        for (uint32_t i = 0; i < maxInAssocPerPeer_ && !jammed; ++i)
        {
            if (dir[i].flowSlot == common::collections::SlotPool::INVALID)
                continue;
            const InAssociation* flow = reinterpret_cast<const InAssociation*>(
                inAssocPool_.ReadLock(dir[i].flowSlot));
            jammed = InAssocJammed(flow, now);
            inAssocPool_.UnlockRead(dir[i].flowSlot);
        }
        return jammed;
    }

    uint32_t FlowTable::EvictJammedInFlows(uint32_t peerSlot, uint64_t now) noexcept
    {
        // Runs under the peer's write lock, exactly like the peer-teardown
        // sweep, so the flow locks nest correctly (peer -> flow) and no admit
        // can publish a slot while this frees one. The condition is re-checked
        // under the write lock, because a racing DeliverIn may have advanced
        // the cursor since the read scan flagged this peer.
        uint32_t evicted = 0;
        FlowDirEntry* dir = InDirFor(peerSlot);
        for (uint32_t i = 0; i < maxInAssocPerPeer_; ++i)
        {
            const uint32_t flowSlot = dir[i].flowSlot;
            if (flowSlot == common::collections::SlotPool::INVALID)
                continue;
            InAssociation* assoc = reinterpret_cast<InAssociation*>(
                inAssocPool_.WriteLock(flowSlot));
            const bool jammed = InAssocJammed(assoc, now);
            if (jammed)
            {
                dir[i] = FlowDirEntry{ internal::INVALID_FLOW_ID, 0,
                                       common::collections::SlotPool::INVALID };
                DrainInHoldback(assoc);
                assoc->life = FlowLifecycle::CLOSED;
            }
            inAssocPool_.UnlockWrite(flowSlot);
            if (jammed)
            {
                inAssocPool_.Release(flowSlot);
                ++evicted;
            }
        }
        return evicted;
    }

    uint32_t FlowTable::InAssocCountForPeer(uint32_t peerSlot) noexcept
    {
        uint32_t count = 0;
        FlowDirEntry* dir = InDirFor(peerSlot);
        for (uint32_t i = 0; i < maxInAssocPerPeer_; ++i)
            if (dir[i].flowSlot != common::collections::SlotPool::INVALID)
                ++count;
        return count;
    }

    uint64_t FlowTable::NextDeadline(uint32_t peerSlot) noexcept
    {
        uint64_t soonest = UINT64_MAX;   // nothing armed
        auto consider = [&](uint64_t deadline) {
            if (deadline < soonest) soonest = deadline;
        };

        if (inAssocDir_)
        {
            FlowDirEntry* dir = InDirFor(peerSlot);
            for (uint32_t i = 0; i < maxInAssocPerPeer_; ++i)
            {
                if (dir[i].flowSlot == common::collections::SlotPool::INVALID) continue;
                const InAssociation* flow = reinterpret_cast<const InAssociation*>(
                    inAssocPool_.ReadLock(dir[i].flowSlot));
                if (flow->newSinceFlush > 0)
                    consider(flow->ackArmedMicros + ackDelayMicros_);
                inAssocPool_.UnlockRead(dir[i].flowSlot);
            }
        }

        if (outAssocDir_)
        {
            FlowDirEntry* dir = OutDirFor(peerSlot);
            for (uint32_t i = 0; i < maxOutAssocPerPeer_; ++i)
            {
                if (dir[i].flowSlot == common::collections::SlotPool::INVALID) continue;
                const OutAssociation* flow = reinterpret_cast<const OutAssociation*>(
                    outAssocPool_.ReadLock(dir[i].flowSlot));
                if (flow->life == FlowLifecycle::OPEN && flow->unresolved > 0)
                {
                    // Earliest RTO across in-flight entries; a full scan
                    // is bounded by the ring cap.
                    const uint64_t rto = RetransmitTimeout(flow, retryIntervalMicros_);
                    const uint32_t cap = flow->inflightCap;
                    const InFlightEntry* ring = flow->InFlight();
                    uint64_t oldest = 0;
                    for (uint32_t k = 0; k < cap; ++k)
                        if (ring[k].seq != 0 &&
                            (oldest == 0 || ring[k].sentAtMicros < oldest))
                            oldest = ring[k].sentAtMicros;
                    if (oldest != 0) consider(oldest + rto);
                }
                outAssocPool_.UnlockRead(dir[i].flowSlot);
            }
        }

        return soonest;
    }

    size_t FlowTable::BuildPeerAckBody(uint32_t peerSlot, uint8_t* out, size_t cap) noexcept
    {
        // One packet carries every association of this peer that owes acks.
        // Each entry: [flowId(2)][epoch(1)][rangeCount(1)][first,last]*count.
        // The epoch is what stops an ack outliving the generation it describes:
        // an id closed and reopened numbers from one again, and without it the
        // sender would resolve the new generation's packets against sequences
        // only the old one ever delivered. Generated under each association's
        // lock (nested inside the peer read lock, which holds the sweep out);
        // owed counters reset here.
        size_t bodyLen = 0;

        FlowDirEntry* dir = InDirFor(peerSlot);
        for (uint32_t i = 0; i < maxInAssocPerPeer_; ++i)
        {
            if (dir[i].flowSlot == common::collections::SlotPool::INVALID) continue;
            const uint32_t flowSlot = dir[i].flowSlot;

            InAssociation* flow = reinterpret_cast<InAssociation*>(
                inAssocPool_.WriteLock(flowSlot));
            if (flow->life == FlowLifecycle::OPEN && flow->newSinceFlush > 0)
            {
                AckRange ranges[internal::FLOW_ACK_RANGE_COUNT];
                const uint8_t rc = BuildAckRanges(flow, ranges,
                                                  internal::FLOW_ACK_RANGE_COUNT);
                const size_t need = 4 + static_cast<size_t>(rc) * 8;
                if (rc > 0 && bodyLen + need <= cap)
                {
                    const uint16_t flowId = flow->flowId;
                    out[bodyLen++] = static_cast<uint8_t>(flowId);
                    out[bodyLen++] = static_cast<uint8_t>(flowId >> 8);
                    out[bodyLen++] = flow->flowEpoch;
                    out[bodyLen++] = rc;
                    for (uint8_t r = 0; r < rc; ++r)
                    {
                        const uint32_t first = ranges[r].first, last = ranges[r].last;
                        out[bodyLen++] = static_cast<uint8_t>(first);
                        out[bodyLen++] = static_cast<uint8_t>(first >> 8);
                        out[bodyLen++] = static_cast<uint8_t>(first >> 16);
                        out[bodyLen++] = static_cast<uint8_t>(first >> 24);
                        out[bodyLen++] = static_cast<uint8_t>(last);
                        out[bodyLen++] = static_cast<uint8_t>(last >> 8);
                        out[bodyLen++] = static_cast<uint8_t>(last >> 16);
                        out[bodyLen++] = static_cast<uint8_t>(last >> 24);
                    }
                    flow->newSinceFlush  = 0;   // owed cleared; re-arms on next arrival
                    flow->ackArmedMicros = 0;
                }
                // else the body is full: this flow's acks ride the next flush
            }
            inAssocPool_.UnlockWrite(flowSlot);
            if (bodyLen + 3 + 8 > cap) break;   // no room for another entry
        }

        return bodyLen;
    }

    void FlowTable::ApplyAckRanges(uint32_t peerSlot, uint16_t flowId, uint8_t flowEpoch,
                                   const AckRange* ranges, uint8_t count, uint64_t now,
                                   CongestionDelta& delta) noexcept
    {
        const uint32_t flowSlot = FindOutAssoc(peerSlot, flowId);
        if (flowSlot == common::collections::SlotPool::INVALID) return;

        // Matched exactly, not walked forward like the data path: an ack
        // describes one generation and has none of its own to catch up to, so
        // anything but this association's own epoch is an ack for a flow that
        // no longer exists and must resolve nothing.
        OutAssociation* flow = reinterpret_cast<OutAssociation*>(
            outAssocPool_.WriteLock(flowSlot));
        if (flow->flowId == flowId && flow->flowEpoch == flowEpoch)
        {
            const uint32_t cap = flow->inflightCap;
            InFlightEntry* ring = flow->InFlight();
            for (uint32_t i = 0; i < cap; ++i)
                if (ring[i].seq != 0 && SeqInRanges(ring[i].seq, ranges, count))
                    ResolveOutEntry(flow, ring[i], true, now, delta);
        }
        outAssocPool_.UnlockWrite(flowSlot);
    }

    bool FlowTable::OutAssocEpochIs(uint32_t assocSlot, uint8_t flowEpoch) noexcept
    {
        if (assocSlot >= outAssocPool_.GetCapacity()) return false;

        const OutAssociation* assoc = reinterpret_cast<const OutAssociation*>(
            outAssocPool_.ReadLock(assocSlot));
        const bool matches = assoc->flowEpoch == flowEpoch;
        outAssocPool_.UnlockRead(assocSlot);

        return matches;
    }

    /** @pre Caller holds the peer write lock; the peer is lent in. */
    uint32_t FlowTable::CreateAssociation(const Peer& peer, uint32_t peerSlot,
                                          uint16_t flowId) noexcept
    {
        const uint32_t flowSlot = FindFlowById(flowId);
        if (flowSlot == common::collections::SlotPool::INVALID)
            return common::collections::SlotPool::INVALID;   // no such flow open here

        FlowMode mode{};
        uint8_t  flowEpoch = 0;
        {
            const Flow* flow = reinterpret_cast<const Flow*>(flowPool_.ReadLock(flowSlot));
            const bool open = flow->life == FlowLifecycle::OPEN;
            mode      = flow->mode;
            flowEpoch = FlowDataEpoch(flow->flowData);
            flowPool_.UnlockRead(flowSlot);
            if (!open)
                return common::collections::SlotPool::INVALID;
        }

        const uint32_t assocSlot = outAssocPool_.Acquire(
            mode == FlowMode::RELIABLE_ORDERED_BULK);
        if (assocSlot == common::collections::SlotPool::INVALID)
            return common::collections::SlotPool::INVALID;

        // Build, then publish, so no lookup reaches a half-built association.
        // mode is copied once here and never read from the flow again, which is
        // what keeps the packet paths one lock deep.
        {
            OutAssociation* assoc = reinterpret_cast<OutAssociation*>(
                outAssocPool_.WriteLock(assocSlot));
            ResetOutAssoc(assoc, peerSlot, peer.addr, &peer.id, flowId, mode, flowEpoch,
                          WindowFor(mode),
                          mode == FlowMode::UNRELIABLE ? outUnreliableWaitCap_
                                                       : outReliableWaitCap_);
            assoc->flowSlot   = common::collections::SlotPool::INVALID;
            assoc->nextInFlow = common::collections::SlotPool::INVALID;
            outAssocPool_.UnlockWrite(assocSlot);
        }

        if (InsertFlowSlot(OutDirFor(peerSlot), maxOutAssocPerPeer_, flowId, assocSlot)
            >= maxOutAssocPerPeer_)
        {
            outAssocPool_.Release(assocSlot);
            return common::collections::SlotPool::INVALID;   // this peer is at its cap
        }

        LinkAssociation(flowSlot, assocSlot);
        return assocSlot;
    }

    /** Decides and mutates under peer-write plus association-write: stamp on a
        pass, route to the waiting ring on a refusal. Sequence numbers are handed
        out in the order packets actually leave, so a non-empty ring forces even
        a passing packet to queue; stamping it now would give newer data a lower
        seq than the packets in front of it.

        @pre Caller holds the peer write lock; the peer is lent in. */
    SendAdmission FlowTable::AdmitOut(Peer& peer, uint32_t peerSlot, PacketSlot& packet,
                                      uint32_t packetSlot, uint16_t wireSize,
                                      bool flying) noexcept
    {
        // The peer is lent, already write-locked: no re-lookup. Take only the
        // flow lock (peer->flow), decide, and mutate.
        if (!outAssocDir_) return SendAdmission::Dead;
        const uint16_t flowId = packet.FlowId();
        if (flowId == internal::INVALID_FLOW_ID) return SendAdmission::Dead;

        uint32_t assocSlot = FindOutAssoc(peerSlot, flowId);
        if (assocSlot == common::collections::SlotPool::INVALID)
        {
            // First send to this peer: OpenFlow knew no address, so the
            // association is created here.
            assocSlot = CreateAssociation(peer, peerSlot, flowId);
            if (assocSlot == common::collections::SlotPool::INVALID)
                return SendAdmission::Dead;
        }

        OutAssociation* assoc = reinterpret_cast<OutAssociation*>(
            outAssocPool_.WriteLock(assocSlot));
        SendAdmission result;
        if (assoc->life != FlowLifecycle::OPEN || assoc->flowId != flowId)
        {
            result = SendAdmission::Dead;
        }
        else
        {
            const bool unreliable = assoc->mode == FlowMode::UNRELIABLE;
            if (assoc->waitingCount == 0 && CanSend(*assoc, peer, wireSize, !unreliable))
            {
                StampFlowPacket(*assoc, peer, packet,
                                unreliable ? common::collections::SlotPool::INVALID
                                           : packetSlot,
                                wireSize, flying);
                result = SendAdmission::Sent;
            }
            else if (assoc->waitingCount < assoc->waitingCap)
            {
                EnqueueWaiting(*assoc, packetSlot, wireSize);
                result = SendAdmission::Queued;
            }
            else if (!unreliable)
            {
                // Reliable never discards accepted data: with the ring full,
                // the NEWEST send is refused, the app's backpressure signal.
                result = SendAdmission::Rejected;
            }
            else if (assoc->waitingCap > 0)
            {
                // Unreliable seats the newest by evicting the oldest waiter;
                // never retransmitted, so nothing downstream misses the slot.
                WaitingEntry& oldest =
                    assoc->Waiting()[assoc->waitingHead & (assoc->waitingCap - 1u)];
                sendPool_->Release(oldest.packetSlot);
                oldest = WaitingEntry{ 0, common::collections::SlotPool::INVALID, 0 };
                assoc->waitingHead  += 1;
                assoc->waitingCount -= 1;
                EnqueueWaiting(*assoc, packetSlot, wireSize);
                result = SendAdmission::Queued;
            }
            else
            {
                result = SendAdmission::Dropped;   // no buffer configured
            }
        }
        outAssocPool_.UnlockWrite(assocSlot);
        return result;
    }

    FlowAdmit FlowTable::AdmitInFlow(uint32_t peerSlot, const Address& from,
                                     const BcpId& peerId, uint16_t flowId,
                                     uint8_t flowData) noexcept
    {
        // The part is a property of this packet, not of the association, so it
        // is decoded only to be validated: framing on a mode that cannot frame
        // is refused here rather than reaching the delivery path.
        FlowMode mode{};
        uint8_t  flowEpoch = 0;
        FlowPart part{};
        if (!DecodeFlowData(flowData, mode, flowEpoch, part))
            return FlowAdmit::Rejected;

        FlowDirEntry* dir = InDirFor(peerSlot);
        const uint32_t existing = FindFlowSlot(dir, maxInAssocPerPeer_, flowId);
        if (existing != common::collections::SlotPool::INVALID)
        {
            InAssociation* assoc = reinterpret_cast<InAssociation*>(
                inAssocPool_.WriteLock(existing));
            const FlowEpochOrder order = CompareFlowEpoch(assoc->flowEpoch, flowEpoch);
            if (order == FlowEpochOrder::Newer)
            {
                // The sender closed this id and opened it again, so it numbers
                // from one now and nothing held against the old generation can
                // ever be completed. Drain first: the reset only stamps the
                // hold-back entries free, and the slots they name are ours to
                // release.
                DrainInHoldback(assoc);
                ResetInAssoc(assoc, peerSlot, from, &peerId, flowId, mode,
                             flowEpoch, WindowFor(mode), ReorderCapFor(mode));
            }
            inAssocPool_.UnlockWrite(existing);

            return order == FlowEpochOrder::Stale ? FlowAdmit::Stale
                                                  : FlowAdmit::Existing;
        }

        // This is the one path where a REMOTE makes this socket allocate, so
        // it is caps-only: a dry pool or a full directory refuses, and the
        // sender is told rather than left retransmitting into silence.
        const uint32_t flowSlot = inAssocPool_.Acquire(mode == FlowMode::RELIABLE_ORDERED_BULK);
        if (flowSlot == common::collections::SlotPool::INVALID)
            return FlowAdmit::Rejected;

        // Build, then publish: no lookup can reach a half-built flow.
        {
            InAssociation* flow = reinterpret_cast<InAssociation*>(
                inAssocPool_.WriteLock(flowSlot));
            ResetInAssoc(flow, peerSlot, from, &peerId, flowId, mode,
                         flowEpoch, WindowFor(mode), ReorderCapFor(mode));
            inAssocPool_.UnlockWrite(flowSlot);
        }
        if (InsertFlowSlot(dir, maxInAssocPerPeer_, flowId, flowSlot)
            == maxInAssocPerPeer_)
        {
            inAssocPool_.Release(flowSlot);
            return FlowAdmit::Rejected;
        }

        return FlowAdmit::Registered;
    }

    FlowAdmit FlowTable::AdmitIn(uint32_t peerSlot, const Address& from, const BcpId& peerId,
                                 uint16_t flowId, uint8_t flowData,
                                 uint32_t& outAssoc) noexcept
    {
        outAssoc = common::collections::SlotPool::INVALID;

        // First packet of a flow registers it: the flow data byte carries
        // everything registration needs.
        const FlowAdmit admit = AdmitInFlow(peerSlot, from, peerId, flowId, flowData);
        if (admit == FlowAdmit::Registered || admit == FlowAdmit::Existing)
            outAssoc = FindFlowSlot(InDirFor(peerSlot), maxInAssocPerPeer_, flowId);
        return admit;
    }

    void FlowTable::UnpublishOut(uint32_t peerSlot, uint32_t assocSlot) noexcept
    {
        EraseFlowSlot(OutDirFor(peerSlot), maxOutAssocPerPeer_, assocSlot);
    }

    void FlowTable::FreeAssoc(uint32_t flowSlot, Peer* refundTo) noexcept
    {
        // The teardown: drain both rings (releasing the leases they hold),
        // refund the still-in-flight bytes to the peer's budget (skipped when
        // the peer is being freed, refundTo null; waiting packets never spent
        // any), mark CLOSED, and recycle the slot. Caller holds the peer's write
        // lock (the refund's guard) and has already unpublished the directory
        // entry.
        // Unlink first: a linked association whose slot is recycled would put
        // a stranger on the flow's list, which CloseFlow walks.
        uint32_t owningFlow = common::collections::SlotPool::INVALID;
        {
            const OutAssociation* peek = reinterpret_cast<const OutAssociation*>(
                outAssocPool_.ReadLock(flowSlot));
            owningFlow = peek->flowSlot;
            outAssocPool_.UnlockRead(flowSlot);
        }
        if (owningFlow != common::collections::SlotPool::INVALID)
            UnlinkAssociation(owningFlow, flowSlot);

        OutAssociation* flow = reinterpret_cast<OutAssociation*>(
            outAssocPool_.WriteLock(flowSlot));
        const uint32_t drained = DrainOutInflight(flow);
        DrainOutWaiting(flow);
        flow->life = FlowLifecycle::CLOSED;
        outAssocPool_.UnlockWrite(flowSlot);

        if (refundTo)
            refundTo->bytesInFlight -= drained <= refundTo->bytesInFlight
                ? drained : refundTo->bytesInFlight;
        outAssocPool_.Release(flowSlot);
    }

    void FlowTable::FailAssoc(uint32_t flowSlot, uint16_t flowId, Peer* refundTo) noexcept
    {
        // FAILED, not freed: the app has to be able to see what happened, so
        // the slot stays leased until CloseFlow. What it held goes back now,
        // since a dead association pinning staging slots and budget would tax
        // every other one to the same peer.
        OutAssociation* flow = reinterpret_cast<OutAssociation*>(
            outAssocPool_.WriteLock(flowSlot));

        uint32_t drained = 0;
        if (flow->flowId == flowId && flow->life != FlowLifecycle::CLOSED)
        {
            drained = DrainOutInflight(flow);
            DrainOutWaiting(flow);
            flow->life = FlowLifecycle::FAILED;
        }
        outAssocPool_.UnlockWrite(flowSlot);

        if (refundTo && drained)
            refundTo->bytesInFlight -= drained <= refundTo->bytesInFlight
                ? drained : refundTo->bytesInFlight;
    }

    void FlowTable::SweepPeer(uint32_t peerSlot) noexcept
    {
        // Both directions, before the peer slot can recycle: a later peer in the
        // same slot must inherit empty directories, never a stranger's flows.
        // Unpublish first, then free; stale FlowHandles read CLOSED from the epoch
        // check. Runs under the peer's write lock (RemovePeer holds it), so the
        // flow locks FreeAssoc / the in-sweep take nest correctly (peer->flow).
        // The peer is being removed, so its congestion budget dies with it: the
        // drained byte count is discarded rather than refunded (refundTo null).
        if (outAssocDir_)
        {
            FlowDirEntry* dir = OutDirFor(peerSlot);
            for (uint32_t i = 0; i < maxOutAssocPerPeer_; ++i)
            {
                const uint32_t flowSlot = dir[i].flowSlot;
                if (flowSlot == common::collections::SlotPool::INVALID)
                    continue;
                dir[i] = FlowDirEntry{ internal::INVALID_FLOW_ID, 0,
                                       common::collections::SlotPool::INVALID };
                FreeAssoc(flowSlot, nullptr);
            }
        }
        if (inAssocDir_)
        {
            FlowDirEntry* dir = InDirFor(peerSlot);
            for (uint32_t i = 0; i < maxInAssocPerPeer_; ++i)
            {
                const uint32_t flowSlot = dir[i].flowSlot;
                if (flowSlot == common::collections::SlotPool::INVALID)
                    continue;
                dir[i] = FlowDirEntry{ internal::INVALID_FLOW_ID, 0,
                                       common::collections::SlotPool::INVALID };
                InAssociation* assoc = reinterpret_cast<InAssociation*>(
                    inAssocPool_.WriteLock(flowSlot));
                DrainInHoldback(assoc);
                assoc->life = FlowLifecycle::CLOSED;
                inAssocPool_.UnlockWrite(flowSlot);
                inAssocPool_.Release(flowSlot);
            }
        }
    }

    // --- Ring drains ---

    uint32_t FlowTable::DrainOutInflight(OutAssociation* flow) noexcept
    {
        uint32_t drainedBytes = 0;
        InFlightEntry* ring = flow->InFlight();
        for (uint32_t i = 0; i < flow->inflightCap; ++i)
        {
            if (ring[i].seq != 0) drainedBytes += ring[i].wireSize;   // still in flight: refund
            if (ring[i].packetSlot != common::collections::SlotPool::INVALID)
                stagingPool_.Release(ring[i].packetSlot);
            ring[i].packetSlot = common::collections::SlotPool::INVALID;
            ring[i].seq        = 0;
            ring[i].wireSize   = 0;
        }
        flow->unresolved = 0;
        return drainedBytes;
    }

    void FlowTable::DrainOutWaiting(OutAssociation* flow) noexcept
    {
        // A close is abortive for waiting packets just as for unacked in-flight
        // ones: the leases go back to their pool. Different pool than the flow's,
        // so releasing under the flow lock is safe.
        common::collections::SlotPool* pool = WaitPoolFor(flow->mode);
        while (flow->waitingCount > 0)
        {
            WaitingEntry& oldest =
                flow->Waiting()[flow->waitingHead & (flow->waitingCap - 1u)];
            if (oldest.packetSlot != common::collections::SlotPool::INVALID)
                pool->Release(oldest.packetSlot);
            oldest = WaitingEntry{ 0, common::collections::SlotPool::INVALID, 0 };
            flow->waitingHead  += 1;
            flow->waitingCount -= 1;
        }
    }

    void FlowTable::DrainInHoldback(InAssociation* flow) noexcept
    {
        if (flow->reorderCap == 0) return;
        HoldbackEntry* ring = flow->Holdback();
        for (uint32_t i = 0; i < flow->reorderCap; ++i)
        {
            if (ring[i].packetSlot != common::collections::SlotPool::INVALID)
                recvPool_->Release(ring[i].packetSlot);
            ring[i].packetSlot = common::collections::SlotPool::INVALID;
            ring[i].seq = 0;
        }
    }

    // --- Retransmit ---

    void FlowTable::ResolveOutEntry(OutAssociation* flow, InFlightEntry& entry,
                                    bool acked, uint64_t nowMicros, CongestionDelta& delta) noexcept
    {
        if (entry.seq == 0) return;   // already resolved: idempotent

        delta.resolvedBytes += entry.wireSize;
        if (acked)
        {
            delta.ackedBytes += entry.wireSize;
            if (nowMicros >= entry.sentAtMicros)
            {
                const uint64_t sample = nowMicros - entry.sentAtMicros;
                SampleRtt(flow, sample);   // per-flow RTT, for this flow's RTO
                delta.rttSampleMicros = sample > UINT32_MAX
                    ? UINT32_MAX : static_cast<uint32_t>(sample);
            }
        }
        else
        {
            delta.sawLoss = true;
        }

        if (flow->unresolved > 0) --flow->unresolved;
        if (entry.packetSlot != common::collections::SlotPool::INVALID)
            stagingPool_.Release(entry.packetSlot);   // different pool: safe under flow lock
        entry.seq        = 0;
        entry.packetSlot = common::collections::SlotPool::INVALID;
        entry.wireSize   = 0;
    }

    void FlowTable::RetransmitInflight(OutAssociation& flow, uint64_t now, CongestionDelta& delta,
                                       uint32_t* resendSeqs, uint32_t* resendSlots,
                                       uint32_t& resendCount, bool& exhausted) noexcept
    {
        // Scan the in-flight ring for entries past their RTO. Reliable ones are
        // collected for retransmit (refresh sentAt, keep them in flight);
        // unreliable ones are declared lost and resolved. Loss feedback goes into
        // `delta`, never the peer: the caller applies it under the peer lock.
        const uint64_t rto  = RetransmitTimeout(&flow, retryIntervalMicros_);
        const uint32_t cap  = flow.inflightCap;
        const FlowMode mode = flow.mode;
        InFlightEntry* ring = flow.InFlight();
        for (uint32_t i = 0; i < cap; ++i)
        {
            InFlightEntry& entry = ring[i];
            if (entry.seq == 0) continue;
            if (now - entry.sentAtMicros < rto) continue;

            // RTO fired: a loss on this path either way.
            if (mode == FlowMode::UNRELIABLE)
            {
                ResolveOutEntry(&flow, entry, false, now, delta);   // lost, dropped
            }
            else
            {
                delta.sawLoss = true;   // reliable: trim the budget, keep it in flight

                // Out of attempts: the remote has stopped answering this flow
                // entirely. Retrying further only burns budget, so the caller
                // fails the flow and the app reads it off the handle. This is
                // the only give-up left now that opening takes no round trip.
                if (entry.retries >= maxAttempts_)
                {
                    exhausted = true;
                    continue;
                }

                if (entry.packetSlot != common::collections::SlotPool::INVALID
                    && resendCount < RESENDS_PER_ASSOC_PER_TICK)
                {
                    resendSeqs[resendCount]    = entry.seq;
                    resendSlots[resendCount++] = entry.packetSlot;
                    entry.sentAtMicros = now;   // don't re-fire before next RTO
                    ++entry.retries;
                }
            }
        }
    }

    void FlowTable::RetransmitPass(uint32_t assocSlot, uint64_t now, CongestionDelta& delta,
                                   uint16_t& outFlowId, uint32_t* resendSeqs,
                                   uint32_t* resendSlots, uint32_t& resendCount,
                                   bool& exhausted) noexcept
    {
        OutAssociation* flow = reinterpret_cast<OutAssociation*>(
            outAssocPool_.WriteLock(assocSlot));
        outFlowId = flow->flowId;

        switch (flow->life)
        {
        case FlowLifecycle::OPEN:
            RetransmitInflight(*flow, now, delta, resendSeqs, resendSlots, resendCount,
                               exhausted);
            break;
        default: break;
        }

        outAssocPool_.UnlockWrite(assocSlot);
    }

    bool FlowTable::ResendStillValid(uint32_t assocSlot, uint32_t expectedSeq,
                                     uint32_t stagingSlot) noexcept
    {
        bool valid = false;
        const OutAssociation* flow = reinterpret_cast<const OutAssociation*>(
            outAssocPool_.ReadLock(assocSlot));
        if (flow->life == FlowLifecycle::OPEN)
        {
            const InFlightEntry& entry =
                flow->InFlight()[expectedSeq & (flow->inflightCap - 1)];
            valid = entry.seq == expectedSeq && entry.packetSlot == stagingSlot;
        }
        outAssocPool_.UnlockRead(assocSlot);
        return valid;
    }

    // --- The waiting-ring drain ---

    bool FlowTable::PeekWaiting(uint32_t peerSlot, const Peer& peer,
                                WaitingCandidate& out) noexcept
    {
        // Read locks only: across this peer's flows, find the OLDEST waiting
        // head that passes the gate right now. Epoch is captured so a flow slot
        // recycled between peek and claim can never be mistaken for the one
        // peeked.
        out = WaitingCandidate{};
        uint64_t oldestSince = 0;

        const FlowDirEntry* dir = OutDirFor(peerSlot);
        for (uint32_t i = 0; i < maxOutAssocPerPeer_; ++i)
        {
            const uint32_t flowSlot = dir[i].flowSlot;
            if (flowSlot == common::collections::SlotPool::INVALID) continue;

            const OutAssociation* flow = reinterpret_cast<const OutAssociation*>(
                outAssocPool_.ReadLock(flowSlot));
            if (flow->life == FlowLifecycle::OPEN && flow->waitingCount > 0)
            {
                const WaitingEntry& head =
                    flow->Waiting()[flow->waitingHead & (flow->waitingCap - 1u)];
                const bool windowed = flow->mode != FlowMode::UNRELIABLE;
                if (CanSend(*flow, peer, head.wireSize, windowed)
                    && (out.assocSlot == common::collections::SlotPool::INVALID
                        || head.waitingSince < oldestSince))
                {
                    out.assocSlot  = flowSlot;
                    out.packetSlot = head.packetSlot;
                    out.epoch      = flow->epoch;
                    oldestSince    = head.waitingSince;
                    out.mode       = flow->mode;
                }
            }
            outAssocPool_.UnlockRead(flowSlot);
        }

        return out.assocSlot != common::collections::SlotPool::INVALID;
    }

    bool FlowTable::ClaimWaiting(const WaitingCandidate& candidate, Peer& peer,
                                 PacketSlot& packet) noexcept
    {
        // A concurrent Update may have drained the head between the peek and
        // this lock, so the current head is re-checked against the very slot
        // the caller's handle holds.
        bool claimed = false;

        OutAssociation* flow = reinterpret_cast<OutAssociation*>(
            outAssocPool_.WriteLock(candidate.assocSlot));
        if (flow->epoch == candidate.epoch
            && flow->life == FlowLifecycle::OPEN
            && flow->waitingCount > 0)
        {
            WaitingEntry& head =
                flow->Waiting()[flow->waitingHead & (flow->waitingCap - 1u)];
            const bool windowed = flow->mode != FlowMode::UNRELIABLE;
            if (head.packetSlot == candidate.packetSlot
                && CanSend(*flow, peer, head.wireSize, windowed))
            {
                const uint16_t wireSize = head.wireSize;
                head = WaitingEntry{ 0, common::collections::SlotPool::INVALID, 0 };
                flow->waitingHead  += 1;
                flow->waitingCount -= 1;
                StampFlowPacket(*flow, peer, packet,
                                candidate.mode == FlowMode::UNRELIABLE
                                    ? common::collections::SlotPool::INVALID
                                    : candidate.packetSlot,
                                wireSize, true);
                claimed = true;
            }
        }
        outAssocPool_.UnlockWrite(candidate.assocSlot);

        return claimed;
    }

    // --- Delivery ---

    bool FlowTable::SplitBatchToReady(const PacketSlot& batch) noexcept
    {
        const size_t header  = batch.ContentOffset();
        const size_t content = batch.ContentLength();
        if (header > batch.dataSize || content == 0) return false;
        const uint8_t* list = batch.data + header;

        // Every message gets a slot before any is queued, so a dry pool leaves
        // the batch uncommitted and the sender resends it whole. Delivering
        // half of one and dropping the rest would lose data the sender was
        // told arrived. Acquiring the slots first also guarantees the pushes
        // below cannot fail: the queue holds one entry per outstanding slot and
        // these are outstanding but not yet queued.
        uint32_t slots[internal::MAX_BATCH_MESSAGES];
        uint32_t taken  = 0;
        uint16_t offset = 0;
        bool     ok     = true;

        while (offset < content)
        {
            const uint8_t* message = nullptr;
            uint16_t       length  = 0;
            if (!wire::BatchNext(list, static_cast<uint16_t>(content), offset, message, length))
            { ok = false; break; }
            if (taken >= internal::MAX_BATCH_MESSAGES) { ok = false; break; }

            const uint32_t slot = recvPool_->Acquire();
            if (slot == common::collections::SlotPool::INVALID) { ok = false; break; }
            slots[taken++] = slot;

            PacketSlot* out = reinterpret_cast<PacketSlot*>(recvPool_->WriteLock(slot));
            if (!out) { ok = false; break; }

            // The batch's own framing becomes this message's, minus the bit
            // saying it is a list, so what the application receives is
            // indistinguishable from a packet that carried one message.
            std::memcpy(out->data, batch.data, header);
            out->data[0] = static_cast<uint8_t>(out->data[0] & ~internal::WIRE_CTRL_BATCH);
            std::memcpy(out->data + header, message, length);
            out->address = batch.address;
            // The trailer is gone once decrypted, but ContentLength still
            // subtracts it, so the room is left for the arithmetic to land on
            // this message's length.
            const size_t trailer = batch.IsSecure() ? internal::WIRE_TAG_SIZE : 0;
            std::memset(out->data + header + length, 0, trailer);
            out->dataSize = static_cast<uint16_t>(header + length + trailer);
            recvPool_->UnlockWrite(slot);
        }

        if (!ok || taken == 0)
        {
            for (uint32_t i = 0; i < taken; ++i)
                recvPool_->Release(slots[i]);
            return false;
        }

        for (uint32_t i = 0; i < taken; ++i)
            (void)readyQueue_->Push(slots[i]);
        return true;
    }

    bool FlowTable::QueueReady(PacketSlotHandle& handle) noexcept
    {
        const uint32_t idx = handle.GetSlotIndex();
        if (idx == common::collections::SlotPool::INVALID) return false;

        const PacketSlot* packet = handle.Read();
        if (packet && packet->IsBatch())
        {
            // The messages are queued in their own slots, so this one has done
            // its job. Not detached: letting the handle release it is what
            // returns it to the pool.
            return SplitBatchToReady(*packet);
        }

        if (!readyQueue_->Push(idx)) return false;   // full: backpressure, caller drops
        (void)handle.Detach();                       // queued; must not release the slot
        return true;
    }

    uint32_t FlowTable::DeliverIn(uint32_t assocSlot, uint16_t flowId, uint32_t seq,
                                  PacketSlotHandle& incoming) noexcept
    {
        InAssociation* flow = reinterpret_cast<InAssociation*>(inAssocPool_.WriteLock(assocSlot));
        uint32_t produced = 0;
        if (flow->life == FlowLifecycle::OPEN && flow->flowId == flowId)
        {
            const uint32_t cursorBefore = flow->recvNext;
            produced = IsOrdered(flow->mode)
                ? DeliverOrdered(*flow, incoming, seq)
                : DeliverUnordered(*flow, incoming, seq);
            // The cursor moving is the only progress the stall timer counts. A
            // held or duplicate packet leaves it where it was, so a flow stuck
            // behind a gap keeps aging toward the jam timeout.
            if (flow->recvNext != cursorBefore)
                flow->lastProgressMicros = common::MonotonicMicros();
        }
        inAssocPool_.UnlockWrite(assocSlot);
        return produced;
    }

    FlowTable::BatchAdmit FlowTable::AppendToBatch(uint32_t assocSlot, const PacketSlot& packet,
                                                   uint16_t limit) noexcept
    {
        const size_t header = packet.ContentOffset();
        if (header > packet.dataSize) return BatchAdmit::Rejected;

        // dataSize less the header, NOT ContentLength: this packet has been
        // built but not sealed, and the seal is what appends the tag, so the
        // trailer ContentLength subtracts is not there yet. Using it would trim
        // the last sixteen bytes off every message.
        const size_t content = packet.dataSize - header;
        if (content == 0 || content > UINT16_MAX) return BatchAdmit::Rejected;

        // The seal will append that tag to whatever the batch holds, so the
        // room it needs comes out of the limit here rather than being
        // discovered when the sealed packet turns out to be too long.
        if (limit > internal::MAX_WIRE_PACKET_SIZE) limit = internal::MAX_WIRE_PACKET_SIZE;
        const uint16_t trailer = packet.IsSecure() ? internal::WIRE_TAG_SIZE : 0;
        if (limit <= trailer) return BatchAdmit::Rejected;
        limit = static_cast<uint16_t>(limit - trailer);

        OutAssociation* flow = reinterpret_cast<OutAssociation*>(
            outAssocPool_.WriteLock(assocSlot));
        if (!flow) return BatchAdmit::Rejected;

        BatchAdmit result;
        uint8_t* buffer = flow->OpenBatch();
        if (flow->openBatchUsed == 0)
        {
            // Nothing open. This packet's own framing becomes the batch's, so
            // the whole thing is copied and the first message sits bare behind
            // it, exactly as an unbatched packet would look.
            if (header + content > limit)
            {
                result = BatchAdmit::Rejected;   // cannot fit even on its own
            }
            else
            {
                std::memcpy(buffer, packet.data, header + content);
                flow->openBatchHeader   = static_cast<uint16_t>(header);
                flow->openBatchUsed     = static_cast<uint16_t>(header + content);
                flow->openBatchCount    = 1;
                flow->openBatchFirstLen = static_cast<uint16_t>(content);
                result = BatchAdmit::Appended;
            }
        }
        else
        {
            wire::BatchCursor cursor{
                buffer + flow->openBatchHeader,
                static_cast<uint16_t>(flow->openBatchUsed - flow->openBatchHeader),
                flow->openBatchCount,
                flow->openBatchFirstLen,
                static_cast<uint16_t>(limit - flow->openBatchHeader)
            };

            if (!wire::BatchAppend(cursor, packet.data + header,
                                   static_cast<uint16_t>(content)))
            {
                // Full. Leave the batch exactly as it is so the caller can send
                // it, then offer this message again into the empty one.
                result = BatchAdmit::Sealed;
            }
            else
            {
                flow->openBatchUsed  = static_cast<uint16_t>(flow->openBatchHeader + cursor.used);
                flow->openBatchCount = cursor.count;
                // Second message onward: the content is a list now, and the
                // controller has to say so or the far side reads it as one
                // message with rubbish appended.
                buffer[0] = static_cast<uint8_t>(buffer[0] | internal::WIRE_CTRL_BATCH);
                result = BatchAdmit::Appended;
            }
        }

        outAssocPool_.UnlockWrite(assocSlot);
        return result;
    }

    uint16_t FlowTable::TakeBatch(uint32_t assocSlot, uint8_t* out, uint16_t capacity,
                                  FlowMode& outMode) noexcept
    {
        if (!out) return 0;

        OutAssociation* flow = reinterpret_cast<OutAssociation*>(
            outAssocPool_.WriteLock(assocSlot));
        if (!flow) return 0;

        outMode = flow->mode;
        uint16_t written = 0;
        if (flow->openBatchUsed != 0 && flow->openBatchUsed <= capacity)
        {
            // Copied, not consumed. The batch stays until the caller reports
            // the send actually happened, because an admission refused at the
            // flush would otherwise throw away messages the caller was told had
            // been accepted.
            std::memcpy(out, flow->OpenBatch(), flow->openBatchUsed);
            written = flow->openBatchUsed;
        }

        outAssocPool_.UnlockWrite(assocSlot);
        return written;
    }

    bool FlowTable::WouldAdmit(const Peer& peer, uint32_t assocSlot,
                               uint16_t wireSize) noexcept
    {
        const OutAssociation* flow = reinterpret_cast<const OutAssociation*>(
            outAssocPool_.ReadLock(assocSlot));
        if (!flow) return false;
        const bool ok = flow->life == FlowLifecycle::OPEN
                     && flow->waitingCount == 0
                     && CanSend(*flow, peer, wireSize, flow->mode != FlowMode::UNRELIABLE);
        outAssocPool_.UnlockRead(assocSlot);
        return ok;
    }

    void FlowTable::ClearBatch(uint32_t assocSlot, uint16_t expectedUsed) noexcept
    {
        OutAssociation* flow = reinterpret_cast<OutAssociation*>(
            outAssocPool_.WriteLock(assocSlot));
        if (!flow) return;
        if (flow->openBatchUsed == expectedUsed)
        {
            flow->openBatchUsed     = 0;
            flow->openBatchHeader   = 0;
            flow->openBatchCount    = 0;
            flow->openBatchFirstLen = 0;
        }
        outAssocPool_.UnlockWrite(assocSlot);
    }

    bool FlowTable::PeekBatch(uint32_t assocSlot, FlowMode& outMode) noexcept
    {
        const OutAssociation* flow = reinterpret_cast<const OutAssociation*>(
            outAssocPool_.ReadLock(assocSlot));
        if (!flow) return false;
        const bool open = flow->openBatchUsed != 0;
        outMode = flow->mode;
        outAssocPool_.UnlockRead(assocSlot);
        return open;
    }

    uint32_t FlowTable::DeliverUnordered(InAssociation& flow, PacketSlotHandle& incoming, uint32_t seq) noexcept
    {
        // Both unordered modes: no hold-back, so no recv slot is ever pinned
        // and nothing can flood. The seen bitmap dedupes retransmits (a fresh
        // nonce clears the replay window, so only this catches them). A
        // duplicate re-arms acking: the sender's FLOW_ACK may have been lost,
        // and only a fresh ack stops the resend.
        if (AlreadySeen(&flow, seq))
        {
            ArmAck(&flow);
            return 0;
        }
        // Unreliable is newest only: a packet older than the newest delivered
        // carries stale state and is dropped. Still committed and acked, so the
        // sender resolves it now rather than waiting out the RTO, and not as a
        // loss, because the network delivered it and policy dropped it.
        if (flow.mode == FlowMode::UNRELIABLE && seq <= flow.recvHighest)
        {
            CommitSeen(&flow, seq);
            ArmAck(&flow);
            return 0;
        }
        // Commit only if it actually queues (two-step: queued == acked).
        if (!QueueReady(incoming))
            return 0;   // ready queue full: uncommitted, unacked -> dropped/resent
        CommitSeen(&flow, seq);
        ArmAck(&flow);
        return 1;
    }

    uint32_t FlowTable::DeliverOrdered(InAssociation& flow, PacketSlotHandle& incoming, uint32_t seq) noexcept
    {
        // Deliver only at the cursor, hold in-window out-of-order packets in the
        // recv pool, EJECT anything past the reorder window so the shared pool
        // cannot be flooded.
        if (seq < flow.recvNext)
        {
            ArmAck(&flow);   // already delivered: re-ack cumulatively
            return 0;
        }

        if (seq == flow.recvNext)
        {
            // Queue the cursor packet first; only advance and commit if it took
            // (full queue -> leave everything untouched, unacked).
            if (!QueueReady(incoming))
                return 0;
            CommitSeen(&flow, seq);
            ArmAck(&flow);
            flow.recvNext = seq + 1;
            if (flow.recvNext == 0) flow.recvNext = 1;
            return 1 + DrainHoldbackRun(flow);
        }

        // seq > recvNext: ahead of the cursor.
        const bool holdable = flow.reorderCap > 0
                           && seq < flow.recvNext + flow.reorderCap;
        if (holdable)
        {
            HoldbackEntry& slot = flow.Holdback()[seq & (flow.reorderCap - 1)];
            if (slot.packetSlot == common::collections::SlotPool::INVALID)
            {
                slot.seq = seq;
                slot.packetSlot = incoming.Detach();   // stays in recv pool, leased
                CommitSeen(&flow, seq);                 // held -> ackable (SACK)
                ArmAck(&flow);
            }
            // else already held: duplicate, incoming drops (releases its slot)
            return 0;
        }

        // Out of the reorder window: EJECT. Do NOT commit-seen (so the sender
        // still retransmits) and do NOT hold it (no copy, no pin). Arm the
        // cumulative ack so the sender learns our recvNext and fills the gap.
        ArmAck(&flow);
        return 0;
    }

    uint32_t FlowTable::DrainHoldbackRun(InAssociation& flow) noexcept
    {
        // Drain the now-contiguous run out of the hold-back ring. Each held
        // packet already lives in its recv slot and was committed (seen) when
        // held, so delivery is just pushing its index. A full queue stops the
        // drain; the tail stays held (already acked, no loss) until room frees.
        uint32_t produced = 0;
        while (flow.reorderCap > 0)
        {
            HoldbackEntry& held = flow.Holdback()[flow.recvNext & (flow.reorderCap - 1)];
            if (held.packetSlot == common::collections::SlotPool::INVALID
                || held.seq != flow.recvNext)
                break;   // gap: stop draining

            // A held batch splits on its way out, exactly as one delivered at
            // the cursor does, so the application never meets one either way.
            const PacketSlot* packet = reinterpret_cast<const PacketSlot*>(
                recvPool_->ReadLock(held.packetSlot));
            const bool batched = packet && packet->IsBatch();
            bool queued;
            if (batched)
            {
                queued = SplitBatchToReady(*packet);
                recvPool_->UnlockRead(held.packetSlot);
                if (queued) recvPool_->Release(held.packetSlot);   // its messages carry on without it
            }
            else
            {
                if (packet) recvPool_->UnlockRead(held.packetSlot);
                queued = readyQueue_->Push(held.packetSlot);
            }
            if (!queued)
                break;   // queue or pool full: leave the tail held

            held.packetSlot = common::collections::SlotPool::INVALID;
            held.seq = 0;
            ++produced;
            flow.recvNext += 1;
            if (flow.recvNext == 0) flow.recvNext = 1;
        }
        return produced;
    }
}
