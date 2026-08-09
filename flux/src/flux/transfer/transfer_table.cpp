#include <flux/transfer/transfer_table.h>

#include <cassert>
#include <cstring>
#include <new>

/** Every transfer this socket has running, both directions.

    A transfer is a length agreed up front and a buffer at each end that the
    application owns, so the interesting work here is arithmetic rather than
    buffering: a packet at sequence s belongs at s * TRANSFER_STRIDE_BYTES and
    nowhere else. That is also the dangerous part, because the destination is
    memory this library does not own, so every bound the sender could influence
    is checked here rather than trusted.

    The tracking is window sized rather than transfer sized. A sender can never
    have more than TRANSFER_WINDOW packets outstanding, so a gigabyte and a
    kilobyte need the same state, and nothing here grows with the length. */

namespace bcp::flux
{
    namespace
    {
        constexpr uint32_t NPOS = common::collections::SlotPool::INVALID;

        constexpr uint16_t INVALID_ID = 0xFFFF;

        [[nodiscard]] bool BitTest(const uint32_t* bits, uint32_t index) noexcept
        {
            return (bits[index >> 5] & (1u << (index & 31u))) != 0;
        }
        void BitSet(uint32_t* bits, uint32_t index) noexcept
        {
            bits[index >> 5] |= (1u << (index & 31u));
        }
        void BitClear(uint32_t* bits, uint32_t index) noexcept
        {
            bits[index >> 5] &= ~(1u << (index & 31u));
        }

        constexpr uint32_t BITMAP_WORDS = internal::TRANSFER_WINDOW / 32u;
        constexpr uint32_t WINDOW_MASK  = internal::TRANSFER_WINDOW - 1u;

        /** Packets a run of `length` bytes takes at the fixed stride. The last
            one is short and every other is exactly the stride. */
        [[nodiscard]] uint32_t PacketsFor(uint64_t length) noexcept
        {
            const uint64_t stride = internal::TRANSFER_STRIDE_BYTES;
            return static_cast<uint32_t>((length + stride - 1) / stride);
        }

        /** Wire bytes one data packet of this run costs, which is what has to
            go back to the peer's congestion budget when it resolves. The last
            packet is short, so the sequence decides. */
        [[nodiscard]] uint32_t WireSizeForSeq(uint64_t length, uint32_t seq) noexcept
        {
            const uint64_t offset =
                static_cast<uint64_t>(seq) * internal::TRANSFER_STRIDE_BYTES;
            const uint64_t remaining = length > offset ? length - offset : 0;
            const uint64_t payload = remaining < internal::TRANSFER_STRIDE_BYTES
                ? remaining : internal::TRANSFER_STRIDE_BYTES;
            return static_cast<uint32_t>(
                internal::WIRE_SECURE_HEAD_SIZE + internal::WIRE_PEER_TAG_SIZE
                + internal::WIRE_SECURE_CHANNEL_SIZE
                + internal::TRANSFER_WIRE_HEADER_SIZE
                + payload + internal::WIRE_TAG_SIZE);
        }
    }

    TransferTable::~TransferTable() { Shutdown(); }

    common::Error TransferTable::Init(const Params& params) noexcept
    {
        if (params.maxPeers == 0) return common::Error::InvalidParam;

        maxPeers_         = params.maxPeers;
        outCount_         = params.outCount;
        inCount_          = params.inCount;
        maxTransferBytes_ = params.maxTransferBytes != 0
            ? params.maxTransferBytes : internal::TRANSFER_MAX_BYTES_DEFAULT;

        // A socket that asked for neither direction stays inert, which is what
        // refuses transfers without a flag to check anywhere else.
        if (outCount_ == 0 && inCount_ == 0) return common::Error::Ok;

        if (outCount_ != 0 && !outPool_.Init(outCount_, sizeof(OutTransfer)))
            return common::Error::AllocFailed;
        if (inCount_ != 0 && !inPool_.Init(inCount_, sizeof(InTransfer)))
            return common::Error::AllocFailed;

        const size_t dirCells = static_cast<size_t>(maxPeers_) * TransferTable::MAX_PER_PEER;
        if (outCount_ != 0)
        {
            outDir_.reset(new (std::nothrow) DirEntry[dirCells]);
            if (!outDir_) return common::Error::AllocFailed;
            for (size_t i = 0; i < dirCells; ++i) outDir_[i] = DirEntry{INVALID_ID, NPOS};
        }
        if (inCount_ != 0)
        {
            inDir_.reset(new (std::nothrow) DirEntry[dirCells]);
            if (!inDir_) return common::Error::AllocFailed;
            for (size_t i = 0; i < dirCells; ++i) inDir_[i] = DirEntry{INVALID_ID, NPOS};
        }

        const uint32_t finishedCap = outCount_ + inCount_;
        finished_.reset(new (std::nothrow) Finished[finishedCap]);
        if (!finished_) return common::Error::AllocFailed;

        // One block per ring rather than one per slot, and allocated here
        // because Init is the only place this library may allocate at all.
        if (outCount_ != 0)
        {
            const size_t stamps = static_cast<size_t>(outCount_) * internal::TRANSFER_WINDOW;
            const size_t words  = static_cast<size_t>(outCount_) * RING_WORDS;
            sentAtRing_.reset(new (std::nothrow) uint64_t[stamps]);
            ackedRing_.reset(new (std::nothrow) uint32_t[words]);
            resentRing_.reset(new (std::nothrow) uint32_t[words]);
            if (!sentAtRing_ || !ackedRing_ || !resentRing_)
                return common::Error::AllocFailed;
            std::memset(sentAtRing_.get(), 0, stamps * sizeof(uint64_t));
            std::memset(ackedRing_.get(), 0, words * sizeof(uint32_t));
            std::memset(resentRing_.get(), 0, words * sizeof(uint32_t));
        }
        if (inCount_ != 0)
        {
            const size_t words = static_cast<size_t>(inCount_) * RING_WORDS;
            placedRing_.reset(new (std::nothrow) uint32_t[words]);
            if (!placedRing_) return common::Error::AllocFailed;
            std::memset(placedRing_.get(), 0, words * sizeof(uint32_t));
        }

        return common::Error::Ok;
    }

    void TransferTable::Shutdown() noexcept
    {
        outPool_.Shutdown();
        inPool_.Shutdown();
        outDir_.reset();
        inDir_.reset();
        finished_.reset();
        sentAtRing_.reset();
        ackedRing_.reset();
        placedRing_.reset();
        resentRing_.reset();
        outCount_ = inCount_ = maxPeers_ = 0;
        finishedHead_ = finishedCount_ = 0;
    }

    uint32_t TransferTable::FindOut(uint32_t peerSlot, uint16_t transferId) const noexcept
    {
        if (!outDir_ || peerSlot >= maxPeers_) return NPOS;
        const DirEntry* row = &outDir_[static_cast<size_t>(peerSlot) * TransferTable::MAX_PER_PEER];
        for (uint32_t i = 0; i < TransferTable::MAX_PER_PEER; ++i)
            if (row[i].slot != NPOS && row[i].transferId == transferId) return row[i].slot;
        return NPOS;
    }

    uint32_t TransferTable::FindIn(uint32_t peerSlot, uint16_t transferId) const noexcept
    {
        if (!inDir_ || peerSlot >= maxPeers_) return NPOS;
        const DirEntry* row = &inDir_[static_cast<size_t>(peerSlot) * TransferTable::MAX_PER_PEER];
        for (uint32_t i = 0; i < TransferTable::MAX_PER_PEER; ++i)
            if (row[i].slot != NPOS && row[i].transferId == transferId) return row[i].slot;
        return NPOS;
    }

    common::Error TransferTable::BeginSend(uint32_t peerSlot, const Address& peer,
                                           uint16_t transferId,
                                           const void* buffer, uint64_t length) noexcept
    {
        if (outCount_ == 0)  return common::Error::InvalidState;
        if (!buffer)         return common::Error::InvalidParam;
        // Zero is refused so a pending length of zero can only ever mean
        // nothing pending, which is what the query relies on.
        if (length == 0)     return common::Error::InvalidParam;
        if (length > maxTransferBytes_) return common::Error::TooLarge;
        if (peerSlot >= maxPeers_)      return common::Error::InvalidParam;
        if (transferId == INVALID_ID)   return common::Error::InvalidParam;

        if (FindOut(peerSlot, transferId) != NPOS) return common::Error::AlreadyPending;

        // A run longer than the window is fine, since the window bounds what
        // is outstanding rather than what may be sent, but the sequence space
        // still has to hold the count.
        const uint32_t packets = PacketsFor(length);
        if (packets == 0) return common::Error::InvalidParam;

        DirEntry* row = &outDir_[static_cast<size_t>(peerSlot) * TransferTable::MAX_PER_PEER];
        uint32_t free = TransferTable::MAX_PER_PEER;
        for (uint32_t i = 0; i < TransferTable::MAX_PER_PEER; ++i)
            if (row[i].slot == NPOS) { free = i; break; }
        if (free == TransferTable::MAX_PER_PEER) return common::Error::LimitReached;

        const uint32_t slot = outPool_.Acquire();
        if (slot == NPOS) return common::Error::PoolExhausted;

        OutTransfer* out = reinterpret_cast<OutTransfer*>(outPool_.WriteLock(slot));
        if (!out) { outPool_.Release(slot); return common::Error::InvalidState; }

        out->peerSlot        = peerSlot;
        out->peerAddr        = peer;
        out->transferId      = transferId;
        out->source          = static_cast<const uint8_t*>(buffer);
        out->length          = length;
        out->packetCount     = packets;
        out->nextSeq         = 0;
        out->acked           = 0;
        out->announced       = false;
        out->announceAcked   = false;
        out->announceSentAt  = 0;
        out->refused         = false;
        out->inFlight        = 0;
        out->contiguousAcked = 0;
        out->highestAcked    = 0;
        out->lossBarrierSeq  = 0;
        std::memset(AckedFor(slot), 0, RING_WORDS * sizeof(uint32_t));
        std::memset(ResentFor(slot), 0, RING_WORDS * sizeof(uint32_t));
        std::memset(SentAtFor(slot), 0, internal::TRANSFER_WINDOW * sizeof(uint64_t));
        outPool_.UnlockWrite(slot);

        row[free] = DirEntry{transferId, slot};
        return common::Error::Ok;
    }

    common::Error TransferTable::OnAnnounce(uint32_t peerSlot, const Address& peer,
                                            uint16_t transferId, uint64_t length,
                                            uint16_t stride, bool& outIsNew) noexcept
    {
        outIsNew = false;
        if (inCount_ == 0) return common::Error::InvalidState;
        if (peerSlot >= maxPeers_) return common::Error::InvalidParam;

        // The stride is announced but never trusted. Both ends derive the same
        // constant, so a value that differs is either a different build or a
        // peer trying to choose the multiplier this receiver will apply to
        // every offset it computes into the application's buffer.
        if (stride != internal::TRANSFER_STRIDE_BYTES) return common::Error::Malformed;
        if (length == 0) return common::Error::Malformed;
        if (length > maxTransferBytes_) return common::Error::TooLarge;

        // A retransmitted announcement finds the transfer already here. That
        // is the common case on a lossy path and must not raise a second
        // event or reset what has already arrived.
        const uint32_t existing = FindIn(peerSlot, transferId);
        if (existing != NPOS) return common::Error::Ok;

        DirEntry* row = &inDir_[static_cast<size_t>(peerSlot) * TransferTable::MAX_PER_PEER];
        uint32_t free = TransferTable::MAX_PER_PEER;
        for (uint32_t i = 0; i < TransferTable::MAX_PER_PEER; ++i)
            if (row[i].slot == NPOS) { free = i; break; }
        if (free == TransferTable::MAX_PER_PEER) return common::Error::LimitReached;

        const uint32_t slot = inPool_.Acquire();
        if (slot == NPOS) return common::Error::PoolExhausted;

        InTransfer* in = reinterpret_cast<InTransfer*>(inPool_.WriteLock(slot));
        if (!in) { inPool_.Release(slot); return common::Error::InvalidState; }

        in->peerSlot    = peerSlot;
        in->peerAddr    = peer;
        in->transferId  = transferId;
        in->length      = length;
        in->packetCount = PacketsFor(length);
        in->destination = nullptr;
        in->announced   = true;
        in->complete    = false;
        in->recvNext    = 0;
        in->placed      = 0;
        in->sinceAck    = 0;
        in->ackOwed     = true;   // the announcement itself is worth answering
        std::memset(PlacedFor(slot), 0, RING_WORDS * sizeof(uint32_t));
        inPool_.UnlockWrite(slot);

        row[free] = DirEntry{transferId, slot};
        outIsNew  = true;
        return common::Error::Ok;
    }

    common::Error TransferTable::OnData(uint32_t peerSlot, uint16_t transferId,
                                        uint32_t seq, const uint8_t* payload,
                                        uint16_t payloadLen) noexcept
    {
        const uint32_t slot = FindIn(peerSlot, transferId);
        if (slot == NPOS) return common::Error::NotFound;

        InTransfer* in = reinterpret_cast<InTransfer*>(inPool_.WriteLock(slot));
        if (!in) return common::Error::InvalidState;

        // Every arrival earns an answer, whatever becomes of it. A duplicate
        // is the clearest case: the sender only resends what it has not heard
        // acknowledged, so staying silent about one guarantees it resends
        // again. Counted here, before any check can bail out, because a packet
        // this receiver refuses is still a packet the sender is waiting on.
        ++in->sinceAck;

        common::Error result = common::Error::Ok;
        do
        {
            // Nowhere to write yet. The sender is not waiting for the answer,
            // so this is the ordinary case for the first packets of every
            // transfer, and dropping them costs a retransmit rather than the
            // transfer.
            // Nothing to write into yet. Still answered, so the sender learns
            // the cursor has not moved and holds rather than blasting.
            if (!in->destination) { in->ackOwed = true;
                                    result = common::Error::AlreadyPending; break; }
            if (in->complete)     { result = common::Error::Ok; break; }

            // Everything the sender could influence is bounded here, because
            // what follows is a write into memory this library does not own.
            if (seq >= in->packetCount) { result = common::Error::Malformed; break; }

            const uint64_t offset =
                static_cast<uint64_t>(seq) * internal::TRANSFER_STRIDE_BYTES;
            if (offset >= in->length) { result = common::Error::Malformed; break; }

            const uint64_t remaining = in->length - offset;
            const uint64_t expected  = remaining < internal::TRANSFER_STRIDE_BYTES
                ? remaining : internal::TRANSFER_STRIDE_BYTES;
            // Every packet but the last carries exactly the stride, so a
            // length that disagrees is not a short read to tolerate.
            if (payloadLen != expected) { result = common::Error::Malformed; break; }

            const uint32_t ringIndex = seq & WINDOW_MASK;
            if (seq < in->recvNext)
            {
                // Below the cursor, so it arrived long ago. The sender is
                // still asking, which means it has not seen the cursor, so
                // answer now rather than on the cadence.
                in->ackOwed = true;
                result = common::Error::Ok;
                break;
            }
            if (BitTest(PlacedFor(slot), ringIndex))
            {
                in->ackOwed = true;
                result = common::Error::Ok;   // already placed, a duplicate
                break;
            }

            std::memcpy(in->destination + offset, payload,
                        static_cast<size_t>(expected));
            const uint32_t cursorBefore = in->recvNext;
            if (!BitTest(PlacedFor(slot), ringIndex))
            {
                BitSet(PlacedFor(slot), ringIndex);
                ++in->placed;
            }
            // A packet that did not extend the cursor means a hole is open in
            // front of it, and the sender needs to hear about that at once
            // rather than on the next cadence tick.
            if (seq != cursorBefore) in->ackOwed = true;

            // The cursor walks forward over everything now contiguous, and
            // clears each bit as it passes so the ring can be reused by a
            // sequence a window further on.
            // Cleared as the cursor passes, because the ring is reused by the
            // sequence a window later and a stale bit there would read as
            // already placed and drop real data.
            while (in->recvNext < in->packetCount
                   && BitTest(PlacedFor(slot), in->recvNext & WINDOW_MASK))
            {
                BitClear(PlacedFor(slot), in->recvNext & WINDOW_MASK);
                ++in->recvNext;
            }
            if (in->recvNext != cursorBefore) in->ackOwed = true;

            if (in->recvNext >= in->packetCount)
            {
                in->complete = true;
                if (finishedCount_ < outCount_ + inCount_)
                {
                    const uint32_t tail =
                        (finishedHead_ + finishedCount_) % (outCount_ + inCount_);
                    finished_[tail] = Finished{slot, true, common::Error::Ok};
                    ++finishedCount_;
                }
            }
        } while (false);

        inPool_.UnlockWrite(slot);
        return result;
    }

    common::Error TransferTable::Allow(uint32_t peerSlot, uint16_t transferId,
                                       void* buffer) noexcept
    {
        if (!buffer) return common::Error::InvalidParam;
        const uint32_t slot = FindIn(peerSlot, transferId);
        if (slot == NPOS) return common::Error::NotFound;

        InTransfer* in = reinterpret_cast<InTransfer*>(inPool_.WriteLock(slot));
        if (!in) return common::Error::InvalidState;

        common::Error result = common::Error::Ok;
        if (!in->announced || in->destination) result = common::Error::InvalidState;
        else                                   in->destination = static_cast<uint8_t*>(buffer);

        inPool_.UnlockWrite(slot);
        return result;
    }

    common::Error TransferTable::Reject(uint32_t peerSlot, uint16_t transferId) noexcept
    {
        const uint32_t slot = FindIn(peerSlot, transferId);
        if (slot == NPOS) return common::Error::NotFound;

        InTransfer* in = reinterpret_cast<InTransfer*>(inPool_.WriteLock(slot));
        if (in) *in = InTransfer{};
        inPool_.UnlockWrite(slot);

        DirEntry* row = &inDir_[static_cast<size_t>(peerSlot) * TransferTable::MAX_PER_PEER];
        for (uint32_t i = 0; i < TransferTable::MAX_PER_PEER; ++i)
            if (row[i].slot == slot) row[i] = DirEntry{INVALID_ID, NPOS};

        inPool_.Release(slot);
        return common::Error::Ok;
    }

    uint64_t TransferTable::PendingLength(uint32_t peerSlot,
                                          uint16_t transferId) const noexcept
    {
        const uint32_t slot = FindIn(peerSlot, transferId);
        if (slot == NPOS) return 0;

        // The pool's read lock is the only way to reach the slot, and this is
        // a const query, so the cast is to satisfy the non-const pool rather
        // than to gain any right to write.
        auto& pool = const_cast<common::collections::SlotPool&>(inPool_);
        const InTransfer* in = reinterpret_cast<const InTransfer*>(pool.ReadLock(slot));
        const uint64_t length = (in && in->announced && !in->destination) ? in->length : 0;
        pool.UnlockRead(slot);
        return length;
    }

    uint64_t TransferTable::Progress(uint32_t peerSlot,
                                     uint16_t transferId) const noexcept
    {
        const uint32_t inSlot = FindIn(peerSlot, transferId);
        if (inSlot != NPOS)
        {
            auto& pool = const_cast<common::collections::SlotPool&>(inPool_);
            const InTransfer* in = reinterpret_cast<const InTransfer*>(pool.ReadLock(inSlot));
            uint64_t done = 0;
            if (in)
            {
                done = static_cast<uint64_t>(in->recvNext) * internal::TRANSFER_STRIDE_BYTES;
                if (done > in->length) done = in->length;
            }
            pool.UnlockRead(inSlot);
            return done;
        }

        const uint32_t outSlot = FindOut(peerSlot, transferId);
        if (outSlot == NPOS) return 0;

        auto& pool = const_cast<common::collections::SlotPool&>(outPool_);
        const OutTransfer* out = reinterpret_cast<const OutTransfer*>(pool.ReadLock(outSlot));
        uint64_t done = 0;
        if (out)
        {
            done = static_cast<uint64_t>(out->contiguousAcked)
                 * internal::TRANSFER_STRIDE_BYTES;
            if (done > out->length) done = out->length;
        }
        pool.UnlockRead(outSlot);
        return done;
    }

    common::Error TransferTable::Complete(uint32_t peerSlot,
                                          uint16_t transferId) noexcept
    {
        const uint32_t slot = FindIn(peerSlot, transferId);
        if (slot == NPOS) return common::Error::NotFound;

        InTransfer* in = reinterpret_cast<InTransfer*>(inPool_.WriteLock(slot));
        if (!in) { inPool_.UnlockWrite(slot); return common::Error::InvalidState; }
        const bool wasComplete = in->complete;
        if (wasComplete) *in = InTransfer{};
        inPool_.UnlockWrite(slot);
        if (!wasComplete) return common::Error::NotFound;

        DirEntry* row = &inDir_[static_cast<size_t>(peerSlot) * TransferTable::MAX_PER_PEER];
        for (uint32_t i = 0; i < TransferTable::MAX_PER_PEER; ++i)
            if (row[i].slot == slot) row[i] = DirEntry{INVALID_ID, NPOS};

        inPool_.Release(slot);
        return common::Error::Ok;
    }

    size_t TransferTable::DrainFinished(TransferView* out, size_t max) noexcept
    {
        if (!out || max == 0 || finishedCount_ == 0) return 0;
        const uint32_t ring = outCount_ + inCount_;

        size_t written = 0;
        while (written < max && finishedCount_ > 0)
        {
            const Finished entry = finished_[finishedHead_];
            finishedHead_ = (finishedHead_ + 1) % ring;
            --finishedCount_;

            if (entry.incoming)
            {
                const InTransfer* in =
                    reinterpret_cast<const InTransfer*>(inPool_.ReadLock(entry.slot));
                if (in)
                {
                    out[written++] = TransferView(in->destination, in->length,
                                                  in->peerAddr, in->transferId,
                                                  entry.outcome);
                }
                inPool_.UnlockRead(entry.slot);
                // The slot stays held: the application still has to read the
                // buffer and call Complete, which is the backpressure.
                continue;
            }

            uint16_t transferId = 0;
            uint64_t length     = 0;
            uint32_t peerSlot   = 0;
            Address  peerAddr{};
            OutTransfer* sent =
                reinterpret_cast<OutTransfer*>(outPool_.WriteLock(entry.slot));
            if (sent)
            {
                transferId = sent->transferId;
                length     = sent->length;
                peerSlot   = sent->peerSlot;
                peerAddr   = sent->peerAddr;
                *sent = OutTransfer{};
            }
            outPool_.UnlockWrite(entry.slot);

            // Nothing more is owed on a finished send, so the slot goes back
            // here rather than waiting on the application.
            if (peerSlot < maxPeers_ && outDir_)
            {
                DirEntry* row = &outDir_[static_cast<size_t>(peerSlot) * TransferTable::MAX_PER_PEER];
                for (uint32_t i = 0; i < TransferTable::MAX_PER_PEER; ++i)
                    if (row[i].slot == entry.slot) row[i] = DirEntry{INVALID_ID, NPOS};
            }
            outPool_.Release(entry.slot);

            out[written++] = TransferView(nullptr, length, peerAddr,
                                          transferId, entry.outcome);
        }
        return written;
    }

    uint32_t TransferTable::OldestOverdue(uint32_t slot, const OutTransfer& out,
                                          uint64_t now, uint64_t rto,
                                          uint64_t lossDelay,
                                          uint32_t fromSeq) const noexcept
    {
        // From the progress cursor forward, so the oldest gap is answered
        // first and a later packet never jumps the queue in front of the one
        // holding the receiver's cursor still. The resume point keeps the
        // whole walk linear in the window per pass. A flat cap on how far one
        // call could look did that job before, and it starved the repair: with
        // hundreds of holes standing, the holes past the cap were invisible
        // until the cursor crawled to within reach of them, so most of the
        // window could not be repaired at all and the cursor advanced a
        // quarter window at a time.
        const uint32_t last = out.nextSeq;
        uint32_t seq = fromSeq > out.contiguousAcked ? fromSeq : out.contiguousAcked;
        for (; seq < last; ++seq)
        {
            const uint32_t ring = seq & WINDOW_MASK;
            if (BitTest(AckedFor(slot), ring)) continue;
            const uint64_t sentAt = SentAtFor(slot)[ring];
            if (sentAt == 0) continue;
            // Missing rather than in transit, decided the way the flow path
            // decides it. Three sequences past it landing means gone, and so
            // does one landing with the packet out longer than a round trip
            // and an eighth. The second rule matters exactly when the window
            // is jammed: nothing new is being sent, so nothing new can
            // overtake, and a count rule alone stops firing for every hole
            // that still had repairs coming.
            //
            // Either rule fires once only. The tests hold on every pass, and
            // passes run far faster than the round trip the answer needs, so
            // without the once-only mark each hole was resent hundreds of
            // times before it could possibly be answered: measured at nine
            // times the payload on the wire against BBR's two. After the
            // first repair the deadline governs, which is what gives the
            // resend time to arrive.
            if (!BitTest(ResentFor(slot), ring))
            {
                if (seq + internal::LOSS_PACKET_THRESHOLD <= out.highestAcked)
                    return seq;
                if (seq < out.highestAcked && now > sentAt
                    && now - sentAt > lossDelay)
                    return seq;
            }
            if (now > sentAt && now - sentAt > rto) return seq;
        }
        return UINT32_MAX;
    }

    void TransferTable::MarkSent(uint32_t slot, OutTransfer& out, uint32_t seq,
                                 uint64_t now) noexcept
    {
        const uint32_t ring = seq & WINDOW_MASK;
        // Only a sequence that was not already outstanding adds to the count,
        // so a retransmit does not double-charge the window. A second send
        // also retires the sequence as a timing source, because an
        // acknowledgement for it could be answering either attempt.
        if (SentAtFor(slot)[ring] == 0) ++out.inFlight;
        else                            BitSet(ResentFor(slot), ring);
        SentAtFor(slot)[ring] = now;
        BitClear(AckedFor(slot), ring);
    }

    uint64_t TransferTable::SendingLength(uint32_t peerSlot, uint16_t transferId) noexcept
    {
        const uint32_t slot = FindOut(peerSlot, transferId);
        if (slot == NPOS) return 0;
        const OutTransfer* out = reinterpret_cast<const OutTransfer*>(outPool_.ReadLock(slot));
        const uint64_t length = out ? out->length : 0;
        outPool_.UnlockRead(slot);
        return length;
    }

    bool TransferTable::ReceiveState(uint32_t peerSlot, uint16_t transferId,
                                     uint32_t& outCursor, uint8_t* outBitmap) noexcept
    {
        outCursor = 0;
        std::memset(outBitmap, 0, internal::TRANSFER_ACK_BITMAP_BYTES);

        const uint32_t slot = FindIn(peerSlot, transferId);
        if (slot == NPOS) return false;

        const InTransfer* in = reinterpret_cast<const InTransfer*>(inPool_.ReadLock(slot));
        bool found = false;
        if (in)
        {
            found     = true;
            outCursor = in->recvNext;

            // Bit i names the sequence cursor + i. The whole window, so the
            // sender learns about every packet that has landed rather than
            // only those near the cursor, and learns it again on the next
            // acknowledgement if this one is lost.
            const uint32_t* placed = PlacedFor(slot);
            const uint32_t span = internal::TRANSFER_WINDOW;
            for (uint32_t i = 0; i < span; ++i)
            {
                const uint32_t seq = in->recvNext + i;
                if (seq >= in->packetCount) break;
                if (BitTest(placed, seq & WINDOW_MASK))
                    outBitmap[i >> 3] |= static_cast<uint8_t>(1u << (i & 7u));
            }
        }
        inPool_.UnlockRead(slot);
        return found;
    }

    bool TransferTable::TakeAckDebt(uint32_t peerSlot, uint16_t transferId) noexcept
    {
        const uint32_t slot = FindIn(peerSlot, transferId);
        if (slot == NPOS) return false;

        InTransfer* in = reinterpret_cast<InTransfer*>(inPool_.WriteLock(slot));
        bool owed = false;
        if (in)
        {
            // Every second arrival earns one even with nothing else to say,
            // the same cadence a flow uses, so a clean run still keeps the
            // sender's window moving without an ack per packet.
            owed = in->ackOwed || in->sinceAck >= internal::ACK_EVERY_PACKETS;
            if (owed) { in->ackOwed = false; in->sinceAck = 0; }
        }
        inPool_.UnlockWrite(slot);
        return owed;
    }

    void TransferTable::OnAck(uint32_t peerSlot, uint16_t transferId, uint32_t recvNext,
                              const uint8_t* bitmap, uint64_t now,
                              uint32_t& outFreedBytes, uint32_t& outFreedPackets,
                              uint32_t& outRttSample, uint32_t& outLostBytes) noexcept
    {
        outFreedBytes   = 0;
        outFreedPackets = 0;
        outRttSample    = 0;
        outLostBytes    = 0;

        const uint32_t slot = FindOut(peerSlot, transferId);
        if (slot == NPOS) return;

        OutTransfer* out = reinterpret_cast<OutTransfer*>(outPool_.WriteLock(slot));
        if (!out) { outPool_.UnlockWrite(slot); return; }

        // Any acknowledgement at all proves the receiver saw the announcement,
        // which is what releases the data packets to start.
        out->announceAcked = true;

        if (recvNext > out->packetCount) recvNext = out->packetCount;

        uint64_t* sentAt = SentAtFor(slot);
        uint32_t* acked  = AckedFor(slot);

        auto resolve = [&](uint32_t seq)
        {
            const uint32_t ring = seq & WINDOW_MASK;
            if (sentAt[ring] != 0)
            {
                // Karn's rule. A sequence sent twice cannot time the path,
                // because nothing says which attempt this answers, and the
                // wrong guess poisons the minimum permanently.
                if (now > sentAt[ring] && !BitTest(ResentFor(slot), ring))
                {
                    const uint64_t elapsed = now - sentAt[ring];
                    if (elapsed < internal::RTT_SAMPLE_MAX_MICROS)
                        outRttSample = static_cast<uint32_t>(elapsed);
                }
                BitClear(ResentFor(slot), ring);
                sentAt[ring] = 0;
                if (out->inFlight != 0) --out->inFlight;
                outFreedBytes += WireSizeForSeq(out->length, seq);
                ++outFreedPackets;
            }
            BitSet(acked, ring);
        };

        for (uint32_t seq = out->contiguousAcked; seq < recvNext; ++seq) resolve(seq);
        if (recvNext > out->contiguousAcked) out->contiguousAcked = recvNext;
        if (recvNext > out->highestAcked)    out->highestAcked    = recvNext;

        // Out of order, which is the whole point: a packet that has landed
        // stops being outstanding now, rather than when the cursor eventually
        // reaches it. Holding it open until then kept the window shut behind a
        // gap and timed the stall instead of the path.
        for (uint32_t i = 0; i < internal::TRANSFER_WINDOW; ++i)
        {
            if ((bitmap[i >> 3] & (1u << (i & 7u))) == 0) continue;
            const uint32_t seq = recvNext + i;
            if (seq >= out->packetCount) break;
            resolve(seq);
            if (seq + 1 > out->highestAcked) out->highestAcked = seq + 1;
        }

        // What is left below the highest thing the receiver holds is missing
        // rather than late, and that is the loss the controller has to see.
        // Charged once per congestion epoch, so a burst that takes twenty
        // packets is one reaction rather than twenty.
        {
            uint32_t missing = 0;
            const uint32_t from = out->contiguousAcked > out->lossBarrierSeq
                ? out->contiguousAcked : out->lossBarrierSeq;
            const uint32_t upTo = out->highestAcked > internal::LOSS_PACKET_THRESHOLD
                ? out->highestAcked - internal::LOSS_PACKET_THRESHOLD : 0;
            for (uint32_t seq = from; seq < upTo; ++seq)
            {
                const uint32_t ring = seq & WINDOW_MASK;
                if (sentAt[ring] != 0 && !BitTest(acked, ring))
                    missing += WireSizeForSeq(out->length, seq);
            }
            if (missing != 0)
            {
                outLostBytes        = missing;
                out->lossBarrierSeq = out->nextSeq;
            }
        }

        if (out->contiguousAcked >= out->packetCount)
        {
            if (finishedCount_ < outCount_ + inCount_)
            {
                const uint32_t tail =
                    (finishedHead_ + finishedCount_) % (outCount_ + inCount_);
                finished_[tail] = Finished{slot, false, common::Error::Ok};
                ++finishedCount_;
            }
        }
        outPool_.UnlockWrite(slot);
    }

    void TransferTable::OnRefused(uint32_t peerSlot, uint16_t transferId,
                                  uint32_t& outFreedBytes,
                                  uint32_t& outFreedPackets) noexcept
    {
        outFreedBytes   = 0;
        outFreedPackets = 0;

        const uint32_t slot = FindOut(peerSlot, transferId);
        if (slot == NPOS) return;

        OutTransfer* out = reinterpret_cast<OutTransfer*>(outPool_.WriteLock(slot));
        if (!out) { outPool_.UnlockWrite(slot); return; }

        if (!out->refused)
        {
            for (uint32_t seq = out->contiguousAcked; seq < out->nextSeq; ++seq)
            {
                const uint32_t ring = seq & WINDOW_MASK;
                if (SentAtFor(slot)[ring] == 0) continue;
                SentAtFor(slot)[ring] = 0;
                if (out->inFlight != 0) --out->inFlight;
                outFreedBytes += WireSizeForSeq(out->length, seq);
                ++outFreedPackets;
            }
            out->refused = true;

            if (finishedCount_ < outCount_ + inCount_)
            {
                const uint32_t tail =
                    (finishedHead_ + finishedCount_) % (outCount_ + inCount_);
                finished_[tail] = Finished{slot, false, common::Error::Refused};
                ++finishedCount_;
            }
        }
        outPool_.UnlockWrite(slot);
    }

    void TransferTable::SweepPeer(uint32_t peerSlot) noexcept
    {
        if (peerSlot >= maxPeers_) return;

        if (outDir_)
        {
            DirEntry* row = &outDir_[static_cast<size_t>(peerSlot) * TransferTable::MAX_PER_PEER];
            for (uint32_t i = 0; i < TransferTable::MAX_PER_PEER; ++i)
            {
                if (row[i].slot == NPOS) continue;
                const uint32_t slot = row[i].slot;
                row[i] = DirEntry{INVALID_ID, NPOS};
                OutTransfer* out = reinterpret_cast<OutTransfer*>(outPool_.WriteLock(slot));
                if (out) *out = OutTransfer{};
                outPool_.UnlockWrite(slot);
                outPool_.Release(slot);
            }
        }
        if (inDir_)
        {
            DirEntry* row = &inDir_[static_cast<size_t>(peerSlot) * TransferTable::MAX_PER_PEER];
            for (uint32_t i = 0; i < TransferTable::MAX_PER_PEER; ++i)
            {
                if (row[i].slot == NPOS) continue;
                const uint32_t slot = row[i].slot;
                row[i] = DirEntry{INVALID_ID, NPOS};
                InTransfer* in = reinterpret_cast<InTransfer*>(inPool_.WriteLock(slot));
                if (in) *in = InTransfer{};
                inPool_.UnlockWrite(slot);
                inPool_.Release(slot);
            }
        }
    }
}
