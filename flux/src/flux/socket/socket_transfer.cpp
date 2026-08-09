#include <flux/socket/socket.h>

#include <cstring>

/** The socket half of transfers: the application entry points, the three
    channel handlers, and the pass that drives outgoing transfers on the tick.

    It sits apart from the flow send path on purpose. A transfer has no flow
    header, no message framing and no staged copy, so nothing here is a variant
    of what the flow path does, and the flow path is not touched to make room
    for it. The one thing the two share is the peer: a transfer spends the same
    congestion budget and the same pacing clock, because a transfer and a flow
    to the same peer cross one link.

    Those gates are duplicated here rather than reached for. Hoisting them out
    of the flow table would mean editing the path every ordinary flow runs
    through, which this mechanism is required not to do. The copies read the
    same constants, so a tuning change still reaches both, and only a change to
    the shape of the arithmetic could make them drift. */

namespace bcp::flux
{
    namespace
    {
        /** Wire header on every transfer packet, inside the seal and after the
            channel byte: [transferId(2)][seq(4)][flags(1)]. */
        void WriteTransferHeader(uint8_t* out, uint16_t transferId,
                                 uint32_t seq, uint8_t flags) noexcept
        {
            out[0] = static_cast<uint8_t>(transferId >> 0);
            out[1] = static_cast<uint8_t>(transferId >> 8);
            out[2] = static_cast<uint8_t>(seq >> 0);
            out[3] = static_cast<uint8_t>(seq >> 8);
            out[4] = static_cast<uint8_t>(seq >> 16);
            out[5] = static_cast<uint8_t>(seq >> 24);
            out[6] = flags;
        }

        void ReadTransferHeader(const uint8_t* in, uint16_t& transferId,
                                uint32_t& seq, uint8_t& flags) noexcept
        {
            transferId = static_cast<uint16_t>(in[0])
                       | static_cast<uint16_t>(in[1]) << 8;
            seq = static_cast<uint32_t>(in[2])
                | static_cast<uint32_t>(in[3]) << 8
                | static_cast<uint32_t>(in[4]) << 16
                | static_cast<uint32_t>(in[5]) << 24;
            flags = in[6];
        }

        /** The peer-side gates, in the same shape the flow path uses them.
            @pre Caller holds the peer write lock. */
        void RefillTransferPacing(Peer& peer, uint64_t now) noexcept
        {
            if (peer.rtt.srttMicros == 0) return;
            if (peer.pacingRefilledAt == 0) { peer.pacingRefilledAt = now; return; }
            const uint64_t elapsed = now > peer.pacingRefilledAt
                ? now - peer.pacingRefilledAt : 0;
            if (elapsed == 0) return;

            const uint64_t gained =
                static_cast<uint64_t>(peer.congestionBudget)
                * internal::CC_PACING_GAIN_PERCENT * elapsed
                / (100ull * peer.rtt.srttMicros);
            if (gained == 0) return;

            const uint64_t topped = static_cast<uint64_t>(peer.pacingTokens) + gained;
            peer.pacingTokens = topped > internal::CC_PACING_BURST_BYTES
                ? internal::CC_PACING_BURST_BYTES : static_cast<uint32_t>(topped);
            peer.pacingRefilledAt = now;
        }

        [[nodiscard]] bool TransferPacingAllows(Peer& peer, uint64_t now,
                                                uint16_t wireSize) noexcept
        {
            if (peer.rtt.srttMicros == 0) return true;
            RefillTransferPacing(peer, now);
            return peer.pacingTokens >= wireSize;
        }

        [[nodiscard]] bool TransferBudgetAllows(const Peer& peer, uint16_t wireSize) noexcept
        {
            if (static_cast<uint64_t>(peer.bytesInFlight) + wireSize > peer.congestionBudget)
                return false;
            return peer.theirGrant == 0 || peer.outstandingToPeer < peer.theirGrant;
        }

        /** A first transmission takes budget, pacing and grant. */
        void TransferSpendFirst(Peer& peer, uint16_t wireSize) noexcept
        {
            peer.pacingTokens = peer.pacingTokens > wireSize
                ? peer.pacingTokens - wireSize : 0;
            peer.bytesInFlight += wireSize;
            peer.outstandingToPeer += 1;
        }

        /** A retransmission takes only the clock.

            Its bytes are already counted as in flight, because the packet was
            never resolved, so charging them again is charging twice. That is
            not a tidiness point: once the window is full of unacknowledged
            packets, the budget refuses the very resend that would clear them,
            nothing resolves, and the transfer stops for good. Measured on a
            link with no configured loss at all, where the opening burst
            overflowed the queue and the transfer froze at 662 of 9017
            packets. */
        void TransferSpendResend(Peer& peer, uint16_t wireSize) noexcept
        {
            peer.pacingTokens = peer.pacingTokens > wireSize
                ? peer.pacingTokens - wireSize : 0;
        }

        void TransferResolve(Peer& peer, uint32_t bytes, uint32_t packets) noexcept
        {
            peer.bytesInFlight -= bytes <= peer.bytesInFlight ? bytes : peer.bytesInFlight;
            peer.outstandingToPeer -= packets <= peer.outstandingToPeer
                ? packets : peer.outstandingToPeer;
        }

        /** Whole wire size of a transfer packet carrying `payload` bytes. */
        [[nodiscard]] uint16_t TransferWireSize(uint16_t payload) noexcept
        {
            return static_cast<uint16_t>(
                internal::WIRE_SECURE_HEAD_SIZE + internal::WIRE_PEER_TAG_SIZE
                + internal::WIRE_SECURE_CHANNEL_SIZE + internal::TRANSFER_WIRE_HEADER_SIZE
                + payload + internal::WIRE_TAG_SIZE);
        }

        /** Data packets one transfer puts on the wire per pass. Bounds the
            stack arrays below and keeps one transfer from taking the whole
            tick from every other. */
        constexpr uint32_t PACKETS_PER_PASS = 64;
    }

// --- Application entry points ---

    common::Error Socket::SendTransfer(uint16_t transferId, const Address& peer,
                                       const void* buffer, uint64_t length)
    {
        if (!initialized_.load(std::memory_order_relaxed))
            return common::Error::NotInitialized;
        if (!transfers_.SendEnabled()) return common::Error::InvalidState;

        // The peer has to exist, but it does not have to be established yet.
        // A flow parks its packets behind the handshake rather than refusing
        // them, and a transfer has even less reason to refuse: the buffer is
        // the application's and is not going anywhere, so the send pass simply
        // finds the peer ready on a later tick.
        PeerHandle peerHandle = peers_.GetPeer(peer);
        if (peerHandle.Failed()) return common::Error::NotFound;

        return transfers_.BeginSend(peerHandle.GetSlotIndex(), peer,
                                    transferId, buffer, length);
    }

    TransferRequest Socket::PendingTransfer(uint16_t transferId, const Address& peer)
    {
        if (!initialized_.load(std::memory_order_relaxed)) return TransferRequest{};

        PeerHandle peerHandle = peers_.GetPeer(peer);
        if (peerHandle.Failed()) return TransferRequest{};

        const uint64_t length =
            transfers_.PendingLength(peerHandle.GetSlotIndex(), transferId);
        if (length == 0) return TransferRequest{};

        return TransferRequest(this, peer, length, transferId);
    }

    uint64_t Socket::TransferProgress(uint16_t transferId, const Address& peer) const
    {
        if (!initialized_.load(std::memory_order_relaxed)) return 0;

        auto& self = const_cast<Socket&>(*this);
        PeerHandle peerHandle = self.peers_.GetPeer(peer);
        if (peerHandle.Failed()) return 0;
        return self.transfers_.Progress(peerHandle.GetSlotIndex(), transferId);
    }

    size_t Socket::PollTransfers(TransferView* out, size_t max)
    {
        if (!initialized_.load(std::memory_order_relaxed)) return 0;
        return transfers_.DrainFinished(out, max);
    }

    common::Error Socket::CompleteTransfer(uint16_t transferId, const Address& peer)
    {
        if (!initialized_.load(std::memory_order_relaxed))
            return common::Error::NotInitialized;

        PeerHandle peerHandle = peers_.GetPeer(peer);
        if (peerHandle.Failed()) return common::Error::NotFound;
        return transfers_.Complete(peerHandle.GetSlotIndex(), transferId);
    }

    common::Error Socket::AllowTransfer(uint16_t transferId, const Address& peer,
                                        void* buffer)
    {
        PeerHandle peerHandle = peers_.GetPeer(peer);
        if (peerHandle.Failed()) return common::Error::NotFound;
        return transfers_.Allow(peerHandle.GetSlotIndex(), transferId, buffer);
    }

    common::Error Socket::RejectTransfer(uint16_t transferId, const Address& peer)
    {
        PeerSendMaterials materials;
        uint32_t peerSlot = 0;
        {
            PeerHandle peerHandle = peers_.GetPeer(peer);
            if (peerHandle.Failed()) return common::Error::NotFound;
            Peer* peerState = peerHandle.Write();
            if (!peerState || !peerState->IsValid()) return common::Error::InvalidState;
            peerSlot  = peerHandle.GetSlotIndex();
            materials = GatherSendMaterials(*peerState);
        }

        const common::Error dropped = transfers_.Reject(peerSlot, transferId);

        uint8_t payload[2];
        payload[0] = static_cast<uint8_t>(transferId >> 0);
        payload[1] = static_cast<uint8_t>(transferId >> 8);
        SendSecureControl(peer, materials, internal::SECURE_CHANNEL_TRANSFER_REJECT,
                          payload, sizeof(payload));
        common::crypto::Wipe(materials.key.data(), materials.key.size());
        return dropped;
    }

    common::Error TransferRequest::Allow(void* buffer) noexcept
    {
        if (!Valid())  return common::Error::InvalidState;
        if (!buffer)   return common::Error::InvalidParam;
        return socket_->AllowTransfer(flowId_, peer_, buffer);
    }

    common::Error TransferRequest::Reject() noexcept
    {
        if (!Valid()) return common::Error::InvalidState;
        return socket_->RejectTransfer(flowId_, peer_);
    }

// --- The tick's send pass ---

    void Socket::TransferPass(const Address& to, PeerHandle peerHandle, uint64_t now)
    {
        if (!transfers_.SendEnabled()) return;

        struct Outgoing
        {
            uint16_t          transferId;
            uint32_t          seq;
            uint8_t           flags;
            uint16_t          payloadLen;
            const uint8_t*    source;
            PeerSendMaterials materials;
        };
        Outgoing queued[PACKETS_PER_PASS];
        uint32_t queuedCount = 0;

        {
            // Gathered under the borrow, sent after it drops. The peer lock is
            // never held across a seal or a syscall, exactly as on the flow
            // path.
            PeerHandle owned = std::move(peerHandle);
            if (owned.Failed()) return;
            Peer* peer = owned.Write();
            if (!peer || !peer->IsValid()) return;

            const uint32_t peerSlot = owned.GetSlotIndex();
            PeerSendMaterials base  = GatherSendMaterials(*peer);
            bool gatheredAny = false;

            transfers_.ForEachSending(peerSlot, [&](uint32_t slot, OutTransfer& out) -> bool
            {
                if (out.refused) return true;

                // The announcement first, and nothing else until the receiver
                // has answered it. Sending data into a receiver that has not
                // been asked for a buffer only fills its holdback.
                if (!out.announced)
                {
                    const uint16_t wireSize =
                        TransferWireSize(internal::TRANSFER_ANNOUNCE_SIZE);
                    if (!TransferBudgetAllows(*peer, wireSize)
                        || !TransferPacingAllows(*peer, now, wireSize)) return true;
                    if (queuedCount >= PACKETS_PER_PASS) return false;

                    TransferSpendFirst(*peer, wireSize);
                    Outgoing& item = queued[queuedCount++];
                    item.transferId = out.transferId;
                    item.seq        = 0;
                    item.flags      = internal::TRANSFER_FLAG_ANNOUNCE;
                    item.payloadLen = internal::TRANSFER_ANNOUNCE_SIZE;
                    item.source     = nullptr;
                    item.materials  = base;
                    item.materials.counter = gatheredAny ? ++peer->sendCounter
                                                         : base.counter;
                    gatheredAny = true;
                    out.announced        = true;
                    out.announceSentAt   = now;
                    return true;
                }

                // Re-announce while the answer is outstanding, so a lost
                // announcement is not a transfer that never starts.
                if (!out.announceAcked)
                {
                    const uint64_t rto = peer->rtt.RetransmitTimeout(
                        flows_.RetryIntervalMicros(), flows_.AckDelayMicros());
                    if (now > out.announceSentAt && now - out.announceSentAt > rto)
                        out.announced = false;
                    return true;
                }

                // Fresh data, then whatever is overdue. Both are read straight
                // out of the application's buffer, which is what makes an
                // outstanding packet cost a ring entry rather than its bytes.
                const uint64_t rto = peer->rtt.RetransmitTimeout(
                    flows_.RetryIntervalMicros(), flows_.AckDelayMicros());
                const uint64_t lossDelay =
                    peer->rtt.LossDelayMicros(flows_.RetryIntervalMicros());

                // Advanced past each overdue answer, so the walk over the
                // window is shared by the whole pass. Once the scan comes back
                // empty it stays empty for this pass: nothing sent below the
                // resume point, and nothing sent this instant can already be
                // overdue.
                uint32_t scanFrom      = 0;
                bool     overdueClear  = false;

                for (uint32_t attempt = 0; attempt < PACKETS_PER_PASS; ++attempt)
                {
                    // Overdue before new, always. The receiver's cursor is
                    // stuck behind the oldest hole, so the packet that fills
                    // it is worth more than the next one in line, and every
                    // byte behind it stays unusable until it lands. Offering
                    // new data first was measured deadlocking the transfer:
                    // the packets dropped before the receiver answered were
                    // never re-offered, the budget stayed full of them, and
                    // nothing ever resolved.
                    uint32_t seq = overdueClear ? UINT32_MAX
                        : transfers_.OldestOverdue(slot, out, now, rto,
                                                   lossDelay, scanFrom);
                    if (seq != UINT32_MAX) scanFrom = seq + 1;
                    else
                    {
                        overdueClear = true;
                        // The window bounds the SEQUENCE SPAN above the
                        // progress cursor, not the count in flight. Both rings
                        // index by seq & (window - 1), so a sequence a whole
                        // window past the cursor lands on a live entry
                        // belonging to an older one.
                        //
                        // Gating on inFlight let exactly that happen: every
                        // out-of-order resolve decremented it while the cursor
                        // stayed stuck, so the sender ran 1031 sequences past a
                        // 1024 ring. Resolving the old sequence then read the
                        // new one's timestamp, which put 27 microsecond samples
                        // into a 60 millisecond path, collapsed the remembered
                        // minimum, and left the controller seeing a permanent
                        // standing queue it could never drain.
                        const uint64_t ceiling =
                            static_cast<uint64_t>(out.contiguousAcked)
                            + internal::TRANSFER_WINDOW;
                        if (out.nextSeq >= out.packetCount
                            || out.nextSeq >= ceiling) break;
                        seq = out.nextSeq;
                    }

                    const uint64_t offset =
                        static_cast<uint64_t>(seq) * internal::TRANSFER_STRIDE_BYTES;
                    const uint64_t remaining = out.length - offset;
                    const uint16_t payloadLen = static_cast<uint16_t>(
                        remaining < internal::TRANSFER_STRIDE_BYTES
                            ? remaining : internal::TRANSFER_STRIDE_BYTES);

                    // A resend is paced like everything else but never
                    // charged to the budget twice, since its bytes are still
                    // counted from the first attempt.
                    const bool firstSend = (seq == out.nextSeq);
                    const uint16_t wireSize = TransferWireSize(payloadLen);
                    if (!TransferPacingAllows(*peer, now, wireSize)) break;
                    if (firstSend && !TransferBudgetAllows(*peer, wireSize)) break;
                    if (queuedCount >= PACKETS_PER_PASS) return false;

                    if (firstSend) TransferSpendFirst(*peer, wireSize);
                    else           TransferSpendResend(*peer, wireSize);

                    Outgoing& item = queued[queuedCount++];
                    item.transferId = out.transferId;
                    item.seq        = seq;
                    item.flags      = 0;
                    item.payloadLen = payloadLen;
                    item.source     = out.source + offset;
                    item.materials  = base;
                    item.materials.counter = gatheredAny ? ++peer->sendCounter
                                                         : base.counter;
                    gatheredAny = true;

                    transfers_.MarkSent(slot, out, seq, now);
                    if (seq == out.nextSeq) ++out.nextSeq;
                }
                return true;
            });

            common::crypto::Wipe(base.key.data(), base.key.size());
        }

        uint8_t payload[internal::TRANSFER_WIRE_HEADER_SIZE
                        + internal::TRANSFER_STRIDE_BYTES];
        for (uint32_t i = 0; i < queuedCount; ++i)
        {
            Outgoing& item = queued[i];
            WriteTransferHeader(payload, item.transferId, item.seq, item.flags);

            size_t bodyLen = internal::TRANSFER_WIRE_HEADER_SIZE;
            if (item.flags & internal::TRANSFER_FLAG_ANNOUNCE)
            {
                // [totalLen(8)][stride(2)]
                uint64_t length = 0;
                {
                    PeerHandle peek = peers_.GetPeer(to);
                    if (!peek.Failed())
                        length = transfers_.SendingLength(peek.GetSlotIndex(),
                                                          item.transferId);
                }
                for (uint32_t b = 0; b < 8; ++b)
                    payload[bodyLen + b] = static_cast<uint8_t>(length >> (8 * b));
                payload[bodyLen + 8] =
                    static_cast<uint8_t>(internal::TRANSFER_STRIDE_BYTES >> 0);
                payload[bodyLen + 9] =
                    static_cast<uint8_t>(internal::TRANSFER_STRIDE_BYTES >> 8);
                bodyLen += internal::TRANSFER_ANNOUNCE_SIZE;
            }
            else
            {
                std::memcpy(payload + bodyLen, item.source, item.payloadLen);
                bodyLen += item.payloadLen;
            }

            SendSecureControl(to, item.materials, internal::SECURE_CHANNEL_TRANSFER,
                              payload, bodyLen);
            common::crypto::Wipe(item.materials.key.data(), item.materials.key.size());
        }
    }

// --- Channel handlers ---

    void Socket::Transfer_Data(const Address& from, const uint8_t* payload, size_t len)
    {
        // The authentication tag sits after the payload and is still counted
        // in what a channel handler is handed, so it comes off before any
        // length is compared. Getting this wrong made every data packet look
        // sixteen bytes too long and refused the lot.
        if (len < static_cast<size_t>(internal::TRANSFER_WIRE_HEADER_SIZE)
                    + internal::WIRE_TAG_SIZE) return;

        uint16_t transferId = 0;
        uint32_t seq        = 0;
        uint8_t  flags      = 0;
        ReadTransferHeader(payload, transferId, seq, flags);

        const uint8_t* body   = payload + internal::TRANSFER_WIRE_HEADER_SIZE;
        const size_t   bodyLen = len - internal::TRANSFER_WIRE_HEADER_SIZE
                                     - internal::WIRE_TAG_SIZE;

        uint32_t peerSlot = 0;
        {
            PeerHandle peerHandle = peers_.GetPeer(from);
            if (peerHandle.Failed()) return;
            const Peer* peer = peerHandle.Read();
            if (!peer || !peer->IsValid()) return;
            peerSlot = peerHandle.GetSlotIndex();
        }

        if (flags & internal::TRANSFER_FLAG_ANNOUNCE)
        {
            if (bodyLen < internal::TRANSFER_ANNOUNCE_SIZE) return;
            uint64_t length = 0;
            for (uint32_t b = 0; b < 8; ++b)
                length |= static_cast<uint64_t>(body[b]) << (8 * b);
            const uint16_t stride = static_cast<uint16_t>(body[8])
                                  | static_cast<uint16_t>(body[9]) << 8;

            bool isNew = false;
            if (transfers_.OnAnnounce(peerSlot, from, transferId, length, stride, isNew)
                    != common::Error::Ok)
                return;

            // Told once, on the announcement that created it, so a
            // retransmitted announcement does not ask the application twice.
            if (isNew)
            {
                if (events_.Record(EventScope::PEER, peerSlot,
                                   readyLanes_.LaneOf(peerSlot),
                                   SocketEvent::TRANSFER_INCOMING, from, transferId))
                {
                    PeerHandle peerHandle = peers_.GetPeer(from);
                    Peer* peer = peerHandle.Failed() ? nullptr : peerHandle.Write();
                    if (peer) peer->emitting = true;
                }
            }
            // Falls through to the acknowledgement below. An announcement that
            // is never answered leaves the sender holding every byte, because
            // it will not release data until it knows the far side heard the
            // length.
        }
        else

        {
            // A packet with nowhere to go yet is normal before the application
            // has answered, and the acknowledgement below is what tells the
            // sender to offer it again.
            (void)transfers_.OnData(peerSlot, transferId, seq, body,
                                    static_cast<uint16_t>(bodyLen));
        }

        // Answered on a cadence rather than per packet. One ack per data
        // packet doubles the packet count on a link whose reverse direction is
        // shaped too, and buys nothing a cursor plus a bitmap does not already
        // say.
        if (!transfers_.TakeAckDebt(peerSlot, transferId)) return;

        uint32_t cursor = 0;
        uint8_t  bitmap[internal::TRANSFER_ACK_BITMAP_BYTES];
        if (!transfers_.ReceiveState(peerSlot, transferId, cursor, bitmap)) return;

        PeerSendMaterials materials;
        {
            PeerHandle peerHandle = peers_.GetPeer(from);
            if (peerHandle.Failed()) return;
            Peer* peer = peerHandle.Write();
            if (!peer || !peer->IsValid()) return;
            materials = GatherSendMaterials(*peer);
        }
        SendTransferAck(from, materials, transferId, cursor, bitmap);
        common::crypto::Wipe(materials.key.data(), materials.key.size());
    }

    void Socket::SendTransferAck(const Address& to, const PeerSendMaterials& materials,
                                 uint16_t transferId, uint32_t recvNext,
                                 const uint8_t* bitmap)
    {
        // [transferId(2)][recvNext(4)][window bitmap]. Bit i names the
        // sequence cursor + i, so the sender is told outright which packets
        // have landed rather than inferring it from a cursor.
        uint8_t payload[6 + internal::TRANSFER_ACK_BITMAP_BYTES];
        payload[0] = static_cast<uint8_t>(transferId >> 0);
        payload[1] = static_cast<uint8_t>(transferId >> 8);
        for (uint32_t b = 0; b < 4; ++b)
            payload[2 + b] = static_cast<uint8_t>(recvNext >> (8 * b));
        std::memcpy(payload + 6, bitmap, internal::TRANSFER_ACK_BITMAP_BYTES);
        SendSecureControl(to, materials, internal::SECURE_CHANNEL_TRANSFER_ACK,
                          payload, sizeof(payload));
    }

    void Socket::Transfer_Ack(const Address& from, const uint8_t* payload, size_t len)
    {
        if (len < 6u + internal::TRANSFER_ACK_BITMAP_BYTES) return;
        const uint16_t transferId = static_cast<uint16_t>(payload[0])
                                  | static_cast<uint16_t>(payload[1]) << 8;
        uint32_t recvNext = 0;
        for (uint32_t b = 0; b < 4; ++b)
            recvNext |= static_cast<uint32_t>(payload[2 + b]) << (8 * b);
        const uint8_t* bitmap = payload + 6;

        PeerHandle peerHandle = peers_.GetPeer(from);
        if (peerHandle.Failed()) return;
        Peer* peer = peerHandle.Write();
        if (!peer || !peer->IsValid()) return;

        const uint64_t now = common::MonotonicMicros();
        uint32_t freedBytes   = 0;
        uint32_t freedPackets = 0;
        uint32_t rttSample    = 0;
        uint32_t lostBytes    = 0;
        transfers_.OnAck(peerHandle.GetSlotIndex(), transferId, recvNext, bitmap,
                         now, freedBytes, freedPackets, rttSample, lostBytes);
        if (freedPackets == 0 && rttSample == 0 && lostBytes == 0) return;

        // Through the same controller the flows use, not a private counter.
        // A transfer and a flow to this peer cross one link, so one budget
        // decides for both, and a transfer that only decremented what it had
        // spent would never let that budget grow: it would sit at the opening
        // window for the life of the transfer, which measured about ten
        // packets a round trip.
        CongestionDelta delta;
        delta.resolvedBytes   = freedBytes;
        delta.resolvedPackets = freedPackets;
        delta.ackedBytes      = freedBytes;
        delta.rttSampleMicros = rttSample;
        // Real loss, reported so the budget answers it. Without this the
        // controller never learns the path is dropping, the window stays far
        // above what the queue holds, and the transfer spends itself
        // overflowing that queue rather than draining it.
        if (lostBytes != 0)
        {
            delta.sawLoss           = true;
            delta.lostDeclaredBytes = lostBytes;
            delta.lostEpoch         = peer->congestionEpoch;
        }
        ApplyCongestion(*peer, delta, now);
    }

    void Socket::Transfer_Reject(const Address& from, const uint8_t* payload, size_t len)
    {
        if (len < 2) return;
        const uint16_t transferId = static_cast<uint16_t>(payload[0])
                                  | static_cast<uint16_t>(payload[1]) << 8;

        PeerHandle peerHandle = peers_.GetPeer(from);
        if (peerHandle.Failed()) return;
        Peer* peer = peerHandle.Write();
        if (!peer || !peer->IsValid()) return;

        uint32_t freedBytes   = 0;
        uint32_t freedPackets = 0;
        transfers_.OnRefused(peerHandle.GetSlotIndex(), transferId,
                             freedBytes, freedPackets);
        // A refusal is not congestion, so what it held goes straight back
        // rather than through the controller.
        if (freedPackets != 0) TransferResolve(*peer, freedBytes, freedPackets);
    }
}
