#include <flux/socket/socket.h>

#include <common/log.h>
#include <common/crypto/crypto.h>
#include <flux/socket/platform/win_socket.h>
#include <flux/socket/platform/posix_socket.h>
#include <flux/internal/constants.h>
#include <flux/wire/packet_builder.h>
#include <flux/socket/packet_slot.h>
#include <flux/socket/pending_packet.h>
#include <flux/peer/peer_handle.h>

#include <cstring>
#include <new>

// --- Foundations: helpers, seal/open, crypto, init + teardown ---

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

        /** Rebuilds the XChaCha20 nonce locally; the wire carries only the 8-byte
            counter. The lane byte splits the nonce space between the two sides'
            independent counters, which share one key. */
        void ExpandNonce(common::crypto::Nonce& out, uint64_t counter, uint8_t lane) noexcept
        {
            out = {};
            for (size_t i = 0; i < internal::WIRE_NONCE_SIZE; ++i)
                out[i] = static_cast<uint8_t>(counter >> (8 * i));
            out[internal::WIRE_NONCE_SIZE] = lane;
        }

        /** Writes the little-endian 8-byte counter into a packet's nonce field. */
        void StampNonceCounter(uint8_t* nonceField, uint64_t counter) noexcept
        {
            for (size_t i = 0; i < internal::WIRE_NONCE_SIZE; ++i)
                nonceField[i] = static_cast<uint8_t>(counter >> (8 * i));
        }

        /** The counter has to travel — the receiver cannot know which packet
            this is otherwise — but travelling in the clear makes it a serial
            number, and a sequence that stops at one address and resumes at the
            next value from another address links a peer across a migration no
            matter how the tag rotates. So the field carries the counter
            encrypted under a mask derived from the peer's header key and this
            packet's AEAD tag: the tag is unique and unpredictable per packet,
            so the same counter never produces the same bytes twice, and an
            observer sees eight bytes that never form a sequence.
            Key-holders both sides recompute it identically; nobody else can.

            Masking is its own inverse, so one function serves both directions.

            @pre `aeadTag` is the packet's final tag: on send that means after
                 the seal, on receive before the open. */
        void MaskNonceCounter(uint8_t* nonceField,
                              const common::crypto::SessionKey& headerKey,
                              const uint8_t* aeadTag) noexcept
        {
            uint8_t mask[common::crypto::KEY_SIZE];
            common::crypto::DeriveSubKey(mask, headerKey.data(), aeadTag);
            for (size_t i = 0; i < internal::WIRE_NONCE_SIZE; ++i)
                nonceField[i] ^= mask[i];
            common::crypto::Wipe(mask, sizeof(mask));
        }

        /** Reads the little-endian 8-byte counter out of a nonce field. */
        uint64_t ReadNonceCounter(const uint8_t* nonceField) noexcept
        {
            uint64_t counter = 0;
            for (size_t i = 0; i < internal::WIRE_NONCE_SIZE; ++i)
                counter |= static_cast<uint64_t>(nonceField[i]) << (8 * i);
            return counter;
        }

        /** Builds the AEAD associated data: the controller byte, plus the 4-byte
            migration tag on a tagged packet. Both are readable on the wire and
            neither is alterable.

            @param tag Null on an untagged packet.
            @return The AAD length. */
        size_t BuildSecureAad(uint8_t* aad, uint8_t controller, const uint8_t* tag) noexcept
        {
            aad[0] = controller;
            size_t aadLen = internal::WIRE_CONTROLLER_SIZE;
            if (tag)
            {
                std::memcpy(aad + aadLen, tag, internal::WIRE_PEER_TAG_SIZE);
                aadLen += internal::WIRE_PEER_TAG_SIZE;
            }
            return aadLen;
        }

        /** Writes every field of a freshly acquired association slot. The pools
            never construct, so a recycled slot holds the previous tenant's bytes
            except epoch, which survives and advances so stale references never
            match again. Born OPEN: opening is local and the remote registers its
            half from the first packet.

            @pre Caller holds the slot write lock. */
        void ResetOutAssoc(OutAssociation* assoc, uint32_t peerSlot, const Address& peerAddr,
                           const BcpId* peerId, uint16_t flowId, FlowMode mode,
                           uint16_t inflightCap, uint16_t waitingCap) noexcept
        {
            assoc->peerSlot   = peerSlot;
            assoc->peerAddr   = peerAddr;
            assoc->peerId     = peerId ? *peerId : BcpId{};
            assoc->flowSlot   = common::collections::SlotPool::INVALID;
            assoc->nextInFlow = common::collections::SlotPool::INVALID;
            assoc->flowId     = flowId;
            assoc->mode       = mode;
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
                          uint16_t windowBits, uint16_t reorderCap) noexcept
        {
            assoc->peerSlot = peerSlot;
            assoc->peerAddr = peerAddr;
            assoc->peerId   = peerId ? *peerId : BcpId{};
            assoc->flowId   = flowId;
            assoc->mode     = mode;
            assoc->life     = FlowLifecycle::OPEN;
            assoc->epoch    = assoc->epoch + 1;

            assoc->recvNext       = 1;
            assoc->recvHighest    = 0;
            assoc->newSinceFlush  = 0;
            assoc->ackArmedMicros = 0;
            assoc->windowBits     = windowBits;
            assoc->reorderCap     = reorderCap;

            std::memset(assoc->Seen(), 0, windowBits / 8);
            HoldbackEntry* holdback = assoc->Holdback();
            for (uint32_t i = 0; i < reorderCap; ++i)
                holdback[i] = HoldbackEntry{ 0, common::collections::SlotPool::INVALID };
        }

        /** The handshake transcript both sides bind into the session key and the
            confirmation MAC. Role-ordered, so both ends assemble identical bytes. */
        void BuildTranscript(uint8_t out[internal::HS_TRANSCRIPT_SIZE],
                             const common::crypto::PublicKey& initiatorPk,
                             const common::crypto::PublicKey& responderPk,
                             const uint8_t saltI[internal::WIRE_HS_SALT_SIZE],
                             const uint8_t saltR[internal::WIRE_HS_SALT_SIZE],
                             const uint32_t initiatorCaps,
                             const uint32_t responderCaps,
                             const uint16_t initiatorVersion,
                             const uint16_t responderVersion,
                             const Certificate::IdentityTag& tag) noexcept
        {
            uint8_t* p = out;
            std::memcpy(p, initiatorPk.data(), initiatorPk.size());         p += initiatorPk.size();
            std::memcpy(p, responderPk.data(), responderPk.size());         p += responderPk.size();
            std::memcpy(p, saltI, internal::WIRE_HS_SALT_SIZE);             p += internal::WIRE_HS_SALT_SIZE;
            std::memcpy(p, saltR, internal::WIRE_HS_SALT_SIZE);             p += internal::WIRE_HS_SALT_SIZE;
            p[0] = static_cast<uint8_t>(initiatorCaps >> 0);
            p[1] = static_cast<uint8_t>(initiatorCaps >> 8);
            p[2] = static_cast<uint8_t>(initiatorCaps >> 16);
            p[3] = static_cast<uint8_t>(initiatorCaps >> 24);                p += internal::VERSION_CAPS_SIZE;
            p[0] = static_cast<uint8_t>(responderCaps >> 0);
            p[1] = static_cast<uint8_t>(responderCaps >> 8);
            p[2] = static_cast<uint8_t>(responderCaps >> 16);
            p[3] = static_cast<uint8_t>(responderCaps >> 24);                p += internal::VERSION_CAPS_SIZE;
            p[0] = static_cast<uint8_t>(initiatorVersion >> 0);
            p[1] = static_cast<uint8_t>(initiatorVersion >> 8);              p += internal::VERSION_SIZE;
            p[0] = static_cast<uint8_t>(responderVersion >> 0);
            p[1] = static_cast<uint8_t>(responderVersion >> 8);              p += internal::VERSION_SIZE;   
            std::memcpy(p, tag.data(), tag.size());
        }

        void BuildCapsBitmap(uint32_t& out)
        {
            // No added caps in v1.
            out = {0};
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
                const uint32_t oldFloor = flow->recvHighest >= bits
                    ? flow->recvHighest - bits + 1 : 1;
                const uint32_t newFloor = seq >= bits ? seq - bits + 1 : 1;
                for (uint32_t s = oldFloor; s < newFloor; ++s)
                    SeenClear(flow->Seen(), s, bits);
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

        /** The Update clock: 0 means read the real monotonic clock now. Passed
            down the tick as a value so each decision point reads fresh. */
        uint64_t Now(uint64_t nowOverride) noexcept
        {
            return nowOverride != 0 ? nowOverride : common::MonotonicMicros();
        }
    }

    static_assert(internal::WIRE_HS_TAG_SIZE == Certificate::IDENTITY_TAG_SIZE,
                  "The announced tag field carries a certificate identity tag verbatim");

    // --- Lifecycle ---

    Socket::~Socket()
    {
        Shutdown();
    }

    void Socket::Shutdown() noexcept
    {
        // Idempotent: the first call marks the socket down and closes the OS
        // handle; the pools and buffers release through their own destructors.
        if (!initialized_.exchange(false, std::memory_order_acq_rel))
            return;
        if (kernel_)
            kernel_->Close();
    }

    common::Error Socket::Init(const Config& config)
    {
        if (initialized_.load()) return common::Error::InvalidState;
        if (config.maxPeers == 0 || config.pendingPacketCount == 0 ||
            config.recvSlotCount == 0 || config.sendSlotCount == 0)
            return common::Error::InvalidParam;

        if (common::Error error = InitIdentity(config); error != common::Error::Ok)
            return error;

        BuildBackendSocket(config.type);
        if (!kernel_)
            return common::Error::NotImplemented;
        if (kernel_->Init(config.port, config.recvSlotCount, config.sendSlotCount) != common::Error::Ok)
            return common::Error::NotInitialized;
        recvPool_ = kernel_->GetRecvPool();   // held packets stay leased here
        sendPool_ = kernel_->GetSendPool();   // waiting unreliable bodies stay leased here

        // The ready path holds recv-slot indices, so it can never need more
        // entries than there are recv slots.
        if (!readyQueue_.Init(config.recvSlotCount))
            return common::Error::NotInitialized;
        if (listener_.Init(kernel_.get()) != common::Error::Ok)
            return common::Error::NotInitialized;
        if (sender_.Init(this, kernel_.get()) != common::Error::Ok)
            return common::Error::NotInitialized;
        if (challengeGenerator_.Init() != common::Error::Ok)
            return common::Error::NotInitialized;

        if (common::Error error = InitPeerTableAndReplay(config); error != common::Error::Ok)
            return error;
        if (common::Error error = InitFlows(config); error != common::Error::Ok)
            return error;
        if (common::Error error = InitLiveness(config); error != common::Error::Ok)
            return error;

        migration_            = config.enableMigration;
        migrateBudgetPerPoll_ = config.migrateBudgetPerPoll;

        initialized_.store(true, std::memory_order_release);
        return common::Error::Ok;
    }

    common::Error Socket::InitIdentity(const Config& config) noexcept
    {
        if (config.identity)
        {
            secretKey_ = config.identity->secretKey;
            publicKey_ = config.identity->publicKey;
            ownTag_    = config.identity->tag;
        }
        else if (!GenerateKeypair())
        {
            return common::Error::NotInitialized;
        }

        if (config.trustedCertCount > 0 &&
            certStore_.Init(config.trustedCertCount) != common::Error::Ok)
            return common::Error::NotInitialized;

        return common::Error::Ok;
    }

    common::Error Socket::InitPeerTableAndReplay(const Config& config) noexcept
    {
        if (peers_.Init(config.maxPeers) != common::Error::Ok)
            return common::Error::NotInitialized;

        const uint32_t pendingStride =
            AlignUp16(sizeof(PendingPacket) + internal::MAX_WIRE_PACKET_SIZE);
        if (!pendingPool_.Init(config.pendingPacketCount, pendingStride))
            return common::Error::NotInitialized;

        // One replay block per peer slot: [highWater][bitmap words...]. Rounds up
        // to a multiple of 64 counters, at least one word. All zero: an unproven
        // peer receives nothing, and each establish resets its block.
        replayWords_ = (config.replayWindowBits + 63) / 64;
        if (replayWords_ == 0)
            replayWords_ = 1;
        const size_t blocks = static_cast<size_t>(config.maxPeers) * (1 + replayWords_);
        replayState_.reset(new (std::nothrow) uint64_t[blocks]());
        if (!replayState_)
            return common::Error::NotInitialized;

        return common::Error::Ok;
    }

    common::Error Socket::InitFlows(const Config& config) noexcept
    {
        const Config::Flows& f = config.flows;
        if (f.outCount == 0 && f.inCount == 0)
            return common::Error::Ok;   // flows disabled entirely
        if (f.inFlightCount == 0)
            return common::Error::InvalidParam;

        // One window knob serves both roles (out-ring capacity and in-bitmap
        // width), rounded to a power of two, floor 64; the wire handshake
        // reconciles two sockets whose knobs differ.
        const uint32_t window = RoundUpPow2(f.inFlightCount, internal::FLOW_WINDOW_MIN,
                                            internal::FLOW_WINDOW_MAX);

        auto initDir = [&](std::unique_ptr<FlowDirEntry[]>& dir, uint32_t width) -> bool
        {
            const size_t entries = static_cast<size_t>(config.maxPeers) * width;
            dir.reset(new (std::nothrow) FlowDirEntry[entries]);
            if (!dir) return false;
            for (size_t i = 0; i < entries; ++i)
                dir[i] = FlowDirEntry{ internal::INVALID_FLOW_ID, 0,
                                       common::collections::SlotPool::INVALID };
            return true;
        };

        if (f.outCount > 0)
        {
            if (f.maxOutPerPeer == 0)
                return common::Error::InvalidParam;
            outInflightCap_ = static_cast<uint16_t>(window);

            // Waiting rings are per-mode: each flow takes the knob its mode
            // names, while every out slot is sized for the larger of the two.
            outReliableWaitCap_ = static_cast<uint16_t>(f.reliableWaitCount > 0
                ? RoundUpPow2(f.reliableWaitCount, 1, internal::FLOW_WINDOW_MAX) : 0);
            outUnreliableWaitCap_ = static_cast<uint16_t>(f.unreliableWaitCount > 0
                ? RoundUpPow2(f.unreliableWaitCount, 1, internal::FLOW_WINDOW_MAX) : 0);
            const uint16_t waitStrideCap = outReliableWaitCap_ > outUnreliableWaitCap_
                ? outReliableWaitCap_ : outUnreliableWaitCap_;

            const uint32_t stride = static_cast<uint32_t>(
                OutAssociation::StrideFor(outInflightCap_, waitStrideCap));
            if (!outAssocPool_.Init(f.outCount, stride))
                return common::Error::NotInitialized;
            if (!initDir(outAssocDir_, f.maxOutPerPeer))
                return common::Error::NotInitialized;
            maxOutAssocPerPeer_ = f.maxOutPerPeer;

            // Retained reliable bodies: same stride as a wire packet (it IS the
            // packet, kept). Only the sending side needs it.
            if (f.stagingCount > 0)
            {
                const uint32_t stagingStride =
                    AlignUp16(sizeof(PacketSlot) + internal::MAX_WIRE_PACKET_SIZE);
                if (!stagingPool_.Init(f.stagingCount, stagingStride))
                    return common::Error::NotInitialized;
            }
        }

        if (f.outCount > 0)
        {
            // Flows are tiny and few, associations large and many.
            if (f.flowCount == 0)
                return common::Error::InvalidParam;
            if (!flowPool_.Init(f.flowCount, static_cast<uint32_t>(sizeof(Flow))))
                return common::Error::NotInitialized;

            // Zero is a legal flow id, so free has to be stamped explicitly.
            for (uint32_t slot = 0; slot < flowPool_.GetCapacity(); ++slot)
            {
                Flow* flow = reinterpret_cast<Flow*>(flowPool_.WriteLock(slot));
                flow->flowId = internal::INVALID_FLOW_ID;
                flow->life   = FlowLifecycle::CLOSED;
                flowPool_.UnlockWrite(slot);
            }
        }

        if (f.inCount > 0)
        {
            if (f.maxInPerPeer == 0)
                return common::Error::InvalidParam;
            inWindowBits_ = static_cast<uint16_t>(window);

            inReorderCap_ = static_cast<uint16_t>(
                f.reorderCount > 0 ? RoundUpPow2(f.reorderCount, 1, internal::FLOW_WINDOW_MAX) : 0);

            const uint32_t stride = static_cast<uint32_t>(
                InAssociation::StrideFor(inWindowBits_, inReorderCap_));
            if (!inAssocPool_.Init(f.inCount, stride))
                return common::Error::NotInitialized;
            if (!initDir(inAssocDir_, f.maxInPerPeer))
                return common::Error::NotInitialized;
            maxInAssocPerPeer_ = f.maxInPerPeer;
        }

        // Floored at one full wire packet: the budget gates sends, and a floor
        // no packet fits under would refuse a full-size packet forever;
        // "throttled, never strangled" requires the floor to admit one.
        minCongestionBudget_ = f.minCongestionBudget != 0
            ? f.minCongestionBudget : internal::CC_MIN_BUDGET_DEFAULT;
        if (minCongestionBudget_ < internal::MAX_WIRE_PACKET_SIZE)
            minCongestionBudget_ = internal::MAX_WIRE_PACKET_SIZE;
        flowAckDelayMicros_      = config.timers.ackDelayMicros;
        flowRetryIntervalMicros_ = config.timers.retryIntervalMicros;
        flowMaxAttempts_         = config.timers.maxAttempts;
        return common::Error::Ok;
    }

    common::Error Socket::InitLiveness(const Config& config) noexcept
    {
        // Converted once into SeenStamp units. The grain folds into the eviction
        // threshold so a stamp lagging by up to one grain delays an eviction but
        // never causes one early. The sum must stay under half the stamp wrap or
        // wrapped comparison turns ambiguous.
        const uint64_t grainStamp =
            config.liveness.refreshGrainMicros >> internal::SEEN_STAMP_SHIFT;
        if (grainStamp >= (1ull << 31))
            return common::Error::InvalidParam;
        seenGrainStamp_ = static_cast<uint32_t>(grainStamp);

        if (config.liveness.idleTimeoutMicros != 0)
        {
            const uint64_t idleStamp =
                (config.liveness.idleTimeoutMicros >> internal::SEEN_STAMP_SHIFT) + seenGrainStamp_;
            if (idleStamp == 0 || idleStamp >= (1ull << 31))
                return common::Error::InvalidParam;
            evictAfterStamp_ = static_cast<uint32_t>(idleStamp);
        }

        acceptUnsecureFromUnknown_ = config.liveness.acceptUnsecureFromUnknown;
        return common::Error::Ok;
    }

    void Socket::BuildBackendSocket(BackendType type) noexcept
    {
        // Each backend exists only on its platform; the wrong one leaves kernel_
        // null and Init reports NotImplemented.
        switch (type)
        {
        case BackendType::STD_UNX:
#ifndef _WIN32
            kernel_ = std::make_unique<platform::PosixSocket>();
#endif
            break;
        case BackendType::STD_WIN:
#ifdef _WIN32
            kernel_ = std::make_unique<platform::WinSocket>();
#endif
            break;
        case BackendType::RIO_WIN:
        case BackendType::URING_UNX:
        default:
            break;   // not implemented; kernel_ stays null
        }
    }

    bool Socket::GenerateKeypair() noexcept
    {
        return common::crypto::GenerateKeypair(secretKey_, publicKey_);
    }

    common::Error Socket::LoadCertificate(const Certificate& cert)
    {
        return certStore_.Add(cert);
    }

    // --- Crypto / seal ---

    ReplayWindow Socket::ReplayFor(uint32_t slot) noexcept
    {
        const size_t block = static_cast<size_t>(slot) * (1 + replayWords_);
        return ReplayWindow{ replayState_.get() + block, replayWords_ };
    }

    uint8_t Socket::LaneTo(const common::crypto::PublicKey& theirPk) const noexcept
    {
        return std::memcmp(publicKey_.data(), theirPk.data(), publicKey_.size()) < 0 ? 0 : 1;
    }

    uint8_t Socket::LaneFrom(const common::crypto::PublicKey& theirPk) const noexcept
    {
        return LaneTo(theirPk) == 0 ? 1 : 0;
    }

    void Socket::DeriveSessionInto(common::crypto::SessionKey& out,
                                    const common::crypto::PublicKey& theirPk,
                                    const uint8_t* transcript, size_t transcriptLen) noexcept
    {
        common::crypto::SharedSecret shared;
        common::crypto::ComputeSharedSecret(shared, secretKey_, theirPk);
        common::crypto::DeriveSessionKey(out, shared, transcript, transcriptLen);
        common::crypto::Wipe(shared.data(), shared.size());
    }

    PeerSendMaterials Socket::GatherSendMaterials(Peer& peer) noexcept
    {
        // The one place a send bumps the counter. Caller holds the peer's write
        // lock; the returned key is a copy the caller Wipes after the send.
        PeerSendMaterials materials;
        materials.key       = peer.session;
        materials.headerKey = peer.headerKey;
        materials.counter   = ++peer.sendCounter;
        materials.lane      = LaneTo(peer.theirPk);
        materials.tag       = peer.myTag;
        return materials;
    }

    void Socket::SealSecurePacket(PacketSlot& dst, const uint8_t* plaintext,
                                   size_t headerSize, size_t bodyLen,
                                   const PeerSendMaterials& materials, bool tagged) noexcept
    {
        // On a tagged packet the migration tag goes into the authenticated
        // header (and the AAD). `dst.data[0]` (controller) is already set; for a
        // retransmit the caller has copied the header from staging, for in-place
        // `plaintext` points into `dst` itself.
        uint8_t aad[internal::WIRE_CONTROLLER_SIZE + internal::WIRE_PEER_TAG_SIZE];
        const uint8_t* tagBytes = nullptr;
        if (tagged)
        {
            uint8_t* tagField = dst.data + internal::MIN_SECURE_WIRE_SIZE;
            std::memcpy(tagField, materials.tag.data(), materials.tag.size());
            tagBytes = materials.tag.data();
        }
        const size_t aadLen = BuildSecureAad(aad, dst.data[0], tagBytes);

        uint8_t* nonceField = dst.data + internal::WIRE_CONTROLLER_SIZE + internal::WIRE_TAG_SIZE;
        StampNonceCounter(nonceField, materials.counter);

        common::crypto::Nonce nonce;
        ExpandNonce(nonce, materials.counter, materials.lane);

        common::crypto::Tag aeadTag;
        common::crypto::Encrypt(dst.data + headerSize, aeadTag, materials.key, nonce,
                                plaintext, bodyLen, aad, aadLen);
        std::memcpy(dst.data + internal::WIRE_CONTROLLER_SIZE, aeadTag.data(), aeadTag.size());

        // Last, because the mask comes from the tag the seal just produced. The
        // nonce was built from the real counter above; only the wire copy is
        // masked, so the AEAD is unaffected.
        MaskNonceCounter(nonceField, materials.headerKey, aeadTag.data());
    }

    bool Socket::OpenSecurePacket(PacketSlot& packet,
                                   const common::crypto::SessionKey& key,
                                   const common::crypto::SessionKey& headerKey,
                                   uint8_t senderLane,
                                   uint64_t& outCounter) noexcept
    {
        const bool tagged = packet.IsTagged();
        const size_t headerSize = tagged
            ? internal::MIN_SECURE_WIRE_SIZE + internal::WIRE_PEER_TAG_SIZE
            : internal::MIN_SECURE_WIRE_SIZE;
        if (packet.dataSize < headerSize)
            return false;

        common::crypto::Tag tag;
        std::memcpy(tag.data(), packet.data + internal::WIRE_CONTROLLER_SIZE, tag.size());

        // Unmask into a local, never back into the header: a wrong key here is
        // routine (the migration path tries every candidate against the same
        // packet), and a header mutated by a failed attempt would poison the
        // next one.
        uint8_t nonceField[internal::WIRE_NONCE_SIZE];
        std::memcpy(nonceField,
                    packet.data + internal::WIRE_CONTROLLER_SIZE + internal::WIRE_TAG_SIZE,
                    sizeof(nonceField));
        MaskNonceCounter(nonceField, headerKey, tag.data());
        const uint64_t counter = ReadNonceCounter(nonceField);

        common::crypto::Nonce nonce;
        ExpandNonce(nonce, counter, senderLane);

        uint8_t aad[internal::WIRE_CONTROLLER_SIZE + internal::WIRE_PEER_TAG_SIZE];
        const size_t aadLen = BuildSecureAad(
            aad, packet.data[0],
            tagged ? packet.data + internal::MIN_SECURE_WIRE_SIZE : nullptr);

        uint8_t* body = packet.data + headerSize;
        const size_t bodyLen = packet.dataSize - headerSize;
        if (!common::crypto::Decrypt(body, key, nonce, body, bodyLen, tag, aad, aadLen))
            return false;

        outCounter = counter;
        return true;
    }

    // --- Send path ---

    wire::PacketBuilder Socket::BuildPacket()
    {
        // Which pool the body comes from depends on whether this is a reliable
        // flow packet, and only NoFlow/WithFlow knows that.
        return wire::PacketBuilder{*this, sender_, migration_};
    }

    common::Result<PacketSlotWriter> Socket::AcquireKernelWriter()
    {
        return kernel_->Write();
    }

    common::Result<PacketSlotWriter> Socket::AcquireFlowWriter(const FlowHandle& flow)
    {
        if (!initialized_.load(std::memory_order_acquire) || !outAssocDir_)
            return common::Result<PacketSlotWriter>::Fail(common::Error::NotInitialized);
        if (flow.Failed() || flow.Slot() >= flowPool_.GetCapacity())
            return common::Result<PacketSlotWriter>::Fail(common::Error::InvalidState);

        // Mode comes off the flow, the only thing this needs. No peer yet: the
        // destination is not known until Send names it. Taking and releasing
        // the flow lock here is what keeps it from ever being held across a
        // peer or association lock.
        FlowMode mode{};
        {
            const Flow* state = reinterpret_cast<const Flow*>(flowPool_.ReadLock(flow.Slot()));
            const bool usable = state->epoch == flow.Epoch()
                             && state->life == FlowLifecycle::OPEN;
            mode = state->mode;
            flowPool_.UnlockRead(flow.Slot());
            if (!usable)
                return common::Result<PacketSlotWriter>::Fail(common::Error::InvalidState);
        }

        // Unreliable bodies are never resent, so they take an ordinary kernel
        // slot and are gone once on the wire. Reliable bodies are their own
        // retransmit source and must outlive the send.
        if (mode == FlowMode::UNRELIABLE)
            return kernel_->Write();

        return AcquireStagingWriter();
    }

    common::Result<PacketSlotWriter> Socket::AcquireStagingWriter()
    {
        const uint32_t slot = stagingPool_.Acquire();
        if (slot == common::collections::SlotPool::INVALID)
            return common::Result<PacketSlotWriter>::Fail(common::Error::PoolExhausted);
        return common::Result<PacketSlotWriter>::Success(
            PacketSlotWriter{PacketSlotHandle{slot, &stagingPool_}});
    }

    /** Pure predicate over the already-locked flow and peer, running every check
        a send needs. The window bounds PACKETS per flow (the receiver's dedupe
        guarantee; reliable only), the congestion budget bounds BYTES per peer
        (the path's capacity; both modes), and the ring slot the next seq maps to
        must be free. The budget sum runs in 64 bits so a saturated budget can
        never wrap the comparison.

        @pre Caller holds the flow and peer locks. */
    bool Socket::CanSend(const OutAssociation& flow, const Peer& peer,
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
    void Socket::StampFlowPacket(OutAssociation& flow, Peer& peer, PacketSlot& packet,
                                  uint32_t stagingSlot, uint16_t wireSize) noexcept
    {
        const uint32_t seq = flow.nextSeq;
        InFlightEntry& entry = flow.InFlight()[seq & (flow.inflightCap - 1)];
        entry.seq          = seq;
        entry.sentAtMicros = common::MonotonicMicros();
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
    void Socket::EnqueueWaiting(OutAssociation& flow, uint32_t packetSlot,
                                 uint16_t wireSize) noexcept
    {
        WaitingEntry& tail =
            flow.Waiting()[(flow.waitingHead + flow.waitingCount) & (flow.waitingCap - 1u)];
        tail.waitingSince = common::MonotonicMicros();
        tail.packetSlot   = packetSlot;
        tail.wireSize     = wireSize;
        flow.waitingCount += 1;
    }

    /** @pre Caller holds the peer write lock; the peer is lent in. */
    uint32_t Socket::CreateAssociation(const Peer& peer, uint32_t peerSlot,
                                       uint16_t flowId) noexcept
    {
        const uint32_t flowSlot = FindFlowById(flowId);
        if (flowSlot == common::collections::SlotPool::INVALID)
            return common::collections::SlotPool::INVALID;   // no such flow open here

        FlowMode mode{};
        uint16_t window = 0;
        {
            const Flow* flow = reinterpret_cast<const Flow*>(flowPool_.ReadLock(flowSlot));
            const bool open = flow->life == FlowLifecycle::OPEN;
            mode   = flow->mode;
            window = flow->window;
            flowPool_.UnlockRead(flowSlot);
            if (!open)
                return common::collections::SlotPool::INVALID;
        }

        const uint32_t assocSlot = outAssocPool_.Acquire();
        if (assocSlot == common::collections::SlotPool::INVALID)
            return common::collections::SlotPool::INVALID;

        // Build, then publish, so no lookup reaches a half-built association.
        // mode is copied once here and never read from the flow again, which is
        // what keeps the packet paths one lock deep.
        {
            OutAssociation* assoc = reinterpret_cast<OutAssociation*>(
                outAssocPool_.WriteLock(assocSlot));
            ResetOutAssoc(assoc, peerSlot, peer.addr, &peer.id, flowId, mode,
                         window,
                         mode == FlowMode::UNRELIABLE ? outUnreliableWaitCap_
                                                      : outReliableWaitCap_);
            assoc->flowSlot   = common::collections::SlotPool::INVALID;
            assoc->nextInFlow = common::collections::SlotPool::INVALID;
            outAssocPool_.UnlockWrite(assocSlot);
        }

        if (InsertFlowSlot(OutAssocDirFor(peerSlot), maxOutAssocPerPeer_, flowId, assocSlot)
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
    SendAdmission Socket::AdmitFlowPacket(Peer& peer, uint32_t peerSlot, PacketSlot& packet,
                                           uint32_t packetSlot, uint16_t wireSize)
    {
        // The peer is lent, already write-locked: no re-lookup. Take only the
        // flow lock (peer->flow), decide, and mutate.
        if (!outAssocDir_) return SendAdmission::Dead;
        const uint16_t flowId = packet.FlowId();
        if (flowId == internal::INVALID_FLOW_ID) return SendAdmission::Dead;

        uint32_t assocSlot = FindFlowSlot(OutAssocDirFor(peerSlot),
                                         maxOutAssocPerPeer_, flowId);
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
                                wireSize);
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

    PacketSlotHandle Socket::PreProcessOut(PacketSlotHandle pHandle, common::Error& status,
                                            bool requireAuth)
    {
        status = common::Error::Ok;
        const PacketSlot* packet = pHandle.Read();
        if (!packet)
        {
            status = common::Error::InvalidState;
            return PacketSlotHandle::Invalid();
        }

        // Handshake traffic must not gate on itself.
        if (packet->IsInternal())
            return pHandle;

        const bool hasFlow  = packet->HasFlow();
        // A reliable flow's plaintext is its own retransmit source, so it lives
        // in staging and outlives the send. Which pool it came from is how that
        // is known here.
        const bool keepsBodyForResend = hasFlow && pHandle.GetPool() == &stagingPool_;

        // One peer WRITE lock, taken directly: NO read-then-upgrade, so no gap
        // in which a racing RemovePeer could invalidate the peer between an
        // IsValid read and the material gather. The valid check, the flow
        // admission, and the gather all run under this one lock; it drops with
        // the scope before the AEAD seal, so the peer is never locked across the
        // encrypt. The flow is admitted here too: AdmitFlowPacket is lent this
        // peer, so the send path touches the peer table ONCE, not twice. For a
        // keepsBodyForResend body the wire slot is taken before the admission, so a dry
        // kernel pool fails cleanly with nothing committed (the stamp is the
        // commit). Lock order: staging(pHandle) -> peer -> flow, then the wire
        // slot; wire slots are freshly acquired so they never cross-contend.
        PacketSlotHandle  wireHandle;
        PacketSlot*       wirePacket = nullptr;
        PeerSendMaterials materials;
        bool established = false;
        {
            PeerHandle peerHandle = peers_.GetPeer(packet->address);
            if (!peerHandle.Failed())
            {
                Peer* peer = peerHandle.Write();
                if (!peer)
                {
                    status = common::Error::InvalidState;
                    return PacketSlotHandle::Invalid();
                }
                if (!peer->IsValid())
                {
                    // Handshake in flight: park behind it. The flag travels with
                    // the packet so the flush restores the right pool.
                    status = pending::Push(pendingPool_, peerHandle, *packet,
                                           requireAuth, keepsBodyForResend);
                    return PacketSlotHandle::Invalid();
                }
                if (requireAuth && !peer->authenticated)
                {
                    status = common::Error::NotAuthenticated;
                    return PacketSlotHandle::Invalid();
                }
                if (!packet->IsSecure())
                    return pHandle;   // established, unsecured: flies plain

                const uint16_t minSize = packet->IsTagged()
                    ? internal::MIN_SECURE_WIRE_SIZE + internal::WIRE_PEER_TAG_SIZE
                    : internal::MIN_SECURE_WIRE_SIZE;
                if (packet->dataSize < minSize)
                {
                    status = common::Error::InvalidHeader;
                    return PacketSlotHandle::Invalid();
                }

                if (hasFlow)
                {
                    PacketSlot* writable = pHandle.Write();
                    if (!writable)
                    {
                        status = common::Error::InvalidState;
                        return PacketSlotHandle::Invalid();
                    }
                    if (keepsBodyForResend)
                    {
                        common::Result<PacketSlotWriter> out = kernel_->Write();
                        if (out.isErr())
                        {
                            status = out.error;
                            return PacketSlotHandle::Invalid();
                        }
                        wireHandle = std::move(out.Take()).ExtractHandle();
                        wirePacket = wireHandle.Write();
                        if (!wirePacket)
                        {
                            status = common::Error::InvalidState;
                            return PacketSlotHandle::Invalid();
                        }
                    }
                    // The plaintext's own slot: staging for a keepsBodyForResend body,
                    // kernel send otherwise, the slot a refused packet waits
                    // in. The gate runs before the materials are gathered, so a
                    // packet that never flies never burns a nonce counter.
                    const SendAdmission admission = AdmitFlowPacket(
                        *peer, peerHandle.GetSlotIndex(), *writable,
                        pHandle.GetSlotIndex(), writable->dataSize);
                    switch (admission)
                    {
                    case SendAdmission::Sent:
                        break;   // stamped and in flight: seal below
                    case SendAdmission::Queued:
                        // The waiting ring owns the slot now; the send is
                        // accepted, like a packet parked behind a handshake.
                        // A pre-acquired wire slot releases with wireHandle.
                        (void)pHandle.Detach();
                        return PacketSlotHandle::Invalid();
                    case SendAdmission::Dropped:
                        // Unreliable with no buffer: discarded by contract,
                        // not an error. pHandle releases the slot.
                        return PacketSlotHandle::Invalid();
                    case SendAdmission::Rejected:
                        status = common::Error::TooManyPending;
                        return PacketSlotHandle::Invalid();
                    case SendAdmission::Dead:
                        status = common::Error::InvalidState;
                        return PacketSlotHandle::Invalid();
                    }
                }
                materials = GatherSendMaterials(*peer);
                established = true;
            }
        }

        if (established)
        {
            // Peer (and flow) lock released with the scope: the seal runs with
            // no peer or flow lock held.
            PacketSlot* writable = pHandle.Write();
            if (!writable)
            {
                common::crypto::Wipe(materials.key.data(), materials.key.size());
                status = common::Error::InvalidState;
                return PacketSlotHandle::Invalid();
            }

            const bool tagged = writable->IsTagged();
            const size_t headerSize = tagged
                ? internal::MIN_SECURE_WIRE_SIZE + internal::WIRE_PEER_TAG_SIZE
                : internal::MIN_SECURE_WIRE_SIZE;
            const size_t bodyLen = writable->dataSize - headerSize;

            // A reliable body is its own retransmit source: the ciphertext goes
            // to the wire slot and the plaintext slot stays leased, held by the
            // ring until the seq resolves. Everything else seals in place.
            if (keepsBodyForResend)
            {
                wirePacket->address  = writable->address;
                wirePacket->dataSize = writable->dataSize;
                std::memcpy(wirePacket->data, writable->data, headerSize);
                SealSecurePacket(*wirePacket, writable->data + headerSize, headerSize,
                                 bodyLen, materials, tagged);
                common::crypto::Wipe(materials.key.data(), materials.key.size());
                (void)pHandle.Detach();   // the ring owns the staging slot now
                return wireHandle;
            }

            SealSecurePacket(*writable, writable->data + headerSize, headerSize,
                             bodyLen, materials, tagged);
            common::crypto::Wipe(materials.key.data(), materials.key.size());
            return pHandle;
        }

        // Unknown peer. Initiating the handshake is what Connect does; the only
        // extra here is a packet to park behind it.
        const Address address = packet->address;
        const common::Error initiated = Connect(address);
        if (initiated != common::Error::Ok)
        {
            status = initiated;
            return PacketSlotHandle::Invalid();
        }
        {
            PeerHandle peerHandle = peers_.GetPeer(address);
            if (peerHandle.Failed())
            {
                status = common::Error::PeerNotFound;
                return PacketSlotHandle::Invalid();
            }
            status = pending::Push(pendingPool_, peerHandle, *packet,
                                   requireAuth, keepsBodyForResend);
        }
        return PacketSlotHandle::Invalid();
    }

    void Socket::SealStagingToWire(const Address& to, const PacketSlot& staging,
                                    const PeerSendMaterials& materials)
    {
        const bool tagged = staging.IsTagged();
        const size_t headerSize = tagged
            ? internal::MIN_SECURE_WIRE_SIZE + internal::WIRE_PEER_TAG_SIZE
            : internal::MIN_SECURE_WIRE_SIZE;
        if (staging.dataSize < headerSize
            || staging.dataSize > internal::MAX_WIRE_PACKET_SIZE)
            return;

        common::Result<PacketSlotWriter> out = kernel_->Write();
        if (out.isErr()) return;
        PacketSlotHandle wireHandle = std::move(out.Take()).ExtractHandle();
        PacketSlot* wire = wireHandle.Write();
        if (!wire) return;

        // Fresh nonce, current tag, current address `to`; the body's seq is
        // whatever the caller left there. The caller's lock on the staging
        // slot keeps the bytes stable across the copy and seal.
        wire->address  = to;
        wire->dataSize = staging.dataSize;
        std::memcpy(wire->data, staging.data, headerSize);
        const size_t bodyLen = staging.dataSize - headerSize;
        SealSecurePacket(*wire, staging.data + headerSize, headerSize, bodyLen,
                         materials, tagged);

        (void)kernel_->SendTo(wire->address.addr, wire->data, wire->dataSize);
    }

    void Socket::ResendStaging(const Address& to, uint32_t flowSlot, uint32_t stagingSlot,
                                uint32_t expectedSeq, const PeerSendMaterials& materials)
    {
        // The staging slot travels as a bare index; touchable only through a
        // handle. The ring owns the lease, so the handle is DETACHED at every
        // exit. Handle read-lock first, THEN flow (staging->peer->flow order).
        PacketSlotHandle stagingHandle{stagingSlot, &stagingPool_};
        const PacketSlot* staging = stagingHandle.Read();
        if (!staging) return;

        // Validate the ring still owns this slot at this seq: a concurrent ack
        // may have resolved it (and recycled the slot) since the caller scanned.
        bool valid = false;
        {
            const OutAssociation* flow = reinterpret_cast<const OutAssociation*>(
                outAssocPool_.ReadLock(flowSlot));
            if (flow->life == FlowLifecycle::OPEN)
            {
                const InFlightEntry& entry =
                    flow->InFlight()[expectedSeq & (flow->inflightCap - 1)];
                valid = entry.seq == expectedSeq && entry.packetSlot == stagingSlot;
            }
            outAssocPool_.UnlockRead(flowSlot);
        }

        if (valid)
            SealStagingToWire(to, *staging, materials);
        (void)stagingHandle.Detach();   // the ring keeps the lease
    }

    void Socket::SendSecureControl(const Address& to, const PeerSendMaterials& materials,
                                    uint8_t channel, const uint8_t* payload, size_t payloadLen)
    {
        common::Result<PacketSlotWriter> result = kernel_->Write();
        if (result.isErr()) return;
        PacketSlotWriter writer = result.Take();

        // Byte-for-byte the wire shape of application data: only the encrypted
        // channel byte differs, which no observer can read. Always tagged.
        writer.WriteAddress(to);
        writer.PutU8(ToByte(Controls::CTRL_TAGGED));
        if (!writer.ReserveSecureHeader(true)) return;
        writer.PutU8(channel);
        if (!writer.PutBytes(payload, payloadLen)) return;

        PacketSlotHandle handle = std::move(writer).ExtractHandle();
        PacketSlot* packet = handle.Write();
        if (!packet) return;

        constexpr size_t headerSize = internal::MIN_SECURE_WIRE_SIZE
                                    + internal::WIRE_PEER_TAG_SIZE;
        const size_t bodyLen = packet->dataSize - headerSize;
        SealSecurePacket(*packet, packet->data + headerSize, headerSize, bodyLen,
                         materials, true);

        // Straight to the wire, already sealed. Routing it back through
        // PreProcessOut would treat this camouflaged packet as fresh app data.
        (void)kernel_->SendTo(packet->address.addr, packet->data, packet->dataSize);
    }

// --- Receive path ---

    uint32_t Socket::Poll(PacketSlotHandle* outPackets, size_t max)
    {
        // Per-Poll-pass migration budget on this thread's stack. Under the
        // fully-concurrent contract several threads may Poll at once, so the
        // budget must not be a shared member; the immutable per-socket ceiling
        // seeds a fresh local each pass.
        if (!initialized_.load(std::memory_order_relaxed))
            return 0;

        uint32_t migrateBudget = migrateBudgetPerPoll_;

        // Pass 1: pull from the kernel and decrypt in place, consume handshake
        // and secure-control traffic, and push every committed app packet onto
        // the ready queue. Nothing is written to the caller's array here; each
        // input slot is consumed (queued, held, or dropped), so pass 2 can reuse
        // the whole array with no aliasing.
        uint32_t count = listener_.Poll(outPackets, max);
        for (size_t scan = 0; scan < count; ++scan)
        {
            const PacketSlot* packet = outPackets[scan].Read();
            if (!packet) continue;   // failed handle, drop

            if (packet->IsInternal())
            {
                // Handshake traffic is never encrypted; an internal packet
                // claiming to be secure is forged or corrupt. Secure control
                // hides in the encrypted channel byte, not this bit.
                if (packet->IsSecure()) continue;
                ProcessInternal(std::move(outPackets[scan]));
                continue;
            }

            // Authenticate and decrypt in place; drop on any failure.
            if (!PreProcessIn(outPackets[scan], migrateBudget))
                continue;

            // The plaintext now reveals data vs. control; control is consumed
            // here, never delivered.
            if (packet->SecureChannel() != internal::SECURE_CHANNEL_APP)
            {
                ProcessSecureControl(std::move(outPackets[scan]));
                continue;
            }

            // Flow packets go through dedupe/order/hold-back; non-flow app
            // packets are the unreliable baseline: queue on arrival. A full
            // queue leaves the packet uncommitted (unacked) and it drops.
            if (packet->HasFlow())
                (void)ProcessFlowIn(std::move(outPackets[scan]));
            else
                (void)QueueReady(outPackets[scan]);
        }

        // Pass 2: drain the ready queue into the caller's array, up to max. A
        // packet's slot stayed leased in the recv pool while queued; rebuild a
        // handle over it. Leftovers stay queued for the next Poll. Delivered
        // handles are stamped with this socket, which is what lets
        // PrepareResponse build a reply from the packet alone.
        size_t delivered = 0;
        uint32_t idx = 0;
        while (delivered < max && readyQueue_.Pop(idx))
        {
            outPackets[delivered] = PacketSlotHandle{ idx, recvPool_ };
            outPackets[delivered].BindSocket(this);
            ++delivered;
        }

        return static_cast<uint32_t>(delivered);
    }

    bool Socket::PreProcessIn(PacketSlotHandle& pHandle, uint32_t& migrateBudget)
    {
        const PacketSlot* packet = pHandle.Read();
        if (!packet) return false;

        // Unsecured traffic carries no integrity, and by default it is a channel
        // between peers that have handshaked at least once: an unknown source is
        // silently dropped. The source stays forgeable (no tag, no AEAD); the
        // gate is hygiene, not authentication. acceptUnsecureFromUnknown restores
        // raw delivery from anyone.
        if (!packet->IsSecure())
        {
            if (acceptUnsecureFromUnknown_)
                return true;
            PeerHandle peerHandle = peers_.GetPeer(packet->address);
            if (peerHandle.Failed()) return false;
            const Peer* peer = peerHandle.Read();
            if (!peer) return false;

            // Refresh the liveness stamp on the grain: the read in hand answers
            // "stale?", and only a stale stamp pays the write (the upgrade drops
            // the read lock first, so the peer is checked again on the far side).
            const uint32_t nowStamp = SeenStamp(common::MonotonicMicros());
            if (static_cast<uint32_t>(nowStamp - peer->lastSeenAt) >= seenGrainStamp_)
            {
                Peer* stamped = peerHandle.Write();
                if (stamped) stamped->lastSeenAt = nowStamp;
            }
            return true;
        }

        const bool tagged = packet->IsTagged();
        const size_t headerSize = tagged
            ? internal::MIN_SECURE_WIRE_SIZE + internal::WIRE_PEER_TAG_SIZE
            : internal::MIN_SECURE_WIRE_SIZE;
        if (packet->dataSize < headerSize)
            return false;

        common::crypto::SessionKey key;
        common::crypto::SessionKey headerKey;
        uint8_t senderLane = 0;
        {
            PeerHandle peerHandle = peers_.GetPeer(packet->address);
            if (peerHandle.Failed())
            {
                // Unknown address carrying a tag: possibly a peer that moved.
                if (migration_ && tagged)
                    return TryMigrate(pHandle, migrateBudget);
                return false;
            }
            const Peer* peer = peerHandle.Read();
            if (!peer || !peer->IsValid()) return false;
            key = peer->session;
            headerKey = peer->headerKey;
            senderLane = LaneFrom(peer->theirPk);
        }

        PacketSlot* writablePacket = pHandle.Write();
        if (!writablePacket)
        {
            common::crypto::Wipe(key.data(), key.size());
            common::crypto::Wipe(headerKey.data(), headerKey.size());
            return false;
        }

        // The counter is masked on the wire, so the open is what recovers it;
        // it then feeds the replay check below.
        uint64_t counter = 0;
        const bool decrypted = OpenSecurePacket(*writablePacket, key, headerKey,
                                                senderLane, counter);
        common::crypto::Wipe(key.data(), key.size());
        common::crypto::Wipe(headerKey.data(), headerKey.size());
        if (!decrypted)
            return false;

        // Replay check, only now that the packet has proven genuine: a forgery
        // never reaches here, so it can never advance the window. The bump is a
        // write under the peer's slot lock, so the liveness stamp rides here for
        // free: an authenticated, replay-accepted packet is the strongest "the
        // peer is alive" evidence there is. The grain still gates the store to
        // keep the peer's cache line quiet at high packet rates.
        {
            PeerHandle peerHandle = peers_.GetPeer(writablePacket->address);
            if (peerHandle.Failed()) return false;
            Peer* peer = peerHandle.Write();
            if (!peer || !peer->IsValid()) return false;
            if (!ReplayFor(peerHandle.GetSlotIndex()).Accept(counter))
                return false;   // duplicate or too old, drop

            const uint32_t nowStamp = SeenStamp(common::MonotonicMicros());
            if (static_cast<uint32_t>(nowStamp - peer->lastSeenAt) >= seenGrainStamp_)
                peer->lastSeenAt = nowStamp;
        }
        return true;
    }

    void Socket::ProcessInternal(PacketSlotHandle pHandle)
    {
        const PacketSlot* packet = pHandle.Read();
        if (!packet) return;
        const Address from = packet->address;

        PacketSlotReader reader{std::move(pHandle)};
        uint8_t opcode;
        if (!reader.TakeU8(opcode)) return;

        switch (static_cast<SocketOpCode>(opcode))
        {
            case SocketOpCode::HS_INIT:   Handshake_Challenge(from);        break;
            case SocketOpCode::HS_CHLG:   Handshake_Respond(from, reader);  break;
            case SocketOpCode::HS_RES:    Handshake_Validate(from, reader); break;
            case SocketOpCode::HS_FINISH: Handshake_Complete(from, reader); break;
            default: break;   // unknown opcode from the network: drop
        }
    }

    void Socket::ProcessSecureControl(PacketSlotHandle pHandle)
    {
        const PacketSlot* packet = pHandle.Read();
        if (!packet) return;
        const Address from    = packet->address;
        const uint8_t channel = packet->SecureChannel();

        // Content starts past the channel byte (ContentOffset covers it).
        const size_t offset = packet->ContentOffset();
        if (offset > packet->dataSize) return;
        const uint8_t* payload = packet->Content(offset);
        const size_t   len     = packet->dataSize - offset;

        // Copy out before releasing: the handlers walk back into the table, and
        // a FLOW_ACK body can fill most of a packet, so the scratch is sized to
        // the wire maximum rather than the small control payloads.
        uint8_t buf[internal::MAX_WIRE_PACKET_SIZE];
        const size_t plen = len < sizeof(buf) ? len : sizeof(buf);
        if (payload) std::memcpy(buf, payload, plen);
        pHandle = PacketSlotHandle::Invalid();

        switch (channel)
        {
            case internal::SECURE_CHANNEL_PATH_CHLG:      PathChallenge_Respond(from, buf, plen);  break;
            case internal::SECURE_CHANNEL_PATH_RESP:      PathChallenge_Complete(from, buf, plen); break;
            case internal::SECURE_CHANNEL_FLOW_REJECT:    Flow_Reject(from, buf, plen);    break;
            case internal::SECURE_CHANNEL_FLOW_ACK:       Flow_Ack(from, buf, plen);       break;
            default: break;   // unknown channel: authenticated but unhandled, drop
        }
    }

    bool Socket::QueueReady(PacketSlotHandle& handle)
    {
        const uint32_t idx = handle.GetSlotIndex();
        if (idx == common::collections::SlotPool::INVALID) return false;
        if (!readyQueue_.Push(idx)) return false;   // full: backpressure, caller drops
        (void)handle.Detach();                      // queued; must not release the slot
        return true;
    }

    uint32_t Socket::ProcessFlowIn(PacketSlotHandle incoming)
    {
        if (!inAssocDir_) return 0;
        const PacketSlot* packet = incoming.Read();
        if (!packet) return 0;

        const uint16_t flowId   = packet->FlowId();
        const uint32_t seq      = packet->FlowSeq();
        const uint8_t  flowData = packet->FlowData();
        const Address  from     = packet->address;
        if (flowId == internal::INVALID_FLOW_ID || seq == 0) return 0;

        // First packet of a flow registers it: the flow data byte carries
        // everything registration needs.
        uint32_t flowSlot = common::collections::SlotPool::INVALID;
        bool     reject   = false;
        PeerSendMaterials rejectMaterials;
        {
            PeerHandle peerHandle = peers_.GetPeer(from);
            if (peerHandle.Failed()) return 0;

            // Write, not read: registration mutates the peer's directory, and
            // the lock has to cover the lookup that decided it was absent.
            Peer* peer = peerHandle.Write();
            if (!peer || !peer->IsValid()) return 0;

            const uint32_t peerSlot = peerHandle.GetSlotIndex();
            switch (AdmitInFlow(peerSlot, from, peer->id, flowId, flowData))
            {
            case FlowAdmit::Rejected:
                // Caps, or a window this socket cannot dedupe. Tell the sender
                // so it stops rather than retransmitting into silence.
                rejectMaterials = GatherSendMaterials(*peer);
                reject = true;
                break;
            case FlowAdmit::Registered:
            case FlowAdmit::Existing:
                flowSlot = FindFlowSlot(InAssocDirFor(peerSlot), maxInAssocPerPeer_, flowId);
                break;
            }
        }

        if (reject)
        {
            const uint8_t payload[2] = { static_cast<uint8_t>(flowId),
                                         static_cast<uint8_t>(flowId >> 8) };
            SendSecureControl(from, rejectMaterials, internal::SECURE_CHANNEL_FLOW_REJECT,
                              payload, sizeof(payload));
            common::crypto::Wipe(rejectMaterials.key.data(), rejectMaterials.key.size());
            return 0;
        }

        if (flowSlot == common::collections::SlotPool::INVALID) return 0;

        InAssociation* flow = reinterpret_cast<InAssociation*>(inAssocPool_.WriteLock(flowSlot));
        uint32_t produced = 0;
        if (flow->life == FlowLifecycle::OPEN && flow->flowId == flowId)
        {
            produced = flow->mode == FlowMode::RELIABLE_ORDERED
                ? DeliverOrdered(*flow, incoming, seq)
                : DeliverUnordered(*flow, incoming, seq);
        }
        inAssocPool_.UnlockWrite(flowSlot);
        return produced;
    }

    uint32_t Socket::DeliverUnordered(InAssociation& flow, PacketSlotHandle& incoming, uint32_t seq)
    {
        // Unordered and unreliable: deliver on arrival, no hold-back, so no recv
        // slot is ever pinned and nothing can flood. The seen bitmap dedupes
        // retransmits (a fresh nonce clears the replay window, so only this
        // catches them). A duplicate re-arms acking: the sender's FLOW_ACK may
        // have been lost, and only a fresh ack stops the resend.
        if (AlreadySeen(&flow, seq))
        {
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

    uint32_t Socket::DeliverOrdered(InAssociation& flow, PacketSlotHandle& incoming, uint32_t seq)
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

    uint32_t Socket::DrainHoldbackRun(InAssociation& flow)
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
            if (!readyQueue_.Push(held.packetSlot))
                break;   // queue full: leave the tail held
            held.packetSlot = common::collections::SlotPool::INVALID;
            held.seq = 0;
            ++produced;
            flow.recvNext += 1;
            if (flow.recvNext == 0) flow.recvNext = 1;
        }
        return produced;
    }

    bool Socket::TryMigrate(PacketSlotHandle& pHandle, uint32_t& migrateBudget)
    {
        // Attacker-reachable path: a spoofed flood of tagged packets buys table
        // lookups and trial decrypts. The per-Poll budget caps that spend; a
        // genuine mover past the cap just retries next packet.
        if (migrateBudget == 0)
            return false;
        --migrateBudget;

        const PacketSlot* packet = pHandle.Read();
        if (!packet) return false;

        const uint8_t* tagField = packet->PeerTagField();
        if (!tagField) return false;

        PeerTag wireTag;
        std::memcpy(wireTag.data(), tagField, wireTag.size());
        const Address from = packet->address;
        // Masked on the wire; the successful trial open below reports it.
        uint64_t counter = 0;

        bool    deliverToUser = false;
        bool    challenge     = false;
        bool    completePath  = false;
        uint8_t challengeBytes[sizeof(Peer{}.pathChallenge)];
        uint8_t respBuf[64];
        size_t  respLen = 0;
        PeerSendMaterials sendMaterials{};
        {
            PeerHandle candidates[4];
            uint32_t count = peers_.GetPeersByTag(wireTag, candidates, 4);
            if (count == 0) return false;
            if (count > 4) count = 4;

            PacketSlot* writablePacket = pHandle.Write();
            if (!writablePacket) return false;

            constexpr size_t headerSize = internal::MIN_SECURE_WIRE_SIZE
                                        + internal::WIRE_PEER_TAG_SIZE;
            if (writablePacket->dataSize < headerSize) return false;

            // Try the open against each candidate: on a tag clash only the
            // genuine mover's key authenticates, and a failed attempt leaves the
            // ciphertext untouched (the AEAD verifies before it writes). A
            // success identifies the peer, so probing stops. The candidates'
            // read locks are held across the attempts; the move event is rare,
            // so the brief hold costs nothing that matters.
            bool matched = false;
            for (uint32_t i = 0; i < count && !matched; ++i)
            {
                const Peer* candidate = candidates[i].Read();
                if (!candidate || !candidate->IsValid()) continue;

                const uint8_t theirLane = LaneFrom(candidate->theirPk);
                common::crypto::SessionKey key       = candidate->session;
                common::crypto::SessionKey headerKey = candidate->headerKey;

                if (!OpenSecurePacket(*writablePacket, key, headerKey, theirLane, counter))
                {
                    common::crypto::Wipe(key.data(), key.size());
                    common::crypto::Wipe(headerKey.data(), headerKey.size());
                    continue;
                }
                common::crypto::Wipe(headerKey.data(), headerKey.size());
                matched = true;

                const uint8_t* body    = writablePacket->data + headerSize;
                const size_t   bodyLen = writablePacket->dataSize - headerSize;

                // The in-band channel decides what this packet is. Replay-check
                // and act under the slot's write lock: a duplicate or stale
                // counter drops it and triggers nothing.
                const uint8_t channel = (bodyLen >= 1) ? body[0] : internal::SECURE_CHANNEL_APP;
                Peer* peer = candidates[i].Write();
                if (peer && peer->IsValid() &&
                    ReplayFor(candidates[i].GetSlotIndex()).Accept(counter))
                {
                    if (channel == internal::SECURE_CHANNEL_PATH_RESP)
                    {
                        // The validation reply, arriving from the not-yet-known
                        // new address. Capture it; PathChallenge_Complete runs
                        // once the handles are released.
                        respLen = (bodyLen - 1 < sizeof(respBuf)) ? bodyLen - 1 : sizeof(respBuf);
                        std::memcpy(respBuf, body + 1, respLen);
                        completePath = true;
                    }
                    else
                    {
                        // ANY other authenticated channel (app data OR a control
                        // op) proves the peer is genuinely at this new address:
                        // the AEAD, not the channel, is the identity proof. So
                        // every one arms the path challenge (the rebind), which
                        // lets a pure flow RECEIVER drive its own migration. The
                        // control content itself is dropped here (its handler is
                        // address-keyed and this address is not yet bound), which
                        // is harmless. Only APP is also delivered (below).

                        // Which window step did the mover present? Needed to
                        // slide the window once the new address validates.
                        uint32_t presented = peer->theirTagStep;
                        for (uint32_t step = 0; step < 3; ++step)
                        {
                            if (DerivePeerTag(peer->session, theirLane,
                                              peer->theirTagStep + step) == wireTag)
                            {
                                presented = peer->theirTagStep + step;
                                break;
                            }
                        }

                        // One validation in flight per peer. A packet from the
                        // same claimed address re-sends the same challenge; a
                        // different one starts fresh: the peer moved again.
                        // Validation either completes or keeps retrying; it never
                        // tears the proven session down, so replayed captures
                        // from a spoofed address achieve nothing but unanswered
                        // challenges.
                        if (!(peer->pathAddr == from))
                        {
                            if (common::crypto::RandomBytes(peer->pathChallenge,
                                                            sizeof(peer->pathChallenge)))
                            {
                                peer->pathAddr = from;
                                peer->pathStep = presented;
                            }
                        }
                        if (peer->pathAddr == from)
                        {
                            std::memcpy(challengeBytes, peer->pathChallenge,
                                        sizeof(challengeBytes));
                            sendMaterials = GatherSendMaterials(*peer);
                            challenge     = true;
                        }
                        // Deliver only app data; a control op is consumed by the
                        // migration, never handed to the user.
                        if (channel == internal::SECURE_CHANNEL_APP)
                            deliverToUser = true;
                    }
                }
                common::crypto::Wipe(key.data(), key.size());
            }
        }

        // Handles released: the identity is proven by the decrypt, so the packet
        // is delivered now; only this side's outgoing route waits for the
        // address to answer the challenge.
        if (challenge)
        {
            SendSecureControl(from, sendMaterials, internal::SECURE_CHANNEL_PATH_CHLG,
                              challengeBytes, sizeof(challengeBytes));
            common::crypto::Wipe(sendMaterials.key.data(), sendMaterials.key.size());
        }

        // A validation reply that came in over the migration path: complete it
        // now that the candidate handles are released (the table ops below take
        // their own locks).
        if (completePath)
            PathChallenge_Complete(from, respBuf, respLen);
        return deliverToUser;
    }

    void Socket::PathChallenge_Respond(const Address& from, const uint8_t* payload, size_t len)
    {
        uint8_t challenge[sizeof(Peer{}.pathChallenge)];
        if (len < sizeof(challenge)) return;
        std::memcpy(challenge, payload, sizeof(challenge));

        // The challenge already authenticated (it rode the secure path), so
        // `from` is a peer this side holds a session with. Echo the bytes back
        // under that session; the reply leaves from this side's current source
        // address, the one the challenger is probing.
        PeerSendMaterials materials;
        {
            PeerHandle peerHandle = peers_.GetPeer(from);
            if (peerHandle.Failed()) return;
            Peer* peer = peerHandle.Write();
            if (!peer || !peer->IsValid()) return;
            materials = GatherSendMaterials(*peer);
        }

        uint8_t reply[internal::WIRE_PEER_TAG_SIZE + sizeof(challenge)];
        std::memcpy(reply, materials.tag.data(), materials.tag.size());
        std::memcpy(reply + materials.tag.size(), challenge, sizeof(challenge));

        SendSecureControl(from, materials, internal::SECURE_CHANNEL_PATH_RESP,
                          reply, sizeof(reply));
        common::crypto::Wipe(materials.key.data(), materials.key.size());
    }

    void Socket::PathChallenge_Complete(const Address& from, const uint8_t* payload, size_t len)
    {
        PeerTag tag;
        uint8_t echo[sizeof(Peer{}.pathChallenge)];
        if (len < tag.size() + sizeof(echo)) return;
        std::memcpy(tag.data(), payload, tag.size());
        std::memcpy(echo, payload + tag.size(), sizeof(echo));

        bool     rebind    = false;
        uint32_t slot      = 0;
        uint32_t oldBase   = 0;
        uint32_t newBase   = 0;
        uint8_t  theirLane = 0;
        common::crypto::SessionKey session;
        {
            PeerHandle candidates[4];
            uint32_t count = peers_.GetPeersByTag(tag, candidates, 4);
            if (count > 4) count = 4;

            for (uint32_t i = 0; i < count && !rebind; ++i)
            {
                const Peer* candidate = candidates[i].Read();
                if (!candidate || !candidate->IsValid()) continue;
                if (!(candidate->pathAddr == from)) continue;   // never pended, or wrong addr

                // The response's authenticity came from its AEAD; the echo binds
                // it to this validation round.
                if (!common::crypto::Equal(candidate->pathChallenge, echo, sizeof(echo)))
                    continue;

                // Claim the validation under the write lock so a concurrent
                // worker completing the same response cannot double-slide.
                Peer* peer = candidates[i].Write();
                if (!peer || !peer->IsValid() || !(peer->pathAddr == from))
                    break;
                peer->pathAddr = Address{};

                slot      = candidates[i].GetSlotIndex();
                oldBase   = peer->theirTagStep;
                newBase   = peer->pathStep;
                theirLane = LaneFrom(peer->theirPk);
                session   = peer->session;
                peer->theirTagStep = newBase;
                rebind = true;
            }
        }

        // Handles released: the table ops below take the writer lock and the
        // slot's own locks, which a held handle would deadlock against.
        if (rebind)
        {
            // A refused rebind (the address raced into use by another peer)
            // leaves the old route; the mover's next packet simply starts a
            // fresh validation round.
            (void)peers_.UpdateAddress(slot, from);
            SlideTagWindow(slot, session, theirLane, oldBase, newBase);
            common::crypto::Wipe(session.data(), session.size());
        }
    }

    PeerTag Socket::DerivePeerTag(const common::crypto::SessionKey& session,
                                   uint8_t lane, uint32_t step) noexcept
    {
        // Fixed-layout message: domain label, the direction, the step, and a
        // re-derivation counter that advances only when the fold lands on the
        // reserved all-zero tag. Every field is explicit bytes: the message must
        // be identical on both ends regardless of host byte order.
        uint8_t msg[8 + 1 + 4 + 1] = { 'B','C','P','-','P','T','A','G' };
        msg[8]  = lane;
        msg[9]  = static_cast<uint8_t>(step >> 0);
        msg[10] = static_cast<uint8_t>(step >> 8);
        msg[11] = static_cast<uint8_t>(step >> 16);
        msg[12] = static_cast<uint8_t>(step >> 24);

        PeerTag tag{};
        for (uint8_t attempt = 0; ; ++attempt)
        {
            msg[13] = attempt;
            common::crypto::Mac mac;
            common::crypto::ComputeMac(mac, session, msg, sizeof(msg));
            std::memcpy(tag.data(), mac.data(), tag.size());
            if (tag != PeerTag{} || attempt == UINT8_MAX)
                return tag;
        }
    }

    void Socket::BindTagWindow(uint32_t slot, const common::crypto::SessionKey& session,
                                uint8_t theirLane, uint32_t baseStep) noexcept
    {
        for (uint32_t i = 0; i < 3; ++i)
        {
            // A failed bind narrows the window instead of failing the session; a
            // move outside what remains falls back to a re-handshake.
            (void)peers_.BindTag(slot, DerivePeerTag(session, theirLane, baseStep + i));
        }
    }

    void Socket::SlideTagWindow(uint32_t slot, const common::crypto::SessionKey& session,
                                 uint8_t theirLane, uint32_t oldBase, uint32_t newBase) noexcept
    {
        if (newBase <= oldBase)
            return;   // same-tag move (NAT rebind): the window already covers it

        for (uint32_t s = oldBase; s < newBase; ++s)
            (void)peers_.UnbindTag(slot, DerivePeerTag(session, theirLane, s));
        for (uint32_t s = oldBase + 3; s <= newBase + 2; ++s)
            (void)peers_.BindTag(slot, DerivePeerTag(session, theirLane, s));
    }

    // --- Handshake ---

    void Socket::SendHandshakeInit(const Address& addr)
    {
        common::Result<PacketSlotWriter> result = BuildInternal(SocketOpCode::HS_INIT);
        if (result.isErr()) return;
        PacketSlotWriter writer = result.Take();

        writer.WriteAddress(addr);

        sender_.Send(std::move(writer).ExtractHandle());
    }

    void Socket::Handshake_Challenge(const Address& from)
    {
        // Stateless on purpose: the challenge is a SipHash cookie the generator
        // can recompute, so an HS_INIT flood costs no memory here.
        common::Result<PacketSlotWriter> result = BuildInternal(SocketOpCode::HS_CHLG);
        if (result.isErr()) return;
        PacketSlotWriter writer = result.Take();

        writer.WriteAddress(from);
        writer.PutU64(challengeGenerator_.Generate(from.addr));

        sender_.Send(std::move(writer).ExtractHandle());
    }

    void Socket::Handshake_Respond(const Address& from, PacketSlotReader& reader)
    {
        uint64_t challenge = 0;
        if (!reader.TakeU64(challenge)) return;

        // This side's KDF salt contribution, remembered until the responder's
        // arrives with HS_FINISH.
        uint8_t saltI[internal::WIRE_HS_SALT_SIZE];
        if (!common::crypto::RandomBytes(saltI, sizeof(saltI))) return;

        common::Result<PacketSlotWriter> result = BuildInternal(SocketOpCode::HS_RES);
        if (result.isErr()) return;
        PacketSlotWriter writer = result.Take();

        {
            PeerHandle peerHandle = peers_.GetPeer(from);
            if (peerHandle.Failed()) return;   // challenge we never asked for
            Peer* peer = peerHandle.Write();
            if (!peer) return;
            if (peer->state != HandshakeState::AWAITING_CHALLENGE) return;
            peer->state = HandshakeState::AWAITING_FINISH;
            std::memcpy(peer->hsSalt, saltI, sizeof(saltI));
        }

        uint32_t initiatorCaps;
        BuildCapsBitmap(initiatorCaps);

        writer.WriteAddress(from);
        writer.PutU64(challenge);
        writer.PutBytes(publicKey_.data(), publicKey_.size());
        writer.PutBytes(saltI, sizeof(saltI));
        writer.PutU16(internal::VERSION);
        writer.PutU32(initiatorCaps);

        sender_.Send(std::move(writer).ExtractHandle());
    }

    void Socket::Handshake_Validate(const Address& from, PacketSlotReader& reader)
    {
        uint64_t challenge = 0;
        common::crypto::PublicKey pk;
        uint8_t saltI[internal::WIRE_HS_SALT_SIZE];
        uint16_t initiatorVersion{0};
        uint32_t initiatorCaps{0};
        if (!reader.TakeU64(challenge)) return;
        if (!reader.TakeBytes(pk.data(), pk.size())) return;
        if (!reader.TakeBytes(saltI, sizeof(saltI))) return;
        if (!reader.TakeU16(initiatorVersion)) return;
        if (!reader.TakeU32(initiatorCaps)) return;

        // The gate. Until this passes, the sender has cost this socket nothing.
        if (!challengeGenerator_.Verify(from.addr, challenge)) return;

        const BcpId id = BcpId::Derive(pk);

        bool established = false;
        bool needBind    = false;
        uint32_t slot    = 0;
        {
            PeerHandle existingHandle = peers_.GetPeer(from);
            if (existingHandle.Failed())
            {
                if (peers_.RegisterPeer(from, &id, slot) != common::Error::Ok)
                    return;   // table full; the initiator's retry will land later
            }
            else
            {
                const Peer* peer = existingHandle.Read();
                slot = existingHandle.GetSlotIndex();
                if (peer->IsValid())
                {
                    // Duplicate HS_RES, or the remote dropped this peer and is
                    // handshaking anew. The key must belong to the id we hold.
                    if (!(peer->id == id)) return;
                    established = true;
                }
                else
                {
                    // Simultaneous handshake: both sides initiated, and the two
                    // crossed exchanges would derive two different salted keys.
                    // Both sides keep the exchange whose initiator has the lower
                    // public key: this side acts as responder only when the
                    // remote is that initiator; otherwise its HS_RES is dropped
                    // and this side's own exchange finishes via HS_FINISH,
                    // landing both on the same salts.
                    if (std::memcmp(pk.data(), publicKey_.data(), pk.size()) >= 0)
                        return;
                    needBind = !peer->hasId;
                }
            }
        }

        if (needBind && peers_.BindId(slot, id) != common::Error::Ok)
            return;   // raced a removal; drop, the initiator retries

        uint8_t saltR[internal::WIRE_HS_SALT_SIZE];
        uint8_t transcript[internal::HS_TRANSCRIPT_SIZE];
        common::crypto::Mac confirm;

        // Tag-window maintenance happens after the handle scopes below close:
        // BindTag/UnbindTags take table locks, and the table's contract forbids
        // calling them with a handle held.
        bool bindWindow  = false;
        bool dropOldTags = false;
        common::crypto::SessionKey tagSession{};
        uint32_t responderCaps;
        BuildCapsBitmap(responderCaps);

        if (!established)
        {
            if (!common::crypto::RandomBytes(saltR, sizeof(saltR))) return;

            BuildTranscript(transcript, pk, publicKey_, saltI, saltR, initiatorCaps, responderCaps, initiatorVersion, internal::VERSION, ownTag_);

            PeerHandle peerHandle = peers_.GetPeer(from);
            if (peerHandle.Failed()) return;
            Peer* peer = peerHandle.Write();
            CommitSession(*peer, pk, transcript, sizeof(transcript));
            common::crypto::ComputeMac(confirm, peer->session, transcript, sizeof(transcript));
            std::memcpy(peer->hsSalt, saltR, sizeof(saltR));
            ReplayFor(peerHandle.GetSlotIndex()).Reset();   // fresh key -> remote's counter restarts at 0
            tagSession = peer->session;
            bindWindow = migration_;
        }
        else
        {
            // Re-derive from the incoming salt and the stored one. A stale
            // duplicate carries the same salt and reproduces the current key, so
            // nothing changes; a genuine re-handshake carries a fresh salt and
            // re-keys both sides consistently. The counter resets only when the
            // key actually changes; resetting it under an unchanged key would
            // reuse nonces.
            PeerHandle peerHandle = peers_.GetPeer(from);
            if (peerHandle.Failed()) return;
            Peer* peer = peerHandle.Write();
            std::memcpy(saltR, peer->hsSalt, sizeof(saltR));
            BuildTranscript(transcript, pk, publicKey_, saltI, saltR, initiatorCaps, responderCaps, initiatorVersion, internal::VERSION, ownTag_);

            common::crypto::SessionKey candidate;
            DeriveSessionInto(candidate, pk, transcript, sizeof(transcript));
            if (!common::crypto::Equal(candidate.data(), peer->session.data(), candidate.size()))
            {
                peer->session = candidate;
                peer->sendCounter = 0;
                peer->myTagStep    = 0;   // new key -> new tag sequence, both sides
                peer->theirTagStep = 0;
                peer->myTag        = DerivePeerTag(peer->session, LaneTo(pk), 0);
                ReplayFor(peerHandle.GetSlotIndex()).Reset();   // key changed -> remote's counter restarts
                tagSession  = peer->session;
                bindWindow  = migration_;
                dropOldTags = true;    // the old key's window is dead weight
            }
            common::crypto::ComputeMac(confirm, peer->session, transcript, sizeof(transcript));
            common::crypto::Wipe(candidate.data(), candidate.size());
        }

        if (bindWindow)
        {
            if (dropOldTags)
                (void)peers_.UnbindTags(slot);
            BindTagWindow(slot, tagSession, LaneFrom(pk), 0);
        }
        common::crypto::Wipe(tagSession.data(), tagSession.size());

        common::Result<PacketSlotWriter> result = BuildInternal(SocketOpCode::HS_FINISH);
        if (result.isErr()) return;
        PacketSlotWriter writer = result.Take();

        writer.WriteAddress(from);
        writer.PutBytes(publicKey_.data(), publicKey_.size());
        writer.PutBytes(saltR, sizeof(saltR));
        writer.PutBytes(ownTag_.data(), ownTag_.size());
        writer.PutU16(internal::VERSION);
        writer.PutU32(responderCaps);
        writer.PutBytes(confirm.data(), confirm.size());

        sender_.Send(std::move(writer).ExtractHandle());

        // Only a simultaneous handshake has anything parked on this side.
        FlushPending(from);
    }

    void Socket::Handshake_Complete(const Address& from, PacketSlotReader& reader)
    {
        common::crypto::PublicKey pk;
        uint8_t saltR[internal::WIRE_HS_SALT_SIZE];
        Certificate::IdentityTag tag;
        uint16_t responderVersion;
        uint32_t responderCaps;
        common::crypto::Mac confirm;
        if (!reader.TakeBytes(pk.data(), pk.size())) return;
        if (!reader.TakeBytes(saltR, sizeof(saltR))) return;
        if (!reader.TakeBytes(tag.data(), tag.size())) return;
        if (!reader.TakeU16(responderVersion)) return;
        if (!reader.TakeU32(responderCaps)) return;
        if (!reader.TakeBytes(confirm.data(), confirm.size())) return;

        const BcpId id = BcpId::Derive(pk);

        uint8_t saltI[internal::WIRE_HS_SALT_SIZE];
        uint32_t slot = 0;
        {
            PeerHandle peerHandle = peers_.GetPeer(from);
            if (peerHandle.Failed()) return;
            const Peer* peer = peerHandle.Read();
            if (peer->state != HandshakeState::AWAITING_FINISH) return;
            slot = peerHandle.GetSlotIndex();
            std::memcpy(saltI, peer->hsSalt, sizeof(saltI));   // our contribution
        }

        // The trust gate. A trusted tag presented with the wrong key is an
        // impersonation attempt (or a stale certificate): hard failure, the
        // peer never establishes. An unknown tag establishes unauthenticated:
        // plain Send stays opportunistic, SendSecured refuses the peer.
        const CertStore::Match match = certStore_.Check(tag, pk);
        if (match == CertStore::Match::Mismatch)
            return;

        uint32_t initiatorCaps;
        BuildCapsBitmap(initiatorCaps);

        // Prove the responder derived the same key from the same transcript: it
        // holds the private half of the key it presented, and nothing in the
        // exchange was tampered with. Checked before anything establishes.
        uint8_t transcript[internal::HS_TRANSCRIPT_SIZE];
        BuildTranscript(transcript, publicKey_, pk, saltI, saltR, initiatorCaps, responderCaps, internal::VERSION, responderVersion, tag);

        common::crypto::SessionKey session;
        DeriveSessionInto(session, pk, transcript, sizeof(transcript));

        common::crypto::Mac expected;
        common::crypto::ComputeMac(expected, session, transcript, sizeof(transcript));
        if (!common::crypto::Equal(expected.data(), confirm.data(), expected.size()))
        {
            common::crypto::Wipe(session.data(), session.size());
            return;
        }

        if (peers_.BindId(slot, id) != common::Error::Ok)
        {
            common::crypto::Wipe(session.data(), session.size());
            return;
        }

        {
            PeerHandle peerHandle = peers_.GetPeer(from);
            if (peerHandle.Failed())
            {
                common::crypto::Wipe(session.data(), session.size());
                return;
            }
            Peer* peer = peerHandle.Write();
            CommitSession(*peer, pk, transcript, sizeof(transcript));
            std::memcpy(peer->announcedTag, tag.data(), tag.size());
            peer->authenticated = (match == CertStore::Match::Trusted);
            ReplayFor(peerHandle.GetSlotIndex()).Reset();   // fresh session -> remote's counter starts at 0
        }

        // Handle scope closed: bind the responder's tag window so its future
        // moves are recognizable from the first packet off a new address.
        if (migration_)
            BindTagWindow(slot, session, LaneFrom(pk), 0);
        common::crypto::Wipe(session.data(), session.size());

        FlushPending(from);
    }

    void Socket::CommitSession(Peer& peer, const common::crypto::PublicKey& theirPk,
                                const uint8_t* transcript, size_t transcriptLen) noexcept
    {
        // The peer-commit core shared by Validate's establish branch and
        // Complete: bind the remote key, derive the session from the transcript,
        // and reset the per-session send state. Caller holds the peer's write
        // lock (the Peer is lent in) and owns the parts that need more than these
        // args: ReplayFor().Reset (needs the slot), and, in Complete, the
        // announced tag and authentication verdict.
        peer.theirPk = theirPk;
        DeriveSessionInto(peer.session, theirPk, transcript, transcriptLen);
        // Split off the counter-masking key. The label is fixed and public; it
        // only has to differ from every other input the session key is ever
        // fed, so the two derivations cannot collide.
        static constexpr uint8_t HEADER_KEY_LABEL[16] = {
            'f','l','u','x','-','h','d','r','-','m','a','s','k',0,0,0
        };
        common::crypto::DeriveSubKey(peer.headerKey.data(), peer.session.data(),
                                     HEADER_KEY_LABEL);
        peer.sendCounter  = 0;
        peer.myTagStep    = 0;
        peer.theirTagStep = 0;
        peer.myTag        = DerivePeerTag(peer.session, LaneTo(theirPk), 0);
        peer.state        = HandshakeState::ESTABLISHED;
    }

    common::Result<PacketSlotWriter> Socket::BuildInternal(SocketOpCode op)
    {
        // The unsecured-internal preamble the four handshake senders share: a
        // kernel slot, the controller byte, and the opcode. The caller still owns
        // WriteAddress (it differs per sender) and any opcode-specific payload.
        common::Result<PacketSlotWriter> result = kernel_->Write();
        if (result.isErr()) return result;
        PacketSlotWriter writer = result.Take();

        writer.PutU8(ToByte(Controls::CTRL_INTERNAL | Controls::CTRL_UNSECURE));
        writer.PutU8(static_cast<uint8_t>(op));

        return common::Result<PacketSlotWriter>::Success(std::move(writer));
    }

    void Socket::FlushPending(const Address& addr)
    {
        // Detach in batches under the handle, send with it dropped: a send walks
        // back into the peer table, and holding a handle across that is the
        // deadlock the table's contract forbids.
        for (;;)
        {
            uint32_t batch[32];
            uint32_t count = 0;
            bool authenticated = false;
            {
                PeerHandle peerHandle = peers_.GetPeer(addr);
                if (peerHandle.Failed()) return;
                const Peer* peer = peerHandle.Read();
                if (peer) authenticated = peer->authenticated;
                while (count < 32)
                {
                    const uint32_t idx = pending::PopFront(pendingPool_, peerHandle);
                    if (idx == common::collections::SlotPool::INVALID) break;
                    batch[count++] = idx;
                }
            }

            for (uint32_t i = 0; i < count; ++i)
            {
                const auto* pending = reinterpret_cast<const PendingPacket*>(
                    pendingPool_.GetSlotPtr(batch[i]));

                // A SendSecured packet parked behind this handshake only flies if
                // the peer proved a trusted identity; otherwise it dies here,
                // never reaching an unauthenticated peer.
                if (pending->requireAuth && !authenticated)
                {
                    pendingPool_.Release(batch[i]);
                    continue;
                }

                // A keepsBodyForResend body must go back to STAGING: the in-flight ring
                // keeps that slot as its retransmit source and releases it
                // there, so a kernel index would be freed into the wrong pool.
                common::Result<PacketSlotWriter> result = pending->keepsBodyForResend
                    ? AcquireStagingWriter()
                    : kernel_->Write();
                if (result.isOk())
                {
                    PacketSlotWriter writer = result.Take();
                    writer.WriteAddress(pending->address);
                    writer.PutBytes(pending->data, pending->dataSize);
                    sender_.Send(std::move(writer).ExtractHandle(), pending->requireAuth != 0);
                }
                // Pool dry: the packet drops, which is all an unreliable send
                // promises; a reliable flow's retransmit covers the rest.
                pendingPool_.Release(batch[i]);
            }

            if (count < 32) return;
        }
    }

    // --- Flow control-plane (open/close) ---

    FlowDirEntry* Socket::OutAssocDirFor(uint32_t peerSlot) noexcept
    {
        return outAssocDir_.get() + static_cast<size_t>(peerSlot) * maxOutAssocPerPeer_;
    }

    FlowDirEntry* Socket::InAssocDirFor(uint32_t peerSlot) noexcept
    {
        return inAssocDir_.get() + static_cast<size_t>(peerSlot) * maxInAssocPerPeer_;
    }

    /** The directory scan every flow lookup shares.

        @return The entry's flow slot, or INVALID when the id is not published in
        this segment. */
    uint32_t Socket::FindFlowSlot(const FlowDirEntry* dir, uint32_t width,
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
    uint32_t Socket::InsertFlowSlot(FlowDirEntry* dir, uint32_t width,
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
    void Socket::EraseFlowSlot(FlowDirEntry* dir, uint32_t width,
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

    uint32_t Socket::FindFlowById(uint16_t flowId) noexcept
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

    void Socket::LinkAssociation(uint32_t flowSlot, uint32_t assocSlot) noexcept
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

    void Socket::UnlinkAssociation(uint32_t flowSlot, uint32_t assocSlot) noexcept
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

    FlowHandle Socket::OpenFlow(uint16_t flowId, FlowMode mode, uint32_t window)
    {
        if (!initialized_.load(std::memory_order_acquire) || !outAssocDir_)
            return FlowHandle{common::Error::NotInitialized};
        if (flowId == internal::INVALID_FLOW_ID)
            return FlowHandle{common::Error::InvalidParam};
        if (mode != FlowMode::RELIABLE_ORDERED &&
            mode != FlowMode::RELIABLE_UNORDERED &&
            mode != FlowMode::UNRELIABLE)
            return FlowHandle{common::Error::InvalidParam};

        // The window this flow declares on every packet. Zero takes the
        // socket's configured ring capacity; anything the wire byte cannot
        // encode is refused here rather than silently declaring a width the
        // ring does not enforce.
        const uint32_t declared = window != 0 ? window : outInflightCap_;
        const uint8_t  flowData = EncodeFlowData(mode, declared);
        if (flowData == 0 || declared > outInflightCap_)
            return FlowHandle{common::Error::InvalidParam};

        // The id is how a remote names the flow, so two sharing one would be
        // indistinguishable on the wire.
        if (FindFlowById(flowId) != common::collections::SlotPool::INVALID)
            return FlowHandle{common::Error::AlreadyInUse};

        const uint32_t flowSlot = flowPool_.Acquire();
        if (flowSlot == common::collections::SlotPool::INVALID)
            return FlowHandle{common::Error::LimitReached};

        uint32_t epoch = 0;
        {
            Flow* flow = reinterpret_cast<Flow*>(flowPool_.WriteLock(flowSlot));
            flow->epoch      = flow->epoch + 1;   // survives the lease; stale handles miss
            flow->firstAssoc = common::collections::SlotPool::INVALID;
            flow->flowId     = flowId;
            flow->window     = static_cast<uint16_t>(declared);
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

    common::Error Socket::CloseFlow(const FlowHandle& flow)
    {
        if (!initialized_.load(std::memory_order_acquire) || !outAssocDir_)
            return common::Error::NotInitialized;
        if (flow.Failed() || flow.Slot() >= flowPool_.GetCapacity())
            return common::Error::InvalidState;

        const uint32_t flowSlot = flow.Slot();

        // Closed first, so nothing opens a new association under a flow that is
        // going away.
        {
            Flow* state = reinterpret_cast<Flow*>(flowPool_.WriteLock(flowSlot));
            if (state->epoch != flow.Epoch() || state->life != FlowLifecycle::OPEN)
            {
                flowPool_.UnlockWrite(flowSlot);
                return common::Error::InvalidState;   // stale handle, or already closing
            }
            state->life = FlowLifecycle::CLOSING;
            flowPool_.UnlockWrite(flowSlot);
        }

        // The list is the only index from a flow to its targets; the
        // directories only answer the reverse.
        for (;;)
        {
            uint32_t assocSlot = common::collections::SlotPool::INVALID;
            {
                const Flow* state = reinterpret_cast<const Flow*>(
                    flowPool_.ReadLock(flowSlot));
                assocSlot = state->firstAssoc;
                flowPool_.UnlockRead(flowSlot);
            }
            if (assocSlot == common::collections::SlotPool::INVALID)
                break;

            // Read the identity out, then approach the peer with no association
            // lock held: the refund needs the peer's write lock.
            Address peerAddr;
            BcpId   peerId{};
            uint16_t assocFlowId = internal::INVALID_FLOW_ID;
            {
                const OutAssociation* assoc = reinterpret_cast<const OutAssociation*>(
                    outAssocPool_.ReadLock(assocSlot));
                peerAddr    = assoc->peerAddr;
                peerId      = assoc->peerId;
                assocFlowId = assoc->flowId;
                outAssocPool_.UnlockRead(assocSlot);
            }

            const bool byId = !(peerId == BcpId{});
            PeerHandle peerHandle = byId ? peers_.GetPeer(peerId)
                                         : peers_.GetPeer(peerAddr);
            Peer* owner = peerHandle.Failed() ? nullptr : peerHandle.Write();
            if (owner)
                EraseFlowSlot(OutAssocDirFor(peerHandle.GetSlotIndex()),
                              maxOutAssocPerPeer_, assocSlot);

            // The unlink inside FreeOutAssoc is what advances this loop. A null
            // owner means the peer is already gone, so the refund is dropped
            // with it and only the drain runs.
            (void)assocFlowId;
            FreeOutAssoc(assocSlot, owner);
        }

        {
            Flow* state = reinterpret_cast<Flow*>(flowPool_.WriteLock(flowSlot));
            state->life   = FlowLifecycle::CLOSED;
            state->flowId = internal::INVALID_FLOW_ID;   // marks the slot free
            flowPool_.UnlockWrite(flowSlot);
        }
        flowPool_.Release(flowSlot);

        return common::Error::Ok;
    }

    FlowLifecycle Socket::GetFlowState(const FlowHandle& flow)
    {
        if (!initialized_.load(std::memory_order_acquire) || flow.Failed()
            || flow.Slot() >= flowPool_.GetCapacity())
            return FlowLifecycle::CLOSED;

        const Flow* state = reinterpret_cast<const Flow*>(flowPool_.ReadLock(flow.Slot()));
        const FlowLifecycle life = state->epoch == flow.Epoch()
            ? state->life : FlowLifecycle::CLOSED;   // stale handle reads closed
        flowPool_.UnlockRead(flow.Slot());

        return life;
    }

    FlowLifecycle Socket::GetFlowState(const FlowHandle& flow, const Address& peer)
    {
        // Where failure lives: a target that rejected or stopped answering
        // reads FAILED while the flow stays OPEN for the rest.
        if (GetFlowState(flow) == FlowLifecycle::CLOSED || !outAssocDir_)
            return FlowLifecycle::CLOSED;

        PeerHandle peerHandle = peers_.GetPeer(peer);
        if (peerHandle.Failed() || !peerHandle.Read())
            return FlowLifecycle::CLOSED;

        const uint32_t assocSlot = FindFlowSlot(OutAssocDirFor(peerHandle.GetSlotIndex()),
                                                maxOutAssocPerPeer_, flow.Id());
        if (assocSlot == common::collections::SlotPool::INVALID)
            return FlowLifecycle::CLOSED;   // never sent to this peer yet

        const OutAssociation* assoc = reinterpret_cast<const OutAssociation*>(
            outAssocPool_.ReadLock(assocSlot));
        const FlowLifecycle life = assoc->life;
        outAssocPool_.UnlockRead(assocSlot);

        return life;
    }

    void Socket::Flow_Reject(const Address& from, const uint8_t* payload, size_t len)
    {
        // The remote refused to register one of OUR flows: it is at its caps,
        // and retrying the same flow would only ask again. Fail it so the app
        // sees the outcome through its handle, and drain what it was holding.
        if (!outAssocDir_ || len < 2) return;
        const uint16_t flowId = static_cast<uint16_t>(payload[0])
                              | static_cast<uint16_t>(payload[1]) << 8;

        PeerHandle peerHandle = peers_.GetPeer(from);
        if (peerHandle.Failed()) return;
        Peer* peer = peerHandle.Write();
        if (!peer || !peer->IsValid()) return;

        const uint32_t flowSlot = FindFlowSlot(OutAssocDirFor(peerHandle.GetSlotIndex()),
                                               maxOutAssocPerPeer_, flowId);
        if (flowSlot == common::collections::SlotPool::INVALID) return;

        FailOutAssoc(flowSlot, flowId, peer);
    }



    void Socket::FreeOutAssoc(uint32_t flowSlot, Peer* refundTo) noexcept
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

    void Socket::FailOutAssoc(uint32_t flowSlot, uint16_t flowId, Peer* refundTo) noexcept
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

    Socket::FlowAdmit Socket::AdmitInFlow(uint32_t peerSlot, const Address& from,
                                          const BcpId& peerId, uint16_t flowId,
                                          uint8_t flowData) noexcept
    {
        FlowDirEntry* dir = InAssocDirFor(peerSlot);
        if (FindFlowSlot(dir, maxInAssocPerPeer_, flowId)
            != common::collections::SlotPool::INVALID)
            return FlowAdmit::Existing;

        FlowMode mode{};
        uint32_t declaredWindow = 0;
        if (!DecodeFlowData(flowData, mode, declaredWindow))
            return FlowAdmit::Rejected;

        // The declared window is what the sender will keep in flight, and the
        // seen bitmap is what this socket can dedupe. Registering a flow wider
        // than the bitmap would let a retransmit arrive older than anything
        // still remembered, and the same message would be delivered twice.
        if (declaredWindow > inWindowBits_)
            return FlowAdmit::Rejected;

        // This is the one path where a REMOTE makes this socket allocate, so
        // it is caps-only: a dry pool or a full directory refuses, and the
        // sender is told rather than left retransmitting into silence.
        const uint32_t flowSlot = inAssocPool_.Acquire();
        if (flowSlot == common::collections::SlotPool::INVALID)
            return FlowAdmit::Rejected;

        // Build, then publish: no lookup can reach a half-built flow.
        {
            InAssociation* flow = reinterpret_cast<InAssociation*>(
                inAssocPool_.WriteLock(flowSlot));
            ResetInAssoc(flow, peerSlot, from, &peerId, flowId, mode,
                        inWindowBits_, inReorderCap_);
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

    uint32_t Socket::DrainOutInflight(OutAssociation* flow) noexcept
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

    common::collections::SlotPool* Socket::WaitPoolFor(FlowMode mode) noexcept
    {
        return mode == FlowMode::UNRELIABLE ? sendPool_ : &stagingPool_;
    }

    void Socket::DrainOutWaiting(OutAssociation* flow) noexcept
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

    void Socket::DrainInHoldback(InAssociation* flow) noexcept
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

    void Socket::Flow_Ack(const Address& from, const uint8_t* payload, size_t len)
    {
        // Answers OUR sent packets: OUT side. Body is a run of
        // [flowId(2)][rangeCount(1)][first(4),last(4)]*count for one peer.
        if (!outAssocDir_) return;
        const uint64_t now = common::MonotonicMicros();

        CongestionDelta ccDelta;

        // One acquisition of the peer, held read across the whole sweep: each
        // per-flow resolve nests its flow write lock under this read lock (the
        // sanctioned peer->flow order), and the gathered feedback is applied
        // once at the end on the same handle upgraded to write, never a second
        // lookup of a peer already held.
        PeerHandle peerHandle = peers_.GetPeer(from);
        if (peerHandle.Failed() || !peerHandle.Read()) return;
        const uint32_t peerSlot = peerHandle.GetSlotIndex();

        size_t off = 0;
        while (off + 3 <= len)
        {
            const uint16_t flowId = static_cast<uint16_t>(payload[off])
                                  | static_cast<uint16_t>(payload[off + 1]) << 8;
            uint8_t rangeCount = payload[off + 2];
            off += 3;
            if (rangeCount > internal::FLOW_ACK_RANGE_COUNT) break;   // malformed: apply what we have

            AckRange ranges[internal::FLOW_ACK_RANGE_COUNT];
            bool truncated = false;
            for (uint8_t i = 0; i < rangeCount; ++i)
            {
                if (off + 8 > len) { truncated = true; break; }
                ranges[i].first = static_cast<uint32_t>(payload[off])
                                | static_cast<uint32_t>(payload[off + 1]) << 8
                                | static_cast<uint32_t>(payload[off + 2]) << 16
                                | static_cast<uint32_t>(payload[off + 3]) << 24;
                ranges[i].last  = static_cast<uint32_t>(payload[off + 4])
                                | static_cast<uint32_t>(payload[off + 5]) << 8
                                | static_cast<uint32_t>(payload[off + 6]) << 16
                                | static_cast<uint32_t>(payload[off + 7]) << 24;
                off += 8;
            }
            if (truncated) break;

            const uint32_t flowSlot = FindFlowSlot(OutAssocDirFor(peerSlot),
                                                   maxOutAssocPerPeer_, flowId);
            if (flowSlot == common::collections::SlotPool::INVALID) continue;

            OutAssociation* flow = reinterpret_cast<OutAssociation*>(
                outAssocPool_.WriteLock(flowSlot));
            if (flow->flowId == flowId)
            {
                const uint32_t cap = flow->inflightCap;
                InFlightEntry* ring = flow->InFlight();
                for (uint32_t i = 0; i < cap; ++i)
                    if (ring[i].seq != 0 && SeqInRanges(ring[i].seq, ranges, rangeCount))
                        ResolveOutEntry(flow, ring[i], true, now, ccDelta);
            }
            outAssocPool_.UnlockWrite(flowSlot);
        }

        // Apply the gathered feedback once, on the same handle upgraded to
        // write. The upgrade drops the read lock before taking write, so the
        // peer is revalidated on the other side of the gap.
        Peer* peer = peerHandle.Write();
        if (peer && peer->IsValid()) ApplyCongestion(*peer, ccDelta, now);
    }

    void Socket::FlushPeerAcks(const Address& addr, PeerHandle peer)
    {
        if (!inAssocDir_) return;

        // One packet carries every association of this peer that owes acks.
        // Each entry: [flowId(2)][rangeCount(1)][first,last]*count. Generated
        // under each association's lock (nested inside the peer read lock, which
        // holds the sweep out); owed counters reset here.
        uint8_t body[internal::MAX_WIRE_PACKET_SIZE];
        size_t  bodyLen = 0;
        bool    any = false;

        // Peer materials, gathered under the handle before it drops.
        PeerSendMaterials materials;

        {
            // The transferred handle is this function's to release: everything
            // locked happens in this scope, the send after it, so the peer lock
            // is never held across the syscall.
            PeerHandle peerHandle = std::move(peer);
            if (peerHandle.Failed() || !peerHandle.Read()) return;
            FlowDirEntry* dir = InAssocDirFor(peerHandle.GetSlotIndex());
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
                    const size_t need = 3 + static_cast<size_t>(rc) * 8;
                    if (rc > 0 && bodyLen + need <= sizeof(body))
                    {
                        const uint16_t flowId = flow->flowId;
                        body[bodyLen++] = static_cast<uint8_t>(flowId);
                        body[bodyLen++] = static_cast<uint8_t>(flowId >> 8);
                        body[bodyLen++] = rc;
                        for (uint8_t r = 0; r < rc; ++r)
                        {
                            const uint32_t first = ranges[r].first, last = ranges[r].last;
                            body[bodyLen++] = static_cast<uint8_t>(first);
                            body[bodyLen++] = static_cast<uint8_t>(first >> 8);
                            body[bodyLen++] = static_cast<uint8_t>(first >> 16);
                            body[bodyLen++] = static_cast<uint8_t>(first >> 24);
                            body[bodyLen++] = static_cast<uint8_t>(last);
                            body[bodyLen++] = static_cast<uint8_t>(last >> 8);
                            body[bodyLen++] = static_cast<uint8_t>(last >> 16);
                            body[bodyLen++] = static_cast<uint8_t>(last >> 24);
                        }
                        flow->newSinceFlush  = 0;   // owed cleared; re-arms on next arrival
                        flow->ackArmedMicros = 0;
                        any = true;
                    }
                    // else the body is full: this flow's acks ride the next flush
                }
                inAssocPool_.UnlockWrite(flowSlot);
                if (bodyLen + 3 + 8 > sizeof(body)) break;   // no room for another entry
            }

            if (!any) return;

            // Upgrade the same handle for the materials: the one lock this
            // thread holds on the peer, juggled, never a second acquisition. The
            // upgrade drops the read lock before taking write, so the peer is
            // revalidated on the other side of the gap.
            Peer* peerState = peerHandle.Write();
            if (!peerState || !peerState->IsValid()) return;
            materials = GatherSendMaterials(*peerState);
        }

        SendSecureControl(addr, materials, internal::SECURE_CHANNEL_FLOW_ACK, body, bodyLen);
        common::crypto::Wipe(materials.key.data(), materials.key.size());
    }

    void Socket::ResolveOutEntry(OutAssociation* flow, InFlightEntry& entry,
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

    void Socket::ApplyCongestion(Peer& peer, const CongestionDelta& delta,
                                  uint64_t nowMicros) noexcept
    {
        // Free what resolved, guarded so a bookkeeping drift can never wrap the
        // counter past zero into a huge value.
        peer.bytesInFlight -= delta.resolvedBytes <= peer.bytesInFlight
            ? delta.resolvedBytes : peer.bytesInFlight;

        // Smooth the per-peer round-trip from the newest acked sample.
        if (delta.rttSampleMicros != 0)
            peer.pathSrttMicros = peer.pathSrttMicros == 0
                ? delta.rttSampleMicros
                : (peer.pathSrttMicros * 7 + delta.rttSampleMicros) / 8;

        // Grow on acknowledged bytes: double the budget per round-trip below the
        // threshold, one packet per round-trip at or above it. Saturating, so
        // growth can never wrap the budget.
        if (delta.ackedBytes != 0)
        {
            uint32_t growth;
            if (peer.congestionBudget < peer.slowStartThreshold)
                growth = delta.ackedBytes;
            else
            {
                growth = static_cast<uint32_t>(
                    static_cast<uint64_t>(internal::MAX_WIRE_PACKET_SIZE)
                    * delta.ackedBytes / peer.congestionBudget);
                if (growth == 0) growth = 1;
            }
            peer.congestionBudget = peer.congestionBudget + growth < peer.congestionBudget
                ? UINT32_MAX : peer.congestionBudget + growth;
        }

        // Trim on loss, at most once per round-trip, never below the floor. The
        // threshold follows the trimmed budget, so growth resumes as the
        // one-packet-per-round-trip crawl rather than doubling.
        if (delta.sawLoss)
        {
            const uint32_t interval = peer.pathSrttMicros != 0
                ? peer.pathSrttMicros : flowRetryIntervalMicros_;
            if (peer.lastLossReactionMicros == 0
                || nowMicros - peer.lastLossReactionMicros >= interval)
            {
                uint32_t trimmed = static_cast<uint32_t>(
                    static_cast<uint64_t>(peer.congestionBudget)
                    * internal::CC_LOSS_RETAIN_PERCENT / 100);
                if (trimmed < minCongestionBudget_) trimmed = minCongestionBudget_;
                peer.congestionBudget       = trimmed;
                peer.slowStartThreshold     = trimmed;
                peer.lastLossReactionMicros = nowMicros;
            }
        }
    }

    // --- Tick + peer management ---

    PeerHandle Socket::GetPeer(const Address& addr)
    {
        return peers_.GetPeer(addr);
    }

    void Socket::SweepPeerAssociations(uint32_t peerSlot) noexcept
    {
        // Both directions, before the peer slot can recycle: a later peer in the
        // same slot must inherit empty directories, never a stranger's flows.
        // Unpublish first, then free; stale FlowHandles read CLOSED from the epoch
        // check. Runs under the peer's write lock (RemovePeer holds it), so the
        // flow locks FreeOutAssoc / the in-sweep take nest correctly (peer->flow).
        // The peer is being removed, so its congestion budget dies with it: the
        // drained byte count is discarded rather than refunded (refundTo null).
        if (outAssocDir_)
        {
            FlowDirEntry* dir = OutAssocDirFor(peerSlot);
            for (uint32_t i = 0; i < maxOutAssocPerPeer_; ++i)
            {
                const uint32_t flowSlot = dir[i].flowSlot;
                if (flowSlot == common::collections::SlotPool::INVALID)
                    continue;
                dir[i] = FlowDirEntry{ internal::INVALID_FLOW_ID, 0,
                                       common::collections::SlotPool::INVALID };
                FreeOutAssoc(flowSlot, nullptr);
            }
        }
        if (inAssocDir_)
        {
            FlowDirEntry* dir = InAssocDirFor(peerSlot);
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

    common::Error Socket::RemovePeer(const Address& addr)
    {
        {
            PeerHandle peer = peers_.GetPeer(addr);
            if (peer.Failed())
                return common::Error::PeerNotFound;
            pending::Clear(pendingPool_, peer);

            // The sweep mutates both directories, so it needs the peer's write
            // lock rather than the read lock above.
            if ((outAssocDir_ || inAssocDir_) && peer.Write())
                SweepPeerAssociations(peer.GetSlotIndex());
        }
        return peers_.RemovePeer(addr);
    }

    common::Error Socket::Connect(const Address& addr)
    {
        if (!initialized_.load(std::memory_order_acquire))
            return common::Error::NotInitialized;

        {
            PeerHandle peerHandle = peers_.GetPeer(addr);
            if (!peerHandle.Failed())
                return common::Error::Ok;   // established or already handshaking
        }

        // We chose this address, so spending a table slot on it is safe: an
        // attacker cannot make this socket initiate. Same reasoning as the
        // unknown-peer path in PreProcessOut, without a packet to park.
        uint32_t slot = 0;
        const common::Error registration = peers_.RegisterPeer(addr, nullptr, slot);
        if (registration == common::Error::AlreadyPending)
            return common::Error::Ok;       // a racing sender registered first;
                                            // its HS_INIT is already on the way
        if (registration != common::Error::Ok)
            return registration;

        {
            PeerHandle peerHandle = peers_.GetPeer(addr);
            if (!peerHandle.Failed())
                peerHandle.Write()->attempts = 1;
        }
        SendHandshakeInit(addr);
        return common::Error::Ok;
    }

    uint32_t Socket::RotateTags()
    {
        if (!initialized_.load(std::memory_order_acquire) || !migration_)
            return 0;

        uint32_t rotated = 0;
        uint32_t cursor  = 0;
        for (;;)
        {
            Address batch[32];
            const uint32_t count = peers_.CollectAddresses(cursor, batch, 32);
            if (count == 0)
                break;

            for (uint32_t i = 0; i < count; ++i)
            {
                PeerHandle peerHandle = peers_.GetPeer(batch[i]);
                if (peerHandle.Failed()) continue;   // gone since the snapshot
                Peer* peer = peerHandle.Write();
                if (!peer || !peer->IsValid()) continue;

                ++peer->myTagStep;
                peer->myTag = DerivePeerTag(peer->session, LaneTo(peer->theirPk), peer->myTagStep);
                ++rotated;
            }
        }
        return rotated;
    }

    uint32_t Socket::RetryHandshakes()
    {
        if (!initialized_.load(std::memory_order_acquire))
            return 0;

        uint32_t retried = 0;
        uint32_t cursor  = 0;
        for (;;)
        {
            Address batch[32];
            const uint32_t count = peers_.CollectAddresses(cursor, batch, 32);
            if (count == 0)
                break;

            for (uint32_t i = 0; i < count; ++i)
            {
                {
                    PeerHandle peerHandle = peers_.GetPeer(batch[i]);
                    if (peerHandle.Failed()) continue;   // gone since the snapshot
                    Peer* peer = peerHandle.Write();
                    if (peer->IsValid()) continue;

                    // Back to square one: HS_CHLG is only answered from
                    // AWAITING_CHALLENGE, so a peer stuck waiting for a lost
                    // FINISH restarts cleanly instead of wedging.
                    peer->state = HandshakeState::AWAITING_CHALLENGE;
                    if (peer->attempts < UINT8_MAX)
                        ++peer->attempts;
                }
                SendHandshakeInit(batch[i]);
                ++retried;
            }
        }
        return retried;
    }

    // --- Tick ---

    void Socket::Update(uint64_t nowOverride)
    {
        if (!initialized_.load(std::memory_order_acquire)) return;
        if (!outAssocDir_ && !inAssocDir_ && evictAfterStamp_ == 0) return;

        uint32_t evicted = 0;
        uint32_t cursor = 0;
        for (;;)
        {
            Address batch[32];
            const uint32_t count = peers_.CollectAddresses(cursor, batch, 32);
            if (count == 0) break;

            for (uint32_t b = 0; b < count; ++b)
            {
                const Address addr = batch[b];

                // One borrow decides whether this peer idled out and whether
                // any association owes an ack past the delay deadline; the flush
                // itself runs on its own transferred handle, so no lock is
                // held across either call boundary.
                bool ackDue = false;
                bool evictIdle = false;
                {
                    PeerHandle peerHandle = peers_.GetPeer(addr);
                    if (peerHandle.Failed() || !peerHandle.Read()) continue;

                    // Idle check under the read borrow. Half-open peers use
                    // the same clock: registration stamped them, handshake
                    // chatter does not refresh (it is forgeable), so an entry
                    // that never completes gets a single timeout to live.
                    if (evictAfterStamp_ != 0 && evicted < internal::MAX_EVICT_PER_UPDATE)
                    {
                        const uint32_t nowStamp = SeenStamp(Now(nowOverride));
                        const uint32_t idleFor =
                            nowStamp - peerHandle.Read()->lastSeenAt;
                        if (idleFor > evictAfterStamp_) evictIdle = true;
                    }
                    if (!evictIdle && inAssocDir_)
                    {
                        const uint64_t now = Now(nowOverride);   // fresh for this peer
                        FlowDirEntry* dir = InAssocDirFor(peerHandle.GetSlotIndex());
                        for (uint32_t i = 0; i < maxInAssocPerPeer_ && !ackDue; ++i)
                        {
                            if (dir[i].flowSlot == common::collections::SlotPool::INVALID)
                                continue;
                            const InAssociation* flow = reinterpret_cast<const InAssociation*>(
                                inAssocPool_.ReadLock(dir[i].flowSlot));
                            if (flow->newSinceFlush > 0 &&
                                now - flow->ackArmedMicros >= flowAckDelayMicros_)
                                ackDue = true;
                            inAssocPool_.UnlockRead(dir[i].flowSlot);
                        }
                    }
                }

                // Eviction runs with no handle held: RemovePeer takes its
                // own locks. A racing removal just reports PeerNotFound.
                if (evictIdle)
                {
                    ++evicted;
                    (void)RemovePeer(addr);
                    continue;
                }

                // Each callee takes a fresh handle by value: ownership moves
                // with the call, so this loop can never hold a peer lock into
                // a function that juggles the same one (FlushPeerAcks sweeps
                // every owing association in one packet).
                if (ackDue)
                    FlushPeerAcks(addr, peers_.GetPeer(addr));

                // Out-flows: open/close retries with give-up, and reliable
                // retransmits / unreliable loss declarations past the RTO. Each
                // reads the clock fresh at entry.
                if (outAssocDir_)
                {
                    for (uint32_t i = 0; i < maxOutAssocPerPeer_; ++i)
                        UpdateOutFlow(addr, peers_.GetPeer(addr), i, nowOverride);

                    // Capacity freed above (and by acks since the last tick)
                    // goes to the packets that have waited longest.
                    DrainWaitingSends(addr);
                }
            }
        }
    }


    void Socket::RetransmitInflight(OutAssociation& flow, uint64_t now, CongestionDelta& delta,
                                     uint32_t* resendSeqs, uint32_t* resendSlots,
                                     uint32_t& resendCount, bool& exhausted)
    {
        // Scan the in-flight ring for entries past their RTO. Reliable ones are
        // collected for retransmit (refresh sentAt, keep them in flight);
        // unreliable ones are declared lost and resolved. Loss feedback goes into
        // `delta`, never the peer: the caller applies it under the peer lock.
        const uint64_t rto  = RetransmitTimeout(&flow, flowRetryIntervalMicros_);
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
                if (entry.retries >= flowMaxAttempts_)
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

    void Socket::UpdateOutFlow(const Address& addr, PeerHandle peer,
                                uint32_t dirIndex, uint64_t nowOverride)
    {
        // Read the clock fresh for this flow, so one that comes due partway
        // through an Update pass fires now, not a tick late.
        const uint64_t now = Now(nowOverride);


        // Gather what to do (and the peer materials) under the transferred
        // handle, then send after it drops: nothing locked across a send.
        bool exhausted = false;   // a reliable packet ran out of retransmits
        uint16_t flowId = 0;
        uint32_t resendSlots[RESENDS_PER_ASSOC_PER_TICK];
        uint32_t resendSeqs[RESENDS_PER_ASSOC_PER_TICK];
        uint32_t resendN = 0;

        CongestionDelta ccDelta;   // loss gathered under the flow lock, applied under the peer's

        // One control materials + one per resend, each carrying its own fresh
        // counter; built under the peer write lock, sent (and wiped) after it drops.
        PeerSendMaterials ctrlMaterials;
        PeerSendMaterials resendMaterials[RESENDS_PER_ASSOC_PER_TICK];

        uint32_t flowSlot = common::collections::SlotPool::INVALID;
        {
            // The transferred handle is this function's to release: the flow
            // gather, the close finish, and the materials all juggle this one
            // peer lock, and it drops with the scope, before any send.
            PeerHandle peerHandle = std::move(peer);
            if (peerHandle.Failed() || !peerHandle.Read()) return;
            flowSlot = OutAssocDirFor(peerHandle.GetSlotIndex())[dirIndex].flowSlot;
            if (flowSlot == common::collections::SlotPool::INVALID) return;

            OutAssociation* flow = reinterpret_cast<OutAssociation*>(
                outAssocPool_.WriteLock(flowSlot));
            flowId = flow->flowId;

            switch (flow->life)
            {
            case FlowLifecycle::OPEN:
                RetransmitInflight(*flow, now, ccDelta, resendSeqs, resendSlots, resendN,
                                   exhausted);
                break;
            default: break;
            }

            outAssocPool_.UnlockWrite(flowSlot);

            // Out of retransmits: the remote stopped answering this target.
            // Runs here because the refund needs the peer's write lock, and
            // after the association lock dropped so the two never nest wrong.
            if (exhausted)
            {
                if (Peer* dying = peerHandle.Write())
                {
                    FailOutAssoc(flowSlot, flowId, dying);
                    return;
                }
            }

            const bool hasDelta = ccDelta.resolvedBytes != 0 || ccDelta.sawLoss;
            if (!hasDelta && resendN == 0) return;

            // Congestion feedback applies under this write lock; the resends run
            // after the scope with nothing held, because a resend takes the
            // staging read lock and the send path takes staging before the peer.
            // Doing it under the peer lock would invert that order.
            Peer* peerState = peerHandle.Write();
            if (!peerState || !peerState->IsValid()) return;
            ApplyCongestion(*peerState, ccDelta, now);
            if (resendN == 0) return;

            // One fresh counter per resend, in the order the source hands them
            // out, so no two packets share a nonce.
            PeerSendMaterials base = GatherSendMaterials(*peerState);
            for (uint32_t i = 0; i < resendN; ++i)
            {
                resendMaterials[i] = base;
                if (i > 0)
                    resendMaterials[i].counter = ++peerState->sendCounter;
            }
            common::crypto::Wipe(base.key.data(), base.key.size());
        }

        // `addr` is the peer's current address: the handle the caller passed was
        // looked up by it, and that lookup only succeeds while the peer is bound
        // there. After a migration a stale addr fails the lookup and this pass
        // does nothing, so the next tick uses the new address. Resends therefore
        // always target the live location, never the one frozen into the staging
        // slot at first send.
        for (uint32_t i = 0; i < resendN; ++i)
            ResendStaging(addr, flowSlot, resendSlots[i], resendSeqs[i], resendMaterials[i]);
        for (uint32_t i = 0; i < resendN; ++i)
            common::crypto::Wipe(resendMaterials[i].key.data(), resendMaterials[i].key.size());
    }

    void Socket::DrainWaitingSends(const Address& addr)
    {
        constexpr uint32_t DRAINS_PER_PEER_PER_TICK = 16;

        for (uint32_t sent = 0; sent < DRAINS_PER_PEER_PER_TICK; ++sent)
        {
            // Step 1, peek, read locks only: across this peer's flows, find
            // the OLDEST waiting head that passes the gate right now. Epoch is
            // captured so a flow slot recycled between peek and claim can
            // never be mistaken for the one peeked.
            uint32_t candidateFlow   = common::collections::SlotPool::INVALID;
            uint32_t candidatePacket = common::collections::SlotPool::INVALID;
            uint32_t candidateEpoch  = 0;
            uint64_t oldestSince     = 0;
            FlowMode candidateMode{};
            {
                PeerHandle peerHandle = peers_.GetPeer(addr);
                if (peerHandle.Failed()) return;
                const Peer* peer = peerHandle.Read();
                if (!peer || !peer->IsValid()) return;

                const FlowDirEntry* dir = OutAssocDirFor(peerHandle.GetSlotIndex());
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
                        if (CanSend(*flow, *peer, head.wireSize, windowed)
                            && (candidateFlow == common::collections::SlotPool::INVALID
                                || head.waitingSince < oldestSince))
                        {
                            candidateFlow   = flowSlot;
                            candidatePacket = head.packetSlot;
                            candidateEpoch  = flow->epoch;
                            oldestSince     = head.waitingSince;
                            candidateMode   = flow->mode;
                        }
                    }
                    outAssocPool_.UnlockRead(flowSlot);
                }
            }
            if (candidateFlow == common::collections::SlotPool::INVALID)
                return;   // nothing waiting can go now

            // Step 2, claim, in the send path's lock order: the packet slot
            // FIRST, then peer, then flow. A concurrent Update may have
            // drained the head between the peek and this lock, so the current
            // head is re-checked against the very slot this handle holds; on
            // any mismatch the slot may already belong to someone else, so
            // DETACH, never release, and peek again.
            PacketSlotHandle packetHandle{candidatePacket, WaitPoolFor(candidateMode)};
            PacketSlot* packet = packetHandle.Write();
            if (!packet) return;

            bool claimed = false;
            PeerSendMaterials materials;
            {
                PeerHandle peerHandle = peers_.GetPeer(addr);
                Peer* peer = peerHandle.Failed() ? nullptr : peerHandle.Write();
                if (!peer || !peer->IsValid())
                {
                    (void)packetHandle.Detach();
                    return;
                }

                OutAssociation* flow = reinterpret_cast<OutAssociation*>(
                    outAssocPool_.WriteLock(candidateFlow));
                if (flow->epoch == candidateEpoch
                    && flow->life == FlowLifecycle::OPEN
                    && flow->waitingCount > 0)
                {
                    WaitingEntry& head =
                        flow->Waiting()[flow->waitingHead & (flow->waitingCap - 1u)];
                    const bool windowed = flow->mode != FlowMode::UNRELIABLE;
                    if (head.packetSlot == candidatePacket
                        && CanSend(*flow, *peer, head.wireSize, windowed))
                    {
                        const uint16_t wireSize = head.wireSize;
                        head = WaitingEntry{ 0, common::collections::SlotPool::INVALID, 0 };
                        flow->waitingHead  += 1;
                        flow->waitingCount -= 1;
                        StampFlowPacket(*flow, *peer, *packet,
                                        candidateMode == FlowMode::UNRELIABLE
                                            ? common::collections::SlotPool::INVALID
                                            : candidatePacket,
                                        wireSize);
                        claimed = true;
                    }
                }
                outAssocPool_.UnlockWrite(candidateFlow);

                if (claimed)
                    materials = GatherSendMaterials(*peer);
            }
            if (!claimed)
            {
                (void)packetHandle.Detach();
                continue;
            }

            // Step 3, seal + send with no peer or flow lock held, to the
            // peer's CURRENT address (the lookup above only succeeds while it
            // is bound there). A reliable body's lease belongs to the
            // in-flight ring now: it is the retransmit source, so it seals
            // into a fresh wire slot and the handle detaches. An unreliable
            // body is its own wire packet: seal in place, send, and the
            // handle's release returns the slot.
            if (candidateMode == FlowMode::UNRELIABLE)
            {
                const bool tagged = packet->IsTagged();
                const size_t headerSize = tagged
                    ? internal::MIN_SECURE_WIRE_SIZE + internal::WIRE_PEER_TAG_SIZE
                    : internal::MIN_SECURE_WIRE_SIZE;
                const size_t bodyLen = packet->dataSize - headerSize;
                packet->address = addr;
                SealSecurePacket(*packet, packet->data + headerSize, headerSize,
                                 bodyLen, materials, tagged);
                (void)kernel_->SendTo(packet->address.addr, packet->data, packet->dataSize);
            }
            else
            {
                SealStagingToWire(addr, *packet, materials);
                (void)packetHandle.Detach();
            }
            common::crypto::Wipe(materials.key.data(), materials.key.size());
        }
    }

    uint64_t Socket::NextTimeout()
    {
        if (!initialized_.load(std::memory_order_acquire)) return 0;
        if (!outAssocDir_ && !inAssocDir_) return 0;

        uint64_t soonest = 0;   // 0 = nothing pending
        auto consider = [&](uint64_t deadline) {
            if (soonest == 0 || deadline < soonest) soonest = deadline;
        };

        uint32_t cursor = 0;
        for (;;)
        {
            Address batch[32];
            const uint32_t count = peers_.CollectAddresses(cursor, batch, 32);
            if (count == 0) break;

            for (uint32_t b = 0; b < count; ++b)
            {
                PeerHandle peerHandle = peers_.GetPeer(batch[b]);
                if (peerHandle.Failed() || !peerHandle.Read()) continue;
                const uint32_t peerSlot = peerHandle.GetSlotIndex();

                if (inAssocDir_)
                {
                    FlowDirEntry* dir = InAssocDirFor(peerSlot);
                    for (uint32_t i = 0; i < maxInAssocPerPeer_; ++i)
                    {
                        if (dir[i].flowSlot == common::collections::SlotPool::INVALID) continue;
                        const InAssociation* flow = reinterpret_cast<const InAssociation*>(
                            inAssocPool_.ReadLock(dir[i].flowSlot));
                        if (flow->newSinceFlush > 0)
                            consider(flow->ackArmedMicros + flowAckDelayMicros_);
                        inAssocPool_.UnlockRead(dir[i].flowSlot);
                    }
                }

                if (outAssocDir_)
                {
                    FlowDirEntry* dir = OutAssocDirFor(peerSlot);
                    for (uint32_t i = 0; i < maxOutAssocPerPeer_; ++i)
                    {
                        if (dir[i].flowSlot == common::collections::SlotPool::INVALID) continue;
                        const OutAssociation* flow = reinterpret_cast<const OutAssociation*>(
                            outAssocPool_.ReadLock(dir[i].flowSlot));
                        if (flow->life == FlowLifecycle::OPEN && flow->unresolved > 0)
                        {
                            // Earliest RTO across in-flight entries; a full scan
                            // is bounded by the ring cap.
                            const uint64_t rto = RetransmitTimeout(flow, flowRetryIntervalMicros_);
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
            }
        }

        return soonest;
    }
}
