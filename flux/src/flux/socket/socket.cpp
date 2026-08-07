#include <flux/socket/socket.h>

#include <common/log.h>
#include <common/crypto/crypto.h>
#include <flux/socket/platform/win_socket.h>
#include <flux/socket/platform/faulty_socket.h>
#include <flux/socket/platform/posix_socket.h>
#include <flux/internal/constants.h>
#include <flux/wire/packet_builder.h>
#include <flux/crypto/packet_seal.h>
#include <flux/wire/batch.h>
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









        /** The challenge cookie as a MAC key, labelled so it cannot collide
            with any other derivation.

            The cookie travels in the clear, so this key is not secret and the
            MAC it produces is not authentication: anyone on the path can
            compute a valid one. What it catches is a corrupted or blindly
            injected HS_RES, which is the failure that binds a peer to a public
            key nobody holds. Real proof of identity arrives with the
            confirmation MAC once a session key exists. */
        common::crypto::SessionKey CookieKey(uint64_t challenge) noexcept
        {
            static constexpr uint8_t LABEL[8] = {'f','l','u','x','-','h','s',0};
            common::crypto::SessionKey key{};
            std::memcpy(key.data(), LABEL, sizeof(LABEL));
            for (size_t i = 0; i < sizeof(challenge); ++i)
                key[sizeof(LABEL) + i] = static_cast<uint8_t>(challenge >> (i * 8));
            return key;
        }



        /** The handshake transcript both sides bind into the session key and the
            confirmation MAC. Role-ordered, so both ends assemble identical bytes. */
        void BuildTranscript(uint8_t out[internal::HS_TRANSCRIPT_SIZE],
                             const common::crypto::PublicKey& initiatorPk,
                             const common::crypto::PublicKey& responderPk,
                             const common::crypto::PublicKey& initiatorEph,
                             const common::crypto::PublicKey& responderEph,
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
            std::memcpy(p, initiatorEph.data(), initiatorEph.size());       p += initiatorEph.size();
            std::memcpy(p, responderEph.data(), responderEph.size());       p += responderEph.size();
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
        // Idempotent: the first call tears the socket down, later calls and the
        // destructor's call return here. The caller must ensure no other thread
        // is in Poll or Update, the same rule the destructor has always had,
        // since this now frees the pools those paths read.
        if (!initialized_.exchange(false, std::memory_order_acq_rel))
            return;

        // Peers and flows first, while the kernel still owns the recv and send
        // pools they point at, then the pools this socket owns, then the kernel
        // itself. Each release nulls its own pointers, so a later Init starts
        // from clean state rather than leaking the previous allocation.
        peers_.Shutdown();
        flows_.Shutdown();
        pendingPool_.Shutdown();
        readyLanes_.Shutdown();
        events_.Shutdown();
        if (kernel_)
        {
            kernel_->Close();
            kernel_.reset();
        }
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
        // Rounding a lane count up would hand out fewer identities than lanes,
        // and the leftover lane fills with packets nobody ever pops until the
        // receive pool is dry and the socket goes quiet. Refuse instead.
        if (config.pollLanes == 0 || config.pollLanes > ReadyLanes::MAX_LANES
            || (config.pollLanes & (config.pollLanes - 1)) != 0)
            return common::Error::InvalidParam;

        // A lane per draining thread, each sized for the whole receive pool.
        // Sharing one pool's worth between them would let a push fail on a busy
        // lane while another sat empty, and a push that fails is a packet
        // dropped after the sender was told it arrived.
        if (!readyLanes_.Init(config.pollLanes, config.recvSlotCount))
            return common::Error::NotInitialized;
        if (listener_.Init(kernel_.get()) != common::Error::Ok)
            return common::Error::NotInitialized;
        if (sender_.Init(this, kernel_.get()) != common::Error::Ok)
            return common::Error::NotInitialized;
        if (challengeGenerator_.Init() != common::Error::Ok)
            return common::Error::NotInitialized;

        if (common::Error error = InitPeerTableAndReplay(config); error != common::Error::Ok)
            return error;
        handshakeRetryMicros_ = config.timers.retryIntervalMicros;

        if (common::Error error = InitFlows(config); error != common::Error::Ok)
            return error;
        if (common::Error error = InitLiveness(config); error != common::Error::Ok)
            return error;
        // Sized from the association pools, so every entity that can exist has
        // an entry of its own and nothing can be crowded out.
        if (common::Error error = events_.Init(
                config.events.hook, config.events.context, config.events.subscribed,
                config.flows.outCount + config.flows.bulkOutCount,
                config.flows.inCount + config.flows.bulkInCount,
                config.maxPeers, readyLanes_.LaneCount());
            error != common::Error::Ok)
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
        // One entry per peer slot, and the peer pool rounds its capacity up to
        // a power of two, so the array has to match or a high slot index reads
        // past the end.
        peerRecvStates_.reset(new (std::nothrow)
                             PeerRecvState[common::NextPowerOfTwo(config.maxPeers)]);
        if (!peerRecvStates_) return common::Error::NotInitialized;

        // Hold-back may fill the receive pool down to the reserve and no
        // further. A pool at or under the reserve leaves nothing to buffer
        // with, which is correct rather than a misconfiguration: reception
        // keeps working and only reordering stops. The derived default is a
        // fraction, because a socket with a large pool is one expecting many
        // peers, and headroom has to track arrivals per tick.
        uint32_t reserve = config.recvReserveSlots;
        if (reserve == 0)
        {
            reserve = config.recvSlotCount / internal::RECV_RESERVE_DIVISOR;
            if (reserve < internal::RECV_RESERVE_FLOOR)
                reserve = internal::RECV_RESERVE_FLOOR;
        }
        recvHoldCeiling_ = config.recvSlotCount > reserve
            ? config.recvSlotCount - reserve : 0;

        recvBatch_ = config.recvBatch != 0 ? config.recvBatch : config.recvSlotCount;

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

        // The public Config groups its knobs the way an embedder thinks about
        // them; the flow table takes them flat.
        FlowTable::Params params;
        params.flowCount           = f.flowCount;
        params.outCount            = f.outCount;
    params.bulkOutCount        = f.bulkOutCount;
        params.inCount             = f.inCount;
        params.bulkInCount         = f.bulkInCount;
        params.maxOutPerPeer       = f.maxOutPerPeer;
        params.maxInPerPeer        = f.maxInPerPeer;
        recvGrant_                 = f.recvGrant;
        params.maxPeers            = config.maxPeers;
        params.stagingCount        = f.stagingCount;
        params.reliableWait        = f.reliableWaitCount;
        params.unreliableWait      = f.unreliableWaitCount;
        params.ackDelayMicros      = config.timers.ackDelayMicros;
        params.retryIntervalMicros = config.timers.retryIntervalMicros;
        params.flowStallTimeoutMicros = config.liveness.flowStallTimeoutMicros;

        if (common::Error error = flows_.Init(params, recvPool_, sendPool_, &readyLanes_,
                                             peerRecvStates_.get(),
                                             &heldTotal_, recvHoldCeiling_);
            error != common::Error::Ok)
            return error;

        // Floored at one full wire packet: the budget gates sends, and a floor
        // no packet fits under would refuse a full-size packet forever;
        // "throttled, never strangled" requires the floor to admit one.
        minCongestionBudget_ = f.minCongestionBudget != 0
            ? f.minCongestionBudget : internal::CC_MIN_BUDGET_DEFAULT;
        {
            // No budget larger than every flow window on this peer full at
            // once can ever bind a send, it can only store a burst.
            const uint64_t ceiling = static_cast<uint64_t>(config.flows.maxOutPerPeer)
                                   * internal::FLOW_WINDOW_BULK
                                   * internal::MAX_WIRE_PACKET_SIZE;
            maxCongestionBudget_ = ceiling == 0 ? internal::CC_INITIAL_WINDOW_BYTES
                                 : ceiling > UINT32_MAX ? UINT32_MAX
                                 : static_cast<uint32_t>(ceiling);
        }
        if (minCongestionBudget_ < internal::MAX_WIRE_PACKET_SIZE)
            minCongestionBudget_ = internal::MAX_WIRE_PACKET_SIZE;
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

        // Idle eviction is mandatory, so zero takes the default rather than
        // switching it off. A live peer refreshes the clock on every packet it
        // sends, so only a silent one ages out, and reclaiming it is what lets a
        // restarted process take its slot back.
        const uint64_t idleMicros = config.liveness.idleTimeoutMicros != 0
            ? config.liveness.idleTimeoutMicros : internal::PEER_IDLE_TIMEOUT_DEFAULT;
        const uint64_t idleStamp =
            (idleMicros >> internal::SEEN_STAMP_SHIFT) + seenGrainStamp_;
        if (idleStamp == 0 || idleStamp >= (1ull << 31))
            return common::Error::InvalidParam;
        evictAfterStamp_   = static_cast<uint32_t>(idleStamp);
        idleTimeoutMicros_ = idleMicros;

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
        case BackendType::FAULTY:
            kernel_ = std::make_unique<platform::FaultySocket>();
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
                                    const common::crypto::SecretKey& myEphSk,
                                    const common::crypto::PublicKey& theirEphPk,
                                    const uint8_t* transcript, size_t transcriptLen) noexcept
    {
        // Two exchanges, both required. The ephemeral pair is what makes the
        // session unrecoverable afterwards, since neither secret half outlives
        // this function on either side. The long-lived pair is what makes it
        // authenticated, since only the holder of that key can arrive at the
        // same answer, which is what the confirmation MAC then proves. Either
        // one alone loses the other property.
        //
        // One KDF pass over both. The long-lived secret keys the hash and the
        // ephemeral one leads the context, which keeps the derivation to a
        // single call and leaves the vendored crypto floor untouched.
        common::crypto::SharedSecret staticShared;
        common::crypto::SharedSecret ephShared;
        common::crypto::ComputeSharedSecret(staticShared, secretKey_, theirPk);
        common::crypto::ComputeSharedSecret(ephShared, myEphSk, theirEphPk);

        uint8_t context[common::crypto::SHARED_SIZE + internal::HS_TRANSCRIPT_SIZE];
        std::memcpy(context, ephShared.data(), ephShared.size());
        std::memcpy(context + ephShared.size(), transcript, transcriptLen);

        common::crypto::DeriveSessionKey(out, staticShared, context,
                                         ephShared.size() + transcriptLen);

        common::crypto::Wipe(context, sizeof(context));
        common::crypto::Wipe(ephShared.data(), ephShared.size());
        common::crypto::Wipe(staticShared.data(), staticShared.size());
    }

    PeerSendMaterials Socket::GatherSendMaterials(Peer& peer) noexcept
    {
        // The one place a send bumps the counter. Caller holds the peer's write
        // lock; the returned key is a copy the caller Wipes after the send.
        PeerSendMaterials materials;
        materials.key       = peer.session;
        materials.headerKey = peer.headerKey;
        materials.macKey    = peer.macKey;
        materials.counter   = ++peer.sendCounter;
        materials.lane      = LaneTo(peer.theirPk);
        materials.tag       = peer.myTag;
        return materials;
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

    bool Socket::FlowModeOf(const FlowHandle& flow, FlowMode& outMode) noexcept
    {
        return flows_.ModeOf(flow, outMode);
    }

    common::Result<PacketSlotWriter> Socket::AcquireFlowWriter(const FlowHandle& flow)
    {
        if (!initialized_.load(std::memory_order_acquire) || !flows_.SendEnabled())
            return common::Result<PacketSlotWriter>::Fail(common::Error::NotInitialized);

        FlowMode mode{};
        if (!flows_.ModeOf(flow, mode))
            return common::Result<PacketSlotWriter>::Fail(common::Error::InvalidState);

        // Unreliable bodies are never resent, so they take an ordinary kernel
        // slot and are gone once on the wire. Reliable bodies are their own
        // retransmit source and must outlive the send.
        if (mode == FlowMode::UNRELIABLE)
            return kernel_->Write();

        return flows_.AcquireStagingWriter();
    }

    bool Socket::OfferToBatch(PacketSlotHandle& pHandle, bool requireAuth,
                              common::Error& status)
    {
        if (!initialized_.load(std::memory_order_acquire) || !flows_.SendEnabled())
            return false;

        const PacketSlot* packet = pHandle.Read();
        if (!packet || !packet->HasFlow() || packet->IsInternal() || !packet->IsSecure())
            return false;

        const uint8_t  flowData = packet->FlowData();
        const uint16_t flowId   = packet->FlowId();
        const Address  to       = packet->address;

        // A message the caller framed itself as part of a larger one keeps its
        // own packet. The framing bits live on the packet and describe its first
        // and last message, so several hand-framed pieces sharing one could not
        // each say what they are. Batching is for whole messages.
        //
        // It still must not overtake what is already waiting. Sequence numbers
        // are handed out when a packet is admitted, so a message that went
        // straight out while a batch sat open would take the lower number and
        // arrive first, reordering a flow the caller sent in order. Emptying the
        // batch first is what keeps send order and wire order the same.
        const bool handFramed = (flowData & (FLOW_PART_MORE | FLOW_PART_CONT)) != 0;
        if (handFramed)
        {
            if (FlushFlowOf(to, flowId)) return false;   // nothing ahead of it, send it now
            status = common::Error::TooManyPending;      // still queued ahead: ask again
            return true;
        }

        // Under the peer borrow only long enough to find the association. The
        // append takes the flow lock after this closes, which keeps the order
        // packet then peer then flow.
        uint32_t assocSlot   = common::collections::SlotPool::INVALID;
        bool     gateRefused = false;
        {
            PeerHandle peerHandle = peers_.GetPeer(to);
            if (peerHandle.Failed()) return false;
            const Peer* peer = peerHandle.Read();
            if (!peer || !peer->IsValid()) return false;   // handshaking: the ordinary path parks it
            if (requireAuth && !peer->authenticated) return false;   // and reports it
            assocSlot = flows_.FindOutAssoc(peerHandle.GetSlotIndex(), flowId);

            // The gate has to answer the caller, not the flush. A batched send
            // returns Ok the moment it is packed, so if this flow could not
            // admit another packet the message must go the ordinary way and let
            // the caller see the refusal, exactly as it did before batching.
            if (assocSlot != common::collections::SlotPool::INVALID
             && !flows_.WouldAdmit(*peer, assocSlot, packet->dataSize))
                gateRefused = true;
        }

        // Emptied before the ordinary path runs, for the same reason as a
        // hand-framed message: whatever is already batched was sent first and
        // must take the lower sequence.
        if (gateRefused)
        {
            if (FlushFlowOf(to, flowId)) return false;
            status = common::Error::TooManyPending;
            return true;
        }
        if (assocSlot == common::collections::SlotPool::INVALID)
            return false;   // first send on this flow: the ordinary path creates the association


        FlowTable::BatchAdmit admitted =
            flows_.AppendToBatch(assocSlot, *packet, internal::MAX_WIRE_PACKET_SIZE);

        if (admitted == FlowTable::BatchAdmit::Sealed)
        {
            // Full. Send what is there, then this message opens the next batch.
            status = FlushOneBatch(to, assocSlot);
            if (status != common::Error::Ok) return true;
            admitted = flows_.AppendToBatch(assocSlot, *packet, internal::MAX_WIRE_PACKET_SIZE);
        }

        if (admitted != FlowTable::BatchAdmit::Appended)
        {
            // A flush is carrying this batch, so the message cannot join it and
            // cannot go around it either: the batch has not been given its
            // sequence yet, and anything sent now would take a lower one and
            // arrive first. Refused instead, which is the answer the caller
            // already handles, and the flush it is waiting on is in progress.
            status = common::Error::TooManyPending;
            return true;
        }

        status = common::Error::Ok;
        return true;
    }

    bool Socket::FlushFlowOf(const Address& to, uint16_t flowId)
    {
        uint32_t assocSlot = common::collections::SlotPool::INVALID;
        {
            PeerHandle peerHandle = peers_.GetPeer(to);
            if (peerHandle.Failed() || !peerHandle.Read()) return true;
            assocSlot = flows_.FindOutAssoc(peerHandle.GetSlotIndex(), flowId);
        }
        if (assocSlot == common::collections::SlotPool::INVALID) return true;

        (void)FlushOneBatch(to, assocSlot);

        // Emptied is the only answer that lets the caller go around the batch.
        // Another thread's flush may hold it, or the gate may have refused it,
        // and in both cases something is still queued ahead of the caller.
        FlowMode mode = FlowMode::RELIABLE_ORDERED;
        return !flows_.PeekBatch(assocSlot, mode);
    }

    Socket::SealedBatch Socket::SealOneBatch(const Address& to, uint32_t assocSlot,
                                             common::Error& status)
    {
        status = common::Error::Ok;

        // The slot comes first, then the batch. Taking the batch empties it, so
        // a dry pool after that point would throw away messages the caller was
        // told had been accepted. This way a dry pool simply leaves the batch
        // where it is, to go out on the next flush.
        FlowMode mode = FlowMode::RELIABLE_ORDERED;
        if (!flows_.PeekBatch(assocSlot, mode)) return {};

        // A reliable batch is its own retransmit source and must outlive the
        // send, so it goes to staging. An unreliable one is gone once on the
        // wire and takes an ordinary kernel slot. Acquired with no peer lock
        // held, since a slot lock is taken before a peer lock, never after.
        common::Result<PacketSlotWriter> out = mode == FlowMode::UNRELIABLE
            ? kernel_->Write() : flows_.AcquireStagingWriter();
        if (out.isErr()) { status = out.error; return {}; }   // batch untouched

        PacketSlotHandle handle = std::move(out.Take()).ExtractHandle();
        PacketSlot* slot = handle.Write();
        if (!slot) { status = common::Error::InvalidState; return {}; }

        // Gather under the borrow, seal after it closes.
        FlowMode taken = mode;
        uint16_t size  = 0;
        {
            PeerHandle peerHandle = peers_.GetPeer(to);
            if (peerHandle.Failed() || !peerHandle.Read()) return {};
            size = flows_.TakeBatch(assocSlot, slot->data,
                                    internal::MAX_WIRE_PACKET_SIZE, taken);
        }
        if (size == 0) return {};   // nothing taken, so nothing to finish

        // Past here the batch is in flight and MUST be finished on every path
        // out, or it stays that way and the flow refuses every later append and
        // every later flush.
        if (taken != mode)
        {
            // Recycled under us, so the slot came from the wrong pool. Give the
            // batch back rather than send it to the wrong place.
            flows_.FinishBatch(assocSlot, size, false);
            status = common::Error::InvalidState;
            return {};
        }

        slot->dataSize = size;
        slot->address  = to;

        // SealForSend, not Send: this came out of a batch and offering it back
        // to the one it came from would loop.
        SealedBatch sealed;
        sealed.packet    = sender_.SealForSend(std::move(handle), status);
        sealed.assocSlot = assocSlot;
        sealed.size      = size;

        // No packet back means the gate consumed it, parked behind a handshake
        // when the status is Ok and refused otherwise. It will never reach
        // SendSealed, so the batch is settled here instead.
        if (!sealed.packet.Read())
        {
            flows_.FinishBatch(assocSlot, size, status == common::Error::Ok);
            return {};
        }
        return sealed;
    }

    uint32_t Socket::SendSealed(SealedBatch* sealed, uint32_t count)
    {
        if (count == 0) return 0;

        ISocketKernel::Outgoing wire[MAX_FLUSH_PER_PEER];
        for (uint32_t i = 0; i < count; ++i)
        {
            const PacketSlot* packet = sealed[i].packet.Read();
            assert(packet && "a sealed batch holds its wire slot until here");
            wire[i].target = &packet->address.addr;
            wire[i].data   = packet->data;
            wire[i].size   = packet->dataSize;
        }

        // One call, so a backend that can put several datagrams out per syscall
        // does. What it reports back is a count from the first, not a mask.
        const uint32_t sent = kernel_->SendBatch(wire, count);

        // Only now is a batch spent. A refusal means nothing of it reached the
        // wire, so it stays in place for a later flush rather than discarding
        // messages the caller was told had been accepted. Either way the flush
        // is over, and saying so is what stops one refusal wedging the flow.
        for (uint32_t i = 0; i < count; ++i)
            flows_.FinishBatch(sealed[i].assocSlot, sealed[i].size, i < sent);

        return sent;
    }

    common::Error Socket::FlushOneBatch(const Address& to, uint32_t assocSlot)
    {
        common::Error status = common::Error::Ok;
        SealedBatch sealed = SealOneBatch(to, assocSlot, status);
        if (!sealed.packet.Read()) return status;

        return SendSealed(&sealed, 1) == 1 ? common::Error::Ok
                                           : common::Error::IoFailed;
    }

    void Socket::Flush()
    {
        if (!initialized_.load(std::memory_order_acquire) || !flows_.SendEnabled())
            return;

        uint32_t cursor = 0;
        for (;;)
        {
            Address batch[32];
            const uint32_t count = peers_.CollectAddresses(cursor, batch, 32);
            if (count == 0) break;

            for (uint32_t b = 0; b < count; ++b)
            {
                // One borrow per peer, not one per flow. Which associations are
                // holding anything is decided here under that single borrow,
                // and only those are sealed afterwards with nothing held. A
                // flush on a socket with nothing waiting costs a peer read and
                // a handful of association reads, which matters because this is
                // called every time round the caller's loop.
                uint32_t holding[MAX_FLUSH_PER_PEER];
                uint32_t holdingCount = 0;
                {
                    PeerHandle peerHandle = peers_.GetPeer(batch[b]);
                    if (peerHandle.Failed() || !peerHandle.Read()) continue;
                    const uint32_t peerSlot = peerHandle.GetSlotIndex();
                    for (uint32_t i = 0; i < flows_.MaxOutPerPeer()
                                      && holdingCount < MAX_FLUSH_PER_PEER; ++i)
                    {
                        const uint32_t assocSlot = flows_.OutAssocAt(peerSlot, i);
                        if (assocSlot == common::collections::SlotPool::INVALID) continue;
                        FlowMode mode = FlowMode::RELIABLE_ORDERED;
                        if (flows_.PeekBatch(assocSlot, mode)) holding[holdingCount++] = assocSlot;
                    }
                }

                // Seal them all, then hand the peer's whole round to the kernel
                // at once. They go to one address, which is the case sendmmsg
                // and its equivalents are for.
                SealedBatch sealed[MAX_FLUSH_PER_PEER];
                uint32_t ready = 0;
                for (uint32_t k = 0; k < holdingCount; ++k)
                {
                    common::Error status = common::Error::Ok;
                    SealedBatch one = SealOneBatch(batch[b], holding[k], status);
                    if (one.packet.Read()) sealed[ready++] = std::move(one);
                }
                (void)SendSealed(sealed, ready);
            }
        }
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
        const bool keepsBodyForResend = hasFlow && flows_.IsRetainedBody(pHandle);

        // One peer WRITE lock, taken directly: NO read-then-upgrade, so no gap
        // in which a racing RemovePeer could invalidate the peer between an
        // IsValid read and the material gather. The valid check, the flow
        // admission, and the gather all run under this one lock; it drops with
        // the scope before the AEAD seal, so the peer is never locked across the
        // encrypt. The flow is admitted here too: AdmitOut is lent this
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

                // A handshake in flight decides where the packet waits, not
                // whether it is accepted. A retained body is admitted to its
                // flow either way, so the flow counts it as sent from here on
                // and the congestion gate answers the caller now rather than
                // the packet being refused later with nobody left to tell.
                const bool sessionUp = peer->IsValid();

                // Authentication is a property of an established session, so a
                // packet waiting on a handshake carries the requirement and is
                // judged once the peer has proved itself.
                if (sessionUp && requireAuth && !peer->authenticated)
                {
                    status = common::Error::NotAuthenticated;
                    return PacketSlotHandle::Invalid();
                }
                if (!packet->IsSecure())
                {
                    if (!sessionUp)
                    {
                        status = pending::Push(pendingPool_, peerHandle, *packet,
                                               requireAuth, keepsBodyForResend);
                        return PacketSlotHandle::Invalid();
                    }
                    return pHandle;   // established, unsecured: flies plain
                }

                const uint16_t minSize = packet->IsTagged()
                    ? internal::WIRE_SECURE_HEAD_SIZE + internal::WIRE_PEER_TAG_SIZE
                    : internal::WIRE_SECURE_HEAD_SIZE;
                if (packet->dataSize < minSize)
                {
                    status = common::Error::Malformed;
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
                    if (keepsBodyForResend && sessionUp)
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
                    const SendAdmission admission = flows_.AdmitOut(
                        *peer, peerHandle.GetSlotIndex(), *writable,
                        pHandle.GetSlotIndex(), writable->dataSize, sessionUp,
                        common::MonotonicMicros());
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
                // Waiting on the handshake. A retained body needs no pending
                // copy: it is in staging with an in-flight entry that owns it,
                // and the retransmit pass carries it once the session opens.
                // Everything else has nowhere else to live, so it parks.
                if (!sessionUp)
                {
                    if (keepsBodyForResend)
                        (void)pHandle.Detach();
                    else
                        status = pending::Push(pendingPool_, peerHandle, *packet,
                                               requireAuth, keepsBodyForResend);
                    return PacketSlotHandle::Invalid();
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
                ? internal::WIRE_SECURE_HEAD_SIZE + internal::WIRE_PEER_TAG_SIZE
                : internal::WIRE_SECURE_HEAD_SIZE;
            const size_t bodyLen = writable->dataSize - headerSize;

            // A reliable body is its own retransmit source: the ciphertext goes
            // to the wire slot and the plaintext slot stays leased, held by the
            // ring until the seq resolves. Everything else seals in place.
            const bool macOnly = writable->IsMacOnly();

            if (keepsBodyForResend)
            {
                wirePacket->address  = writable->address;
                wirePacket->dataSize = writable->dataSize;
                // MAC-only covers the whole datagram, so the copy is the whole
                // datagram rather than just the header the seal would rewrite.
                std::memcpy(wirePacket->data, writable->data,
                            macOnly ? writable->dataSize : headerSize);
                if (macOnly)
                    SealMacOnlyPacket(*wirePacket, headerSize, bodyLen, materials, tagged);
                else
                    SealSecurePacket(*wirePacket, writable->data + headerSize, headerSize,
                                     bodyLen, materials, tagged);
                common::crypto::Wipe(materials.key.data(), materials.key.size());
                (void)pHandle.Detach();   // the ring owns the staging slot now
                return wireHandle;
            }

            if (macOnly)
                SealMacOnlyPacket(*writable, headerSize, bodyLen, materials, tagged);
            else
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
        // The peer exists now, mid-handshake, which is a case handled above.
        // Running it again rather than repeating that handling here is what
        // keeps one admission path: the retry cannot loop, because Connect
        // either produced the peer or returned an error.
        if (peers_.GetPeer(address).Failed())
        {
            status = common::Error::NotFound;
            return PacketSlotHandle::Invalid();
        }
        return PreProcessOut(std::move(pHandle), status, requireAuth);
    }

    bool Socket::SealStagingToWire(const Address& to, const PacketSlot& staging,
                                    const PeerSendMaterials& materials)
    {
        const bool tagged = staging.IsTagged();
        const size_t headerSize = tagged
            ? internal::WIRE_SECURE_HEAD_SIZE + internal::WIRE_PEER_TAG_SIZE
            : internal::WIRE_SECURE_HEAD_SIZE;
        if (staging.dataSize < headerSize
            || staging.dataSize > internal::MAX_WIRE_PACKET_SIZE)
            return false;

        common::Result<PacketSlotWriter> out = kernel_->Write();
        if (out.isErr()) return false;   // send pool dry: nothing went anywhere
        PacketSlotHandle wireHandle = std::move(out.Take()).ExtractHandle();
        PacketSlot* wire = wireHandle.Write();
        if (!wire) return false;

        // Fresh nonce, current tag, current address `to`; the body's seq is
        // whatever the caller left there. The caller's lock on the staging
        // slot keeps the bytes stable across the copy and seal.
        wire->address  = to;
        wire->dataSize = staging.dataSize;
        const size_t bodyLen = staging.dataSize - headerSize;
        if (staging.IsMacOnly())
        {
            std::memcpy(wire->data, staging.data, staging.dataSize);
            SealMacOnlyPacket(*wire, headerSize, bodyLen, materials, tagged);
        }
        else
        {
            std::memcpy(wire->data, staging.data, headerSize);
            SealSecurePacket(*wire, staging.data + headerSize, headerSize, bodyLen,
                             materials, tagged);
        }

        return kernel_->SendTo(wire->address.addr, wire->data, wire->dataSize)
               == common::Error::Ok;
    }

    bool Socket::ResendStaging(const Address& to, uint32_t flowSlot, uint32_t stagingSlot,
                                uint32_t expectedSeq, const PeerSendMaterials& materials)
    {
        // The staging slot travels as a bare index; touchable only through a
        // handle. The ring owns the lease, so the handle is DETACHED at every
        // exit. Handle read-lock first, THEN flow (staging->peer->flow order).
        PacketSlotHandle stagingHandle{stagingSlot, flows_.StagingPool()};
        const PacketSlot* staging = stagingHandle.Read();
        if (!staging) return false;

        // Validate the ring still owns this slot at this seq: a concurrent ack
        // may have resolved it (and recycled the slot) since the caller scanned.
        // A seq the ring no longer owns was resolved while this pass ran. That
        // is not a failed attempt, and the entry it would refund no longer
        // exists, so it reports sent.
        bool sent = true;
        if (flows_.ResendStillValid(flowSlot, expectedSeq, stagingSlot))
            sent = SealStagingToWire(to, *staging, materials);
        (void)stagingHandle.Detach();   // the ring keeps the lease
        return sent;
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

        constexpr size_t headerSize = internal::WIRE_SECURE_HEAD_SIZE
                                    + internal::WIRE_PEER_TAG_SIZE;
        const size_t bodyLen = packet->dataSize - headerSize;
        SealSecurePacket(*packet, packet->data + headerSize, headerSize, bodyLen,
                         materials, true);

        // Straight to the wire, already sealed. Routing it back through
        // PreProcessOut would treat this camouflaged packet as fresh app data.
        (void)kernel_->SendTo(packet->address.addr, packet->data, packet->dataSize);
    }

// --- Receive path ---

    void Socket::ReceiveIntoPool()
    {
        // Per-pass migration budget on this thread's stack. Several threads may
        // drive the socket at once, so the budget must not be a shared member.
        // The immutable per-socket ceiling seeds a fresh local each pass.
        uint32_t migrateBudget = migrateBudgetPerPoll_;

        // Pull from the kernel and decrypt in place, consume handshake and
        // secure-control traffic, and push every committed app packet onto the
        // ready queue for Poll to hand over. Every slot taken here is consumed:
        // queued, held, or dropped.
        //
        // Bounded by the batch rather than by anything a caller asked for,
        // because emptying the OS buffer is the point. What can actually be
        // taken is bounded by the free recv slots regardless, and a peer's share
        // of those is bounded by its grant.
        PacketSlotHandle inbox[internal::RECV_CHUNK];
        for (uint32_t taken = 0; taken < recvBatch_; )
        {
        const uint32_t count = listener_.Poll(inbox, internal::RECV_CHUNK);
        if (count == 0) break;   // socket empty, nothing left to take this tick
        taken += count;
        for (size_t scan = 0; scan < count; ++scan)
        {
            const PacketSlot* packet = inbox[scan].Read();
            if (!packet) continue;   // failed handle, drop

            if (packet->IsInternal())
            {
                // Handshake traffic is never encrypted; an internal packet
                // claiming to be secure is forged or corrupt. Secure control
                // hides in the encrypted channel byte, not this bit.
                if (packet->IsSecure()) continue;
                ProcessInternal(std::move(inbox[scan]));
                continue;
            }

            // Authenticate and decrypt in place; drop on any failure.
            if (!PreProcessIn(inbox[scan], migrateBudget))
                continue;

            // The plaintext now reveals data vs. control; control is consumed
            // here, never delivered.
            if (packet->SecureChannel() != internal::SECURE_CHANNEL_APP)
            {
                ProcessSecureControl(std::move(inbox[scan]));
                continue;
            }

            // Flow packets go through dedupe/order/hold-back; non-flow app
            // packets are the unreliable baseline: queue on arrival. A full
            // queue leaves the packet uncommitted (unacked) and it drops.
            if (packet->HasFlow())
                (void)ProcessFlowIn(std::move(inbox[scan]));
            else
                (void)QueueReady(inbox[scan]);
        }
        }
    }

    void Socket::RecordPeerEvent(Peer& peer, uint32_t peerSlot, SocketEvent what) noexcept
    {
        // The caller holds this peer's write lock, so the flag is set through
        // the peer it already has. Asking the table for the lock again would be
        // the re-acquire that self-deadlocks.
        if (events_.Record(EventScope::PEER, peerSlot, readyLanes_.LaneOf(peerSlot),
                           what, peer.addr, internal::INVALID_FLOW_ID))
            peer.emitting = true;
    }

    void Socket::OnEventDelivered(void* context, EventScope scope, uint32_t slot) noexcept
    {
        // The slot may have been torn down while its event waited, in which
        // case the teardown left the lease alone for this moment.
        Socket& socket = *static_cast<Socket*>(context);
        if (scope == EventScope::PEER) socket.peers_.ClearEmitting(slot);
        else                           socket.flows_.ClearEmitting(scope, slot);
    }

    PollCursor Socket::Poll(PacketSlotHandle* outPackets, size_t max,
                            ThreadIdentity identity)
    {
        if (!initialized_.load(std::memory_order_relaxed))
            return PollCursor{nullptr, ReadyLanes::NO_LANE, outPackets, 0};

        // Delivery only. Reception happens in Update, which is what empties the
        // OS buffer into the recv pool and applies the receive rules there. A
        // packet's slot stayed leased in the recv pool while queued, so rebuild
        // a handle over it. Leftovers stay queued for the next Poll. Delivered
        // handles are stamped with this socket, which is what lets
        // PrepareResponse build a reply from the packet alone.
        // Claim before draining, and the cursor holds it until the caller is
        // done reading. A lane nobody claims is simply taken by whichever
        // thread arrives next, so no lane silts up because a thread stopped
        // calling, and preferring the caller's last lane keeps a thread on one
        // lane while nothing contends.
        const uint32_t lane = readyLanes_.ClaimLane(identity.lane);
        if (lane == ReadyLanes::NO_LANE)
            return PollCursor{nullptr, ReadyLanes::NO_LANE, outPackets, 0};

        // Before the packets, and only for this lane. An event about a peer
        // reaches the thread that handles that peer's traffic, so an
        // application holding per-peer state without a lock keeps it. Holding
        // the lane across a handler is what makes that exact rather than
        // usually right, and it is also what keeps a second thread out of these
        // entries.
        events_.Dispatch(lane, &Socket::OnEventDelivered, this);

        size_t delivered = 0;
        ReadyEntry ready{};
        while (delivered < max && readyLanes_.Pop(lane, ready))
        {
            // Out of the lane and into the caller's hands, so it stops counting
            // against the peer that sent it. Non-flow packets are unattributed
            // and never counted, so there is nothing to give back for them.
            if (ready.peerSlot != common::collections::SlotPool::INVALID)
            {
                peerRecvStates_[ready.peerSlot].ReleaseOne();
                heldTotal_.fetch_sub(1, std::memory_order_relaxed);
            }
            outPackets[delivered] = PacketSlotHandle{ ready.slotIndex, recvPool_ };
            outPackets[delivered].BindSocket(this);
            ++delivered;
        }

        return PollCursor{&readyLanes_, lane, outPackets, static_cast<uint32_t>(delivered)};
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
            ? internal::WIRE_SECURE_HEAD_SIZE + internal::WIRE_PEER_TAG_SIZE
            : internal::WIRE_SECURE_HEAD_SIZE;
        if (packet->dataSize < headerSize)
            return false;

        common::crypto::SessionKey key;
        common::crypto::SessionKey headerKey;
        common::crypto::SessionKey macKey;
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
            macKey = peer->macKey;
            senderLane = LaneFrom(peer->theirPk);
        }

        PacketSlot* writablePacket = pHandle.Write();
        if (!writablePacket)
        {
            common::crypto::Wipe(key.data(), key.size());
            common::crypto::Wipe(headerKey.data(), headerKey.size());
            common::crypto::Wipe(macKey.data(), macKey.size());
            return false;
        }

        // The counter is masked on the wire, so the open is what recovers it;
        // it then feeds the replay check below. A MAC-only packet is verified
        // rather than decrypted, and everything past this point is identical
        // because the two share a layout.
        uint64_t counter = 0;
        const bool opened = writablePacket->IsMacOnly()
            ? OpenMacOnlyPacket(*writablePacket, macKey, headerKey, counter)
            : OpenSecurePacket(*writablePacket, key, headerKey, senderLane, counter);
        common::crypto::Wipe(key.data(), key.size());
        common::crypto::Wipe(headerKey.data(), headerKey.size());
        common::crypto::Wipe(macKey.data(), macKey.size());
        if (!opened)
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

            // The peer has now opened something under the session key, which is
            // the first proof that the identity bound to this slot is the one
            // that holds the key. Handshake_Validate refuses to disturb a peer
            // past this point.
            peer->confirmed = true;

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

        PacketSlotReader reader{pHandle};
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
            case internal::SECURE_CHANNEL_GRANT:          Grant_Update(from, buf, plen);   break;
            case internal::SECURE_CHANNEL_GRANT_ACK:      Grant_Acked(from, buf, plen);    break;
            case internal::SECURE_CHANNEL_FLOW_ACK:       Flow_Ack(from, buf, plen);       break;
            default: break;   // unknown channel: authenticated but unhandled, drop
        }
    }

    bool Socket::QueueReady(PacketSlotHandle& handle)
    {
        const uint32_t idx = handle.GetSlotIndex();
        if (idx == common::collections::SlotPool::INVALID) return false;
        const PacketSlot* packet = handle.Read();
        if (!packet) return false;
        // A non-flow packet carries no sequence, so there is no order to keep.
        // Hashing the address only keeps one sender's traffic landing together.
        const uint32_t lane = readyLanes_.LaneOf(packet->address.hash());
        // No flow means no association and so no peer slot in hand. Attributing
        // it would cost a peer lookup on every non-flow packet, so this rides
        // unattributed and does not count against anyone's occupancy.
        if (!readyLanes_.Push(lane, idx, common::collections::SlotPool::INVALID))
            return false;   // full: backpressure, caller drops
        (void)handle.Detach();                      // queued; must not release the slot
        return true;
    }

    uint32_t Socket::ProcessFlowIn(PacketSlotHandle incoming)
    {
        if (!flows_.ReceiveEnabled()) return 0;
        const PacketSlot* packet = incoming.Read();
        if (!packet) return 0;

        const uint16_t flowId   = packet->FlowId();
        const uint32_t seq      = packet->FlowSeq();
        const uint8_t  flowData = packet->FlowData();
        const Address  from     = packet->address;
        if (flowId == internal::INVALID_FLOW_ID || seq == 0) return 0;

        // A batch is only as trustworthy as its length chain. Checked here,
        // before the flow machinery sees it, so a damaged one is never
        // committed to the seen bitmap and the sender resends it rather than
        // being told it arrived.
        if (packet->IsBatch()
         && !wire::BatchValidate(packet->Content(packet->ContentOffset()),
                                 static_cast<uint16_t>(packet->ContentLength())))
            return 0;

        uint32_t flowSlot  = common::collections::SlotPool::INVALID;
        uint32_t flowEpoch = 0;
        bool     reject    = false;
        PeerSendMaterials rejectMaterials;
        {
            PeerHandle peerHandle = peers_.GetPeer(from);
            if (peerHandle.Failed()) return 0;

            // Write, not read: registration mutates the peer's directory, and
            // the lock has to cover the lookup that decided it was absent.
            Peer* peer = peerHandle.Write();
            if (!peer || !peer->IsValid()) return 0;

            const uint32_t peerSlot = peerHandle.GetSlotIndex();
            const FlowAdmit admit = flows_.AdmitIn(peerSlot, from, peer->id, flowId,
                                                   flowData, flowSlot, flowEpoch);
            if (admit == FlowAdmit::Rejected)
            {
                // An undecodable flow data byte, or caps. Tell the sender so it
                // stops rather than retransmitting into silence.
                rejectMaterials = GatherSendMaterials(*peer);
                reject = true;
            }
            // Registered means this packet is the first of a flow the remote
            // opened. Existing says nothing new, and every later packet of the
            // same flow reports Existing. Recorded here, under the peer lock
            // that still holds the association's slot, so the entry it writes
            // is that association's own.
            // Marked while the peer lock is still held, so the teardown that
            // reads the mark cannot run between recording and marking.
            // Reopened is the same association numbering from one again, with
            // everything it held thrown away, so it is news in the same way a
            // first registration is.
            if (admit == FlowAdmit::Registered || admit == FlowAdmit::Reopened)
            {
                const SocketEvent what = admit == FlowAdmit::Registered
                    ? SocketEvent::INCOMING_FLOW_OPENED
                    : SocketEvent::INCOMING_FLOW_REOPENED;
                if (events_.Record(EventScope::IN_FLOW, flowSlot,
                                   readyLanes_.LaneOf(peerSlot), what, from, flowId))
                    flows_.MarkEmitting(EventScope::IN_FLOW, flowSlot);
            }
        }

        if (reject)
        {
            // The generation is echoed from the packet being refused, so the
            // sender can tell a refusal of this flow from one aimed at a
            // generation of the same id it has already closed.
            const uint8_t payload[3] = { static_cast<uint8_t>(flowId),
                                         static_cast<uint8_t>(flowId >> 8),
                                         FlowDataEpoch(flowData) };
            SendSecureControl(from, rejectMaterials, internal::SECURE_CHANNEL_FLOW_REJECT,
                              payload, sizeof(payload));
            common::crypto::Wipe(rejectMaterials.key.data(), rejectMaterials.key.size());
            return 0;
        }

        if (flowSlot == common::collections::SlotPool::INVALID) return 0;

        return flows_.DeliverIn(flowSlot, flowId, flowEpoch, seq, incoming);
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

            constexpr size_t headerSize = internal::WIRE_SECURE_HEAD_SIZE
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
            const bool moved = peers_.UpdateAddress(slot, from) == common::Error::Ok;
            SlideTagWindow(slot, session, theirLane, oldBase, newBase);
            common::crypto::Wipe(session.data(), session.size());

            // Recorded after the rebind and under a fresh borrow, because the
            // table ops above cannot run with a handle held, and because the
            // address worth reporting is the one it moved to.
            if (moved)
            {
                PeerHandle movedHandle = peers_.GetPeer(from);
                if (Peer* movedPeer = movedHandle.Failed() ? nullptr : movedHandle.Write())
                    RecordPeerEvent(*movedPeer, movedHandle.GetSlotIndex(),
                                    SocketEvent::PEER_MIGRATED);
            }
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

        // Handshake traffic bypasses the flow gate, so the only failure here
        // is a dry pool. A lost one is recovered by the handshake retry.
        (void)sender_.Send(std::move(writer).ExtractHandle());
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

        // Handshake traffic bypasses the flow gate, so the only failure here
        // is a dry pool. A lost one is recovered by the handshake retry.
        (void)sender_.Send(std::move(writer).ExtractHandle());
    }

    void Socket::Handshake_Respond(const Address& from, PacketSlotReader& reader)
    {
        uint64_t challenge = 0;
        if (!reader.TakeU64(challenge)) return;

        // This side's KDF salt contribution, remembered until the responder's
        // arrives with HS_FINISH.
        uint8_t saltI[internal::WIRE_HS_SALT_SIZE];
        if (!common::crypto::RandomBytes(saltI, sizeof(saltI))) return;

        // The throwaway pair, one per attempt. The public half travels, the
        // secret half waits on the peer for HS_FINISH and is wiped there.
        common::crypto::SecretKey ephSk;
        common::crypto::PublicKey ephPk;
        if (!common::crypto::GenerateKeypair(ephSk, ephPk)) return;

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
            peer->hsEphSecret = ephSk;
            peer->hsEphPub    = ephPk;
        }
        common::crypto::Wipe(ephSk.data(), ephSk.size());

        uint32_t initiatorCaps;
        BuildCapsBitmap(initiatorCaps);

        writer.WriteAddress(from);
        writer.PutU64(challenge);
        writer.PutBytes(publicKey_.data(), publicKey_.size());
        writer.PutBytes(ephPk.data(), ephPk.size());
        writer.PutBytes(saltI, sizeof(saltI));
        writer.PutU16(internal::VERSION);
        writer.PutU32(initiatorCaps);

        // Cover the whole message, keyed by the cookie the responder minted and
        // this side is echoing back. Both ends hold that value, so the check
        // costs no exchange, and it is the only thing standing between a
        // damaged public key and a peer entry bound to an identity nobody
        // holds. Appended last, so the range is one unbroken run.
        PacketSlotHandle resHandle = std::move(writer).ExtractHandle();
        {
            PacketSlot* raw = resHandle.Write();
            if (!raw) return;
            if (static_cast<size_t>(raw->dataSize) + internal::WIRE_HS_MAC_SIZE
                > internal::MAX_WIRE_PACKET_SIZE)
                return;

            common::crypto::Mac mac;
            common::crypto::ComputeMac(mac, CookieKey(challenge), raw->data, raw->dataSize);
            std::memcpy(raw->data + raw->dataSize, mac.data(), mac.size());
            raw->dataSize = static_cast<uint16_t>(raw->dataSize + internal::WIRE_HS_MAC_SIZE);
        }

        // Handshake traffic bypasses the flow gate, so the only failure here
        // is a dry pool. A lost one is recovered by the handshake retry.
        (void)sender_.Send(std::move(resHandle));
    }

    void Socket::Handshake_Validate(const Address& from, PacketSlotReader& reader)
    {
        uint64_t challenge = 0;
        common::crypto::PublicKey pk;
        common::crypto::PublicKey ephI;
        uint8_t saltI[internal::WIRE_HS_SALT_SIZE];
        uint16_t initiatorVersion{0};
        uint32_t initiatorCaps{0};
        if (!reader.TakeU64(challenge)) return;

        // The gate, first because it is the cheap one and it is what stops a
        // flood costing this socket anything.
        if (!challengeGenerator_.Verify(from.addr, challenge)) return;

        // Then integrity, before a single field is read out. Everything below
        // derives an identity from bytes this side did not choose, and a
        // corrupted key here is indistinguishable from a real one: it registers
        // a peer under an id nobody holds and locks the address out. Checking
        // first means a damaged message never reaches that code.
        {
            const PacketSlot* raw = reader.Packet();
            if (!raw || raw->dataSize < internal::WIRE_HS_MAC_SIZE) return;

            const size_t covered = raw->dataSize - internal::WIRE_HS_MAC_SIZE;
            common::crypto::Mac expected;
            common::crypto::ComputeMac(expected, CookieKey(challenge), raw->data, covered);
            if (!common::crypto::Equal(expected.data(), raw->data + covered,
                                       expected.size()))
                return;
        }

        if (!reader.TakeBytes(pk.data(), pk.size())) return;
        if (!reader.TakeBytes(ephI.data(), ephI.size())) return;
        if (!reader.TakeBytes(saltI, sizeof(saltI))) return;
        if (!reader.TakeU16(initiatorVersion)) return;
        if (!reader.TakeU32(initiatorCaps)) return;

        const BcpId id = BcpId::Derive(pk);

        bool established = false;   // answering a duplicate, not building anew
        bool repeat      = false;
        bool needBind    = false;
        bool unprovenId  = false;
        uint32_t slot    = 0;
        {
            PeerHandle existingHandle = peers_.GetPeer(from);
            if (existingHandle.Failed())
            {
                if (peers_.RegisterPeer(from, &id, slot) != common::Error::Ok)
                    return;   // table full; the initiator's retry will land later
                SeedPeerRecvState(slot);
            }
            else
            {
                const Peer* peer = existingHandle.Read();
                slot = existingHandle.GetSlotIndex();
                if (peer->IsValid())
                {
                    // Duplicate HS_RES, or the remote dropped this peer and is
                    // handshaking anew. The key must belong to the id we hold.
                    if (!(peer->id == id))
                    {
                        // Unless nothing here was ever proven. A responder
                        // establishes from HS_RES alone, and no part of that
                        // message is authenticated: the initiator cannot sign
                        // it, because it does not learn this side's key until
                        // HS_FINISH. So one corrupted or forged HS_RES binds an
                        // identity nobody holds, and refusing every later
                        // handshake would strand the address for good. A peer
                        // that has opened a packet under the session key is
                        // kept, because there the refusal is what stops an
                        // off-path rebind of a working session.
                        if (peer->confirmed) return;
                        unprovenId = true;
                    }
                    else
                    {
                        // Same ephemeral means the same attempt arriving twice,
                        // so the answer already sent is the only correct one. A
                        // different ephemeral is a fresh attempt, and it re-keys
                        // only an unconfirmed peer. A confirmed session has been
                        // proven live, and no part of an HS_RES is authenticated,
                        // so letting one re-key it would let an on-path forgery
                        // replace a working session with garbage nobody can open.
                        // A live peer changes only by migration; a dead one is
                        // reconnected to after its entry idles out.
                        repeat = common::crypto::Equal(peer->hsPeerEph.data(),
                                                       ephI.data(), ephI.size());
                        if (!repeat && peer->confirmed) return;
                        established = repeat;
                    }
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

        // Dropped rather than rebound in place, because the id index still
        // holds the claimed one and BindId refuses a slot that already carries
        // an id. Removing it frees both, and the initiator is already
        // retrying, so its next HS_RES registers cleanly. Done outside the
        // handle scope above: the table refuses a removal with a handle held.
        if (unprovenId)
        {
            (void)RemovePeer(from);
            return;
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
        common::crypto::SessionKey tagSession{};
        uint32_t responderCaps;
        BuildCapsBitmap(responderCaps);

        common::crypto::PublicKey ephR;
        if (!established)
        {
            // A fresh attempt, so a fresh throwaway pair to answer it with. The
            // secret half never leaves this scope.
            common::crypto::SecretKey ephSk;
            if (!common::crypto::RandomBytes(saltR, sizeof(saltR))) return;
            if (!common::crypto::GenerateKeypair(ephSk, ephR)) return;

            BuildTranscript(transcript, pk, publicKey_, ephI, ephR, saltI, saltR, initiatorCaps, responderCaps, initiatorVersion, internal::VERSION, ownTag_);

            PeerHandle peerHandle = peers_.GetPeer(from);
            if (peerHandle.Failed())
            {
                common::crypto::Wipe(ephSk.data(), ephSk.size());
                return;
            }
            Peer* peer = peerHandle.Write();
            CommitSession(*peer, pk, ephSk, ephI, transcript, sizeof(transcript));
            RecordPeerEvent(*peer, peerHandle.GetSlotIndex(), SocketEvent::PEER_ESTABLISHED);
            common::crypto::Wipe(ephSk.data(), ephSk.size());   // the whole point

            common::crypto::ComputeMac(confirm, peer->session, transcript, sizeof(transcript));
            std::memcpy(peer->hsSalt, saltR, sizeof(saltR));

            // Enough to repeat this exact answer, and nothing that could
            // reconstruct the key. A duplicate HS_RES is replied to from here.
            peer->hsPeerEph = ephI;
            peer->hsEphPub  = ephR;
            std::memcpy(peer->hsConfirm, confirm.data(), sizeof(peer->hsConfirm));

            ReplayFor(peerHandle.GetSlotIndex()).Reset();   // fresh key -> remote's counter restarts at 0
            tagSession = peer->session;
            bindWindow = migration_;
        }
        else
        {
            // The same attempt arriving again, which means the answer was lost
            // rather than refused. Repeat it verbatim. Re-deriving is not an
            // option and re-keying is not either: the secret that made this
            // session was wiped at both ends when it was made, so the only
            // reachable key is the one already installed.
            PeerHandle peerHandle = peers_.GetPeer(from);
            if (peerHandle.Failed()) return;
            const Peer* peer = peerHandle.Read();
            std::memcpy(saltR, peer->hsSalt, sizeof(saltR));
            ephR = peer->hsEphPub;
            std::memcpy(confirm.data(), peer->hsConfirm, sizeof(peer->hsConfirm));
        }

        if (bindWindow)
        {
            // Clear any window a previous key left before binding this one. A
            // first establish holds none, so this is a no-op; a re-key holds a
            // window whose tags derive from the key just replaced, and dropping
            // them is the only correct move, so it is not conditional. Left
            // bound, they pile up in the shared tag index and eventually starve
            // every peer's migration.
            (void)peers_.UnbindTags(slot);
            BindTagWindow(slot, tagSession, LaneFrom(pk), 0);
        }
        common::crypto::Wipe(tagSession.data(), tagSession.size());

        common::Result<PacketSlotWriter> result = BuildInternal(SocketOpCode::HS_FINISH);
        if (result.isErr()) return;
        PacketSlotWriter writer = result.Take();

        writer.WriteAddress(from);
        writer.PutBytes(publicKey_.data(), publicKey_.size());
        writer.PutBytes(ephR.data(), ephR.size());
        writer.PutBytes(saltR, sizeof(saltR));
        writer.PutBytes(ownTag_.data(), ownTag_.size());
        writer.PutU16(internal::VERSION);
        writer.PutU32(responderCaps);
        writer.PutBytes(confirm.data(), confirm.size());

        // Handshake traffic bypasses the flow gate, so the only failure here
        // is a dry pool. A lost one is recovered by the handshake retry.
        (void)sender_.Send(std::move(writer).ExtractHandle());

        // Only a simultaneous handshake has anything parked on this side.
        FlushPending(from);
    }

    void Socket::Handshake_Complete(const Address& from, PacketSlotReader& reader)
    {
        common::crypto::PublicKey pk;
        common::crypto::PublicKey ephR;
        uint8_t saltR[internal::WIRE_HS_SALT_SIZE];
        Certificate::IdentityTag tag;
        uint16_t responderVersion;
        uint32_t responderCaps;
        common::crypto::Mac confirm;
        if (!reader.TakeBytes(pk.data(), pk.size())) return;
        if (!reader.TakeBytes(ephR.data(), ephR.size())) return;
        if (!reader.TakeBytes(saltR, sizeof(saltR))) return;
        if (!reader.TakeBytes(tag.data(), tag.size())) return;
        if (!reader.TakeU16(responderVersion)) return;
        if (!reader.TakeU32(responderCaps)) return;
        if (!reader.TakeBytes(confirm.data(), confirm.size())) return;

        const BcpId id = BcpId::Derive(pk);

        uint8_t saltI[internal::WIRE_HS_SALT_SIZE];
        common::crypto::SecretKey ephSk;
        common::crypto::PublicKey ephI;
        uint32_t slot = 0;
        {
            PeerHandle peerHandle = peers_.GetPeer(from);
            if (peerHandle.Failed()) return;
            const Peer* peer = peerHandle.Read();
            // Either waiting state accepts a FINISH, because the confirmation
            // MAC below is what authenticates it and the state only sequences.
            // A retry resets a peer to AWAITING_CHALLENGE to unwedge one stuck
            // on a lost FINISH, and on a path slower than the retry interval
            // that reset lands while a good FINISH is still in flight. A stale
            // one is refused regardless: answering a new challenge regenerates
            // the salt, which changes the transcript, which fails the MAC.
            if (peer->state != HandshakeState::AWAITING_FINISH
             && peer->state != HandshakeState::AWAITING_CHALLENGE) return;
            slot = peerHandle.GetSlotIndex();
            std::memcpy(saltI, peer->hsSalt, sizeof(saltI));   // our contribution
            ephSk = peer->hsEphSecret;
            ephI  = peer->hsEphPub;
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
        BuildTranscript(transcript, publicKey_, pk, ephI, ephR, saltI, saltR, initiatorCaps, responderCaps, internal::VERSION, responderVersion, tag);

        common::crypto::SessionKey session;
        DeriveSessionInto(session, pk, ephSk, ephR, transcript, sizeof(transcript));

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
            CommitSession(*peer, pk, ephSk, ephR, transcript, sizeof(transcript));
            RecordPeerEvent(*peer, peerHandle.GetSlotIndex(), SocketEvent::PEER_ESTABLISHED);
            std::memcpy(peer->announcedTag, tag.data(), tag.size());
            peer->authenticated = (match == CertStore::Match::Trusted);
            ReplayFor(peerHandle.GetSlotIndex()).Reset();   // fresh session -> remote's counter starts at 0

            // The session exists now, so the secret that made it must not.
            // Leaving it on the peer would keep the exchange reconstructible
            // for as long as the peer lives, which is the whole thing this
            // exists to prevent.
            common::crypto::Wipe(peer->hsEphSecret.data(), peer->hsEphSecret.size());
        }
        common::crypto::Wipe(ephSk.data(), ephSk.size());

        // Handle scope closed: bind the responder's tag window so its future
        // moves are recognizable from the first packet off a new address.
        if (migration_)
            BindTagWindow(slot, session, LaneFrom(pk), 0);
        common::crypto::Wipe(session.data(), session.size());

        FlushPending(from);
    }

    void Socket::CommitSession(Peer& peer, const common::crypto::PublicKey& theirPk,
                                const common::crypto::SecretKey& myEphSk,
                                const common::crypto::PublicKey& theirEphPk,
                                const uint8_t* transcript, size_t transcriptLen) noexcept
    {
        // The peer-commit core shared by Validate's establish branch and
        // Complete: bind the remote key, derive the session from the transcript,
        // and reset the per-session send state. Caller holds the peer's write
        // lock (the Peer is lent in) and owns the parts that need more than these
        // args: ReplayFor().Reset (needs the slot), and, in Complete, the
        // announced tag and authentication verdict.
        peer.theirPk = theirPk;
        DeriveSessionInto(peer.session, theirPk, myEphSk, theirEphPk, transcript, transcriptLen);
        // Split off the counter-masking key. The label is fixed and public; it
        // only has to differ from every other input the session key is ever
        // fed, so the two derivations cannot collide.
        static constexpr uint8_t HEADER_KEY_LABEL[16] = {
            'f','l','u','x','-','h','d','r','-','m','a','s','k',0,0,0
        };
        common::crypto::DeriveSubKey(peer.headerKey.data(), peer.session.data(),
                                     HEADER_KEY_LABEL);

        // Same mechanism, different label, so the two never share a domain.
        static constexpr uint8_t MAC_KEY_LABEL[16] = {
            'f','l','u','x','-','m','a','c','-','o','n','l','y',0,0,0
        };
        common::crypto::DeriveSubKey(peer.macKey.data(), peer.session.data(),
                                     MAC_KEY_LABEL);
        peer.sendCounter  = 0;
        peer.myTagStep    = 0;
        peer.theirTagStep = 0;
        // A secure channel exists from here, so this is the first moment a
        // grant can be told to anyone, and the tick does the sending.
        // Generation advances rather than resetting, because the remote
        // compares against what it already applied and a restart at zero would
        // read as stale.
        //
        // A socket that grants no limit announces nothing. There is no value to
        // carry, and staying silent is what keeps an unconfigured socket byte
        // for byte what it was before grants existed.
        if (recvGrant_ != 0)
        {
            ++peer.ourGrantGeneration;
            peer.grantSendPending  = true;
            peer.grantSentAtMicros = 0;   // send at the next tick, not one RTO later
        }
        peer.myTag        = DerivePeerTag(peer.session, LaneTo(theirPk), 0);
        peer.state        = HandshakeState::ESTABLISHED;
        // The acknowledgement silence clock starts here, so a peer that never
        // acknowledges anything still has a defined death, measured from the
        // moment it could first have answered.
        peer.rtt.MarkAcked(common::MonotonicMicros());
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
                    ? flows_.AcquireStagingWriter()
                    : kernel_->Write();
                if (result.isOk())
                {
                    PacketSlotWriter writer = result.Take();
                    writer.WriteAddress(pending->address);
                    writer.PutBytes(pending->data, pending->dataSize);
                    // Nothing parked here is owed delivery. A reliable flow
                    // packet was admitted when it was accepted and waits in
                    // staging with an in-flight entry, so it never reaches this
                    // list, and a refusal is the caller's to see at that point
                    // rather than something to discover here.
                    (void)sender_.Send(std::move(writer).ExtractHandle(),
                                       pending->requireAuth != 0);
                }
                pendingPool_.Release(batch[i]);
            }

            if (count < 32) return;
        }
    }

    // --- Flow control-plane (open/close) ---

    FlowHandle Socket::OpenFlow(uint16_t flowId, FlowMode mode)
    {
        if (!initialized_.load(std::memory_order_acquire) || !flows_.SendEnabled())
            return FlowHandle{common::Error::NotInitialized};

        return flows_.Open(flowId, mode);
    }

    common::Error Socket::CloseFlow(const FlowHandle& flow)
    {
        if (!initialized_.load(std::memory_order_acquire) || !flows_.SendEnabled())
            return common::Error::NotInitialized;

        // Anything still sitting in a batch goes now. Its association is about
        // to be torn down and the batch would go with it, which on a reliable
        // flow would silently lose messages the caller was told were accepted.
        Flush();

        if (!flows_.BeginClose(flow))
            return common::Error::InvalidState;   // stale handle, or already closing

        const uint32_t flowSlot = flow.Slot();

        for (;;)
        {
            Address peerAddr;
            BcpId   peerId{};
            uint32_t assocSlot = common::collections::SlotPool::INVALID;
            if (!flows_.NextAssocToClose(flowSlot, peerAddr, peerId, assocSlot))
                break;

            const bool byId = !(peerId == BcpId{});
            PeerHandle peerHandle = byId ? peers_.GetPeer(peerId)
                                         : peers_.GetPeer(peerAddr);
            Peer* owner = peerHandle.Failed() ? nullptr : peerHandle.Write();
            if (owner)
                flows_.UnpublishOut(peerHandle.GetSlotIndex(), assocSlot);

            // The unlink inside FreeAssoc is what advances this loop. A null
            // owner means the peer is already gone, so the refund is dropped
            // with it and only the drain runs.
            flows_.FreeAssoc(assocSlot, owner);
        }

        flows_.FinishClose(flowSlot);

        return common::Error::Ok;
    }

    FlowLifecycle Socket::GetFlowState(const FlowHandle& flow)
    {
        if (!initialized_.load(std::memory_order_acquire))
            return FlowLifecycle::CLOSED;

        return flows_.StateOf(flow);
    }

    FlowLifecycle Socket::GetFlowState(const FlowHandle& flow, const Address& peer)
    {
        // Where failure lives: a target that rejected or stopped answering
        // reads FAILED while the flow stays OPEN for the rest.
        if (GetFlowState(flow) == FlowLifecycle::CLOSED || !flows_.SendEnabled())
            return FlowLifecycle::CLOSED;

        PeerHandle peerHandle = peers_.GetPeer(peer);
        if (peerHandle.Failed() || !peerHandle.Read())
            return FlowLifecycle::CLOSED;

        return flows_.StateOf(flow, peerHandle.GetSlotIndex());
    }

    uint32_t Socket::ReceivingFlowCount(const Address& peer)
    {
        if (!flows_.ReceiveEnabled()) return 0;

        PeerHandle peerHandle = peers_.GetPeer(peer);
        if (peerHandle.Failed() || !peerHandle.Read())
            return 0;

        return flows_.InAssocCountForPeer(peerHandle.GetSlotIndex());
    }

    void Socket::SeedPeerRecvState(uint32_t slot) noexcept
    {
        peerRecvStates_[slot].Reset();   // a reused slot starts owing nothing
        peerRecvStates_[slot].grant.store(recvGrant_, std::memory_order_relaxed);
    }

    void Socket::ApplyGrant(uint32_t slot, Peer& peer, uint32_t value) noexcept
    {
        peerRecvStates_[slot].grant.store(value, std::memory_order_relaxed);
        ++peer.ourGrantGeneration;
        peer.grantSendPending  = true;
        peer.grantSentAtMicros = 0;   // go on the next tick, not one interval later
    }

    void Socket::CutGrantIfAbusive(PeerHandle peerHandle)
    {
        if (peerHandle.Failed()) return;
        const uint32_t slot = peerHandle.GetSlotIndex();
        PeerRecvState& state = peerRecvStates_[slot];

        if (state.stallReclaims.load(std::memory_order_relaxed)
            < internal::GRANT_STRIKES_BEFORE_CUT)
            return;

        // A peer with no limit has nothing to cut. Giving it one here would let
        // a lossy path invent a restriction the socket never configured.
        const uint32_t current = state.grant.load(std::memory_order_relaxed);
        if (current == 0)
        {
            state.stallReclaims.store(0, std::memory_order_relaxed);
            return;
        }

        uint32_t cut = current / internal::GRANT_CUT_DIVISOR;
        if (cut < internal::GRANT_CUT_FLOOR) cut = internal::GRANT_CUT_FLOOR;
        state.stallReclaims.store(0, std::memory_order_relaxed);
        if (cut >= current) return;   // already at the floor, nothing to say

        Peer* peer = peerHandle.Write();
        if (!peer) return;
        ApplyGrant(slot, *peer, cut);
        RecordPeerEvent(*peer, slot, SocketEvent::PEER_GRANT_CUT);
    }

    common::Error Socket::SetRecvGrant(const Address& peer, uint32_t slots)
    {
        if (!initialized_.load(std::memory_order_acquire))
            return common::Error::NotInitialized;

        PeerHandle peerHandle = peers_.GetPeer(peer);
        if (peerHandle.Failed()) return common::Error::NotFound;
        Peer* state = peerHandle.Write();
        if (!state) return common::Error::InvalidState;

        // In force from here. A peer already past the new figure is not made to
        // give anything back, it simply stops being buffered for until it
        // drains under it.
        ApplyGrant(peerHandle.GetSlotIndex(), *state, slots);
        return common::Error::Ok;
    }

    uint32_t Socket::RecvGrantFor(const Address& peer)
    {
        if (!initialized_.load(std::memory_order_acquire)) return 0;
        PeerHandle peerHandle = peers_.GetPeer(peer);
        if (peerHandle.Failed() || !peerHandle.Read()) return 0;
        return peerRecvStates_[peerHandle.GetSlotIndex()].grant.load(
            std::memory_order_relaxed);
    }

    void Socket::SendGrant(const Address& to, const PeerSendMaterials& materials,
                           uint32_t grant, uint32_t generation)
    {
        uint8_t payload[internal::WIRE_GRANT_PAYLOAD_SIZE];
        payload[0] = static_cast<uint8_t>(grant >> 0);
        payload[1] = static_cast<uint8_t>(grant >> 8);
        payload[2] = static_cast<uint8_t>(grant >> 16);
        payload[3] = static_cast<uint8_t>(grant >> 24);
        payload[4] = static_cast<uint8_t>(generation >> 0);
        payload[5] = static_cast<uint8_t>(generation >> 8);
        payload[6] = static_cast<uint8_t>(generation >> 16);
        payload[7] = static_cast<uint8_t>(generation >> 24);

        SendSecureControl(to, materials, internal::SECURE_CHANNEL_GRANT,
                          payload, sizeof(payload));
    }

    void Socket::Grant_Update(const Address& from, const uint8_t* payload, size_t len)
    {
        if (len < internal::WIRE_GRANT_PAYLOAD_SIZE) return;
        const uint32_t grant = static_cast<uint32_t>(payload[0])
                             | static_cast<uint32_t>(payload[1]) << 8
                             | static_cast<uint32_t>(payload[2]) << 16
                             | static_cast<uint32_t>(payload[3]) << 24;
        const uint32_t generation = static_cast<uint32_t>(payload[4])
                                  | static_cast<uint32_t>(payload[5]) << 8
                                  | static_cast<uint32_t>(payload[6]) << 16
                                  | static_cast<uint32_t>(payload[7]) << 24;

        PeerSendMaterials materials;
        {
            PeerHandle peerHandle = peers_.GetPeer(from);
            if (peerHandle.Failed()) return;
            Peer* peer = peerHandle.Write();
            if (!peer || !peer->IsValid()) return;

            // Wrap-safe ordering. A signed difference treats generation 0
            // arriving after 0xFFFFFFFF as newer, which it is, where a plain
            // comparison would freeze the value at the wrap.
            const int32_t age = static_cast<int32_t>(generation - peer->theirGrantGeneration);
            if (age > 0)
            {
                peer->theirGrantGeneration = generation;
                if (peer->theirGrant != grant)
                {
                    peer->theirGrant = grant;
                    RecordPeerEvent(*peer, peerHandle.GetSlotIndex(),
                                    SocketEvent::PEER_GRANT_CHANGED);
                }
            }
            materials = GatherSendMaterials(*peer);
        }

        uint8_t ack[internal::WIRE_GRANT_ACK_PAYLOAD_SIZE];
        ack[0] = static_cast<uint8_t>(generation >> 0);
        ack[1] = static_cast<uint8_t>(generation >> 8);
        ack[2] = static_cast<uint8_t>(generation >> 16);
        ack[3] = static_cast<uint8_t>(generation >> 24);
        SendSecureControl(from, materials, internal::SECURE_CHANNEL_GRANT_ACK,
                          ack, sizeof(ack));
        common::crypto::Wipe(materials.key.data(), materials.key.size());
    }

    void Socket::Grant_Acked(const Address& from, const uint8_t* payload, size_t len)
    {
        if (len < internal::WIRE_GRANT_ACK_PAYLOAD_SIZE) return;
        const uint32_t generation = static_cast<uint32_t>(payload[0])
                                  | static_cast<uint32_t>(payload[1]) << 8
                                  | static_cast<uint32_t>(payload[2]) << 16
                                  | static_cast<uint32_t>(payload[3]) << 24;

        PeerHandle peerHandle = peers_.GetPeer(from);
        if (peerHandle.Failed()) return;
        Peer* peer = peerHandle.Write();
        if (!peer) return;

        // Only the outstanding generation clears the flag. An ack for an older
        // one is a straggler from a value already superseded.
        if (peer->grantSendPending && generation == peer->ourGrantGeneration)
            peer->grantSendPending = false;
    }

    void Socket::SendPendingGrant(const Address& to, PeerHandle peerHandle, uint64_t now)
    {
        PeerSendMaterials materials;
        uint32_t generation = 0;
        uint32_t grant      = 0;
        {
            // The transferred handle is this function's to release: the gather
            // happens in this scope and the send after it, so the peer lock is
            // never held across the syscall.
            PeerHandle owned = std::move(peerHandle);
            if (owned.Failed()) return;
            Peer* peer = owned.Write();
            if (!peer || !peer->IsValid() || !peer->grantSendPending) return;

            // Paced like a retransmit. Without this the flag would put one op
            // on the wire every tick until the ack lands.
            if (peer->grantSentAtMicros != 0
                && now - peer->grantSentAtMicros < internal::HANDSHAKE_RETRY_DEFAULT)
                return;
            peer->grantSentAtMicros = now;

            generation = peer->ourGrantGeneration;
            grant      = peerRecvStates_[owned.GetSlotIndex()].grant.load(
                             std::memory_order_relaxed);
            materials  = GatherSendMaterials(*peer);
        }

        SendGrant(to, materials, grant, generation);
        common::crypto::Wipe(materials.key.data(), materials.key.size());
    }

    void Socket::Flow_Reject(const Address& from, const uint8_t* payload, size_t len)
    {
        // The remote refused to register one of OUR flows: it is at its caps,
        // and retrying the same flow would only ask again. Fail it so the app
        // sees the outcome through its handle, and drain what it was holding.
        if (!flows_.SendEnabled() || len < 3) return;
        const uint16_t flowId = static_cast<uint16_t>(payload[0])
                              | static_cast<uint16_t>(payload[1]) << 8;
        const uint8_t flowEpoch = payload[2] & FLOW_EPOCH_MASK;

        PeerHandle peerHandle = peers_.GetPeer(from);
        if (peerHandle.Failed()) return;
        Peer* peer = peerHandle.Write();
        if (!peer || !peer->IsValid()) return;

        const uint32_t flowSlot = flows_.FindOutAssoc(peerHandle.GetSlotIndex(), flowId);
        if (flowSlot == common::collections::SlotPool::INVALID) return;

        // A refusal outlives the flow it refused when the id is reopened
        // quickly, and failing the new association on it would take down a flow
        // the remote has never objected to.
        if (!flows_.OutAssocEpochIs(flowSlot, flowEpoch)) return;

        if (!flows_.FailAssoc(flowSlot, flowId, peer)) return;
        if (events_.Record(EventScope::OUT_FLOW, flowSlot,
                           readyLanes_.LaneOf(peerHandle.GetSlotIndex()),
                           SocketEvent::OUTGOING_FLOW_REFUSED, from, flowId))
            flows_.MarkEmitting(EventScope::OUT_FLOW, flowSlot);
    }

    void Socket::Flow_Ack(const Address& from, const uint8_t* payload, size_t len)
    {
        // Answers OUR sent packets: OUT side. Body is a run of
        // [flowId(2)][epoch(1)][rangeCount(1)][recvNext(4)][ackDelay(2)]
        // [first(4),last(4)]*count for one peer. The epoch names which
        // generation of that id the entry belongs to, and an entry naming any
        // other one resolves nothing. recvNext is the remote's delivery cursor:
        // everything below it has been handed to its application and can never
        // be asked for again. ackDelay is how long the remote sat on this reply
        // after the newest sequence it names arrived, which comes back out of
        // the round trip so what we measure is the path.
        if (!flows_.SendEnabled()) return;
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
        while (off + internal::WIRE_ACK_ENTRY_HEAD_SIZE <= len)
        {
            const uint16_t flowId = static_cast<uint16_t>(payload[off])
                                  | static_cast<uint16_t>(payload[off + 1]) << 8;
            const uint8_t flowEpoch = payload[off + 2] & FLOW_EPOCH_MASK;
            uint8_t rangeCount = payload[off + 3];
            const uint32_t remoteRecvNext = static_cast<uint32_t>(payload[off + 4])
                                          | static_cast<uint32_t>(payload[off + 5]) << 8
                                          | static_cast<uint32_t>(payload[off + 6]) << 16
                                          | static_cast<uint32_t>(payload[off + 7]) << 24;
            const uint16_t remoteAckDelay = static_cast<uint16_t>(payload[off + 8])
                                          | static_cast<uint16_t>(payload[off + 9]) << 8;
            off += internal::WIRE_ACK_ENTRY_HEAD_SIZE;
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

            flows_.ApplyAckRanges(peerSlot, *peerHandle.Read(), flowId, flowEpoch, remoteRecvNext,
                                  remoteAckDelay, ranges, rangeCount, now, ccDelta);
        }

        // Apply the gathered feedback once, on the same handle upgraded to
        // write. The upgrade drops the read lock before taking write, so the
        // peer is revalidated on the other side of the gap.
        Peer* peer = peerHandle.Write();
        if (peer && peer->IsValid()) ApplyCongestion(*peer, ccDelta, now);
    }

    void Socket::FlushPeerAcks(const Address& addr, PeerHandle peer)
    {
        if (!flows_.ReceiveEnabled()) return;

        uint8_t body[internal::MAX_WIRE_PACKET_SIZE];
        size_t  bodyLen = 0;

        // Peer materials, gathered under the handle before it drops.
        PeerSendMaterials materials;

        {
            // The transferred handle is this function's to release: everything
            // locked happens in this scope, the send after it, so the peer lock
            // is never held across the syscall.
            PeerHandle peerHandle = std::move(peer);
            if (peerHandle.Failed() || !peerHandle.Read()) return;

            bodyLen = flows_.BuildPeerAckBody(peerHandle.GetSlotIndex(), body, sizeof(body));
            if (bodyLen == 0) return;

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


    // --- Tick + peer management ---

    PeerHandle Socket::GetPeer(const Address& addr)
    {
        return peers_.GetPeer(addr);
    }

    common::Error Socket::RemovePeer(const Address& addr)
    {
        {
            PeerHandle peer = peers_.GetPeer(addr);
            if (peer.Failed())
                return common::Error::NotFound;
            pending::Clear(pendingPool_, peer);

            // The sweep mutates both directories, so it needs the peer's write
            // lock rather than the read lock above.
            if (Peer* dying = peer.Write())
            {
                // Recorded before the removal below, which is what leaves the
                // slot leased until this is read. Idle eviction and a handshake
                // that stopped answering both reach here too, so this one site
                // covers every way a peer goes away.
                RecordPeerEvent(*dying, peer.GetSlotIndex(), SocketEvent::PEER_LOST);
                if (flows_.SendEnabled() || flows_.ReceiveEnabled())
                    flows_.SweepPeer(peer.GetSlotIndex());
            }
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
        SeedPeerRecvState(slot);

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

        // A zero interval would make every tick a retry, so an unset timer
        // falls back to the protocol default rather than flooding.
        const uint32_t interval = handshakeRetryMicros_ != 0
            ? handshakeRetryMicros_ : internal::HANDSHAKE_RETRY_DEFAULT;
        const uint32_t retryStamps = interval >> internal::SEEN_STAMP_SHIFT;

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
                bool unreachable = false;
                {
                    PeerHandle peerHandle = peers_.GetPeer(batch[i]);
                    if (peerHandle.Failed()) continue;   // gone since the snapshot
                    Peer* peer = peerHandle.Write();
                    if (peer->IsValid()) continue;

                    if (peer->attempts >= internal::HANDSHAKE_MAX_ATTEMPTS)
                    {
                        unreachable = true;
                    }
                    else
                    {
                        // Attempt N is due one interval after attempt N-1,
                        // measured from registration, so a tick running far
                        // faster than the path's round trip does not flood.
                        // Read fresh and floored at zero: a peer registered
                        // during this same pass is younger than any stamp taken
                        // before it, and an unsigned wrap there would fire a
                        // retry immediately and restart a healthy handshake.
                        const uint32_t stampNow = SeenStamp(common::MonotonicMicros());
                        const uint32_t elapsed  = stampNow > peer->firstSeenAt
                            ? stampNow - peer->firstSeenAt : 0;
                        if (elapsed < static_cast<uint32_t>(peer->attempts + 1) * retryStamps)
                            continue;

                        // Back to square one: HS_CHLG is only answered from
                        // AWAITING_CHALLENGE, so a peer stuck waiting for a lost
                        // FINISH restarts cleanly instead of wedging.
                        peer->state = HandshakeState::AWAITING_CHALLENGE;
                        ++peer->attempts;
                    }
                }

                // Out of attempts: the peer never answered. Dropping it releases
                // what parked behind the handshake and fails its associations,
                // so the application sees the outcome instead of waiting on an
                // idle timeout that may be off.
                if (unreachable)
                {
                    (void)RemovePeer(batch[i]);
                    continue;
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

        // Before anything else: a handshake nobody finishes strands whatever
        // parked behind it, and the packet carrying it is the one thing here
        // that no retransmit covers, because a peer with no session has no
        // flow state to scan. Paced and bounded internally.
        // Before anything else on the tick: take what has arrived. Everything
        // below reasons about peer and flow state that this updates.
        ReceiveIntoPool();

        (void)RetryHandshakes();

        // No flow gate on the sweep: idle eviction is mandatory, so the per-peer
        // pass runs even on a socket with no flows. An empty peer table makes
        // the loop below break at once.

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
                bool jammed = false;
                {
                    PeerHandle peerHandle = peers_.GetPeer(addr);
                    if (peerHandle.Failed() || !peerHandle.Read()) continue;

                    // Idle check under the read borrow. Half-open peers use
                    // the same clock: registration stamped them, handshake
                    // chatter does not refresh (it is forgeable), so an entry
                    // that never completes gets a single timeout to live.
                    if (evicted < internal::MAX_EVICT_PER_UPDATE)
                    {
                        const Peer* alive = peerHandle.Read();
                        const uint32_t nowStamp = SeenStamp(Now(nowOverride));
                        const uint32_t idleFor  = nowStamp - alive->lastSeenAt;
                        if (idleFor > evictAfterStamp_) evictIdle = true;

                        // The second silence. A peer can stay alive on the
                        // receive clock, its data reaches us, while it
                        // acknowledges nothing we send. Retransmission cannot
                        // mend a session broken like that, and without this
                        // check it limps forever: flows fail, the application
                        // reopens them, and the loop never ends. Same timeout
                        // as the receive silence, ending in the same clear
                        // death, and the application answers PEER_LOST with a
                        // reconnect that rebuilds the state fresh.
                        if (!evictIdle
                            && alive->IsValid()
                            && alive->bytesInFlight > 0
                            && alive->rtt.SilentForMicros(Now(nowOverride))
                                   > idleTimeoutMicros_)
                            evictIdle = true;
                    }
                    if (!evictIdle && flows_.ReceiveEnabled())
                    {
                        const uint64_t now = Now(nowOverride);   // fresh for this peer
                        ackDue = flows_.AnyAckDue(peerHandle.GetSlotIndex(), now);
                        jammed = flows_.AnyJammed(peerHandle.GetSlotIndex(), now);
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

                // Judged before the announcement, so a cut decided on this tick
                // goes out on this tick rather than waiting for the next.
                CutGrantIfAbusive(peers_.GetPeer(addr));

                // Retried every tick until the peer acknowledges it, so a lost
                // announcement is not a peer that never learns its limit.
                SendPendingGrant(addr, peers_.GetPeer(addr), Now(nowOverride));

                // Out-flows: open/close retries with give-up, and reliable
                // retransmits / unreliable loss declarations past the RTO. Each
                // reads the clock fresh at entry.
                if (flows_.SendEnabled())
                {
                    for (uint32_t i = 0; i < flows_.MaxOutPerPeer(); ++i)
                        UpdateOutFlow(addr, peers_.GetPeer(addr), i, nowOverride);

                    // Capacity freed above (and by acks since the last tick)
                    // goes to the packets that have waited longest.
                    DrainWaitingSends(addr);
                }

                // A jammed receiving flow pins recv slots for a gap the sender
                // is not filling. Flagged read-only above, freed here under the
                // peer write lock, the same context the teardown sweep runs in,
                // so the flow locks nest peer -> flow. The free re-checks, since
                // a racing DeliverIn may have moved the cursor meanwhile.
                if (jammed)
                {
                    PeerHandle reclaimHandle = peers_.GetPeer(addr);
                    Peer* stalled = reclaimHandle.Failed() ? nullptr : reclaimHandle.Write();
                    if (stalled
                        && flows_.ReclaimJammedInFlows(reclaimHandle.GetSlotIndex(),
                                                       Now(nowOverride)) > 0)
                        RecordPeerEvent(*stalled, reclaimHandle.GetSlotIndex(),
                                        SocketEvent::PEER_FLOW_JAMMED);
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
        bool assocDead = false;   // owed packets, and nothing resolved for the whole bound
        uint16_t flowId = 0;
        uint32_t resendSlots[FlowTable::RESENDS_PER_ASSOC_PER_TICK];
        uint32_t resendSeqs[FlowTable::RESENDS_PER_ASSOC_PER_TICK];
        uint32_t resendN = 0;

        CongestionDelta ccDelta;   // loss gathered under the flow lock, applied under the peer's

        // One control materials + one per resend, each carrying its own fresh
        // counter; built under the peer write lock, sent (and wiped) after it drops.
        PeerSendMaterials ctrlMaterials;
        PeerSendMaterials resendMaterials[FlowTable::RESENDS_PER_ASSOC_PER_TICK];

        uint32_t flowSlot = common::collections::SlotPool::INVALID;
        {
            // The transferred handle is this function's to release: the flow
            // gather, the close finish, and the materials all juggle this one
            // peer lock, and it drops with the scope, before any send.
            PeerHandle peerHandle = std::move(peer);
            if (peerHandle.Failed()) return;
            const Peer* readPeer = peerHandle.Read();
            // A packet admitted while the handshake was still running sits in
            // an association with no session to seal it. Retransmits wait for
            // the session rather than burning attempts on a key that does not
            // exist yet.
            if (!readPeer || !readPeer->IsValid()) return;
            flowSlot = flows_.OutAssocAt(peerHandle.GetSlotIndex(), dirIndex);
            if (flowSlot == common::collections::SlotPool::INVALID) return;

            flows_.RetransmitPass(flowSlot, *readPeer, now, ccDelta, flowId, resendSeqs, resendSlots,
                                  resendN, assocDead);

            // The target stopped resolving this flow for the whole stall
            // bound: a clear death, reported through the event, rather than
            // probing into silence forever. Runs here because the teardown
            // needs the peer's write lock, after the association lock dropped
            // so the two never nest wrong.
            if (assocDead)
            {
                if (Peer* dying = peerHandle.Write())
                {
                    const bool justFailed = flows_.FailAssoc(flowSlot, flowId, dying);
                    if (justFailed && events_.Record(EventScope::OUT_FLOW, flowSlot,
                                       readyLanes_.LaneOf(peerHandle.GetSlotIndex()),
                                       SocketEvent::OUTGOING_FLOW_LOST, addr, flowId))
                        flows_.MarkEmitting(EventScope::OUT_FLOW, flowSlot);
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
        // An attempt is only spent when the bytes leave. A dry send pool or a
        // refused syscall costs the flow nothing, or a peer under load would
        // exhaust its retries against its own backpressure and fail a flow that
        // never had a packet dropped.
        uint32_t unsentSeqs[FlowTable::RESENDS_PER_ASSOC_PER_TICK];
        uint32_t unsentN = 0;
        for (uint32_t i = 0; i < resendN; ++i)
            if (!ResendStaging(addr, flowSlot, resendSlots[i], resendSeqs[i], resendMaterials[i]))
                unsentSeqs[unsentN++] = resendSeqs[i];
        if (unsentN > 0)
            flows_.RefundResendAttempts(flowSlot, unsentSeqs, unsentN);
        for (uint32_t i = 0; i < resendN; ++i)
            common::crypto::Wipe(resendMaterials[i].key.data(), resendMaterials[i].key.size());
    }

    void Socket::DrainWaitingSends(const Address& addr)
    {
        constexpr uint32_t DRAINS_PER_PEER_PER_TICK = 16;

        for (uint32_t sent = 0; sent < DRAINS_PER_PEER_PER_TICK; ++sent)
        {
            // Step 1, peek, read locks only: across this peer's flows, find
            // the OLDEST waiting head that passes the gate right now.
            FlowTable::WaitingCandidate candidate;
            {
                PeerHandle peerHandle = peers_.GetPeer(addr);
                if (peerHandle.Failed()) return;
                const Peer* peer = peerHandle.Read();
                if (!peer || !peer->IsValid()) return;

                if (!flows_.PeekWaiting(peerHandle.GetSlotIndex(), *peer, candidate))
                    return;   // nothing waiting can go now
            }

            // Step 2, claim, in the send path's lock order: the packet slot
            // FIRST, then peer, then flow. A concurrent Update may have
            // drained the head between the peek and this lock, so the current
            // head is re-checked against the very slot this handle holds; on
            // any mismatch the slot may already belong to someone else, so
            // DETACH, never release, and peek again.
            PacketSlotHandle packetHandle{candidate.packetSlot,
                                          flows_.WaitPoolFor(candidate.mode)};
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

                claimed = flows_.ClaimWaiting(candidate, *peer, *packet,
                                              common::MonotonicMicros());

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
            if (candidate.mode == FlowMode::UNRELIABLE)
            {
                const bool tagged = packet->IsTagged();
                const size_t headerSize = tagged
                    ? internal::WIRE_SECURE_HEAD_SIZE + internal::WIRE_PEER_TAG_SIZE
                    : internal::WIRE_SECURE_HEAD_SIZE;
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
        if (!flows_.SendEnabled() && !flows_.ReceiveEnabled()) return 0;

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

                const Peer* readPeer = peerHandle.Read();
                const uint64_t deadline =
                    flows_.NextDeadline(peerHandle.GetSlotIndex(), *readPeer);
                if (deadline != UINT64_MAX) consider(deadline);
            }
        }

        return soonest;
    }
}
