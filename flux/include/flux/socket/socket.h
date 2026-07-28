#pragma once

// Socket, the connectionless, zero-alloc, encrypted transport. Uniform
// behaviour and lock discipline throughout; the structure keeps each concern
// legible:
//   - the seal (encrypt/decrypt) lives in ONE place, not six copies;
//   - session materials travel as a PeerSendMaterials value, not 8 loose args;
//   - the god-functions (PreProcessOut, TryMigrate, Handshake_Validate,
//     UpdateOutFlow, ProcessFlowIn, Init) are thin dispatchers over named
//     helpers, none more than a couple of levels deep;
//   - the send gate is a decision (CanSend) then a mutation (StampFlowPacket),
//     returning a status the caller switches on; the congestion budget gates
//     it, and refused packets wait on per-flow rings drained oldest-first by
//     the tick.
// It stays ONE class: a flow/CC engine would own storage but not the peer
// state its operations mutate (lines saved, clarity lost), so it fails the
// "do not over-abstract" bar. See ARCHITECTURE.md.

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <memory>

#include <common/platform.h>
#include <common/result.h>
#include <common/error.h>
#include <common/crypto/crypto.h>
#include <common/collections/fifo_queue.h>
#include <common/collections/slot_pool.h>

#include <flux/util/challenge.h>
#include <flux/internal/constants.h>
#include <flux/internal/replay_window.h>
#include <flux/crypto/certificate.h>
#include <flux/crypto/cert_store.h>
#include <flux/crypto/identity.h>
#include <flux/socket/i_socket_kernel.h>
#include <flux/socket/packet_slot.h>
#include <flux/socket/socket_listener.h>
#include <flux/socket/socket_sender.h>
#include <flux/peer/peer.h>
#include <flux/peer/peer_table.h>
#include <flux/flow/flow.h>
#include <flux/flow/flow_handle.h>

namespace bcp::flux
{
    class ChallengeGenerator;

    namespace wire { class PacketBuilder; }

    /** Per-packet control bitflags on the wire controller byte. */
    enum class Controls : uint8_t
    {
        CTRL_INTERNAL = (1u << 0),   ///< handshake traffic; consumed, never delivered
        CTRL_HAS_FLOW = (1u << 1),
        CTRL_UNSECURE = (1u << 2),   ///< plaintext opt-out: no tag, no nonce, no integrity
        CTRL_TAGGED   = (1u << 3),   ///< secure header carries a migration peer tag
    };

    constexpr Controls operator|(Controls a, Controls b) noexcept
    {
        return static_cast<Controls>(static_cast<uint8_t>(a) | static_cast<uint8_t>(b));
    }
    constexpr Controls operator&(Controls a, Controls b) noexcept
    {
        return static_cast<Controls>(static_cast<uint8_t>(a) & static_cast<uint8_t>(b));
    }
    /** The left operand is taken by reference and mutated, so `x |= y;` sets
        the flag. */
    constexpr Controls& operator|=(Controls& a, Controls b) noexcept { a = a | b; return a; }
    constexpr Controls& operator&=(Controls& a, Controls b) noexcept { a = a & b; return a; }

    constexpr uint8_t ToByte(Controls c) noexcept { return static_cast<uint8_t>(c); }

    /** Opcodes of unsecured internal packets, handshake only, the sole cleartext
        opcodes. Secure control (path validation, flow control) is not an opcode:
        it rides the encrypted in-band channel byte, indistinguishable from
        data. */
    enum class SocketOpCode : uint8_t
    {
        HS_INIT   = 0x00,
        HS_CHLG   = 0x01,
        HS_RES    = 0x02,
        HS_FINISH = 0x03,
    };

    /** The session materials one send needs, gathered once under the peer's
        write lock and carried by value to the seal. Trivially copyable; the
        caller Wipes `key` after the send. */
    struct PeerSendMaterials
    {
        common::crypto::SessionKey key;
        common::crypto::SessionKey headerKey;   ///< masks the wire counter field
        uint64_t                   counter = 0;   ///< a fresh ++sendCounter per send
        uint8_t                    lane    = 0;
        PeerTag                    tag{};
    };

    /** Outcome of trying to admit a flow packet to the wire, decided under the
        peer and flow locks. Only Sent proceeds to the seal; every other outcome
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

    class Socket
    {
        // Both reach the socket's private send machinery: the builder picks a
        // writer source; the sender drives the outbound gate.
        friend class wire::PacketBuilder;
        friend class SocketSender;

    public:
        static constexpr uint32_t MAX_PACKET_SLOTS = 2048;

        enum class BackendType : uint8_t
        {
            STD_WIN,
            STD_UNX,
            RIO_WIN,
            URING_UNX,
        };

        /** Every count is a memory budget, and memory budgets belong to the
            embedder. Defaults are a workable middle ground, not
            recommendations. Fields are grouped by subsystem. */
        struct Config
        {
            BackendType type;
            uint16_t    port               = 0;
            uint32_t    maxPeers           = 1024;   ///< sizes the peer table
            uint32_t    pendingPacketCount = 1024;   ///< pending pool, shared by all peers
            uint32_t    recvSlotCount      = internal::SOCK_KERNEL_ZLOCKPCKT_COUNT;
            uint32_t    sendSlotCount      = internal::SOCK_KERNEL_SENDSLOT_COUNT;

            /** Long-term identity (see Identity::Generate), copied by Init; the
                caller may Wipe its own copy after. Null = anonymous (fresh
                keypair, zero tag). */
            const Identity* identity       = nullptr;

            /** Trusted-cert store capacity. 0 disables it: LoadCertificate
                fails, every peer stays unauthenticated, SendSecured never
                delivers. */
            uint32_t    trustedCertCount   = 0;

            /** Anti-replay window in counters (rounded up to a multiple of 64,
                min 64): tolerance for out-of-order secure packets, at
                (bits/8 + 8) bytes per peer. */
            uint32_t    replayWindowBits   = 512;

            /** Address migration by rotating 4-byte tag: a connection survives
                its peer's address changing without a re-handshake. Costs
                WIRE_PEER_TAG_SIZE bytes per secure packet. */
            bool        enableMigration    = true;

            /** Unknown-address tag lookups (+ trial decrypts) one Poll pass
                spends before dropping the rest, the flood cap on the shared
                peer table. PER POLL PASS, so aggregate load ~= (poll threads)
                x this. 0 disables the migration receive path. */
            uint32_t    migrateBudgetPerPoll = internal::MIGRATE_BUDGET_PER_POLL;

            /** Flow storage, split by direction because the two sides are
                different commitments. OUT-flows are the ones this socket opens
                (self-budgeting, each costs the in-flight ring); IN-flows are
                the ones remotes open (defensive bounds, each costs only the
                small receive half). Separate pools mean a hostile peer's opens
                can never starve this socket's own. A zero count disables that
                direction. */
            struct Flows
            {
                uint32_t outCount          = 0;    ///< socket-wide out-flow pool
                uint32_t inCount           = 0;    ///< socket-wide in-flow pool
                uint32_t maxOutPerPeer     = 8;    ///< out-directory width per peer
                uint32_t maxInPerPeer      = 8;    ///< DEFENSIVE: flows one remote may register

                /** Both roles at once: the out-flow ring capacity, which is the
                    window this socket declares on every flow packet, and the
                    in-flow seen-bitmap width, which is the widest window it
                    will register from a remote. A flow declaring more than the
                    receiver's bitmap covers is rejected, since a retransmit
                    could then arrive older than anything still remembered.
                    Power of two, floor 64, and it must be one of the widths
                    the flow data byte can encode (32 through 32768). */
                uint32_t inFlightCount     = 256;
                /** How far ahead of a gap an ordered in-flow buffers (beyond
                    it: dropped, a resend fills it later). Power of two, or 0. */
                uint32_t reorderCount      = 64;
                /** Retained reliable bodies, held send-until-ack for retransmit.
                    Socket-wide ceiling on unacked reliable traffic; running dry
                    is backpressure. Sized apart from send slots so a busy flow
                    can never starve handshakes, acks, or unreliable traffic. */
                uint32_t stagingCount      = 512;
                /** In-flight byte budget never drops below this on a loss run:
                    throttled, never strangled. 0 takes CC_MIN_BUDGET_DEFAULT;
                    floored at one full wire packet either way, so the gate can
                    always admit a full-size packet once the path drains. */
                uint32_t minCongestionBudget = 0;

                /** Sends held per flow while the window or the peer's congestion
                    budget is full, drained oldest-first as capacity frees (the
                    tick's drain). The two modes part ways when the buffer fills:
                    a reliable flow rejects the NEWEST send (TooManyPending, the
                    app's backpressure signal, nothing accepted is ever
                    dropped); an unreliable flow drops its OLDEST waiting packet
                    to seat the newest, so an unreliable send is never refused
                    for capacity. 0 disables the buffer for that mode: reliable
                    rejects immediately, unreliable drops immediately. Rounded
                    up to a power of two. Waiting reliable bodies keep their
                    staging slot; waiting unreliable bodies pin a kernel send
                    slot. */
                uint32_t reliableWaitCount   = 8;
                uint32_t unreliableWaitCount = 8;
            } flows;

            /** Flow timers, microseconds, read only by Update. Precision equals
                the app's Update cadence, a floor not a promise. */
            struct Timers
            {
                uint32_t ackDelayMicros      = 5000;     ///< forced FLOW_ACK cadence
                uint32_t retryIntervalMicros = 200000;   ///< open/close + retransmit fallback
                uint8_t  maxAttempts         = 8;        ///< give-up bound on open/close
            } timers;

            /** Idle-peer eviction and the unsecured-inbound gate. See each
                field. */
            struct Liveness
            {
                /** 0 disables the eviction sweep (default). When set, a peer
                    from whom nothing has been RECEIVED for this long is evicted
                    on the Update tick (at most MAX_EVICT_PER_UPDATE per call),
                    full teardown. Received-only: our own sends prove nothing
                    about the remote. A fresh peer gets one timeout to complete
                    its handshake; forgeable handshake chatter does not refresh
                    the clock. Init rejects values at/above half the stamp wrap
                    (~24 d). */
                uint64_t idleTimeoutMicros   = 0;
                /** How stale lastSeenAt may grow before the receive path pays a
                    write to refresh it; bounds stamp writes to one per grain per
                    peer. Eviction only fires past idleTimeout + this, so a stale
                    stamp delays an eviction by a grain, never causes one
                    early. */
                uint64_t refreshGrainMicros  = 100000;   ///< 100 ms
                /** Accept unsecured packets from addresses with no peer entry.
                    Off by default: plaintext is a channel between handshaked
                    peers, and unknown-source unsecured traffic is silently
                    dropped. Known source stays forgeable (no tag, no AEAD); the
                    gate is hygiene, not authentication. */
                bool     acceptUnsecureFromUnknown = false;
            } liveness;
        };

        Socket() = default;
        ~Socket();

        Socket(const Socket&)            = delete;
        Socket(Socket&&)                 = delete;
        Socket& operator=(const Socket&) = delete;
        Socket& operator=(Socket&&)      = delete;

        [[nodiscard]] common::Error Init(const Config& config);

        /** Idempotent teardown: closes the kernel, releases pools, drops peers.
            The destructor calls it; calling it twice is a no-op. */
        void Shutdown() noexcept;

        /** Adds a certificate to the trust store; safe at any time, including
            under live traffic. Trust is by provenance. Re-loading a stored tag
            replaces its cert (key rotation). NotInitialized when the store is
            disabled, LimitReached when full. */
        [[nodiscard]] common::Error LoadCertificate(const Certificate& cert);

        wire::PacketBuilder BuildPacket();

        /** Pass 1 processes the kernel batch (decrypt, dispatch, commit); pass
            2 drains the ready queue into `outPackets`. Packets never leave the
            recv pool. Safe to call concurrently. */
        uint32_t Poll(PacketSlotHandle* outPackets, size_t max);

        /** The tick: flush owed acks, retransmit, retry open/close, evict idle
            peers. Flux owns no thread, so time-based work happens only here.
            The clock is internal and read FRESH at each decision point (via
            Now), so a deadline coming due mid-pass fires this tick, not the
            next. Safe to call from several threads at once.

            @param nowOverride test seam only; non-zero pins virtual time, the
                   default 0 reads the real clock and is the sole production
                   behaviour. */
        void Update(uint64_t nowOverride = 0);

        /** Soonest future deadline across all flows, absolute monotonic micros,
            or 0 when nothing is pending. Best-effort, for a blocking app to wait
            on. */
        [[nodiscard]] uint64_t NextTimeout();

        /** The peer for an address, or a failed handle.

            @warning Drop the handle before calling anything else on this socket
                     for that peer. */
        [[nodiscard]] PeerHandle GetPeer(const Address& addr);

        /** Starts a session now with no data attached, so the app can pay the
            handshake at a moment it chooses. Ok when started, already under way,
            or complete. Progress is observable via GetPeer. */
        [[nodiscard]] common::Error Connect(const Address& addr);

        /** Opens a flow to the peer. Local and immediate: nothing goes on the
            wire, the flow comes back OPEN, and it can be sent on straight
            away, including before the peer handshake has finished (those
            packets park behind it like any other). The remote registers its
            receiving half from the first packet that arrives, and refuses only
            when it is at its caps, which fails the flow rather than the send.
            Unknown address handshakes first, like Send. The id is the app's to
            choose and must be free with this peer; the failed handle says why
            otherwise. */
        [[nodiscard]] FlowHandle OpenFlow(const Address& peer, uint16_t flowId, FlowMode mode);

        /** Begins closing: no new sends, tell the remote (FLOW_CLOSE), recycle
            the slot once the close completes or retries run out. Idempotent; a
            stale handle is InvalidState. */
        [[nodiscard]] common::Error CloseFlow(const FlowHandle& flow);

        /** Where the flow stands. CLOSED for a stale handle (epoch check). */
        [[nodiscard]] FlowLifecycle GetFlowState(const FlowHandle& flow);

        /** Advances this side's migration tag for every established peer, so
            packets after a deliberate local address change wear unlinkable
            tags. All peers rotate together; 3+ rotations unheard outruns a
            peer's window and degrades that connection to a re-handshake.
            Returns peers rotated. */
        uint32_t RotateTags();

        /** Re-sends HS_INIT for every peer whose handshake has not completed;
            returns how many. Give-up policy stays with the caller (read
            attempts, RemovePeer). Runs on the calling thread. */
        uint32_t RetryHandshakes();

        /** Drops the peer: releases pending, closes and frees every flow, then
            removes it from the table (waiting out live handles). Idempotent-ish;
            PeerNotFound if it was already gone. */
        [[nodiscard]] common::Error RemovePeer(const Address& addr);

    private:
        // --- State ---
        // Grouped by subsystem; all trailing-underscored.

        // Lifecycle / identity.
        std::atomic<bool>              initialized_{false};
        std::unique_ptr<ISocketKernel> kernel_;
        SocketListener                 listener_;
        SocketSender                   sender_;
        ChallengeGenerator             challengeGenerator_;
        common::crypto::SecretKey      secretKey_;
        common::crypto::PublicKey      publicKey_;
        Certificate::IdentityTag       ownTag_{};   ///< announced in HS_FINISH; zero when anonymous
        CertStore                      certStore_;

        // Peers, replay, and the pending-behind-handshake pool.
        PeerTable                      peers_;
        std::unique_ptr<uint64_t[]>    replayState_;   ///< (1 + replayWords_) u64 per peer slot
        uint32_t                       replayWords_ = 0;
        common::collections::SlotPool  pendingPool_;

        // Migration, fixed at Init.
        bool                           migration_            = true;
        uint32_t                       migrateBudgetPerPoll_ = internal::MIGRATE_BUDGET_PER_POLL;

        // Flow storage, split by direction; per-peer directory segments indexed
        // by peer slot, under that peer's lock (the replayState_ shape).
        common::collections::SlotPool  outFlowPool_;
        common::collections::SlotPool  inFlowPool_;
        std::unique_ptr<FlowDirEntry[]> outFlowDir_;
        std::unique_ptr<FlowDirEntry[]> inFlowDir_;
        uint32_t                       maxOutFlowsPerPeer_ = 0;
        uint32_t                       maxInFlowsPerPeer_  = 0;
        uint16_t                       outInflightCap_     = 0;
        uint16_t                       inWindowBits_       = 0;
        uint16_t                       inReorderCap_       = 0;
        uint16_t                       outReliableWaitCap_   = 0;   ///< waiting ring, reliable flows
        uint16_t                       outUnreliableWaitCap_ = 0;   ///< waiting ring, unreliable flows

        // Retained reliable bodies (send-until-ack), and the recv/ready path.
        common::collections::SlotPool  stagingPool_;
        common::collections::SlotPool* recvPool_ = nullptr;   ///< borrowed from the kernel
        common::collections::SlotPool* sendPool_ = nullptr;   ///< borrowed from the kernel
        common::collections::FifoQueue<uint32_t> readyQueue_;   ///< recv-slot indices awaiting Poll

        // Fixed-at-Init scalars.
        uint32_t                       minCongestionBudget_ = internal::CC_MIN_BUDGET_DEFAULT;
        uint32_t                       flowAckDelayMicros_      = 0;
        uint32_t                       flowRetryIntervalMicros_ = 0;
        uint8_t                        flowMaxAttempts_         = 0;
        uint32_t                       evictAfterStamp_ = 0;   ///< idleTimeout + grain, SeenStamp units; 0 = off
        uint32_t                       seenGrainStamp_  = 0;
        bool                           acceptUnsecureFromUnknown_ = false;

        /** Feedback gathered under a flow lock, applied to the peer under the
            peer lock. The flow side only accumulates, so it never reaches the
            peer lock (the reverse of peer->flow). */
        struct CongestionDelta
        {
            uint32_t resolvedBytes   = 0;   ///< in-flight bytes freed (acked or lost)
            uint32_t ackedBytes      = 0;   ///< of those, the acked ones; grow the budget
            uint32_t rttSampleMicros = 0;   ///< newest acked round-trip, 0 if none
            bool     sawLoss         = false;
        };

        // --- Lifecycle / Init ---
        // Init is a thin sequence over these; each returns an Error.
        [[nodiscard]] common::Error InitIdentity(const Config& config) noexcept;
        [[nodiscard]] common::Error InitPeerTableAndReplay(const Config& config) noexcept;
        [[nodiscard]] common::Error InitFlows(const Config& config) noexcept;
        [[nodiscard]] common::Error InitLiveness(const Config& config) noexcept;
        void BuildBackendSocket(BackendType type) noexcept;
        [[nodiscard]] bool GenerateKeypair() noexcept;

        // --- Crypto / seal ---
        // The ONE seal and the ONE open. Every outbound secure packet (data,
        // retransmit, control) seals here; every inbound one opens here.
        static void SealSecurePacket(PacketSlot& dst, const uint8_t* plaintext,
                                     size_t headerSize, size_t bodyLen,
                                     const PeerSendMaterials& materials, bool tagged) noexcept;

        /** Opens a secure packet in place and reports the sender's counter in
            `outCounter`. The counter is masked on the wire, so it cannot be
            read off the header; this is the only place it is recovered, and the
            header is left exactly as it arrived either way — which is what lets
            the migration path try one candidate key after another against the
            same packet. `outCounter` is meaningful only when this returns
            true. */
        [[nodiscard]] static bool OpenSecurePacket(PacketSlot& packet,
                                                   const common::crypto::SessionKey& key,
                                                   const common::crypto::SessionKey& headerKey,
                                                   uint8_t senderLane,
                                                   uint64_t& outCounter) noexcept;
        /** Copies a peer's send materials and bumps its counter, the one place
            ++sendCounter happens for a send. Non-static because it derives the
            lane from this socket's own public key.

            @pre Caller holds the peer's write lock. */
        [[nodiscard]] PeerSendMaterials GatherSendMaterials(Peer& peer) noexcept;

        /** Nonce lanes: the lower public key is lane 0, the other lane 1, so the
            two independent send counters never collide under the shared key. */
        [[nodiscard]] uint8_t LaneTo(const common::crypto::PublicKey& theirPk) const noexcept;
        [[nodiscard]] uint8_t LaneFrom(const common::crypto::PublicKey& theirPk) const noexcept;
        [[nodiscard]] ReplayWindow ReplayFor(uint32_t slot) noexcept;

        /** Rotating migration tag: keyed MAC of (lane, step) folded to 4 bytes,
            computed identically both ends, never exchanged. All-zero never
            occurs. */
        [[nodiscard]] static PeerTag DerivePeerTag(const common::crypto::SessionKey& session,
                                                   uint8_t lane, uint32_t step) noexcept;
        void BindTagWindow(uint32_t slot, const common::crypto::SessionKey& session,
                           uint8_t theirLane, uint32_t baseStep) noexcept;
        void SlideTagWindow(uint32_t slot, const common::crypto::SessionKey& session,
                            uint8_t theirLane, uint32_t oldBase, uint32_t newBase) noexcept;

        // --- Send path ---
        // Writer sources for PacketBuilder: kernel slot for transient packets,
        // staging slot for reliable bodies that must outlive the send.
        [[nodiscard]] common::Result<PacketSlotWriter> AcquireKernelWriter();
        [[nodiscard]] common::Result<PacketSlotWriter> AcquireFlowWriter(const FlowHandle& flow);

        /** A writer over a retained staging slot, the pool a reliable flow's
            plaintext lives in until its sequence resolves. Shared by the flow
            send path and the pending flush, so both put a retained body in the
            one pool the in-flight ring releases into. */
        [[nodiscard]] common::Result<PacketSlotWriter> AcquireStagingWriter();

        /** The outbound gate (called by SocketSender for every packet). Internal
            packets pass through; established peers seal and fly; unknown or
            mid-handshake peers park. Thin: validate -> gather -> stamp ->
            SealSecure. Invalid handle out with `status` Ok means parked; other
            status says why. */
        PacketSlotHandle PreProcessOut(PacketSlotHandle pHandle, common::Error& status,
                                       bool requireAuth = false);

        /** The send gate as decision-then-mutation. CanSend is a pure predicate
            over the (already-locked) flow and peer: ring slot free, unresolved
            < grantedWindow (reliable only), and the peer's congestion budget
            covers wireSize. A caller it passes runs to the wire without
            re-checking. StampFlowPacket assumes it passed and only mutates:
            assign seq, take the ring entry, spend bytesInFlight, write the seq.
            AdmitFlowPacket takes the FLOW lock and sequences the two under the
            PEER lock the caller already holds; the peer is lent (by reference),
            never re-looked-up, so the send path touches the peer table once. A
            packet the gate refuses is routed by mode: enqueued on the flow's
            waiting ring (strict FIFO, while anything waits a new packet joins
            the back even if capacity just freed, or its seq would outrun older
            data), the oldest waiting unreliable packet evicted to seat the
            newest, or refused outright. The returned status says which;
            ownership of packetSlot (staging for reliable, kernel send for
            unreliable) moves with it. See SendAdmission. */
        [[nodiscard]] static bool CanSend(const OutFlowState& flow, const Peer& peer,
                                          uint16_t wireSize, bool windowed) noexcept;
        static void StampFlowPacket(OutFlowState& flow, Peer& peer, PacketSlot& packet,
                                    uint32_t stagingSlot, uint16_t wireSize) noexcept;
        static void EnqueueWaiting(OutFlowState& flow, uint32_t packetSlot,
                                   uint16_t wireSize) noexcept;
        [[nodiscard]] SendAdmission AdmitFlowPacket(Peer& peer, uint32_t peerSlot,
                                                    PacketSlot& packet,
                                                    uint32_t packetSlot, uint16_t wireSize);

        /** Retransmit: re-seal a retained body from its staging slot under a
            fresh nonce (same seq) to the peer's CURRENT address. Locks staging
            then flow (the global order) and validates the ring still owns the
            slot at `expectedSeq` before sending. Materials, including `to`, come
            from the caller. */
        void ResendStaging(const Address& to, uint32_t flowSlot, uint32_t stagingSlot,
                           uint32_t expectedSeq, const PeerSendMaterials& materials);

        /** Seals a retained plaintext into a fresh wire slot bound for `to` and
            sends it; the transmit tail ResendStaging and the waiting-ring drain
            share it. A dry kernel pool or an out-of-bounds body drops this
            transmission, and the retransmit path re-offers it.

            @pre Caller holds the source slot's lock and keeps its lease (the
                 in-flight ring owns it). */
        void SealStagingToWire(const Address& to, const PacketSlot& staging,
                               const PeerSendMaterials& materials);

        /** Builds and sends one secure-channel control packet, wire-identical to
            application data (only the encrypted channel byte differs). Materials
            from the caller's peer-lock scope; the counter must be a sendCounter
            bump so data and control never share a nonce. */
        void SendSecureControl(const Address& to, const PeerSendMaterials& materials,
                               uint8_t channel, const uint8_t* payload, size_t payloadLen);

        // --- Receive path ---
        /** Inbound gate: unsecured passes the known-peer gate (or migration path
            for an unknown tagged packet); secure opens via OpenSecurePacket,
            then replay and liveness. False = drop. */
        [[nodiscard]] bool PreProcessIn(PacketSlotHandle& pHandle, uint32_t& migrateBudget);
        void ProcessInternal(PacketSlotHandle pHandle);
        void ProcessSecureControl(PacketSlotHandle pHandle);

        /** Commit one packet to the ready queue (Detaches on success so Poll
            rebuilds the handle). False = queue full, caller must not ack it. */
        [[nodiscard]] bool QueueReady(PacketSlotHandle& handle);

        /** Flow receive (step 2). Dispatches by mode to one of the three
            deliverers; the ordered one parks in-window gaps in hold-back and
            ejects past-window. Returns packets committed to the ready queue. */
        uint32_t ProcessFlowIn(PacketSlotHandle incoming);
        uint32_t DeliverUnordered(InFlowState& flow, PacketSlotHandle& incoming, uint32_t seq);
        uint32_t DeliverOrdered(InFlowState& flow, PacketSlotHandle& incoming, uint32_t seq);
        uint32_t DrainHoldbackRun(InFlowState& flow);

        /** Migration receive: find candidates by tag, trial-decrypt each
            (OpenSecurePacket), and on the genuine mover arm the path challenge.
            Delivers immediately (AEAD proves identity); only the return route
            waits on validation. */
        [[nodiscard]] bool TryMigrate(PacketSlotHandle& pHandle, uint32_t& migrateBudget);
        void PathChallenge_Respond(const Address& from, const uint8_t* payload, size_t len);
        void PathChallenge_Complete(const Address& from, const uint8_t* payload, size_t len);

        // --- Handshake ---
        //   initiator                     responder
        //   SendHandshakeInit  --INIT-->   Handshake_Challenge (stateless)
        //   Handshake_Respond  --RES--->   Handshake_Validate (verify, then
        //                      <-FINISH-    register + key + finish)
        //   Handshake_Complete (key, flush)
        void SendHandshakeInit(const Address& addr);
        void Handshake_Challenge(const Address& from);
        void Handshake_Respond(const Address& from, PacketSlotReader& reader);
        void Handshake_Validate(const Address& from, PacketSlotReader& reader);
        void Handshake_Complete(const Address& from, PacketSlotReader& reader);
        /** The key-derive, MAC, and peer-commit block shared by Validate's
            establish branch and Complete. */
        void CommitSession(Peer& peer, const common::crypto::PublicKey& theirPk,
                           const uint8_t* transcript, size_t transcriptLen) noexcept;
        void DeriveSessionInto(common::crypto::SessionKey& out,
                               const common::crypto::PublicKey& theirPk,
                               const uint8_t* transcript, size_t transcriptLen) noexcept;
        /** The kernel_->Write + CTRL_INTERNAL|CTRL_UNSECURE + opcode preamble,
            one writer factory for the handshake senders. */
        [[nodiscard]] common::Result<PacketSlotWriter> BuildInternal(SocketOpCode op);
        void FlushPending(const Address& addr);

        // --- Flow directory and control plane ---
        // Directory helpers over the FlowDirEntry[] segment: three scan idioms.
        [[nodiscard]] FlowDirEntry* OutFlowDirFor(uint32_t peerSlot) noexcept;
        [[nodiscard]] FlowDirEntry* InFlowDirFor(uint32_t peerSlot) noexcept;
        [[nodiscard]] static uint32_t FindFlowSlot(const FlowDirEntry* dir, uint32_t width, uint16_t flowId) noexcept;
        [[nodiscard]] static uint32_t InsertFlowSlot(FlowDirEntry* dir, uint32_t width, uint16_t flowId, uint32_t flowSlot) noexcept;
        static void EraseFlowSlot(FlowDirEntry* dir, uint32_t width, uint32_t flowSlot) noexcept;

        void Flow_Reject(const Address& from, const uint8_t* payload, size_t len);
        void Flow_Close(const Address& from, const uint8_t* payload, size_t len);
        void Flow_CloseAck(const Address& from, const uint8_t* payload, size_t len);
        void Flow_Ack(const Address& from, const uint8_t* payload, size_t len);

        /** The teardown {drain rings -> refund bytesInFlight (skip if the peer
            is dying) -> life=CLOSED -> Release}. Waiting packets never spent
            budget (the spend happens at stamp), so their drain releases leases
            only.

            @param refundTo null when the peer itself is being freed. */
        void FreeOutFlow(uint32_t flowSlot, Peer* refundTo) noexcept;

        /** Marks an out-flow FAILED and gives back everything it holds: the
            in-flight ring's leases and their congestion bytes, and the waiting
            ring's parked packets. The slot itself stays leased so the app can
            still observe the failure through its handle; CloseFlow recycles it.

            @pre Caller holds the peer's write lock (the refund's guard). */
        void FailOutFlow(uint32_t flowSlot, uint16_t flowId, Peer* refundTo) noexcept;

        /** Registers a remote's flow on first sight, from the flow header of a
            data packet. Caps-only refusal: a dry pool, a full per-peer
            directory, or a declared window wider than this socket's dedupe
            bitmap yields Rejected, and the sender is told so it can stop.

            @pre Caller holds the peer's write lock. */
        enum class FlowAdmit : uint8_t { Registered, Existing, Rejected };
        [[nodiscard]] FlowAdmit AdmitInFlow(uint32_t peerSlot, const Address& from,
                                            const BcpId& peerId, uint16_t flowId,
                                            uint8_t flowData) noexcept;
        [[nodiscard]] uint32_t DrainOutInflight(OutFlowState* flow) noexcept;
        void DrainOutWaiting(OutFlowState* flow) noexcept;
        void DrainInHoldback(InFlowState* flow) noexcept;

        /** Which pool a mode's waiting packets lease from: staging for reliable
            (the body must outlive its first send), the kernel send pool for
            unreliable (gone once on the wire). */
        [[nodiscard]] common::collections::SlotPool* WaitPoolFor(FlowMode mode) noexcept;

        // --- Flow data-plane / congestion ---
        void FlushPeerAcks(const Address& addr, PeerHandle peer);   ///< transferred handle
        /** Resolve one in-flight entry (acked or lost); accumulate feedback into
            `delta` (never touches the peer). ApplyCongestion does the peer-side
            arithmetic under the peer's write lock. */
        void ResolveOutEntry(OutFlowState* flow, InFlightEntry& entry,
                             bool acked, uint64_t nowMicros, CongestionDelta& delta) noexcept;
        void ApplyCongestion(Peer& peer, const CongestionDelta& delta, uint64_t nowMicros) noexcept;

        // --- Tick / eviction ---
        // Update threads `nowOverride` (0 = real clock) to each sub-step, which
        // reads Now(nowOverride) fresh, never a captured value. Idle eviction is
        // inline in Update's per-peer pass. One out-flow's tick splits into a
        // lifecycle-retry step and a retransmit step; each reads the clock once
        // at entry, for that flow.
        void UpdateOutFlow(const Address& addr, PeerHandle peer, uint32_t dirIndex, uint64_t nowOverride);
        void RetryClose(OutFlowState& flow, uint64_t now, /*out*/ bool& giveUp);
        void RetransmitInflight(OutFlowState& flow, uint64_t now, CongestionDelta& delta,
                                /*out*/ uint32_t* resendSeqs, uint32_t* resendSlots,
                                uint32_t& resendCount, /*out*/ bool& exhausted);

        /** The waiting-ring drain, one peer per call: while the gate passes,
            send the packet that has waited longest across the peer's flows,
            stamped at drain, so seq order is drain order. Each iteration locks
            the packet slot FIRST, then peer, then flow (the send path's order),
            revalidates the head it peeked, and seals + sends with no peer or
            flow lock held. Bounded per tick; the remainder rides the next. */
        void DrainWaitingSends(const Address& addr);

        // --- Peer management ---
        void SweepPeerFlows(uint32_t peerSlot) noexcept;
    };
}
