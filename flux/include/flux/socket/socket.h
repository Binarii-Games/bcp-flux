#pragma once

// Socket: the connectionless, zero-alloc, encrypted transport.
//
// One seal and one open serve every secure packet. Session materials travel as
// a PeerSendMaterials value, gathered under the peer lock and carried past it,
// so no lock is held across an encrypt or a send. The send gate lives in
// FlowTable and decides under the peer lock this socket already holds, and a
// packet the budget refuses waits on its association's ring until the tick
// drains it oldest first.
//
// Flows and peers are separate: a flow is what the application opens, an
// association is what a flow keeps with one peer. FlowTable holds every flow
// and every association, and it can never reach a peer, which is what keeps
// the packet slot then peer then flow order acyclic. See ARCHITECTURE.md.

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
#include <flux/transfer/transfer.h>
#include <flux/transfer/transfer_table.h>
#include <flux/internal/constants.h>
#include <flux/internal/replay_window.h>
#include <flux/crypto/certificate.h>
#include <flux/crypto/cert_store.h>
#include <flux/crypto/identity.h>
#include <flux/crypto/identity_table.h>
#include <flux/socket/i_socket_kernel.h>
#include <flux/crypto/packet_seal.h>
#include <flux/socket/packet_slot.h>
#include <flux/peer/peer_recv_state.h>
#include <flux/socket/ready_lanes.h>
#include <flux/socket/socket_events.h>
#include <flux/socket/socket_listener.h>
#include <flux/socket/socket_sender.h>
#include <flux/peer/peer.h>
#include <flux/peer/peer_table.h>
#include <flux/flow/flow.h>
#include <flux/flow/flow_handle.h>
#include <flux/flow/flow_table.h>

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
        /** Authenticated but not encrypted. Same framing as an encrypted
            packet, so the offsets are identical; only the transform differs.
            The payload is readable by anyone and alterable by nobody. */
        CTRL_MACONLY  = (1u << 4),
        /** The content is a list of messages, each behind a two-byte length,
            rather than one message filling it. Set only from the second message
            on, so a packet carrying one is byte-identical to an unbatched one
            and costs nothing. Every message in the list belongs to the same
            flow with the same security, which is why they share this
            controller instead of each carrying one. */
        CTRL_BATCH    = internal::WIRE_CTRL_BATCH,
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
        HS_KNOCK  = 0x04,   ///< HS_INIT that carries data under an interim key
    };

    /** The lane a thread last drained, handed back to Poll so it returns to the
        same one.

        Nothing is registered and nothing is owed: Poll takes whichever lane is
        free, preferring this. A thread that keeps passing back what Poll gave it
        stays on one lane, which is what keeps its peers' state in one cache, and
        a lane whose usual thread stops calling is simply taken by another rather
        than filling up untouched.

        Default-constructed names lane zero, which is the only lane when Config
        leaves pollLanes at one, so a single-threaded caller never mentions it. */
    struct ThreadIdentity
    {
        uint32_t lane = 0;
    };

    class Socket
    {
        // Both reach the socket's private send machinery: the builder picks a
        // writer source; the sender drives the outbound gate.
        friend class wire::PacketBuilder;
        friend class SocketSender;

    public:
        static constexpr uint32_t MAX_PACKET_SLOTS = 2048;

        /** Payload bytes that always fit, whatever the target's state and
            whichever way the packet is sent. A caller that does not want to
            track what a peer is doing can size everything to this and never
            be refused: it is the smallest ceiling the transport has, the one
            an opener carrying a flow packet leaves.

            The tightest case is an opener that carries both a flow packet and
            a resume note, since any opener may carry one and this figure has
            to hold whether it does or not.

            MaxPayload reports what this particular target can take right now,
            which is larger in every case but that one, and larger again once
            the session replaces the opener. Prefer it when the extra room is
            worth a call, and use this when it is not. */
        static constexpr uint32_t SAFE_PAYLOAD_BYTES =
            static_cast<uint32_t>(internal::KNOCK_PAYLOAD_MAX
                                  - internal::TICKET_WIRE_SIZE
                                  - internal::WIRE_SECURE_CHANNEL_SIZE
                                  - internal::WIRE_FLOW_HEADER_SIZE);

        // The claim above, held to the two framings that bound it: an opener
        // carrying a flow packet, and an established session carrying one with
        // a migration tag. If either ever drops below this, the constant is
        // lying and the build says so.
        static_assert(SAFE_PAYLOAD_BYTES
                      <= internal::MAX_WIRE_PACKET_SIZE
                         - internal::WIRE_SECURE_HEAD_SIZE
                         - internal::WIRE_PEER_TAG_SIZE
                         - internal::WIRE_TAG_SIZE
                         - internal::WIRE_SECURE_CHANNEL_SIZE
                         - internal::WIRE_FLOW_HEADER_SIZE,
                      "A session packet must carry at least the always-safe payload");
        static_assert(SAFE_PAYLOAD_BYTES > 0,
                      "The opener must leave room for a payload");

        enum class BackendType : uint8_t
        {
            STD_WIN,
            STD_UNX,
            RIO_WIN,
            URING_UNX,
            /** The platform socket with deliberate faults on top: loss, delay,
                reordering, duplication, corruption. For tests, because loopback
                never loses anything. Reach it through
                platform::FaultySocket to set rates or script exact failures. */
            FAULTY,
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

            /** Receive slots that buffering may never take, so an arriving
                packet always has somewhere to land. Without it a pool filled
                with packets waiting behind a gap leaves nothing to receive
                into, and the socket goes deaf to every peer rather than
                throttling one.

                Zero derives it from recvSlotCount, a sixteenth with a floor of
                64. Set it directly when the default does not suit: a socket
                fielding thousands of peers wants far more headroom per tick
                than one fielding ten, and only the embedder knows which it is.
                A reserve at or above recvSlotCount simply never buffers, which
                costs reordering and never reception. */
            uint32_t    recvReserveSlots   = 0;

            /** Packets one Update takes off the socket before returning.
                Emptying the OS buffer is the point of receiving on the tick, so
                this is a budget rather than anything a caller asks for, and a
                socket under load wants it high enough that the kernel never
                becomes the queue.

                Zero drains as much as the receive pool could hold, which is the
                natural ceiling: nothing more can be taken while every slot is
                occupied. Set it lower to bound the work one tick does, higher
                to keep draining as slots free during the same pass. */
            uint32_t    recvBatch          = 0;

            /** How many threads will drain delivered packets. One means Poll
                behaves exactly as it always has and the identity argument can be
                left off.

                Above one it must be a power of two, and Init refuses anything
                else rather than rounding, because a rounded-up count leaves a
                lane no thread was told to drain. Every lane needs its own
                thread: an undrained one fills until the receive pool is dry and
                then the socket stops hearing anyone. Each lane is sized for the
                whole receive pool, so this multiplies queue memory. */
            uint32_t    pollLanes          = 1;

            /** Long-term identity (see Identity::Generate), copied by Init; the
                caller may Wipe its own copy after. Null = anonymous (fresh
                keypair, zero tag). */
            const Identity* identity       = nullptr;

            /** Resume notes this socket keeps when a peer issues one, so the
                application can read the bytes and persist them. Off by
                default, because a note is only useful to the side that will
                reconnect: a server issues them and has no reason to keep the
                ones its clients issue back. Issuing is unaffected either way,
                and costs no memory, since a note is sealed for the issuer's
                own future self and never stored by it. */
            bool        keepResumeNotes    = false;

            /** Validity stamped into notes this socket issues. Zero selects
                the default of two days. */
            uint32_t    resumeNoteSeconds  = 0;

            /** Previous keypairs kept past a RotateIdentity, so a peer whose
                certificate has not caught up can still open toward this
                socket. Zero is a socket that never rotates, which is what
                every socket did before rotation existed. Each costs one
                keypair of memory and one more entry an arriving opener may
                name. Init refuses more than internal::MAX_IDENTITY_HISTORY. */
            uint8_t     identityHistory    = 0;

            /** Trusted-cert store capacity. 0 disables it: LoadCertificate
                fails, every peer stays unauthenticated, SendSecured never
                delivers. */
            uint32_t    trustedCertCount   = 0;

            /** Anti-replay window in counters (rounded up to a multiple of 64,
                min 64): tolerance for out-of-order secure packets, at
                (bits/8 + 8) bytes per peer. */
            uint32_t    replayWindowBits   = 512;

            /** Bytes sealed to one peer before its session key rotates
                itself, counted in full wire packets, so rotation may come
                early and never late. Zero selects the default. */
            uint64_t    rotateAfterBytes   = 0;

            /** The 0-RTT opener. A send to a peer whose identity this socket
                holds a certificate for goes as a knock: data rides the first
                packet under an interim key while the ordinary handshake
                completes behind it. All zero disables nothing that already
                worked, it only declines to open early. */
            struct Knock
            {
                /** Master switch for sending knocks. Off means a fresh
                    connection always takes the plain handshake, even with
                    material in hand. Receiving is always on: a knock that
                    arrives is handled whatever this says, because refusing to
                    understand one would just strand a peer. */
                bool        enable            = false;

                /** Peers that may exist before their address is proven by the
                    handshake cookie echo. Zero selects the default. */
                uint32_t    maxUnprovenPeers  = 0;

                /** Packets accepted from one unproven peer before further ones
                    are ejected unbuffered until its echo lands. Zero selects
                    the default. */
                uint32_t    unprovenPacketLimit = 0;

                /** Knock validations one tick pays for, each a key agreement.
                    Zero selects the default. */
                uint32_t    budgetPerTick     = 0;

                /** Seconds of clock disagreement past which a knock is stale.
                    Zero selects the default. */
                uint32_t    ttlWindowSeconds  = 0;
            };
            Knock       knock;

            /** Address migration by rotating 4-byte tag: a connection survives
                its peer's address changing without a re-handshake. Costs
                WIRE_PEER_TAG_SIZE bytes per secure packet. */
            bool        enableMigration    = true;

            /** Unknown-address tag lookups (+ trial decrypts) one Poll pass
                spends before dropping the rest, the flood cap on the shared
                peer table. PER POLL PASS, so aggregate load ~= (poll threads)
                x this. 0 disables the migration receive path. */
            uint32_t    migrateBudgetPerPoll = internal::MIGRATE_BUDGET_PER_POLL;

            /** Association storage, split by direction because the two sides are
                different commitments. Outbound ones this socket creates by
                sending (self-budgeting, each costs the in-flight ring);
                inbound ones a remote creates by sending to us (defensive
                bounds, each costs only the small receive half). Separate pools
                mean a hostile peer's traffic
                can never starve this socket's own. A zero count disables that
                direction. */
            struct Flows
            {
                /** Flows the application may hold open at once, socket-wide.
                    A flow is small (id, mode, lifecycle), and the per-peer
                    state it spawns is sized by outCount below. */
                uint32_t flowCount         = 64;
                uint32_t outCount          = 0;    ///< sending associations, socket-wide
                /** Sending associations for RELIABLE_ORDERED_BULK, which draw
                    from a pool of their own because their in-flight ring is
                    four times as deep (24 KB a slot against 6). Zero refuses
                    the mode, so a socket that never sends bulk pays nothing
                    for it. */
                uint32_t bulkOutCount      = 0;
                uint32_t inCount           = 0;    ///< receiving associations, socket-wide
                uint32_t bulkInCount       = 0;    ///< of which bulk-capable; sized for the deep window

                /** Transfers this socket may have running at once, in each
                    direction. They live in pools of their own, outside the
                    association pools, because a transfer shares none of an
                    association's state. Their in-flight ring is eight times a
                    bulk one, which they can afford because a transfer stages
                    no packet bodies: an outstanding packet costs its ring
                    entry rather than its bytes. Zero refuses transfers
                    outright, so a socket that never moves buffers pays
                    nothing for them. */
                uint32_t transferOutCount  = 0;
                uint32_t transferInCount   = 0;

                /** Largest transfer this socket will accept an announcement
                    for. 0 takes internal::TRANSFER_MAX_BYTES_DEFAULT.

                    It sizes nothing inside flux, because a transfer's tracking
                    is window sized rather than transfer sized. What it bounds
                    is what a remote may ask the application to find room for,
                    so a peer cannot announce a length no buffer could serve
                    and have the handler try. */
                uint64_t maxTransferBytes  = 0;
                uint32_t maxOutPerPeer     = 8;    ///< sending associations per peer
                /** DEFENSIVE: what one remote may create. It also bounds how
                    much of the receive pool that remote can pin, because each
                    receiving association can hold a full window of packets
                    behind a gap it never fills. maxInPerPeer times the window
                    is the worst case for one peer, and at the defaults that is
                    the whole pool, so a socket exposed to untrusted remotes
                    wants this low, recvSlotCount high, or both. */
                uint32_t maxInPerPeer      = 8;

                /** Receive slots one peer may occupy at once, told to that peer
                    over the secure channel once a session exists. Counts
                    packets held behind a gap plus packets delivered and not yet
                    polled, since both pin a slot.

                    A throughput ceiling as much as a memory one: a peer can
                    never receive more than this many packets per round trip, so
                    a small value caps every remote permanently. Zero means no
                    limit, which is the behaviour before grants existed. */
                uint32_t recvGrant         = 0;

                /** Retained reliable bodies, kept as retransmit sources. Held
                    from send until the receiver reports a delivery cursor past
                    them, which is later than the acknowledgement: a packet can
                    be acknowledged while merely buffered, and a buffer can be
                    dropped. Running dry is backpressure rather than loss. Sized apart from send
                    slots so a busy flow can never starve handshakes, acks, or
                    unreliable traffic.

                    A body is retained from send until the receiver's cursor
                    passes it, so a flow whose receiver has stalled holds on to
                    everything in its window. Few enough of those and the pool
                    is gone, and then every reliable send on the socket fails,
                    including the ones to peers that are perfectly healthy.

                    It is also a ceiling on throughput, and a quiet one. Every
                    reliable packet in flight holds a slot, so the pool caps
                    what can be on the path however large the congestion budget
                    grows. At 512 that was about 520 KB, below what a 50 Mbit
                    link at 100 ms holds, so the pool was the limit rather than
                    the controller and no measurement said so. 2048 clears any
                    path this transport is likely to meet. Lower it deliberately
                    if memory is tighter than throughput. */
                uint32_t stagingCount      = 2048;
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
                /** Paces handshake retries and is the retransmit fallback
                    before a peer has a round-trip sample. */
                uint32_t retryIntervalMicros = 200000;
            } timers;

            /** Idle-peer eviction and the unsecured-inbound gate. See each
                field. */
            struct Liveness
            {
                /** A peer from whom nothing has been RECEIVED for this long is
                    evicted on the Update tick (at most MAX_EVICT_PER_UPDATE per
                    call), full teardown. Eviction is mandatory, so 0 takes
                    internal::PEER_IDLE_TIMEOUT_DEFAULT rather than switching it
                    off: a live peer refreshes the clock on every packet, only a
                    silent one ages out, and reclaiming a dead entry is what lets
                    a restarted process reconnect. Received-only, our own sends
                    prove nothing about the remote. A fresh peer gets one timeout
                    to complete its handshake; forgeable handshake chatter does
                    not refresh the clock. Init rejects values at/above half the
                    stamp wrap (~24 d). */
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
                /** A receiving ordered flow holding a gap whose cursor has not
                    advanced for this long is jammed: it is pinning recv slots
                    for a gap the sender is not filling, so the tick reclaims it.
                    0 takes internal::FLOW_STALL_TIMEOUT_DEFAULT. There is no
                    "off": a jammed flow is pure waste, and holding it only lets
                    a misbehaving peer keep recv slots hostage. */
                uint32_t flowStallTimeoutMicros = 0;
            } liveness;

            /** Being told what happened instead of asking every tick.
                Leaving `hook` null costs nothing: no storage is allocated and
                nothing is ever recorded. */
            struct Events
            {
                EventHook hook       = nullptr;
                void*     context    = nullptr;   ///< handed back untouched

                /** Which events `hook` is called for, as the OR of SocketEvent
                    values. Anything outside it is never recorded, so an empty
                    set disables the hook as surely as a null pointer does. */
                uint32_t  subscribed = 0;
            } events;
        };

        Socket() = default;
        ~Socket();

        Socket(const Socket&)            = delete;
        Socket(Socket&&)                 = delete;
        Socket& operator=(const Socket&) = delete;
        Socket& operator=(Socket&&)      = delete;

        [[nodiscard]] common::Error Init(const Config& config);

        /** Idempotent teardown: closes the kernel, releases the pools, drops the
            peers. The destructor calls it; calling it twice is a no-op. After it
            the socket may be Init'd again from scratch. No other thread may be in
            Poll or Update while it runs, since it frees the pools those paths
            read, the same rule that has always applied to the destructor. */
        void Shutdown() noexcept;

        /** Adds a certificate to the trust store; safe at any time, including
            under live traffic. Trust is by provenance. Re-loading a stored tag
            replaces its cert (key rotation). NotInitialized when the store is
            disabled, LimitReached when full. */
        [[nodiscard]] common::Error LoadCertificate(const Certificate& cert);

        /** Stops trusting whatever key is pinned to this identity tag, at
            runtime, under live traffic. The tag's entry stays and its key
            becomes one nobody can own, so every later check against it is a
            hard mismatch rather than an open question, which is strictly
            stronger than never having pinned the tag. An authenticated peer
            keeps its live session, and everything that consults the store
            afresh refuses from the next call on. NotFound when the tag was
            never pinned. */
        common::Error RemoveCertificate(const Certificate::IdentityTag& tag);

        /** Replaces the keypair this socket proves its identity with, under
            live traffic. The tag does not change, so every peer relationship
            survives and only the proof is new: sessions already running are
            untouched, because their keys came from the handshake ephemerals
            and never from this one.

            The previous keypair is retained if Config::identityHistory made
            room, so a peer still holding the old certificate can open toward
            this socket while its copy catches up. Its handshake is answered
            with the new key, which its pinned certificate will refuse until
            it fetches a fresh one, and the CERT_MISMATCH event is what tells
            it to. Distributing the new certificate is the application's, the
            same way the first one got there.

            InvalidParam when next carries a different tag. */
        common::Error RotateIdentity(const Identity& next);

        /** Wipes every retained keypair, leaving only the current one. An
            opener aimed at any of them stops being answerable and its sender
            falls back to the plain handshake. For a leaked key, where cutting
            off the peers still using it is the point. */
        void ForgetPreviousIdentities();

        /** The identity tag this socket announces, zero when anonymous. Fixed
            at Init: a rotation changes the key, never the tag. */
        [[nodiscard]] const Certificate::IdentityTag& IdentityTag() const noexcept
        {
            return ownTag_;
        }

        wire::PacketBuilder BuildPacket();

        /** Pass 1 processes the kernel batch (decrypt, dispatch, commit); pass
            2 drains the ready queue into `outPackets`. Packets never leave the
            recv pool. Safe to call concurrently.

            The cursor walks the messages those packets carried, so a caller
            reads one loop and never handles a batch itself. It borrows
            `outPackets`, which therefore has to outlive it. */
        PollCursor Poll(PacketSlotHandle* outPackets, size_t max,
                        ThreadIdentity identity = {});

        /** Poll for a caller that wants indices rather than handles: same lane
            claim, same event dispatch, same drain, but each delivered packet
            arrives as its bare recv-pool index, leased and unlocked. The lease
            alone keeps the bytes stable, which is the same footing a queued
            packet already waits on; a reader takes the slot's lock only while
            actually reading (PacketAt then Read then Detach).

            The lane stays claimed until ReleasePollLane, and holding it across
            the reading is what keeps one peer's traffic on one thread, exactly
            as the cursor does for Poll. `lane` is in-out: the preference in,
            the claimed lane out, ReadyLanes::NO_LANE when every lane was busy.

            Every index handed out owes the pool one release, through
            ReleaseRecvSlot with the generation read at delivery. Nothing else
            returns these slots; forgetting one drains the pool for good. */
        uint32_t PollSlots(uint32_t* outIndices, size_t max, uint32_t& lane);

        /** Hands the lane back. With no cursor to do it, the caller of
            PollSlots owes exactly one of these per successful claim. A stale
            or NO_LANE value is ignored. */
        void ReleasePollLane(uint32_t lane) noexcept;

        /** A handle over a delivered recv slot, rebuilt from its index and
            stamped with this socket, so it can read the packet and build a
            reply. The handle owns the lease while it lives: a caller keeping
            the slot MUST Detach() rather than let the handle die, or the death
            releases what the index still names. Invalid when out of range or
            the socket is down. */
        [[nodiscard]] PacketSlotHandle PacketAt(uint32_t idx);

        /** Returns a delivered slot to the receive pool, guarded by the
            generation taken at delivery: a stale pair reports NotFound and
            frees nothing, which is what makes a double release from an
            undisciplined caller harmless. The one legitimate end of every
            index PollSlots handed out. */
        [[nodiscard]] common::Error ReleaseRecvSlot(uint32_t idx, uint32_t generation);

        /** The generation currently on a recv slot, to pair with its index
            into a name. Read it at delivery, while the lease is yours. */
        [[nodiscard]] uint32_t RecvGenerationOf(uint32_t idx) const;


        /** The tick: flush owed acks, retransmit, retry open/close, evict idle
            peers. Flux owns no thread, so time-based work happens only here.
            The clock is internal and read FRESH at each decision point (via
            Now), so a deadline coming due mid-pass fires this tick, not the
            next.

            Safe to call from any number of threads, and exactly one runs it:
            while a pass is in flight every other caller returns immediately.
            The pass takes exclusive peer locks as it walks, so concurrent
            passes serialize against each other and against the receive path,
            and past a couple of threads that contention costs more than the
            extra passes earn. Callers therefore just include Update in their
            loop, whatever the thread count, and the socket keeps the tick
            single.

            @param nowOverride test seam only; non-zero pins virtual time, the
                   default 0 reads the real clock and is the sole production
                   behaviour. */
        void Update(uint64_t nowOverride = 0);

        /** Puts every flow's part-filled batch on the wire.

            A flow send is packed into a batch rather than sent, so several
            small messages share one datagram, one seal and one staging slot.
            Nothing leaves until a batch fills or this is called, which makes
            the moment bytes go out something the caller chooses rather than
            something a timer decides. Drive it beside Update and Poll: send
            what the tick produced, then Flush.

            There is deliberately no automatic flush. One that fired sometimes
            would make send timing unpredictable and would hide a forgotten
            call rather than surfacing it. */
        void Flush();

        /** Soonest future deadline across all flows, absolute monotonic micros,
            or 0 when nothing is pending. Best-effort, for a blocking app to wait
            on. */
        [[nodiscard]] uint64_t NextTimeout();

        /** The peer for an address, or a failed handle.

            @warning Drop the handle before calling anything else on this socket
                     for that peer. */
        [[nodiscard]] PeerHandle GetPeer(const Address& addr);

        /** The peer in `slot`, but only if it is still the one `generation`
            was taken for, so a caller can name a peer by a pair of integers
            instead of by an address it would have to store.

            For a boundary that cannot hold an Address: a language binding, a
            table keyed by peer, anything that wants a peer to be a value small
            enough to copy. A slot index alone would not do, because slots are
            recycled and the next tenant would answer to the old number; the
            generation is what makes a stale pair report a failed handle
            instead. Pair it with PeerGenerationOf.

            @warning Same rule as the address overload: drop the handle before
                     calling anything else on this socket for that peer. */
        [[nodiscard]] PeerHandle GetPeerBySlot(uint32_t slot, uint32_t generation);

        /** The generation currently on a peer slot, to pair with it into a
            name. Meaningful for a slot the caller has just registered or is
            holding a handle to; without one, the peer may be removed between
            this call and the next. */
        [[nodiscard]] uint32_t PeerGenerationOf(uint32_t slot) const;

        /** Starts a session now with no data attached, so the app can pay the
            handshake at a moment it chooses. Ok when started, already under way,
            or complete. Progress is observable via GetPeer. */
        [[nodiscard]] common::Error Connect(const Address& addr);

        /** Names the identity expected at an address before any contact, so a
            first send can knock: encrypt toward that identity's pinned
            certificate and carry data from the first packet. The certificate
            must already be loaded. Without this, a first send takes the plain
            handshake. NotFound when no loaded certificate carries the tag,
            NotInitialized when knocking is disabled. */
        [[nodiscard]] common::Error Connect(const Address& addr,
                                            const Certificate::IdentityTag& expect);

        /** Names the identity AND presents a resume note this peer issued
            before, so a process that restarted picks its session back up
            instead of waiting out the entry the far side still holds.

            The note rides inside the first packet. Opening that packet proves
            this socket holds the key the note names, so the two together are
            what a handshake would have established and none of it runs: the
            session is live and authenticated from the first exchange.

            A note that will not open, or names a tag the far side no longer
            trusts, costs nothing. The opener is treated as a first contact and
            the ordinary handshake carries it, so a stale note is never worse
            than no note. InvalidParam when len is not the size a note is,
            otherwise the same answers as the overload above. */
        [[nodiscard]] common::Error Connect(const Address& addr,
                                            const Certificate::IdentityTag& expect,
                                            const uint8_t* note, size_t len);

        /** Copies out the resume note this peer most recently issued, as the
            RESUME_NOTE_RECEIVED event announced. Persist the bytes and hand
            them back to Connect after a restart. Returns how many were
            written, or 0 when this peer has issued none or the buffer is too
            small. Kept only when Config::keepResumeNotes asked.

            Nothing secret is in a note, so wherever these bytes land needs no
            more care than a certificate does. */
        [[nodiscard]] uint32_t ResumeNoteFor(const Address& addr,
                                            uint8_t* out, uint32_t cap);

        /** The size a resume note always is, so a caller can size storage
            without asking. */
        static constexpr uint32_t RESUME_NOTE_BYTES =
            static_cast<uint32_t>(internal::TICKET_WIRE_SIZE);

        /** Payload bytes the next packet to this target can carry, as a
            caller may put them: the channel byte the seal writes is already
            subtracted, and a packet sent on a flow spends
            internal::WIRE_FLOW_HEADER_SIZE more than this.

            Full when a session is established, less the opener overhead while
            the first packet must still open one. An address with no peer yet
            reports the opener's figure, because that is what a send to it
            would produce. A send past this is refused with TooLarge rather
            than truncated or dropped. */
        [[nodiscard]] uint32_t MaxPayload(const Address& addr);

        /** Opens a flow. Local, immediate, and NOT bound to a peer: send on it
            to any address and the per-target state is created on first use, so
            one flow serves many peers with an independent sequence for each.
            Nothing goes on the wire, and it can be sent on straight away, even
            before a peer handshake has finished; those packets park behind it
            like any other. The remote registers its receiving half from the
            first packet that arrives and refuses only when it is at its caps,
            which fails that one target rather than the flow.

            The in-flight window comes from the mode (see WindowFor), so
            nothing about it is declared here or on the wire. The id is the
            app's to choose and must be free on this socket. */
        [[nodiscard]] FlowHandle OpenFlow(uint16_t flowId, FlowMode mode);

        /** Closes the flow and every target it was talking to, releasing their
            rings and refunding what they held in flight. The flow slot is
            recycled, so the id becomes free and the handle goes stale.
            InvalidState on a stale handle or one already closing. */
        [[nodiscard]] common::Error CloseFlow(const FlowHandle& flow);

        // --- Transfers ---
        //
        // Beside flows, not inside them. A transfer has its own secure
        // channels, its own header and its own ids, so nothing on the flow
        // path changes to carry one. The id space is the transfer's own: it
        // does not collide with flow ids and needs no OpenFlow. What the two
        // mechanisms do share is the peer's congestion budget and pacing
        // clock, because they share a link.

        /** Moves one run of bytes to one peer, on the transfer id both ends
            agree on.

            The buffer is the retransmit source rather than something to copy,
            so it must stay alive and unmodified until PollTransfers reports it
            finished. That is the whole reason the window can be deep: nothing
            is staged, so an outstanding packet costs its ring entry rather
            than its bytes.

            One transfer at a time per id per peer, since the pair is what
            names it. AlreadyPending when one is already running there,
            InvalidState when the socket provisioned no transfer pool,
            TooLarge past the peer's ceiling, InvalidParam for a null buffer or
            a zero length. Zero is refused so a zero-length announcement can
            never be a valid thing to wait for, which is what lets a pending
            length of zero mean nothing pending. */
        [[nodiscard]] common::Error SendTransfer(uint16_t transferId,
                                                 const Address& peer,
                                                 const void* buffer,
                                                 uint64_t length);

        /** The announcement waiting on this id from this peer, to answer with
            Allow or Reject. Both are named by a TRANSFER_INCOMING event.

            Legal from inside an event handler: events dispatch with no peer or
            association lock held, and the slot the event names is kept alive
            across the handler for exactly this. A handler must not call Poll,
            which is true of every handler and not special here.

            An invalid request comes back when nothing is pending. */
        [[nodiscard]] TransferRequest PendingTransfer(uint16_t transferId,
                                                      const Address& peer);

        /** Bytes of a transfer that are contiguous from its start, so an
            application can watch one move without waiting for it. Answers for
            either direction on this id and peer.

            Contiguous on purpose: packets land at their own offsets and a hole
            can sit anywhere, so a count of what has arrived would report bytes
            ready while the middle is still untouched. Zero when nothing is
            running. */
        [[nodiscard]] uint64_t TransferProgress(uint16_t transferId,
                                                const Address& peer) const;

        /** Finished transfers, both directions, oldest first, into the
            caller's array. Returns how many were written.

            Separate from Poll because the two share nothing: a finished
            transfer carries no packet, no slot and no message, and it happens
            once per transfer rather than once per packet. Keeping it out means
            the message path pays nothing for a feature it does not use.

            An incoming transfer stays held until CompleteTransfer, so its
            bytes outlive this call. An outgoing one reports a null buffer and
            means the source is free again. */
        [[nodiscard]] size_t PollTransfers(TransferView* out, size_t max);

        /** Releases a completed incoming transfer, freeing the id for this
            peer's next one.

            Deliberately not automatic. Holding it is the backpressure: the
            peer cannot start another transfer on this id until the application
            says it is done with the last, so a receiver that hands each buffer
            to a worker thread throttles the sender instead of racing it.
            NotFound when nothing is completed and waiting. */
        [[nodiscard]] common::Error CompleteTransfer(uint16_t transferId,
                                                     const Address& peer);

        /** The flow's own state: OPEN until closed, whatever any one target is
            doing. CLOSED for a stale handle. */
        [[nodiscard]] FlowLifecycle GetFlowState(const FlowHandle& flow);

        /** This flow's state with ONE peer, which is where failure lives. A
            target that rejected the flow or stopped answering reads FAILED
            here while the flow stays OPEN for everybody else. CLOSED means no
            association exists yet, which is also what a target never sent to
            reads. */
        [[nodiscard]] FlowLifecycle GetFlowState(const FlowHandle& flow, const Address& peer);

        /** How many receiving flows currently exist for this peer, the
            associations built from its incoming traffic. Zero when the peer is
            unknown. Read-only introspection: a jammed flow the tick has
            reclaimed no longer counts. */
        [[nodiscard]] uint32_t ReceivingFlowCount(const Address& peer);

        /** Changes how much of this socket's receive pool one peer may occupy,
            and tells that peer.

            Raising it lets the peer keep more in flight, lowering it throttles
            it. A reduction takes effect here immediately, so a peer already
            past the new figure simply stops being buffered for until it drains
            back under it. Nothing already accepted is discarded.

            The peer is told over the secure channel and retold until it
            acknowledges, so the announcement survives a lost packet. Until it
            arrives the peer keeps sending to its old figure and is trimmed by
            this side, which costs it retransmits and nothing else.

            Zero means no limit, which is the same as never having set one.

            @return NotFound if this socket has no such peer. The value is
                    remembered for a peer that exists but has not finished its
                    handshake, and goes out when it does. */
        common::Error SetRecvGrant(const Address& peer, uint32_t slots);

        /** The grant currently in force for one peer, or zero when it has no
            limit. Zero is also what an unknown peer reports. */
        [[nodiscard]] uint32_t RecvGrantFor(const Address& peer);


        /** Advances this side's migration tag for every established peer, so
            packets after a deliberate local address change wear unlinkable
            tags. All peers rotate together; 3+ rotations unheard outruns a
            peer's window and degrades that connection to a re-handshake.
            Returns peers rotated. */
        uint32_t RotateTags();

        /** Advances the session key with this peer one step along the
            rotation chain. Silent on the wire: the peer discovers the change
            by opening. Refused for a peer that is unknown or not established
            (NotFound) and while a previous rotation is still unconfirmed
            (AlreadyPending). Runs unprompted when Config::rotateAfterBytes
            is crossed. */
        [[nodiscard]] common::Error RotateKeys(const Address& addr);

        /** Re-sends HS_INIT for every peer whose handshake has not completed,
            and drops the ones that have stopped answering. Update calls this,
            so an application driving only Poll and Update recovers a lost
            handshake without knowing this exists.

            Paced from each peer's registration by
            Config::timers::retryIntervalMicros, and bounded by
            internal::HANDSHAKE_MAX_ATTEMPTS, past which the peer is removed and
            whatever parked behind it fails visibly. Returns how many were
            retried. Runs on the calling thread. */
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

        /** Held true while an Update pass runs, so a second caller returns
            instead of running a concurrent pass. Managed only by Update
            itself: taken with an acquire exchange, dropped with a release
            store, never touched on any other path. */
        std::atomic<bool>              updateGate_{false};
        std::unique_ptr<ISocketKernel> kernel_;
        SocketListener                 listener_;
        SocketSender                   sender_;
        ChallengeGenerator             challengeGenerator_;
        IdentityTable                  identities_;
        common::crypto::SessionKey     ticketSealKey_{};      ///< from the identity secret, set at Init
        uint32_t                       ticketLifetime_ = 0;   ///< seconds, resolved at Init
        bool                           keepResumeNotes_ = false;
        Certificate::IdentityTag       ownTag_{};   ///< announced in HS_FINISH; zero when anonymous
        CertStore                      certStore_;

        // Knock: the 0-RTT opener. The ring is a fixed array of recent
        // first-flight fingerprints, guarded by its own spinlock because it is
        // touched from the receive path under no peer lock. The unproven count
        // is the approved socket-wide cap, relaxed because it decides policy
        // and never ownership, the PeerRecvState pattern.
        bool                           knockEnabled_ = false;
        uint32_t                       knockMaxUnproven_ = 0;
        uint32_t                       knockUnprovenPacketLimit_ = 0;
        uint32_t                       knockBudgetPerTick_ = 0;
        uint32_t                       knockTtlWindowSeconds_ = 0;
        std::atomic<uint32_t>          unprovenPeers_{0};
        uint32_t                       knockBudgetThisTick_ = 0;   ///< refilled by the tick

        // Peers, replay, and the pending-behind-handshake pool.
        PeerTable                      peers_;
        /** One per peer slot, sized with the peer pool. Holds what that peer
            pins of the receive pool and what it was granted. Written on the
            receive path, which holds no peer lock, so both fields are atomic
            and every access is relaxed. See peer_recv_state.h for why that is
            sufficient. */
        std::unique_ptr<PeerRecvState[]> peerRecvStates_;
        uint32_t recvGrant_ = 0;   ///< Config::flows::recvGrant, what every peer is told

        /** Recv slots pinned by hold-back across every peer. Read to keep the
            reserve free, moved at the same four points as the per-peer count,
            and relaxed for the same reason: nothing is published through it. */
        std::atomic<uint32_t> heldTotal_{0};
        uint32_t recvHoldCeiling_ = 0;   ///< recvSlotCount less the reserve
        uint32_t recvBatch_ = 0;         ///< packets one tick takes off the socket
        std::unique_ptr<uint64_t[]>    replayState_;   ///< (1 + replayWords_) u64 per peer slot
        uint32_t                       replayWords_ = 0;
        uint64_t                       rotateAfterBytes_ = internal::KEY_ROTATE_AFTER_BYTES_DEFAULT;
        common::collections::SlotPool  pendingPool_;

        // Migration, fixed at Init.
        bool                           migration_            = true;
        uint32_t                       migrateBudgetPerPoll_ = internal::MIGRATE_BUDGET_PER_POLL;

        /** Every flow, every association, and the algorithms that read only
            those. It cannot reach a peer, so it cannot invert the packet-slot
            then peer then flow lock order. */
        FlowTable                      flows_;

        /** Every transfer running on this socket, beside the flows rather than
            inside them. Like the flow table it can never reach a peer, so it
            cannot invert the packet-slot then peer then transfer lock order. */
        TransferTable                  transfers_;

        // The recv/ready path. The flow table borrows all three.
        common::collections::SlotPool* recvPool_ = nullptr;   ///< borrowed from the kernel
        common::collections::SlotPool* sendPool_ = nullptr;   ///< borrowed from the kernel
        ReadyLanes readyLanes_;   ///< recv-slot indices awaiting Poll, split per draining thread

        /** What happened, held until someone polls for it. Inert unless a hook
            was registered at Init, and drained by Poll. */
        EventTable events_;

        /** Handed to EventTable::Dispatch so a slot kept alive only to carry an
            event can be let go once it has been delivered. */
        static void OnEventDelivered(void* context, EventScope scope, uint32_t slot) noexcept;

        /** The one way a peer-scoped event is recorded: note it, and mark the
            peer as owing a delivery so its slot is not returned before then.

            @pre The caller holds this peer's write lock and lends the Peer in,
                 which is what keeps the mark from needing a second
                 acquisition. */
        void RecordPeerEvent(Peer& peer, uint32_t peerSlot, SocketEvent what) noexcept;

        // Fixed-at-Init scalars.
        uint32_t                       minCongestionBudget_ = internal::CC_MIN_BUDGET_DEFAULT;

        /** Largest the congestion budget may be, from what every flow window on
            one peer could hold in flight at once. Above that the number cannot
            bind anything, it only stores a burst for the moment a real limit
            lifts. Computed at Init from the per-peer association cap. */
        uint32_t                       maxCongestionBudget_ = UINT32_MAX;

        /** The idle timeout in raw microseconds, kept beside the stamp form
            because the acknowledgement clock runs on the monotonic clock, not
            on SeenStamp grains. */
        uint64_t                       idleTimeoutMicros_ = 0;
        /** Paces handshake retries. Kept here rather than read from the flow
            table because a handshake happens whether or not flows are
            configured, and the table is empty when they are not. */
        uint32_t                       handshakeRetryMicros_ = 0;
        uint32_t                       evictAfterStamp_ = 0;   ///< idleTimeout + grain, in SeenStamp units; never zero once Init succeeds
        uint32_t                       seenGrainStamp_  = 0;
        bool                           acceptUnsecureFromUnknown_ = false;

        // --- Lifecycle / Init ---
        // Init is a thin sequence over these; each returns an Error.
        [[nodiscard]] common::Error InitIdentity(const Config& config) noexcept;
        [[nodiscard]] common::Error InitPeerTableAndReplay(const Config& config) noexcept;
        [[nodiscard]] common::Error InitFlows(const Config& config) noexcept;
        [[nodiscard]] common::Error InitLiveness(const Config& config) noexcept;
        void BuildBackendSocket(BackendType type) noexcept;
        [[nodiscard]] bool GenerateKeypair() noexcept;


        /** Copies a peer's send materials and bumps its counter, the one place
            ++sendCounter happens for a send.

            @pre Caller holds the peer's write lock. */
        [[nodiscard]] PeerSendMaterials GatherSendMaterials(Peer& peer) noexcept;

        /** Nonce lanes: the lower public key is lane 0, the other lane 1, so the
            two independent send counters never collide under the shared key.
            Both sides must agree, so the comparison uses the key that peer
            knows this socket by. It is settled once when the session key is
            installed and then read off Peer::lane, because a rotation must
            never move a running session from one lane to the other. */
        [[nodiscard]] static uint8_t NonceLaneBetween(const common::crypto::PublicKey& myPk,
                                                 const common::crypto::PublicKey& theirPk) noexcept;
        [[nodiscard]] ReplayWindow ReplayFor(uint32_t slot) noexcept;

        /** Rotating migration tag: keyed MAC of (lane, step) folded to 4 bytes,
            computed identically both ends, never exchanged. All-zero never
            occurs. */
        [[nodiscard]] static PeerTag DerivePeerTag(const common::crypto::SessionKey& session,
                                                   uint8_t lane, uint32_t step) noexcept;
        void BindTagWindow(uint32_t slot, const common::crypto::SessionKey& session,
                           uint8_t theirNonceLane, uint32_t baseStep) noexcept;
        void SlideTagWindow(uint32_t slot, const common::crypto::SessionKey& session,
                            uint8_t theirNonceLane, uint32_t oldBase, uint32_t newBase) noexcept;

        // --- Send path ---
        // Writer sources for PacketBuilder: kernel slot for transient packets,
        // staging slot for reliable bodies that must outlive the send.
        [[nodiscard]] common::Result<PacketSlotWriter> AcquireKernelWriter();
        [[nodiscard]] common::Result<PacketSlotWriter> AcquireFlowWriter(const FlowHandle& flow);

        /** The flow's mode, for the builder's framing gate. False when the
            handle is stale or the flow is not open. */
        [[nodiscard]] bool FlowModeOf(const FlowHandle& flow, FlowMode& outMode) noexcept;

        /** The outbound gate (called by SocketSender for every packet). Internal
            packets pass through; established peers seal and fly; unknown or
            mid-handshake peers park. Thin: validate -> gather -> stamp ->
            SealSecure. Invalid handle out with `status` Ok means parked; other
            status says why. */
        PacketSlotHandle PreProcessOut(PacketSlotHandle pHandle, common::Error& status,
                                       bool requireAuth = false);

        /** Offers a flow packet's payload to that flow's open batch.

            @return false when the batch cannot take it and the caller should
                    send the packet the ordinary way: not a flow packet, the
                    peer still handshaking (the ordinary path parks it), or no
                    association yet (the ordinary path creates one). True means
                    the message is accounted for and `status` says how it went.

            Locks in the standard order, packet then peer then flow, and holds
            no peer lock across a send. */
        [[nodiscard]] bool OfferToBatch(PacketSlotHandle& pHandle, bool requireAuth,
                                        common::Error& status);

        /** Empties one flow's batch before something that cannot join it goes
            out, so send order and wire order stay the same.

            @return false when the batch still holds messages, because another
                    flush has it or the gate refused it. The caller must not go
                    around it then, since anything sent would take the lower
                    sequence and arrive first. */
        [[nodiscard]] bool FlushFlowOf(const Address& to, uint16_t flowId);

        /** A batch taken off its flow and sealed, waiting for the kernel.

            Its flow refuses every later append and every later flush until
            FinishBatch is called for it, so whoever holds one owes that call on
            every path out. `packet` reads null when there was nothing to take,
            and the debt does not exist in that case. */
        /** Associations one peer can have a batch flushed for in a single
            pass. The rest ride the next one, which costs a loop of latency and
            cannot lose anything, since an unflushed batch stays where it is. */
        static constexpr uint32_t MAX_FLUSH_PER_PEER = 32;

        struct SealedBatch
        {
            PacketSlotHandle packet;
            uint32_t         assocSlot = 0;
            uint16_t         size      = 0;
        };

        /** Takes one association's open batch under the peer borrow and seals
            it with nothing held. Gather under the lock, seal after release.

            A failure after the batch is taken is settled here, so the returned
            SealedBatch either carries a packet the caller owes FinishBatch for
            or carries nothing at all. */
        [[nodiscard]] SealedBatch SealOneBatch(const Address& to, uint32_t assocSlot,
                                               common::Error& status);

        /** Hands sealed batches to the kernel together and settles each one.

            The kernel reports how many of them reached the wire, counting from
            the first, so the rest stay with their flows for a later flush
            rather than discarding messages the caller was told were accepted.

            @return how many reached the wire, always counting from the
                    first. */
        uint32_t SendSealed(SealedBatch* sealed, uint32_t count);

        /** Seals one association's batch and sends it on its own. */
        common::Error FlushOneBatch(const Address& to, uint32_t assocSlot);

        /** Retransmit: re-seal a retained body from its staging slot under a
            fresh nonce (same seq) to the peer's CURRENT address. Locks staging
            then flow (the global order) and validates the ring still owns the
            slot at `expectedSeq` before sending. Materials, including `to`, come
            from the caller. */
        bool ResendStaging(const Address& to, uint32_t flowSlot, uint32_t stagingSlot,
                           uint32_t expectedSeq, const PeerSendMaterials& materials);

        /** Seals a retained plaintext into a fresh wire slot bound for `to` and
            sends it; the transmit tail ResendStaging and the waiting-ring drain
            share it. A dry kernel pool or an out-of-bounds body drops this
            transmission, and the retransmit path re-offers it.

            @pre Caller holds the source slot's lock and keeps its lease (the
                 in-flight ring owns it). */
        bool SealStagingToWire(const Address& to, const PacketSlot& staging,
                               const PeerSendMaterials& materials);

        /** Builds and sends one secure-channel control packet, wire-identical to
            application data (only the encrypted channel byte differs). Materials
            from the caller's peer-lock scope; the counter must be a sendCounter
            bump so data and control never share a nonce. */
        /** Tells one peer how much of this socket's receive pool it may hold.

            Sent when a session commits and again whenever the value changes, so
            session start and every later change are the same path. Carries a
            generation, because an op that overtakes an older one must not be
            undone by it.

            Materials and both values are gathered by the caller under the peer
            lock and passed by value, so nothing is held across the send. */
        void SendGrant(const Address& to, const PeerSendMaterials& materials,
                       uint32_t grant, uint32_t generation);

        /** Applies a peer's advertised grant, ignoring one older than the last
            applied, and acknowledges it either way.

            The acknowledgement is unconditional on purpose. Acking only a value
            that was new would wedge the sender's retry: its resend carries a
            generation this side has already applied, so it would be ignored in
            silence and resent forever. */
        void Grant_Update(const Address& from, const uint8_t* payload, size_t len);

        /** Clears a peer's pending flag once it names the generation currently
            outstanding. An ack for anything else is stale and ignored. */
        void Grant_Acked(const Address& from, const uint8_t* payload, size_t len);

        /** Sends this socket's grant to one peer, if that peer still owes an
            acknowledgement. Called from the tick, so a lost announcement is
            retried until it lands. Takes the handle by value: the gather
            happens under it and the send after it is released. */
        void SendPendingGrant(const Address& to, PeerHandle peerHandle, uint64_t now);

        // --- Resume notes (socket_ticket.cpp) ---
        /** Derives the key this socket seals its own notes under, from its
            identity secret, so a restart re-derives the same one and a note
            issued before it still opens. Rotating the identity is therefore
            what retires outstanding notes, which is the only ceiling on their
            stated lifetime. */
        void InitResumeNotes(const Config& config) noexcept;
        /** Seals a note naming this holder for this socket's own future self.
            The holder's public key is the associated data rather than content,
            so the note only ever opens against the key its presenter proves.
            Writes internal::TICKET_WIRE_SIZE bytes. */
        void SealResumeNote(uint8_t* out,
                            const common::crypto::PublicKey& holderKey,
                            const uint8_t holderTag[internal::WIRE_HS_TAG_SIZE]) noexcept;
        /** Opens one this socket issued. False when it was not ours, was not
            issued to this key, or has outlived its stated validity. */
        [[nodiscard]] bool OpenResumeNote(const uint8_t* note,
                                          const common::crypto::PublicKey& holderKey,
                                          uint8_t outTag[internal::WIRE_HS_TAG_SIZE]) noexcept;
        /** Sends the note this session owes its peer, paced like the grant
            resend, until Ticket_Acked clears the flag. Takes the handle by
            value: the gather happens under it and the send after it. */
        void SendPendingTicket(const Address& to, PeerHandle peerHandle, uint64_t now);
        /** A note arrived. Kept for the application when Config asks, dropped
            otherwise, and acknowledged either way so a full or uninterested
            holder does not turn the issuer into a resender. */
        void Ticket_Update(const Address& from, const uint8_t* payload, size_t len);
        void Ticket_Acked(const Address& from, const uint8_t* payload, size_t len);

        // --- Knock (socket_knock.cpp) ---
        /** Resolves the knock limits, each zero in Config selecting its
            default. */
        [[nodiscard]] common::Error InitKnock(const Config& config);
        /** Arms a peer's knock window toward a pinned certificate key, so
            PreProcessOut seals its sends as knocks. Returns false when the
            window could not be armed, which is the caller's cue to fall back
            to a plain handshake. Caller holds the peer write lock. */
        bool ArmKnock(Peer& peer, const common::crypto::PublicKey& certKey,
                      const uint8_t* note);
        /** Combines the two knock DH results into the interim key and its
            header key. The two shared secrets are computed by the caller
            because their roles differ by side (the sender pairs its ephemeral
            with the receiver's static, the receiver its static with the
            sender's ephemeral), but they come out equal, so this half of the
            derivation is one function. */
        void CombineKnockKey(common::crypto::SessionKey& outKey,
                             common::crypto::SessionKey& outHeaderKey,
                             const common::crypto::SharedSecret& staticShared,
                             const common::crypto::SharedSecret& ephShared,
                             const uint8_t salt[internal::WIRE_HS_SALT_SIZE]) noexcept;
        /** The whole receiver pipeline for one HS_KNOCK: budget, TTL, ring,
            key rebuild, open, peer create-or-find under the unproven caps,
            deliver the carried packet, then let the ordinary handshake run
            by sending the challenge. */
        void Handshake_Knock(PacketSlotHandle pHandle);
        /** Sends a knock carrying no payload, which is what a Connect with no
            data attached puts on the wire when material is in hand: the
            opener and the interim key in one packet, with nothing to deliver
            on the far side. */
        void SendKnockOpener(const Address& addr);
        /** Clears the unproven flag and releases its slot in the cap. Called
            where the cookie echo proves the address. Caller holds the peer
            write lock. */
        void MarkAddressProven(Peer& peer) noexcept;

        /** Starts a freshly registered slot on this socket's configured grant.

            A recycled slot carries its previous occupant's counts, so this
            wipes them before the new peer is charged for anything. Nothing is
            announced: a peer with no session cannot be told, and CommitSession
            raises the flag once there is a channel to say it on. */
        void SeedPeerRecvState(uint32_t slot) noexcept;

        /** Changes what one peer may occupy and arranges for it to be told.

            Changing a grant is four steps that have to happen together: the
            value, a fresh generation so the peer takes this over whatever it
            last applied, the pending flag, and a cleared send stamp so the tick
            carries it at once rather than an interval later. Every caller goes
            through here, because three of the four done right is a peer that
            never learns its limit moved.

            The caller holds `peer` write-locked and `slot` is its slot. */
        void ApplyGrant(uint32_t slot, Peer& peer, uint32_t value) noexcept;

        /** Cuts a peer's grant once it has had buffer reclaimed too often.

            A peer whose gaps get filled never reaches this. One that repeatedly
            fills buffer and leaves it to time out is holding what it is not
            using, and the answer is to let it hold less. Halving rather than
            closing, so a peer that recovers can still work.

            The strikes reset with the cut, so a peer is judged on what it does
            next rather than on a total it can never work off. Takes the handle
            by value: the decision is made under it and the announcement goes out
            on the tick afterwards. */
        void CutGrantIfAbusive(PeerHandle peerHandle);

        /** Empties the OS receive buffer into the recv pool, consuming handshake
            and control traffic and queueing application packets for Poll.

            Driven by Update rather than by Poll, so the socket is drained on the
            tick and the receive rules, the per-peer grant among them, are
            applied where this socket takes responsibility for a packet. Nothing
            waits in the kernel for a caller that may be slow to ask. */
        void ReceiveIntoPool();

        // --- Transfers, internal ---
        // The three channel handlers, and the pass that drives outgoing
        // transfers on the tick. TransferRequest reaches Allow and Reject
        // through the socket, so it is a friend of it rather than of the
        // table, which keeps the table unable to reach a peer.
        friend class TransferRequest;

        void Transfer_Data(const Address& from, const uint8_t* payload, size_t len);
        void Transfer_Ack(const Address& from, const uint8_t* payload, size_t len);
        void Transfer_Reject(const Address& from, const uint8_t* payload, size_t len);

        /** One tick's work for every transfer this peer is sending: the
            announcement if it is still owed, then as many data packets as the
            window, the congestion budget and the pacing clock allow, then
            whatever is overdue. Gathers under the peer lock and sends after
            it, like every other send path here. */
        void TransferPass(const Address& to, PeerHandle peerHandle, uint64_t now);

        /** Tells a peer what has arrived, so it can stop holding what has
            landed and resend what has not. */
        void SendTransferAck(const Address& to, const PeerSendMaterials& materials,
                             uint16_t transferId, uint32_t recvNext,
                             const uint8_t* bitmap);

        [[nodiscard]] common::Error AllowTransfer(uint16_t transferId,
                                                  const Address& peer, void* buffer);
        common::Error RejectTransfer(uint16_t transferId, const Address& peer);

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

        /** Flow receive (step 2). Registers the remote's flow when this is the
            first packet on it, then hands the packet to the flow table, which
            orders and dedupes it. Returns packets committed to the ready
            queue. */
        uint32_t ProcessFlowIn(PacketSlotHandle incoming);

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
        void CommitSession(Peer& peer, const IdentityTable::Entry& mine,
                           const common::crypto::PublicKey& theirPk,
                           const common::crypto::SecretKey& myEphSk,
                           const common::crypto::PublicKey& theirEphPk,
                           const uint8_t* transcript, size_t transcriptLen) noexcept;

        /** Combines the ephemeral exchange with the long-lived one, producing
            both per-session roots in one pass: the session key and the resume
            root, derived under different contexts so neither reveals the
            other. The caller wipes its ephemeral secret as soon as this
            returns, which is what makes the session unrecoverable once the
            handshake is over. */
        void DeriveSessionInto(common::crypto::SessionKey& outSession,
                               const common::crypto::SecretKey& mySk,
                               const common::crypto::PublicKey& theirPk,
                               const common::crypto::SecretKey& myEphSk,
                               const common::crypto::PublicKey& theirEphPk,
                               const uint8_t* transcript, size_t transcriptLen) noexcept;

        /** Moves the peer one link along the rotation chain: current keys to
            the prev slots, next session derived from the current one, helper
            keys and tags re-derived, counters restarted. The caller holds the
            peer's write lock and has already checked the guards. */
        void RotatePeerKeys(Peer& peer) noexcept;


        /** The kernel_->Write + CTRL_INTERNAL|CTRL_UNSECURE + opcode preamble,
            one writer factory for the handshake senders. */
        [[nodiscard]] common::Result<PacketSlotWriter> BuildInternal(SocketOpCode op);
        void FlushPending(const Address& addr);

        // --- Flow control plane ---
        void Flow_Reject(const Address& from, const uint8_t* payload, size_t len);
        void Flow_Ack(const Address& from, const uint8_t* payload, size_t len);

        // --- Flow data-plane / congestion ---
        void FlushPeerAcks(const Address& addr, PeerHandle peer);   ///< transferred handle
        /** Applies the feedback the flow table gathered: free what resolved,
            smooth the round-trip, grow on acks and trim on loss. */
        void ApplyCongestion(Peer& peer, const CongestionDelta& delta, uint64_t nowMicros) noexcept;

        /** Debug guard on the congestion budget, asked on every path that
            leaves ApplyCongestion. */
        void AssertBudgetInRange(const Peer& peer) const noexcept;

        // --- Tick / eviction ---
        // Update threads `nowOverride` (0 = real clock) to each sub-step, which
        // reads Now(nowOverride) fresh, never a captured value. Idle eviction is
        // inline in the per-peer pass. One association's tick splits into a
        // lifecycle-retry step and a retransmit step; each reads the clock once
        // at entry, for that flow.

        /** The tick's whole body. Only Update calls it, under the gate that
            keeps passes from overlapping. */
        void UpdatePass(uint64_t nowOverride);

        void UpdateOutFlow(const Address& addr, PeerHandle peer, uint32_t dirIndex, uint64_t nowOverride);

        /** The waiting-ring drain, one peer per call: while the gate passes,
            send the packet that has waited longest across the peer's flows,
            stamped at drain, so seq order is drain order. Each iteration locks
            the packet slot FIRST, then peer, then flow (the send path's order),
            revalidates the head it peeked, and seals + sends with no peer or
            flow lock held. Bounded per tick; the remainder rides the next. */
        void DrainWaitingSends(const Address& addr);
    };
}
