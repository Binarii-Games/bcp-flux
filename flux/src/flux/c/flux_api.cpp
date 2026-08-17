// The bridge. One foot in each world: C++ inside, numbers on the outside.
//
// Nothing here decides anything about the transport. Every entry point turns a
// number back into the thing it names, forwards to the same C++ method the C++
// caller would have used, and converts the result. A wrapper that starts
// holding opinions has become a second implementation, and that is the thing
// to avoid.
//
// What it does hold is storage, and only where the C++ API asks its caller for
// some: the array Poll fills, and the builders a half-written packet lives in.
// Both are sized at Init from the config and nothing allocates after that. The
// point of holding them here is that no flux object, and no size of one, ever
// reaches a binding: C# copies structs on assignment, Python zero-fills them,
// Rust moves them, and any of those would corrupt a live object.
//
// NAMES. A number is a slot and a generation packed together, plus one so that
// zero is never valid. The generation is what makes a stale number report
// not-found instead of naming whatever took the slot next; peers get theirs
// from PeerTable, flows carry one already, and packets get one from the table
// below. A binding must never take a number apart, and nothing here depends on
// it not trying: an unpacked slot still has to pass its generation.
#include <flux/c/flux_api_v1.h>

#include <flux/address.h>
#include <flux/flow/flow.h>
#include <flux/flow/flow_handle.h>
#include <flux/peer/peer.h>
#include <flux/peer/peer_handle.h>
#include <flux/socket/packet_slot.h>
#include <flux/socket/socket.h>
#include <flux/socket/socket_events.h>
#include <flux/transfer/transfer.h>
#include <flux/wire/packet_builder.h>

#include <atomic>
#include <cstddef>
#include <cstring>
#include <memory>
#include <new>

namespace flux   = bcp::flux;
namespace common = bcp::common;

// --- The welds -------------------------------------------------------------
//
// Every number the C header repeats on its own authority is checked against
// the original here, because this is the only file that can see both. A
// renumbering over there stops the build with both names in the message,
// rather than leaving shipped bindings quietly reading the wrong thing.

static_assert(static_cast<int>(common::Error::Ok)               == FLUX_OK);
static_assert(static_cast<int>(common::Error::NotInitialized)   == FLUX_ERR_NOT_INITIALIZED);
static_assert(static_cast<int>(common::Error::InvalidParam)     == FLUX_ERR_INVALID_PARAM);
static_assert(static_cast<int>(common::Error::InvalidState)     == FLUX_ERR_INVALID_STATE);
static_assert(static_cast<int>(common::Error::LimitReached)     == FLUX_ERR_LIMIT_REACHED);
static_assert(static_cast<int>(common::Error::ResolveFailed)    == FLUX_ERR_RESOLVE_FAILED);
static_assert(static_cast<int>(common::Error::NotImplemented)   == FLUX_ERR_NOT_IMPLEMENTED);
static_assert(static_cast<int>(common::Error::RandomFailed)     == FLUX_ERR_RANDOM_FAILED);
static_assert(static_cast<int>(common::Error::AlreadyInUse)     == FLUX_ERR_ALREADY_IN_USE);
static_assert(static_cast<int>(common::Error::NotFound)         == FLUX_ERR_NOT_FOUND);
static_assert(static_cast<int>(common::Error::IoFailed)         == FLUX_ERR_IO_FAILED);
static_assert(static_cast<int>(common::Error::BindFailed)       == FLUX_ERR_BIND_FAILED);
static_assert(static_cast<int>(common::Error::SendFailed)       == FLUX_ERR_SEND_FAILED);
static_assert(static_cast<int>(common::Error::AllocFailed)      == FLUX_ERR_ALLOC_FAILED);
static_assert(static_cast<int>(common::Error::PoolExhausted)    == FLUX_ERR_POOL_EXHAUSTED);
static_assert(static_cast<int>(common::Error::BufferFull)       == FLUX_ERR_BUFFER_FULL);
static_assert(static_cast<int>(common::Error::TooLarge)         == FLUX_ERR_TOO_LARGE);
static_assert(static_cast<int>(common::Error::Malformed)        == FLUX_ERR_MALFORMED);
static_assert(static_cast<int>(common::Error::NotAuthenticated) == FLUX_ERR_NOT_AUTHENTICATED);
static_assert(static_cast<int>(common::Error::AlreadyPending)   == FLUX_ERR_ALREADY_PENDING);
static_assert(static_cast<int>(common::Error::TooManyPending)   == FLUX_ERR_TOO_MANY_PENDING);
static_assert(static_cast<int>(common::Error::Refused)          == FLUX_ERR_REFUSED);

// FLUX_ERR_INTERNAL is this API's own, in a gap common::Error leaves free.
// Nothing may ever mean two things.
static_assert(FLUX_ERR_INTERNAL == 13);

static_assert(static_cast<int>(flux::FlowMode::RELIABLE_ORDERED)      == FLUX_FLOW_RELIABLE_ORDERED);
static_assert(static_cast<int>(flux::FlowMode::RELIABLE_UNORDERED)    == FLUX_FLOW_RELIABLE_UNORDERED);
static_assert(static_cast<int>(flux::FlowMode::UNRELIABLE)            == FLUX_FLOW_UNRELIABLE);
static_assert(static_cast<int>(flux::FlowMode::RELIABLE_ORDERED_BULK) == FLUX_FLOW_RELIABLE_ORDERED_BULK);

static_assert(static_cast<int>(flux::FlowLifecycle::OPEN)    == FLUX_FLOW_STATE_OPEN);
static_assert(static_cast<int>(flux::FlowLifecycle::CLOSING) == FLUX_FLOW_STATE_CLOSING);
static_assert(static_cast<int>(flux::FlowLifecycle::CLOSED)  == FLUX_FLOW_STATE_CLOSED);
static_assert(static_cast<int>(flux::FlowLifecycle::FAILED)  == FLUX_FLOW_STATE_FAILED);

static_assert(static_cast<int>(flux::FlowPart::Whole)  == FLUX_PART_WHOLE);
static_assert(static_cast<int>(flux::FlowPart::First)  == FLUX_PART_FIRST);
static_assert(static_cast<int>(flux::FlowPart::Middle) == FLUX_PART_MIDDLE);
static_assert(static_cast<int>(flux::FlowPart::Last)   == FLUX_PART_LAST);

static_assert(flux::ToBits(flux::SocketEvent::INCOMING_FLOW_OPENED)   == FLUX_EVENT_INCOMING_FLOW_OPENED);
static_assert(flux::ToBits(flux::SocketEvent::OUTGOING_FLOW_REFUSED)  == FLUX_EVENT_OUTGOING_FLOW_REFUSED);
static_assert(flux::ToBits(flux::SocketEvent::OUTGOING_FLOW_LOST)     == FLUX_EVENT_OUTGOING_FLOW_LOST);
static_assert(flux::ToBits(flux::SocketEvent::INCOMING_FLOW_REOPENED) == FLUX_EVENT_INCOMING_FLOW_REOPENED);
static_assert(flux::ToBits(flux::SocketEvent::PEER_ESTABLISHED)       == FLUX_EVENT_PEER_ESTABLISHED);
static_assert(flux::ToBits(flux::SocketEvent::PEER_LOST)              == FLUX_EVENT_PEER_LOST);
static_assert(flux::ToBits(flux::SocketEvent::PEER_MIGRATED)          == FLUX_EVENT_PEER_MIGRATED);
static_assert(flux::ToBits(flux::SocketEvent::PEER_GRANT_CHANGED)     == FLUX_EVENT_PEER_GRANT_CHANGED);
static_assert(flux::ToBits(flux::SocketEvent::PEER_GRANT_CUT)         == FLUX_EVENT_PEER_GRANT_CUT);
static_assert(flux::ToBits(flux::SocketEvent::PEER_FLOW_JAMMED)       == FLUX_EVENT_PEER_FLOW_JAMMED);
static_assert(flux::ToBits(flux::SocketEvent::TRANSFER_INCOMING)      == FLUX_EVENT_TRANSFER_INCOMING);

namespace
{
    // --- Packing ----------------------------------------------------------
    //
    // Slot and generation in one 64-bit number, biased so that zero is never a
    // valid name and a zeroed struct in any language reads as "none".

    // The top three bits of every number name what kind of thing it is, so a
    // number of one kind handed to a call expecting another is refused rather
    // than decoded as if it belonged. Without this a builder number and a
    // received-packet number, both a slot plus a generation from zero, share
    // an encoding: releasing a builder number would free a receive slot that
    // was never acquired and wedge the pool. The kind is what keeps the four
    // spaces disjoint. Zero stays FLUX_NONE, since kind zero is no kind.
    constexpr uint64_t KIND_SHIFT   = 61;
    constexpr uint64_t KIND_MASK    = uint64_t{7} << KIND_SHIFT;
    constexpr uint64_t PAYLOAD_MASK = (uint64_t{1} << KIND_SHIFT) - 1;

    enum Kind : uint64_t
    {
        KIND_NONE      = 0,
        KIND_PEER      = 1,
        KIND_FLOW      = 2,
        KIND_PKT_BUILD = 3,   ///< a packet under construction, in this glue's table
        KIND_PKT_RECV  = 4,   ///< a received packet, a recv-pool slot
    };

    uint64_t KindOf(uint64_t name) noexcept { return (name & KIND_MASK) >> KIND_SHIFT; }

    // Slot and generation share the 61-bit payload: the slot low, biased so a
    // zero payload is never valid, the generation above it. 24 bits of slot
    // covers every pool this transport sizes; 37 bits of generation holds any
    // uint32 without loss.
    constexpr uint64_t SLOT_BITS = 24;
    constexpr uint64_t SLOT_MASK = (uint64_t{1} << SLOT_BITS) - 1;

    uint64_t PackName(uint64_t kind, uint32_t slot, uint32_t generation) noexcept
    {
        if (slot > SLOT_MASK - 1) return FLUX_NONE;
        return (kind << KIND_SHIFT)
             | (static_cast<uint64_t>(slot) + 1)
             | (static_cast<uint64_t>(generation) << SLOT_BITS);
    }

    bool UnpackName(uint64_t kind, uint64_t name, uint32_t& slot, uint32_t& generation) noexcept
    {
        if (name == FLUX_NONE || KindOf(name) != kind) return false;
        const uint64_t payload = name & PAYLOAD_MASK;
        const uint64_t biased  = payload & SLOT_MASK;
        if (biased == 0) return false;
        slot       = static_cast<uint32_t>(biased - 1);
        generation = static_cast<uint32_t>(payload >> SLOT_BITS);
        return true;
    }

    // A flow carries more than a slot: the epoch that spots a recycled slot,
    // plus the id and the wire byte the builder stamps, all fixed for the
    // flow's whole life. Packed rather than looked up, so a flow number needs
    // no table of its own and CloseFlow can rebuild the handle exactly. The
    // fields fill the 61-bit payload exactly: slot 20, epoch 17, id 16, the
    // wire byte 8. Seventeen bits of epoch means a stale handle could only
    // alias after the same slot has been reopened 131072 times, which no run
    // reaches.
    constexpr uint64_t FLOW_SLOT_BITS   = 20;
    constexpr uint64_t FLOW_EPOCH_BITS  = 17;
    constexpr uint64_t FLOW_ID_BITS     = 16;
    constexpr uint64_t FLOW_EPOCH_SHIFT = FLOW_SLOT_BITS;
    constexpr uint64_t FLOW_ID_SHIFT    = FLOW_EPOCH_SHIFT + FLOW_EPOCH_BITS;
    constexpr uint64_t FLOW_DATA_SHIFT  = FLOW_ID_SHIFT + FLOW_ID_BITS;

    uint64_t PackFlow(const flux::FlowHandle& flow) noexcept
    {
        const uint64_t slot  = flow.Slot();
        const uint64_t epoch = flow.Epoch();
        if (slot >= (uint64_t{1} << FLOW_SLOT_BITS) - 1) return FLUX_NONE;
        if (epoch >= (uint64_t{1} << FLOW_EPOCH_BITS))   return FLUX_NONE;
        return (KIND_FLOW << KIND_SHIFT)
             | (slot + 1)
             | (epoch << FLOW_EPOCH_SHIFT)
             | (static_cast<uint64_t>(flow.Id())       << FLOW_ID_SHIFT)
             | (static_cast<uint64_t>(flow.FlowData()) << FLOW_DATA_SHIFT);
    }

    bool UnpackFlow(uint64_t name, flux::FlowHandle& out) noexcept
    {
        if (name == FLUX_NONE || KindOf(name) != KIND_FLOW) return false;
        const uint64_t biased = name & ((uint64_t{1} << FLOW_SLOT_BITS) - 1);
        if (biased == 0) return false;

        const uint32_t slot  = static_cast<uint32_t>(biased - 1);
        const uint32_t epoch = static_cast<uint32_t>(
            (name >> FLOW_EPOCH_SHIFT) & ((uint64_t{1} << FLOW_EPOCH_BITS) - 1));
        const uint16_t id    = static_cast<uint16_t>(
            (name >> FLOW_ID_SHIFT) & ((uint64_t{1} << FLOW_ID_BITS) - 1));
        const uint8_t  data  = static_cast<uint8_t>(name >> FLOW_DATA_SHIFT);

        out = flux::FlowHandle(slot, epoch, id, data);
        return true;
    }

    // --- One packet under construction ------------------------------------
    struct PacketEntry
    {
        enum class Stage : uint8_t { Free = 0, Declaring = 1, Writing = 2 };

        std::atomic_flag busy = ATOMIC_FLAG_INIT;

        // Atomic because another thread may read it, through FindEntry, while
        // this entry is being freed and its generation advanced. A stale
        // packet number carries an old generation and so mismatches and is
        // rejected before any storage is touched; the atomic is what makes
        // that rejecting read defined rather than a torn one. stage stays
        // plain: FindEntry only reads it once the generation has matched, and
        // a matching generation means a live number, which by contract one
        // thread owns.
        std::atomic<uint32_t> generation{0};
        Stage    stage      = Stage::Free;

        // Whether NoFlow or WithFlow has been called. The builder needs that
        // choice before the first put decides which pool the body goes to, so
        // a put or send before it is refused here rather than left to fault
        // its way through Begin.
        bool     declared   = false;

        alignas(flux::wire::PacketBuilder)      unsigned char builderStore[sizeof(flux::wire::PacketBuilder)];
        alignas(flux::wire::PacketContentStage) unsigned char contentStore[sizeof(flux::wire::PacketContentStage)];

        // WithFlow keeps a pointer to the handle it was given and dereferences
        // it later, at the first put. In C++ that is one chained expression
        // and always safe; here the two are separate calls, so the builder is
        // pointed at this copy instead of at anything the caller owns.
        flux::FlowHandle flow;

        flux::wire::PacketBuilder* Builder() noexcept
        { return reinterpret_cast<flux::wire::PacketBuilder*>(builderStore); }

        flux::wire::PacketContentStage* Content() noexcept
        { return reinterpret_cast<flux::wire::PacketContentStage*>(contentStore); }
    };

    // --- What a FluxSocket* really points at -------------------------------
    struct SocketBox
    {
        flux::Socket socket;

        // The caller's two pointers. Registering the C hook directly is
        // impossible, since it takes a FluxEvent* where flux calls with an
        // EventInfo&, so the socket is given EventTrampoline and this box.
        FluxEventHook hook{nullptr};
        void*         context{nullptr};

        std::unique_ptr<PacketEntry[]> packets;
        uint32_t packetCount{0};

        // Where the search for a free builder starts, so concurrent senders
        // spread out instead of all colliding on entry zero.
        std::atomic<uint32_t> packetHint{0};
    };

    SocketBox* Box(FluxSocket* s) noexcept { return reinterpret_cast<SocketBox*>(s); }

    FluxError Err(common::Error e) noexcept { return static_cast<FluxError>(e); }

    // --- Peers ------------------------------------------------------------
    //
    // A peer number is its table slot and the generation PeerTable advances
    // whenever a slot stops naming its peer. Turning one back into an Address
    // costs a locked lookup, which every peer-taking call below pays once.
    bool PeerAddressOf(SocketBox* box, FluxPeer name, flux::Address& out) noexcept
    {
        uint32_t slot = 0, generation = 0;
        if (!UnpackName(KIND_PEER, name, slot, generation)) return false;

        flux::PeerHandle handle = box->socket.GetPeerBySlot(slot, generation);
        if (handle.Failed()) return false;
        const flux::Peer* peer = handle.Read();
        if (peer == nullptr) return false;

        out = peer->addr;
        return true;
    }

    FluxPeer PeerNameOf(SocketBox* box, const flux::Address& addr) noexcept
    {
        flux::PeerHandle handle = box->socket.GetPeer(addr);
        if (handle.Failed()) return FLUX_NONE;
        const uint32_t slot = handle.GetSlotIndex();
        // Read the generation while the handle still holds the slot's read
        // lock, so a removal cannot slip between the two and mint a name that
        // was already stale when it was made.
        const uint32_t generation = box->socket.PeerGenerationOf(slot);
        if (handle.Read() == nullptr) return FLUX_NONE;
        return PackName(KIND_PEER, slot, generation);
    }

    // --- The event trampoline ---------------------------------------------
    void EventTrampoline(void* context, const flux::EventInfo& info)
    {
        SocketBox* box = static_cast<SocketBox*>(context);
        if (box == nullptr || box->hook == nullptr) return;
        box->hook(box->context, reinterpret_cast<const FluxEvent*>(&info));
    }

    // The current event, so EventPeer can turn its address into a number
    // without the hook having to carry a socket. Set around the dispatch that
    // Poll performs, on the thread doing it.
    thread_local SocketBox* t_eventBox = nullptr;

#ifdef _WIN32
    struct WinsockBoot
    {
        WinsockBoot() { WSADATA data; WSAStartup(MAKEWORD(2, 2), &data); }
    };
    WinsockBoot g_winsockBoot;
    constexpr flux::Socket::BackendType NATIVE_BACKEND = flux::Socket::BackendType::STD_WIN;
#else
    constexpr flux::Socket::BackendType NATIVE_BACKEND = flux::Socket::BackendType::STD_UNX;
#endif

    constexpr uint32_t DEFAULT_PACKET_BUILDERS = 64;

    // Nothing in flux throws by design, but Init allocates through
    // std::make_unique and the build enables exceptions, so an allocation
    // failure would otherwise unwind straight into C, which is undefined. Every
    // entry point that can reach an allocation wears this.
    #define FLUX_GUARD_BEGIN try {
    #define FLUX_GUARD_END(fallback) } catch (...) { return fallback; }
}

extern "C" {

// --- Layout and defaults ---------------------------------------------------

void FLUX_CALL flux_layout_check(FluxLayout* out)
{
    if (out == nullptr) return;
    std::memset(out, 0, sizeof(*out));
    out->sizeofConfig           = static_cast<uint32_t>(sizeof(FluxConfig));
    out->sizeofFlowsConfig      = static_cast<uint32_t>(sizeof(FluxFlowsConfig));
    out->sizeofTimersConfig     = static_cast<uint32_t>(sizeof(FluxTimersConfig));
    out->sizeofLivenessConfig   = static_cast<uint32_t>(sizeof(FluxLivenessConfig));
    out->sizeofEventsConfig     = static_cast<uint32_t>(sizeof(FluxEventsConfig));
    out->sizeofTransferView     = static_cast<uint32_t>(sizeof(FluxTransferView));
    out->sizeofApiTable         = static_cast<uint32_t>(sizeof(FluxApiV1));
    out->offsetofConfigFlows    = static_cast<uint32_t>(offsetof(FluxConfig, flows));
    out->offsetofConfigLiveness = static_cast<uint32_t>(offsetof(FluxConfig, liveness));
    out->offsetofConfigEvents   = static_cast<uint32_t>(offsetof(FluxConfig, events));
    out->offsetofConfigTimers   = static_cast<uint32_t>(offsetof(FluxConfig, timers));
    out->offsetofConfigPort     = static_cast<uint32_t>(offsetof(FluxConfig, port));
    out->sizeofKnockConfig      = static_cast<uint32_t>(sizeof(FluxKnockConfig));
    out->offsetofConfigKnock    = static_cast<uint32_t>(offsetof(FluxConfig, knock));
}

void FLUX_CALL flux_default_config(FluxConfig* out)
{
    if (out == nullptr) return;

    // Read the defaults off a real Config rather than repeating them, so the
    // two can never disagree about what a fresh socket starts from.
    const flux::Socket::Config d{};
    std::memset(out, 0, sizeof(*out));

    out->rotateAfterBytes          = d.rotateAfterBytes;
    out->trustedCertCount          = d.trustedCertCount;
    out->identityHistory           = d.identityHistory;
    out->knock.enable              = d.knock.enable ? 1u : 0u;
    out->knock.maxUnprovenPeers    = d.knock.maxUnprovenPeers;
    out->knock.unprovenPacketLimit = d.knock.unprovenPacketLimit;
    out->knock.budgetPerTick       = d.knock.budgetPerTick;
    out->knock.ttlWindowSeconds    = d.knock.ttlWindowSeconds;
    out->knock.ringSize            = d.knock.ringSize;

    out->flows.maxTransferBytes    = d.flows.maxTransferBytes;
    out->flows.flowCount           = d.flows.flowCount;
    out->flows.outCount            = d.flows.outCount;
    out->flows.bulkOutCount        = d.flows.bulkOutCount;
    out->flows.inCount             = d.flows.inCount;
    out->flows.bulkInCount         = d.flows.bulkInCount;
    out->flows.transferOutCount    = d.flows.transferOutCount;
    out->flows.transferInCount     = d.flows.transferInCount;
    out->flows.maxOutPerPeer       = d.flows.maxOutPerPeer;
    out->flows.maxInPerPeer        = d.flows.maxInPerPeer;
    out->flows.recvGrant           = d.flows.recvGrant;
    out->flows.stagingCount        = d.flows.stagingCount;
    out->flows.minCongestionBudget = d.flows.minCongestionBudget;
    out->flows.reliableWaitCount   = d.flows.reliableWaitCount;
    out->flows.unreliableWaitCount = d.flows.unreliableWaitCount;

    out->liveness.idleTimeoutMicros         = d.liveness.idleTimeoutMicros;
    out->liveness.refreshGrainMicros        = d.liveness.refreshGrainMicros;
    out->liveness.flowStallTimeoutMicros    = d.liveness.flowStallTimeoutMicros;
    out->liveness.acceptUnsecureFromUnknown = d.liveness.acceptUnsecureFromUnknown ? 1u : 0u;

    out->timers.ackDelayMicros      = d.timers.ackDelayMicros;
    out->timers.retryIntervalMicros = d.timers.retryIntervalMicros;

    out->maxPeers             = d.maxPeers;
    out->pendingPacketCount   = d.pendingPacketCount;
    out->recvSlotCount        = d.recvSlotCount;
    out->sendSlotCount        = d.sendSlotCount;
    out->recvReserveSlots     = d.recvReserveSlots;
    out->recvBatch            = d.recvBatch;
    out->pollLanes            = d.pollLanes;
    out->packetBuilders       = DEFAULT_PACKET_BUILDERS;
    out->migrateBudgetPerPoll = d.migrateBudgetPerPoll;
    out->replayWindowBits     = d.replayWindowBits;
    out->backend              = FLUX_BACKEND_DEFAULT;
    out->port                 = d.port;
    out->enableMigration      = d.enableMigration ? 1u : 0u;
}

// --- Socket lifetime -------------------------------------------------------

FluxSocket* FLUX_CALL flux_create_socket(void)
{
    return reinterpret_cast<FluxSocket*>(new (std::nothrow) SocketBox());
}

FluxError FLUX_CALL flux_init_socket(FluxSocket* s, const FluxConfig* in)
{
    if (s == nullptr || in == nullptr) return FLUX_ERR_INVALID_PARAM;
    SocketBox* box = Box(s);

FLUX_GUARD_BEGIN
    flux::Socket::Config cfg{};
    cfg.type                 = NATIVE_BACKEND;
    cfg.port                 = in->port;
    cfg.maxPeers             = in->maxPeers;
    cfg.pendingPacketCount   = in->pendingPacketCount;
    cfg.recvSlotCount        = in->recvSlotCount;
    cfg.sendSlotCount        = in->sendSlotCount;
    cfg.recvReserveSlots     = in->recvReserveSlots;
    cfg.recvBatch            = in->recvBatch;
    cfg.pollLanes            = in->pollLanes;
    cfg.replayWindowBits     = in->replayWindowBits;
    cfg.enableMigration      = in->enableMigration != 0;
    cfg.migrateBudgetPerPoll = in->migrateBudgetPerPoll;
    cfg.rotateAfterBytes     = in->rotateAfterBytes;
    cfg.trustedCertCount     = in->trustedCertCount;
    if (in->identityHistory > flux::internal::MAX_IDENTITY_HISTORY)
        return FLUX_ERR_INVALID_PARAM;
    cfg.identityHistory      = static_cast<uint8_t>(in->identityHistory);

    cfg.knock.enable              = in->knock.enable != 0;
    cfg.knock.maxUnprovenPeers    = in->knock.maxUnprovenPeers;
    cfg.knock.unprovenPacketLimit = in->knock.unprovenPacketLimit;
    cfg.knock.budgetPerTick       = in->knock.budgetPerTick;
    cfg.knock.ttlWindowSeconds    = in->knock.ttlWindowSeconds;
    cfg.knock.ringSize            = in->knock.ringSize;

    // Init copies the identity, so the parsed one is wiped as this scope ends
    // and the only lasting copy of the secret is the socket's own.
    flux::Identity identity;
    if (in->identity != nullptr)
    {
        common::Result<flux::Identity> parsed =
            flux::Identity::Parse(in->identity, FLUX_IDENTITY_SIZE);
        if (parsed.isErr()) return FLUX_ERR_INVALID_PARAM;
        identity     = parsed.Take();
        cfg.identity = &identity;
    }
    const struct IdentityWipe
    {
        flux::Identity& held;
        ~IdentityWipe() { held.Wipe(); }
    } identityWipe{ identity };

    cfg.flows.flowCount           = in->flows.flowCount;
    cfg.flows.outCount            = in->flows.outCount;
    cfg.flows.bulkOutCount        = in->flows.bulkOutCount;
    cfg.flows.inCount             = in->flows.inCount;
    cfg.flows.bulkInCount         = in->flows.bulkInCount;
    cfg.flows.transferOutCount    = in->flows.transferOutCount;
    cfg.flows.transferInCount     = in->flows.transferInCount;
    cfg.flows.maxTransferBytes    = in->flows.maxTransferBytes;
    cfg.flows.maxOutPerPeer       = in->flows.maxOutPerPeer;
    cfg.flows.maxInPerPeer        = in->flows.maxInPerPeer;
    cfg.flows.recvGrant           = in->flows.recvGrant;
    cfg.flows.stagingCount        = in->flows.stagingCount;
    cfg.flows.minCongestionBudget = in->flows.minCongestionBudget;
    cfg.flows.reliableWaitCount   = in->flows.reliableWaitCount;
    cfg.flows.unreliableWaitCount = in->flows.unreliableWaitCount;

    cfg.timers.ackDelayMicros      = in->timers.ackDelayMicros;
    cfg.timers.retryIntervalMicros = in->timers.retryIntervalMicros;

    cfg.liveness.idleTimeoutMicros         = in->liveness.idleTimeoutMicros;
    cfg.liveness.refreshGrainMicros        = in->liveness.refreshGrainMicros;
    cfg.liveness.flowStallTimeoutMicros    = in->liveness.flowStallTimeoutMicros;
    cfg.liveness.acceptUnsecureFromUnknown = in->liveness.acceptUnsecureFromUnknown != 0;

    box->hook    = in->events.hook;
    box->context = in->events.context;
    cfg.events.hook       = (in->events.hook != nullptr) ? &EventTrampoline : nullptr;
    cfg.events.context    = box;
    cfg.events.subscribed = in->events.subscribed;

    const common::Error status = box->socket.Init(cfg);
    if (status != common::Error::Ok) return Err(status);

    const uint32_t builders = (in->packetBuilders == 0) ? DEFAULT_PACKET_BUILDERS : in->packetBuilders;

    box->packets.reset(new (std::nothrow) PacketEntry[builders]);
    if (!box->packets)
    {
        box->socket.Shutdown();
        return FLUX_ERR_ALLOC_FAILED;
    }

    box->packetCount  = builders;
    box->packetHint.store(0, std::memory_order_relaxed);
    return FLUX_OK;
FLUX_GUARD_END(FLUX_ERR_INTERNAL)
}

void FLUX_CALL flux_shutdown_socket(FluxSocket* s)
{
    if (s == nullptr) return;
    SocketBox* box = Box(s);

    // Everything the shim holds points into pools the socket is about to free,
    // so it all goes first. A stranded handle released afterwards would unlock
    // and return a slot to a pool that no longer exists.
    for (uint32_t i = 0; i < box->packetCount; ++i)
    {
        PacketEntry& e = box->packets[i];
        if (e.stage == PacketEntry::Stage::Writing)      e.Content()->~PacketContentStage();
        else if (e.stage == PacketEntry::Stage::Declaring) e.Builder()->~PacketBuilder();
        e.stage = PacketEntry::Stage::Free;
    }

    // Packet numbers a binding still holds die with the pool; the guarded
    // release refuses them afterwards because the socket reports itself down.
    box->socket.Shutdown();
}

void FLUX_CALL flux_destroy_socket(FluxSocket* s)
{
    if (s == nullptr) return;
    flux_shutdown_socket(s);
    delete Box(s);
}

// --- The loop --------------------------------------------------------------

void FLUX_CALL flux_update(FluxSocket* s)
{
    if (s == nullptr) return;
    t_eventBox = Box(s);
    Box(s)->socket.Update();
    t_eventBox = nullptr;
}

void FLUX_CALL flux_flush(FluxSocket* s)
{
    if (s == nullptr) return;
    Box(s)->socket.Flush();
}

uint64_t FLUX_CALL flux_next_timeout(FluxSocket* s)
{
    if (s == nullptr) return 0;
    return Box(s)->socket.NextTimeout();
}

// --- Peers -----------------------------------------------------------------

FluxPeer FLUX_CALL flux_peer(FluxSocket* s, const char* host, uint16_t port)
{
    if (s == nullptr || host == nullptr) return FLUX_NONE;
    SocketBox* box = Box(s);

FLUX_GUARD_BEGIN
    common::Result<flux::Address> resolved = flux::Address::From(host, port);
    if (resolved.isErr()) return FLUX_NONE;
    const flux::Address addr = resolved.Take();

    // Registers the peer if it is new, which is what gives it the slot the
    // number is built from. Ok also means already under way or already
    // established, so asking twice is cheap and idempotent.
    if (box->socket.Connect(addr) != common::Error::Ok) return FLUX_NONE;

    return PeerNameOf(box, addr);
FLUX_GUARD_END(FLUX_NONE)
}

uint32_t FLUX_CALL flux_peer_text(FluxSocket* s, FluxPeer name, char* out, uint32_t cap)
{
    if (s == nullptr || out == nullptr || cap == 0) return 0;
    flux::Address addr;
    if (!PeerAddressOf(Box(s), name, addr)) return 0;
    if (addr.ToChar(out, cap) == nullptr) return 0;
    return static_cast<uint32_t>(std::strlen(out));
}

uint32_t FLUX_CALL flux_peer_alive(FluxSocket* s, FluxPeer name)
{
    if (s == nullptr) return 0;
    flux::Address addr;
    return PeerAddressOf(Box(s), name, addr) ? 1u : 0u;
}

uint32_t FLUX_CALL flux_peer_ready(FluxSocket* s, FluxPeer name)
{
    if (s == nullptr) return 0;
    uint32_t slot = 0, generation = 0;
    if (!UnpackName(KIND_PEER, name, slot, generation)) return 0;

    flux::PeerHandle handle = Box(s)->socket.GetPeerBySlot(slot, generation);
    if (handle.Failed()) return 0;
    const flux::Peer* peer = handle.Read();
    return (peer != nullptr && peer->IsValid()) ? 1u : 0u;
}

FluxError FLUX_CALL flux_remove_peer(FluxSocket* s, FluxPeer name)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;
    flux::Address addr;
    if (!PeerAddressOf(Box(s), name, addr)) return FLUX_ERR_NOT_FOUND;
    return Err(Box(s)->socket.RemovePeer(addr));
}

FluxError FLUX_CALL flux_set_recv_grant(FluxSocket* s, FluxPeer name, uint32_t slots)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;
    flux::Address addr;
    if (!PeerAddressOf(Box(s), name, addr)) return FLUX_ERR_NOT_FOUND;
    return Err(Box(s)->socket.SetRecvGrant(addr, slots));
}

uint32_t FLUX_CALL flux_recv_grant(FluxSocket* s, FluxPeer name)
{
    if (s == nullptr) return 0;
    flux::Address addr;
    if (!PeerAddressOf(Box(s), name, addr)) return 0;
    return Box(s)->socket.RecvGrantFor(addr);
}

uint32_t FLUX_CALL flux_rotate_tags(FluxSocket* s)
{
    if (s == nullptr) return 0;
    return Box(s)->socket.RotateTags();
}

// --- Flows -----------------------------------------------------------------

FluxFlow FLUX_CALL flux_open_flow(FluxSocket* s, uint16_t flowId, FluxFlowMode mode)
{
    if (s == nullptr) return FLUX_NONE;
    if (mode < FLUX_FLOW_RELIABLE_ORDERED || mode > FLUX_FLOW_RELIABLE_ORDERED_BULK)
        return FLUX_NONE;

    flux::FlowHandle flow = Box(s)->socket.OpenFlow(flowId, static_cast<flux::FlowMode>(mode));
    if (flow.Failed()) return FLUX_NONE;
    return PackFlow(flow);
}

FluxError FLUX_CALL flux_close_flow(FluxSocket* s, FluxFlow name)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;
    flux::FlowHandle flow;
    if (!UnpackFlow(name, flow)) return FLUX_ERR_INVALID_PARAM;
    return Err(Box(s)->socket.CloseFlow(flow));
}

FluxFlowState FLUX_CALL flux_flow_state(FluxSocket* s, FluxFlow name)
{
    if (s == nullptr) return FLUX_FLOW_STATE_CLOSED;
    flux::FlowHandle flow;
    if (!UnpackFlow(name, flow)) return FLUX_FLOW_STATE_CLOSED;
    return static_cast<FluxFlowState>(Box(s)->socket.GetFlowState(flow));
}

FluxFlowState FLUX_CALL flux_flow_state_for(FluxSocket* s, FluxFlow name, FluxPeer peerName)
{
    if (s == nullptr) return FLUX_FLOW_STATE_CLOSED;
    flux::FlowHandle flow;
    if (!UnpackFlow(name, flow)) return FLUX_FLOW_STATE_CLOSED;
    flux::Address addr;
    if (!PeerAddressOf(Box(s), peerName, addr)) return FLUX_FLOW_STATE_CLOSED;
    return static_cast<FluxFlowState>(Box(s)->socket.GetFlowState(flow, addr));
}

// --- Receiving -------------------------------------------------------------

namespace {

// A packet number is a recv-pool index and the generation read at delivery.
// Turning one back into an index refuses a stale pair, so a released packet's
// number reports not-found instead of naming whatever landed in the slot next.
bool UnpackPacket(SocketBox* box, FluxPacket name, uint32_t& idx) noexcept
{
    uint32_t slot = 0, generation = 0;
    if (!UnpackName(KIND_PKT_RECV, name, slot, generation)) return false;
    if (box->socket.RecvGenerationOf(slot) != generation) return false;
    idx = slot;
    return true;
}

}   // namespace

uint32_t FLUX_CALL flux_poll(FluxSocket* s, uint32_t* lane, FluxPacket* out, uint32_t max)
{
    if (s == nullptr || lane == nullptr || out == nullptr || max == 0) return 0;
    SocketBox* box = Box(s);

    // The indices land in the front of the caller's own u64 array, viewed as
    // u32s, and are widened into packet numbers back to front. The write at
    // entry i never reaches an unread source: sources end at 4(i+1), the
    // write starts at 8i, and 8i >= 4(i+1) for every i above zero, while entry
    // zero is read before it is written.
    uint32_t* indices = reinterpret_cast<uint32_t*>(out);

    t_eventBox = box;
    const uint32_t count = box->socket.PollSlots(indices, max, *lane);
    t_eventBox = nullptr;

    for (uint32_t i = count; i-- > 0;)
    {
        const uint32_t idx = indices[i];
        out[i] = PackName(KIND_PKT_RECV, idx, box->socket.RecvGenerationOf(idx));
    }
    return count;
}

uint32_t FLUX_CALL flux_messages(FluxSocket* s, FluxPacket name,
                                 FluxMessage* out, uint32_t max,
                                 FluxPacketInfo* info)
{
    if (s == nullptr || out == nullptr || max == 0) return 0;
    SocketBox* box = Box(s);

    uint32_t idx = 0;
    if (!UnpackPacket(box, name, idx)) return 0;

    // One lock for everything the packet has to say. The handle is detached
    // at the end, never destroyed: destruction would return the slot to the
    // pool, and the slot stays the caller's until ReleasePacket.
    flux::PacketSlotHandle handle = box->socket.PacketAt(idx);
    const flux::PacketSlot* packet = handle.Read();
    if (packet == nullptr)
    {
        (void)handle.Detach();
        return 0;
    }

    if (info != nullptr)
    {
        info->peer     = PeerNameOf(box, packet->address);
        info->part     = static_cast<FluxFlowPart>(packet->Part());
        info->flowId   = packet->HasFlow() ? packet->FlowId() : UINT16_MAX;
        info->reserved = 0;
    }

    // The reader walks a batch exactly as the C++ cursor would; a packet
    // carrying one message and a batch carrying many read the same way.
    flux::PacketSlotReader reader{handle};
    uint32_t n = 0;
    do
    {
        if (reader.Content() == nullptr) break;
        out[n].bytes     = reader.Content();
        out[n].length    = reader.ContentLength();
        out[n].reserved  = 0;
        out[n].reserved2 = 0;
        ++n;
    } while (n < max && reader.NextMessage());

    (void)handle.Detach();   // the lock goes, the lease stays
    return n;
}

FluxError FLUX_CALL flux_release_packet(FluxSocket* s, FluxPacket name)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;

    uint32_t slot = 0, generation = 0;
    if (!UnpackName(KIND_PKT_RECV, name, slot, generation)) return FLUX_ERR_INVALID_PARAM;

    // Straight to the guarded release: the check and the void of the number
    // are one atomic step in the pool, so a repeat and a race both lose.
    return Err(Box(s)->socket.ReleaseRecvSlot(slot, generation));
}

void FLUX_CALL flux_end_poll(FluxSocket* s, uint32_t lane)
{
    if (s == nullptr) return;
    Box(s)->socket.ReleasePollLane(lane);   // NO_LANE and stale values are ignored
}

// --- Sending ---------------------------------------------------------------

namespace {

PacketEntry* TakeEntry(SocketBox* box, uint32_t& index) noexcept
{
    const uint32_t start = box->packetHint.fetch_add(1, std::memory_order_relaxed);
    for (uint32_t i = 0; i < box->packetCount; ++i)
    {
        const uint32_t candidate = (start + i) % box->packetCount;
        if (!box->packets[candidate].busy.test_and_set(std::memory_order_acquire))
        {
            index = candidate;
            return &box->packets[candidate];
        }
    }
    return nullptr;
}

PacketEntry* FindEntry(SocketBox* box, FluxPacket name, PacketEntry::Stage want) noexcept
{
    uint32_t index = 0, generation = 0;
    if (!UnpackName(KIND_PKT_BUILD, name, index, generation)) return nullptr;
    if (index >= box->packetCount) return nullptr;

    PacketEntry& e = box->packets[index];
    if (e.generation.load(std::memory_order_relaxed) != generation
        || e.stage != want) return nullptr;
    return &e;
}

// The builder's stage-two half is reached only through a put, because
// PacketBuilder::Begin is private and every public Put calls it. A put of
// nothing is the transition, with a real pointer and a zero length so the
// writer is never handed a null.
void MoveToWriting(PacketEntry& e) noexcept
{
    static const uint8_t NOTHING = 0;
    new (e.contentStore) flux::wire::PacketContentStage(e.Builder()->PutBytes(&NOTHING, 0));
    e.Builder()->~PacketBuilder();
    e.stage = PacketEntry::Stage::Writing;
}

void FreeEntry(SocketBox* box, PacketEntry& e) noexcept
{
    if (e.stage == PacketEntry::Stage::Writing)        e.Content()->~PacketContentStage();
    else if (e.stage == PacketEntry::Stage::Declaring) e.Builder()->~PacketBuilder();
    e.stage    = PacketEntry::Stage::Free;
    e.declared = false;
    e.flow     = flux::FlowHandle{};
    // The number that named it is dead now. Released so a concurrent FindEntry
    // sees this bump rather than a torn value.
    e.generation.fetch_add(1, std::memory_order_relaxed);
    e.busy.clear(std::memory_order_release);
    (void)box;
}

FluxError EnsureWriting(PacketEntry*& e, SocketBox* box, FluxPacket name) noexcept
{
    e = FindEntry(box, name, PacketEntry::Stage::Writing);
    if (e != nullptr) return FLUX_OK;

    e = FindEntry(box, name, PacketEntry::Stage::Declaring);
    if (e == nullptr) return FLUX_ERR_INVALID_STATE;
    if (!e->declared) return FLUX_ERR_INVALID_STATE;   // NoFlow/WithFlow owed first
    MoveToWriting(*e);
    return FLUX_OK;
}

}   // namespace

FluxPacket FLUX_CALL flux_build_packet(FluxSocket* s)
{
    if (s == nullptr) return FLUX_NONE;
    SocketBox* box = Box(s);

    uint32_t index = 0;
    PacketEntry* e = TakeEntry(box, index);
    if (e == nullptr) return FLUX_NONE;

    new (e->builderStore) flux::wire::PacketBuilder(box->socket.BuildPacket());
    e->stage = PacketEntry::Stage::Declaring;
    return PackName(KIND_PKT_BUILD, index, e->generation.load(std::memory_order_relaxed));
}

FluxPacket FLUX_CALL flux_reply(FluxSocket* s, FluxPacket received)
{
    if (s == nullptr) return FLUX_NONE;
    SocketBox* box = Box(s);

    uint32_t idx = 0;
    if (!UnpackPacket(box, received, idx)) return FLUX_NONE;

    uint32_t index = 0;
    PacketEntry* e = TakeEntry(box, index);
    if (e == nullptr) return FLUX_NONE;

    // PrepareResponse reads the packet to take its source address, which the
    // builder keeps as a copy; the borrow ends at the Detach, so the reply
    // outlives the packet it answers.
    flux::PacketSlotHandle handle = box->socket.PacketAt(idx);
    new (e->builderStore) flux::wire::PacketBuilder(handle.PrepareResponse());
    (void)handle.Detach();

    e->stage = PacketEntry::Stage::Declaring;
    return PackName(KIND_PKT_BUILD, index, e->generation.load(std::memory_order_relaxed));
}

FluxError FLUX_CALL flux_no_flow(FluxSocket* s, FluxPacket name)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;
    PacketEntry* e = FindEntry(Box(s), name, PacketEntry::Stage::Declaring);
    if (e == nullptr) return FLUX_ERR_INVALID_STATE;
    e->Builder()->NoFlow();
    e->declared = true;
    return FLUX_OK;
}

FluxError FLUX_CALL flux_with_flow(FluxSocket* s, FluxPacket name, FluxFlow flowName,
                                   FluxFlowPart part)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;
    PacketEntry* e = FindEntry(Box(s), name, PacketEntry::Stage::Declaring);
    if (e == nullptr) return FLUX_ERR_INVALID_STATE;
    if (part < FLUX_PART_WHOLE || part > FLUX_PART_LAST) return FLUX_ERR_INVALID_PARAM;
    if (!UnpackFlow(flowName, e->flow)) return FLUX_ERR_INVALID_PARAM;

    // Pointed at our copy, never at anything the caller owns: the builder
    // keeps the address and reads it at the first put, which is a separate
    // call away, and a managed runtime is free to move its own storage between
    // the two.
    e->Builder()->WithFlow(e->flow, static_cast<flux::FlowPart>(part));
    e->declared = true;
    return FLUX_OK;
}

FluxError FLUX_CALL flux_unsecured(FluxSocket* s, FluxPacket name)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;
    PacketEntry* e = FindEntry(Box(s), name, PacketEntry::Stage::Declaring);
    if (e == nullptr) return FLUX_ERR_INVALID_STATE;
    e->Builder()->Unsecured();
    return FLUX_OK;
}

FluxError FLUX_CALL flux_mac_only(FluxSocket* s, FluxPacket name)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;
    PacketEntry* e = FindEntry(Box(s), name, PacketEntry::Stage::Declaring);
    if (e == nullptr) return FLUX_ERR_INVALID_STATE;
    e->Builder()->MacOnly();
    return FLUX_OK;
}

#define FLUX_PUT(fn, type, call)                                              \
FluxError FLUX_CALL fn(FluxSocket* s, FluxPacket name, type value)            \
{                                                                             \
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;                          \
    PacketEntry* e = nullptr;                                                 \
    const FluxError ready = EnsureWriting(e, Box(s), name);                   \
    if (ready != FLUX_OK) return ready;                                       \
    e->Content()->call(value);                                                \
    return FLUX_OK;                                                           \
}

FLUX_PUT(flux_put_u8,  uint8_t,  PutU8)
FLUX_PUT(flux_put_u16, uint16_t, PutU16)
FLUX_PUT(flux_put_u32, uint32_t, PutU32)
FLUX_PUT(flux_put_u64, uint64_t, PutU64)

#undef FLUX_PUT

FluxError FLUX_CALL flux_put_bytes(FluxSocket* s, FluxPacket name,
                                   const uint8_t* data, uint16_t len)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;
    if (data == nullptr && len != 0) return FLUX_ERR_INVALID_PARAM;
    PacketEntry* e = nullptr;
    const FluxError ready = EnsureWriting(e, Box(s), name);
    if (ready != FLUX_OK) return ready;
    static const uint8_t NOTHING = 0;
    e->Content()->PutBytes(data != nullptr ? data : &NOTHING, len);
    return FLUX_OK;
}

// The four ways out. Each sends and then frees the entry on EVERY path,
// including a failed send: PacketContentStage::Send returns early on a stage
// that already failed, before it hands the slot over, so the destructor is the
// only thing that gives that slot back.

FluxError FLUX_CALL flux_send(FluxSocket* s, FluxPacket name, FluxPeer peerName)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;
    SocketBox* box = Box(s);
    flux::Address addr;
    if (!PeerAddressOf(box, peerName, addr)) return FLUX_ERR_NOT_FOUND;

    PacketEntry* e = nullptr;
    const FluxError ready = EnsureWriting(e, box, name);
    if (ready != FLUX_OK) return ready;

    const common::Error status = e->Content()->Send(addr);
    FreeEntry(box, *e);
    return Err(status);
}

FluxError FLUX_CALL flux_send_secured(FluxSocket* s, FluxPacket name, FluxPeer peerName)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;
    SocketBox* box = Box(s);
    flux::Address addr;
    if (!PeerAddressOf(box, peerName, addr)) return FLUX_ERR_NOT_FOUND;

    PacketEntry* e = nullptr;
    const FluxError ready = EnsureWriting(e, box, name);
    if (ready != FLUX_OK) return ready;

    const common::Error status = e->Content()->SendSecured(addr);
    FreeEntry(box, *e);
    return Err(status);
}

FluxError FLUX_CALL flux_respond(FluxSocket* s, FluxPacket name)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;
    SocketBox* box = Box(s);
    PacketEntry* e = nullptr;
    const FluxError ready = EnsureWriting(e, box, name);
    if (ready != FLUX_OK) return ready;

    const common::Error status = e->Content()->Respond();
    FreeEntry(box, *e);
    return Err(status);
}

FluxError FLUX_CALL flux_respond_secured(FluxSocket* s, FluxPacket name)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;
    SocketBox* box = Box(s);
    PacketEntry* e = nullptr;
    const FluxError ready = EnsureWriting(e, box, name);
    if (ready != FLUX_OK) return ready;

    const common::Error status = e->Content()->RespondSecured();
    FreeEntry(box, *e);
    return Err(status);
}

FluxError FLUX_CALL flux_abandon(FluxSocket* s, FluxPacket name)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;
    SocketBox* box = Box(s);

    PacketEntry* e = FindEntry(box, name, PacketEntry::Stage::Writing);
    if (e == nullptr) e = FindEntry(box, name, PacketEntry::Stage::Declaring);
    if (e == nullptr) return FLUX_ERR_INVALID_STATE;

    FreeEntry(box, *e);
    return FLUX_OK;
}

// --- Events ----------------------------------------------------------------

uint32_t FLUX_CALL flux_event_has(const FluxEvent* e, FluxEventBits bits)
{
    if (e == nullptr) return 0;
    const flux::EventInfo* info = reinterpret_cast<const flux::EventInfo*>(e);

    // Has answers about one event and the C side may ask about several at
    // once, so the set is walked a bit at a time.
    for (uint32_t bit = 1; bit != 0; bit <<= 1)
    {
        if ((bits & bit) == 0) continue;
        if (info->Has(static_cast<flux::SocketEvent>(bit))) return 1u;
    }
    return 0u;
}

FluxPeer FLUX_CALL flux_event_peer(FluxSocket* s, const FluxEvent* e)
{
    if (e == nullptr) return FLUX_NONE;
    SocketBox* box = (s != nullptr) ? Box(s) : t_eventBox;
    if (box == nullptr) return FLUX_NONE;

    const flux::EventInfo* info = reinterpret_cast<const flux::EventInfo*>(e);
    return PeerNameOf(box, info->Peer());
}

uint16_t FLUX_CALL flux_event_flow(const FluxEvent* e)
{
    if (e == nullptr) return UINT16_MAX;
    return reinterpret_cast<const flux::EventInfo*>(e)->Flow();
}

// --- Transfers -------------------------------------------------------------

FluxError FLUX_CALL flux_send_transfer(FluxSocket* s, uint16_t transferId, FluxPeer peerName,
                                       const void* buffer, uint64_t length)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;
    flux::Address addr;
    if (!PeerAddressOf(Box(s), peerName, addr)) return FLUX_ERR_NOT_FOUND;
    return Err(Box(s)->socket.SendTransfer(transferId, addr, buffer, length));
}

uint64_t FLUX_CALL flux_transfer_length(FluxSocket* s, uint16_t transferId, FluxPeer peerName)
{
    if (s == nullptr) return 0;
    flux::Address addr;
    if (!PeerAddressOf(Box(s), peerName, addr)) return 0;
    flux::TransferRequest request = Box(s)->socket.PendingTransfer(transferId, addr);
    return request.Valid() ? request.Length() : 0;
}

FluxError FLUX_CALL flux_allow_transfer(FluxSocket* s, uint16_t transferId,
                                        FluxPeer peerName, void* buffer)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;
    flux::Address addr;
    if (!PeerAddressOf(Box(s), peerName, addr)) return FLUX_ERR_NOT_FOUND;
    flux::TransferRequest request = Box(s)->socket.PendingTransfer(transferId, addr);
    if (!request.Valid()) return FLUX_ERR_NOT_FOUND;
    return Err(request.Allow(buffer));
}

FluxError FLUX_CALL flux_reject_transfer(FluxSocket* s, uint16_t transferId, FluxPeer peerName)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;
    flux::Address addr;
    if (!PeerAddressOf(Box(s), peerName, addr)) return FLUX_ERR_NOT_FOUND;
    flux::TransferRequest request = Box(s)->socket.PendingTransfer(transferId, addr);
    if (!request.Valid()) return FLUX_ERR_NOT_FOUND;
    return Err(request.Reject());
}

uint64_t FLUX_CALL flux_transfer_progress(FluxSocket* s, uint16_t transferId, FluxPeer peerName)
{
    if (s == nullptr) return 0;
    flux::Address addr;
    if (!PeerAddressOf(Box(s), peerName, addr)) return 0;
    return Box(s)->socket.TransferProgress(transferId, addr);
}

uint32_t FLUX_CALL flux_poll_transfers(FluxSocket* s, FluxTransferView* out, uint32_t max)
{
    if (s == nullptr || out == nullptr || max == 0) return 0;
    SocketBox* box = Box(s);

    constexpr uint32_t CHUNK = 8;
    flux::TransferView staged[CHUNK];

    uint32_t written = 0;
    while (written < max)
    {
        const uint32_t want = (max - written) < CHUNK ? (max - written) : CHUNK;
        const uint32_t got  = static_cast<uint32_t>(box->socket.PollTransfers(staged, want));
        if (got == 0) break;

        for (uint32_t i = 0; i < got; ++i)
        {
            FluxTransferView& v = out[written + i];
            v.bytes      = staged[i].Bytes();
            v.length     = staged[i].Length();
            v.peer       = PeerNameOf(box, staged[i].Peer());
            v.outcome    = Err(staged[i].Outcome());
            v.transferId = staged[i].Flow();
            v.reserved   = 0;
        }
        written += got;
        if (got < want) break;
    }
    return written;
}

FluxError FLUX_CALL flux_complete_transfer(FluxSocket* s, uint16_t transferId, FluxPeer peerName)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;
    flux::Address addr;
    if (!PeerAddressOf(Box(s), peerName, addr)) return FLUX_ERR_NOT_FOUND;
    return Err(Box(s)->socket.CompleteTransfer(transferId, addr));
}

}   // extern "C"

// --- The table -------------------------------------------------------------
//
// Filled once, lives for the life of the process, sits in read-only memory.
// The initializer is positional, so this order and the struct's order in
// flux_api_v1.h are the same order, and a line moved in one has to move in the
// other.
// --- Identity and certificates ---

// The C constant is what a binding sizes buffers against and the C++ one is
// what the transport enforces, so the build refuses to let them drift.
static_assert(FLUX_TAG_SIZE == flux::Certificate::IDENTITY_TAG_SIZE,
              "FLUX_TAG_SIZE must match the certificate's tag");
static_assert(FLUX_IDENTITY_SIZE == flux::Identity::FILE_SIZE,
              "FLUX_IDENTITY_SIZE must match the serialized identity");
static_assert(FLUX_CERT_SIZE == flux::Certificate::PINNED_SIZE,
              "FLUX_CERT_SIZE must match the serialized certificate");
static_assert(FLUX_SAFE_PAYLOAD_BYTES == flux::Socket::SAFE_PAYLOAD_BYTES,
              "FLUX_SAFE_PAYLOAD_BYTES must match the always-safe payload");

FluxError FLUX_CALL flux_identity_generate(const uint8_t* tag, uint8_t* out)
{
    if (tag == nullptr || out == nullptr) return FLUX_ERR_INVALID_PARAM;
FLUX_GUARD_BEGIN
    flux::Certificate::IdentityTag wanted{};
    std::memcpy(wanted.data(), tag, wanted.size());

    common::Result<flux::Identity> made = flux::Identity::Generate(wanted);
    if (made.isErr()) return Err(made.error);

    flux::Identity identity = made.Take();
    const bool wrote = identity.Serialize(out, FLUX_IDENTITY_SIZE);
    identity.Wipe();
    return wrote ? FLUX_OK : FLUX_ERR_INVALID_PARAM;
FLUX_GUARD_END(FLUX_ERR_INVALID_PARAM)
}

FluxError FLUX_CALL flux_identity_certificate(const uint8_t* identityBytes, uint8_t* out)
{
    if (identityBytes == nullptr || out == nullptr) return FLUX_ERR_INVALID_PARAM;
FLUX_GUARD_BEGIN
    common::Result<flux::Identity> parsed =
        flux::Identity::Parse(identityBytes, FLUX_IDENTITY_SIZE);
    if (parsed.isErr()) return Err(parsed.error);

    flux::Identity identity = parsed.Take();
    const flux::Certificate cert = identity.ToCertificate();
    identity.Wipe();
    return cert.Serialize(out, FLUX_CERT_SIZE) ? FLUX_OK : FLUX_ERR_INVALID_PARAM;
FLUX_GUARD_END(FLUX_ERR_INVALID_PARAM)
}

FluxError FLUX_CALL flux_load_certificate(FluxSocket* s, const uint8_t* certBytes)
{
    if (s == nullptr || certBytes == nullptr) return FLUX_ERR_INVALID_PARAM;
FLUX_GUARD_BEGIN
    common::Result<flux::Certificate> parsed =
        flux::Certificate::Parse(certBytes, FLUX_CERT_SIZE);
    if (parsed.isErr()) return Err(parsed.error);
    return Err(Box(s)->socket.LoadCertificate(parsed.Take()));
FLUX_GUARD_END(FLUX_ERR_INVALID_PARAM)
}

FluxError FLUX_CALL flux_remove_certificate(FluxSocket* s, const uint8_t* tag)
{
    if (s == nullptr || tag == nullptr) return FLUX_ERR_INVALID_PARAM;
FLUX_GUARD_BEGIN
    flux::Certificate::IdentityTag wanted{};
    std::memcpy(wanted.data(), tag, wanted.size());
    return Err(Box(s)->socket.RemoveCertificate(wanted));
FLUX_GUARD_END(FLUX_ERR_INVALID_PARAM)
}

FluxError FLUX_CALL flux_rotate_identity(FluxSocket* s, const uint8_t* identityBytes)
{
    if (s == nullptr || identityBytes == nullptr) return FLUX_ERR_INVALID_PARAM;
FLUX_GUARD_BEGIN
    common::Result<flux::Identity> parsed =
        flux::Identity::Parse(identityBytes, FLUX_IDENTITY_SIZE);
    if (parsed.isErr()) return Err(parsed.error);

    flux::Identity next = parsed.Take();
    const common::Error result = Box(s)->socket.RotateIdentity(next);
    next.Wipe();
    return Err(result);
FLUX_GUARD_END(FLUX_ERR_INVALID_PARAM)
}

void FLUX_CALL flux_forget_previous_identities(FluxSocket* s)
{
    if (s == nullptr) return;
    Box(s)->socket.ForgetPreviousIdentities();
}

uint32_t FLUX_CALL flux_identity_tag(FluxSocket* s, uint8_t* out)
{
    if (s == nullptr || out == nullptr) return 0;
FLUX_GUARD_BEGIN
    const flux::Certificate::IdentityTag& tag = Box(s)->socket.IdentityTag();
    bool anonymous = true;
    for (size_t i = 0; i < tag.size(); ++i)
        if (tag[i] != 0) { anonymous = false; break; }
    if (anonymous) return 0;
    std::memcpy(out, tag.data(), tag.size());
    return static_cast<uint32_t>(tag.size());
FLUX_GUARD_END(0)
}

FluxError FLUX_CALL flux_rotate_keys(FluxSocket* s, FluxPeer name)
{
    if (s == nullptr) return FLUX_ERR_INVALID_PARAM;
FLUX_GUARD_BEGIN
    flux::Address addr;
    if (!PeerAddressOf(Box(s), name, addr)) return FLUX_ERR_NOT_FOUND;
    return Err(Box(s)->socket.RotateKeys(addr));
FLUX_GUARD_END(FLUX_ERR_INVALID_PARAM)
}

// --- The first-flight opener ---

FluxPeer FLUX_CALL flux_peer_expecting(FluxSocket* s, const char* host, uint16_t port,
                                       const uint8_t* tag)
{
    if (s == nullptr || host == nullptr || tag == nullptr) return FLUX_NONE;
FLUX_GUARD_BEGIN
    common::Result<flux::Address> resolved = flux::Address::From(host, port);
    if (resolved.isErr()) return FLUX_NONE;
    const flux::Address addr = resolved.Take();

    flux::Certificate::IdentityTag expect{};
    std::memcpy(expect.data(), tag, expect.size());
    if (Box(s)->socket.Connect(addr, expect) != common::Error::Ok) return FLUX_NONE;
    return PeerNameOf(Box(s), addr);
FLUX_GUARD_END(FLUX_NONE)
}

uint32_t FLUX_CALL flux_max_payload(FluxSocket* s, FluxPeer name)
{
    if (s == nullptr) return 0;
FLUX_GUARD_BEGIN
    flux::Address addr;
    if (!PeerAddressOf(Box(s), name, addr)) return 0;
    return Box(s)->socket.MaxPayload(addr);
FLUX_GUARD_END(0)
}

uint32_t FLUX_CALL flux_packet_was_knock(FluxSocket* s, FluxPacket name)
{
    if (s == nullptr) return 0;
    SocketBox* box = Box(s);

    uint32_t idx = 0;
    if (!UnpackPacket(box, name, idx)) return 0;

    // Detached rather than destroyed, as flux_messages does it: the slot is
    // the caller's until ReleasePacket and destruction would hand it back.
    flux::PacketSlotHandle handle = box->socket.PacketAt(idx);
    const flux::PacketSlot* packet = handle.Read();
    const uint32_t knocked = (packet != nullptr && packet->WasKnock()) ? 1u : 0u;
    (void)handle.Detach();
    return knocked;
}

static const FluxApiV1 API_V1 = {
    1,

    flux_layout_check,
    flux_default_config,

    flux_create_socket,
    flux_init_socket,
    flux_shutdown_socket,
    flux_destroy_socket,

    flux_update,
    flux_flush,
    flux_next_timeout,

    flux_peer,
    flux_peer_text,
    flux_peer_alive,
    flux_peer_ready,
    flux_remove_peer,
    flux_set_recv_grant,
    flux_recv_grant,
    flux_rotate_tags,

    flux_open_flow,
    flux_close_flow,
    flux_flow_state,
    flux_flow_state_for,

    flux_poll,
    flux_messages,
    flux_release_packet,
    flux_end_poll,

    flux_build_packet,
    flux_reply,
    flux_no_flow,
    flux_with_flow,
    flux_unsecured,
    flux_mac_only,
    flux_put_u8,
    flux_put_u16,
    flux_put_u32,
    flux_put_u64,
    flux_put_bytes,
    flux_send,
    flux_send_secured,
    flux_respond,
    flux_respond_secured,
    flux_abandon,

    flux_event_has,
    flux_event_peer,
    flux_event_flow,

    flux_send_transfer,
    flux_transfer_length,
    flux_allow_transfer,
    flux_reject_transfer,
    flux_transfer_progress,
    flux_poll_transfers,
    flux_complete_transfer,

    flux_identity_generate,
    flux_identity_certificate,
    flux_load_certificate,
    flux_remove_certificate,

    flux_rotate_identity,
    flux_forget_previous_identities,
    flux_identity_tag,

    flux_rotate_keys,

    flux_peer_expecting,
    flux_max_payload,
    flux_packet_was_knock,
};
extern "C" const void* FLUX_CALL flux_get_api(uint32_t version)
{
    switch (version)
    {
        case 1:  return &API_V1;
        default: return nullptr;
    }
}
