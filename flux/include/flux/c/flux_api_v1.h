/* The C surface of flux, version 1. This is the file other languages read, so
   it is plain C, includes nothing from flux, and is frozen the day it ships.
   Everything it mirrors from the C++ side is repeated here as its own numbers;
   the glue holds a static_assert per value, so a change over there breaks the
   build instead of quietly changing what a binding means.

   NOTHING BUT NUMBERS CROSSES THIS BOUNDARY. A caller never holds a flux
   object, never provides storage for one, and never learns a size. Peers,
   flows and packets are 64-bit numbers naming something the socket already
   owns, and a number can be copied, zeroed, moved between threads or garbage
   collected without harming anything. That is deliberate: C# copies structs on
   assignment, Python zero-fills them, Rust moves them, and every one of those
   would corrupt a live object if this API handed out memory.

   Every number carries a generation beside its slot, so one that names
   something already gone is refused rather than silently naming whatever took
   its place. Zero is never a valid number; it is what a failed call leaves and
   what an empty field means.

   The one exception is a received payload, which is borrowed read-only memory
   (see FluxMessage), stable until the packet it lives in is released.

   One symbol is exported, flux_get_api. It hands back this version's table of
   function pointers and everything else comes from the table.

   Certificates and identity are here. A socket given no identity is still
   anonymous and a socket given no trust store still authenticates nobody, so
   the earlier behaviour is what leaving those fields alone produces. */
#ifndef FLUX_API_V1_H
#define FLUX_API_V1_H

#include <stdint.h>

/* Fixed sizes a binding allocates against. An identity is the private form,
   secret key then tag, which is exactly what a private identity file holds. A
   certificate is the public form, version then key then tag. Both are plain
   caller-owned bytes rather than handles, because a server has to persist its
   identity and a handle could never leave the process. The secret half of an
   identity is secret: whoever holds those bytes owns protecting and wiping
   them, the same duty the identity file already carries. */
#define FLUX_TAG_SIZE       32
#define FLUX_IDENTITY_SIZE  64
#define FLUX_CERT_SIZE      65

/* Payload bytes that always fit, whatever the target's state. MaxPayload
   reports what one particular peer can take right now, which is larger in
   every case but the tightest; this is the figure for a caller that would
   rather not ask. Checked against the C++ constant at build time. */
#define FLUX_SAFE_PAYLOAD_BYTES 968

#ifdef __cplusplus
extern "C" {
#endif

/* Pins the calling convention where a platform has more than one, which is
   32-bit Windows. Everywhere else it expands to nothing. */
#if defined(_WIN32) && !defined(_WIN64)
#   define FLUX_CALL __cdecl
#else
#   define FLUX_CALL
#endif

/* The socket is the one thing that is a pointer rather than a number, because
   it is the root everything else is named relative to. A caller holds it and
   passes it back, and cannot look inside or take its size. */
typedef struct FluxSocket FluxSocket;

/* The event a hook is called with. Valid only for the duration of that call. */
typedef struct FluxEvent FluxEvent;

/* Names something the socket owns. Opaque: the bits are the glue's business,
   and a binding must never build one, take one apart, or reason about the
   ordering of two. Compare them for equality (the same number always means the
   same thing) and use them as dictionary keys. FLUX_NONE means none. */
typedef uint64_t FluxPeer;
typedef uint64_t FluxFlow;
typedef uint64_t FluxPacket;

#define FLUX_NONE ((uint64_t)0)

/* What Poll reports when every lane was busy: no lane was claimed, nothing
   was drained, and EndPoll on this value is a harmless no-op. */
#define FLUX_NO_LANE 0xFFFFFFFFu

/* Mirrors common::Error, same numbers, grouped by range so a group can grow
   without renumbering. The width comes from the typedef rather than from the
   enum because the size of an enum type is the compiler's to choose, and an
   ABI cannot have a field whose width depends on who compiled it. */
typedef int32_t FluxError;
enum {
    FLUX_OK                    = 0,

    /* General */
    FLUX_ERR_NOT_INITIALIZED   = 1,
    FLUX_ERR_INVALID_PARAM     = 2,
    FLUX_ERR_INVALID_STATE     = 3,
    FLUX_ERR_LIMIT_REACHED     = 4,
    FLUX_ERR_RESOLVE_FAILED    = 5,
    FLUX_ERR_NOT_IMPLEMENTED   = 6,
    FLUX_ERR_RANDOM_FAILED     = 7,
    FLUX_ERR_ALREADY_IN_USE    = 8,
    FLUX_ERR_NOT_FOUND         = 9,

    /* Platform */
    FLUX_ERR_IO_FAILED         = 10,
    FLUX_ERR_BIND_FAILED       = 11,
    FLUX_ERR_SEND_FAILED       = 12,

    /* Raised by this API alone, in a gap common::Error leaves free. Something
       inside threw where nothing was expected to; the call did nothing. It has
       a code because an exception reaching a C caller is undefined behaviour,
       so the glue catches every one and has to say something. */
    FLUX_ERR_INTERNAL          = 13,

    /* Memory */
    FLUX_ERR_ALLOC_FAILED      = 20,
    FLUX_ERR_POOL_EXHAUSTED    = 21,
    FLUX_ERR_BUFFER_FULL       = 22,
    FLUX_ERR_TOO_LARGE         = 23,

    /* Data */
    FLUX_ERR_MALFORMED         = 30,
    FLUX_ERR_NOT_AUTHENTICATED = 31,

    /* Work already under way */
    FLUX_ERR_ALREADY_PENDING   = 40,
    FLUX_ERR_TOO_MANY_PENDING  = 41,

    /* Declined by the far side rather than failed locally */
    FLUX_ERR_REFUSED           = 50,
};

/* Mirrors FlowMode. All four number and acknowledge every packet, so loss
   feeds congestion control even where nothing is resent; what the mode decides
   is what gets retransmitted and in what order it is delivered. Bulk is the
   ordered mode with four times the window, drawn from a pool of its own, so a
   socket that never sends bulk pays nothing for it. */
typedef int32_t FluxFlowMode;
enum {
    FLUX_FLOW_RELIABLE_ORDERED      = 0,
    FLUX_FLOW_RELIABLE_UNORDERED    = 1,
    FLUX_FLOW_UNRELIABLE            = 2,
    FLUX_FLOW_RELIABLE_ORDERED_BULK = 3,
};

/* Mirrors FlowLifecycle. FAILED is per peer: a flow stays OPEN while one
   target has stopped answering, which is why the two state calls differ. */
typedef int32_t FluxFlowState;
enum {
    FLUX_FLOW_STATE_OPEN    = 0,
    FLUX_FLOW_STATE_CLOSING = 1,
    FLUX_FLOW_STATE_CLOSED  = 2,
    FLUX_FLOW_STATE_FAILED  = 3,
};

/* Mirrors FlowPart: where a packet sits in a message spanning several of them.
   Whole is a message of one, which is what every send that does not care about
   framing already is. The others need an ordered flow, because ordered
   delivery is what lets two bits carry the whole framing. The transport never
   assembles the run: it carries the framing and the receiver reads it off each
   message with MessagePart, so a message has no size limit and nothing is
   allocated to hold one. */
typedef int32_t FluxFlowPart;
enum {
    FLUX_PART_WHOLE  = 0,
    FLUX_PART_FIRST  = 1,
    FLUX_PART_MIDDLE = 2,
    FLUX_PART_LAST   = 3,
};

/* Mirrors SocketEvent, same bit per event. One hook call can carry several at
   once, which is why they are bits and why a handler asks EventHas per event
   rather than switching on a value. Every one describes something that already
   happened; a handler that does nothing leaves the socket working exactly as
   it would have. */
typedef uint32_t FluxEventBits;

/* A remote created a receiving flow here. */
#define FLUX_EVENT_INCOMING_FLOW_OPENED   (1u << 0)

/* A peer would not accept a flow this socket opened: it is at its cap or it
   could not read the flow byte. Asking again on the same terms gets the same
   answer. */
#define FLUX_EVENT_OUTGOING_FLOW_REFUSED  (1u << 1)

/* A flow this socket opened stopped reaching one peer, because a packet on it
   ran out of retransmits. Unlike a refusal this says the path or the peer
   broke rather than that the flow was never wanted, and the flow stays open
   for every other peer. */
#define FLUX_EVENT_OUTGOING_FLOW_LOST     (1u << 2)

/* A remote closed this flow id and opened it again. It numbers from one now
   and everything held against the old generation is gone, so treat what comes
   next as a fresh start. There is no event for a remote merely closing a flow,
   because closing puts nothing on the wire. */
#define FLUX_EVENT_INCOMING_FLOW_REOPENED (1u << 3)

/* The handshake completed and there is a session with this peer. */
#define FLUX_EVENT_PEER_ESTABLISHED       (1u << 4)

/* This peer is gone: idled out, removed, or it stopped answering the
   handshake. Its number is dead from here on and every call naming it reports
   not found, which is how a binding knows to drop it from its own tables. */
#define FLUX_EVENT_PEER_LOST              (1u << 5)

/* This peer proved a new address and was rebound to it. Same session, same
   number: a peer that moves is still the same peer, which is the whole point
   of naming it rather than its address. */
#define FLUX_EVENT_PEER_MIGRATED          (1u << 6)

/* This peer changed what it says we may occupy of its receive pool, which is
   what bounds how much we can have in flight to it. */
#define FLUX_EVENT_PEER_GRANT_CHANGED     (1u << 7)

/* We cut what this peer may occupy of OUR receive pool, because it kept
   holding buffer it never used. The other side of PEER_GRANT_CHANGED, and a
   decision this socket made rather than one it was told. */
#define FLUX_EVENT_PEER_GRANT_CUT         (1u << 8)

/* A flow from this peer jammed: it held packets behind a gap the sender did
   not fill, so the buffer was taken back. The flow survives and the sender
   resends into the same gap, so the cost is a round trip rather than data. */
#define FLUX_EVENT_PEER_FLOW_JAMMED       (1u << 9)

/* A peer announced a transfer and is waiting to be told where to put it. The
   length is not here: ask TransferLength with the id and peer this event
   names, then answer with AllowTransfer or RejectTransfer, both legal from
   inside the handler. Answering with neither leaves the transfer pending until
   the flow stall timeout takes it. */
#define FLUX_EVENT_TRANSFER_INCOMING      (1u << 10)

/* This peer arrived on a first-flight opener, so its data was delivered
   before its address was proven. Every message that rode it also answers
   PacketIsKnock, which is the per-message form of the same news. */
#define FLUX_EVENT_PEER_KNOCKED           (1u << 11)

/* This peer's opener named a key this socket has since replaced, so its
   certificate for us is out of date. Its data still arrived. Its handshake
   will be answered with the current key and refused until it holds a fresh
   certificate. */
#define FLUX_EVENT_PEER_STALE_IDENTITY    (1u << 12)

/* A peer announced a tag this socket trusts but presented a key that tag is
   not pinned to, so the session was refused. Either it rotated its identity
   and the certificate here is stale, or something is impersonating it.
   Fetching a fresh certificate answers both. */
#define FLUX_EVENT_PEER_CERT_MISMATCH     (1u << 13)

/* One message, as Messages reports it. bytes aims into the socket's receive
   pool: real memory, read-only, valid from the Messages call that produced it
   until ReleasePacket frees the packet it lives in — writing through it is
   undefined, and copying out is the caller's business if it wants the bytes to
   outlive the packet. */
typedef struct {
    const uint8_t* bytes;
    uint16_t       length;
    uint16_t       reserved;
    uint32_t       reserved2;
} FluxMessage;

/* What one packet says about itself, filled by the same Messages call so a
   packet costs one lock however much is asked about it. peer is the sender.
   flowId is 0xFFFF for traffic outside any flow. part places the packet in a
   message spanning several of them. */
typedef struct {
    FluxPeer     peer;
    FluxFlowPart part;
    uint16_t     flowId;
    uint16_t     reserved;
} FluxPacketInfo;

/* A finished transfer, as PollTransfers reports it. Incoming, bytes is the
   destination buffer now whole and the transfer stays held until
   CompleteTransfer. Outgoing, bytes is null and the source buffer is free
   again. Which direction this is reads off bytes being null. outcome is
   FLUX_OK when the run arrived whole, FLUX_ERR_REFUSED when the far side
   declined it, and a path error when it stopped answering.

   The only struct that crosses, and it carries no flux object: a pointer the
   caller supplied in the first place, a length, a peer number and two codes.
   Fixed-width throughout, widest first, padding named. */
typedef struct {
    const void* bytes;
    uint64_t    length;
    FluxPeer    peer;
    FluxError   outcome;
    uint16_t    transferId;
    uint16_t    reserved;
} FluxTransferView;

/* Called from Poll, once per entity that had something happen to it, with
   nothing locked, so the handler can read any state and send from inside it.

   What it must NOT do is drive or tear down a socket from within the call:
   no Poll, no Update, and no lifetime call (Init, Shutdown, Destroy) on any
   socket. Those re-enter the very dispatch the hook runs inside, and the hook
   is meant to be a leaf. Reading state, building and sending packets, and
   answering a transfer are all fine.

   It runs on whichever thread called Poll, which two bindings have to care
   about: a C# delegate must be kept alive by the binding for the socket's
   whole life and declared Cdecl, and a Python callback arriving on a thread
   the interpreter did not create must take the GIL before touching anything.

   The event pointer dies when the call returns, so read what is needed with
   EventHas, EventPeer and EventFlow before it does. context is whatever was
   registered beside the hook and flux never reads it. */
typedef void (FLUX_CALL *FluxEventHook)(void* context, const FluxEvent* event);

/* Which platform socket to build on. The glue picks the native one per OS and
   starts Winsock before the first socket exists, so a binding never inherits
   that wart. */
typedef int32_t FluxBackend;
enum { FLUX_BACKEND_DEFAULT = 0 };

/* Configuration, mirroring Socket::Config in fixed-width types, plus the two
   counts this API needs that the C++ one does not (see inboxPerLane and
   packetBuilders). Every count is a memory budget and memory budgets belong to
   the embedder, so nothing here is a recommendation.

   A zeroed struct is not the defaults. Call DefaultConfig first and change
   what matters, because zero already means something per field: derive it, no
   limit, or disabled, depending on which one.

   No binding includes this file, so every binding retypes this struct by hand
   and a field out of place is silent corruption. LayoutCheck exists for
   exactly that; call it once at startup. */
typedef struct {
    uint64_t maxTransferBytes;      /* largest transfer a peer may announce; 0 takes the default */
    uint32_t flowCount;             /* flows the application may hold open at once */
    uint32_t outCount;              /* sending associations, socket-wide */
    uint32_t bulkOutCount;          /* of them bulk-capable; 0 refuses the mode outright */
    uint32_t inCount;               /* receiving associations, socket-wide */
    uint32_t bulkInCount;           /* of them sized for the deep window */
    uint32_t transferOutCount;      /* transfers running at once, outgoing; 0 refuses them */
    uint32_t transferInCount;       /* and incoming */
    uint32_t maxOutPerPeer;         /* sending associations one peer may hold */
    uint32_t maxInPerPeer;          /* defensive: what one remote may create here */
    uint32_t recvGrant;             /* receive slots one peer may occupy; 0 is no limit */
    uint32_t stagingCount;          /* retained reliable bodies, the retransmit sources */
    uint32_t minCongestionBudget;   /* in-flight bytes never dropped below on a loss run */
    uint32_t reliableWaitCount;     /* sends parked per flow while the window is full */
    uint32_t unreliableWaitCount;   /* the same, for a mode that drops its oldest instead */
} FluxFlowsConfig;

typedef struct {
    uint32_t ackDelayMicros;         /* the forced ack cadence */
    uint32_t retryIntervalMicros;    /* paces handshake retries, and the retransmit
                                        fallback before a peer has a round-trip sample */
} FluxTimersConfig;

typedef struct {
    uint64_t idleTimeoutMicros;      /* silence before a peer is evicted; 0 takes the default */
    uint64_t refreshGrainMicros;     /* how stale a peer's last-seen stamp may grow */
    uint32_t flowStallTimeoutMicros; /* gap age before a jammed flow is reclaimed; 0 takes the default */
    uint8_t  acceptUnsecureFromUnknown;  /* plaintext from addresses with no peer entry */
    uint8_t  reserved[3];
} FluxLivenessConfig;

typedef struct {
    FluxEventHook hook;         /* null costs nothing: no storage, nothing recorded */
    void*         context;      /* handed back untouched */
    FluxEventBits subscribed;   /* OR of FLUX_EVENT_*; empty disables as surely as a null hook */
    uint8_t       reserved[4];
} FluxEventsConfig;

/* The first-flight opener. A send to a peer named through PeerExpecting, whose
   certificate this socket holds, carries application data in its first packet
   under a key the sender derives alone, while the ordinary handshake completes
   behind it. All zero leaves it off, which is what every socket did before it
   existed. Every count zero takes a workable default. */
typedef struct {
    uint32_t enable;              /* nonzero sends openers; receiving one is always handled */
    uint32_t maxUnprovenPeers;    /* peers allowed to exist before their address is proven */
    uint32_t unprovenPacketLimit; /* packets one unproven peer may land before the rest drop */
    uint32_t budgetPerTick;       /* openers one Update pass will pay a key agreement for */
    uint32_t ttlWindowSeconds;    /* clock disagreement past which an opener is stale */
} FluxKnockConfig;

typedef struct {
    FluxFlowsConfig    flows;
    FluxLivenessConfig liveness;
    FluxEventsConfig   events;
    FluxTimersConfig   timers;
    uint32_t    maxPeers;             /* sizes the peer table */
    uint32_t    pendingPacketCount;   /* packets parked behind handshakes, shared by all peers */
    uint32_t    recvSlotCount;        /* the receive pool */
    uint32_t    sendSlotCount;        /* the send pool */
    uint32_t    recvReserveSlots;     /* slots buffering may never take, so an arriving
                                         packet always has somewhere to land; 0 derives it */
    uint32_t    recvBatch;            /* packets one Update takes off the socket; 0 derives it */
    uint32_t    pollLanes;            /* threads that will poll; above one must be a power of
                                         two, and every lane needs its own thread */

    /* Packets that may be under construction at once, socket-wide. A number
       from BuildPacket or Reply occupies one until it is sent or abandoned,
       so this bounds how many sends a binding may have half-built, across
       every thread. 0 takes a workable default. */
    uint32_t    packetBuilders;

    uint32_t    migrateBudgetPerPoll; /* unknown-address tag lookups one Poll pass spends
                                         before dropping the rest; 0 disables migration receive */
    uint32_t    replayWindowBits;     /* tolerance for out-of-order secure packets */

    /* This socket's own long-term identity, FLUX_IDENTITY_SIZE bytes, copied
       by Init so the caller may wipe its own afterwards. Null is anonymous: a
       fresh keypair and a zero tag, which no peer can pin. */
    const uint8_t* identity;

    /* Bytes sealed to one peer before its session key rotates itself. 0 takes
       the default. */
    uint64_t    rotateAfterBytes;

    /* Certificates this socket may pin. 0 disables the trust store, so
       LoadCertificate fails, every peer stays unauthenticated and SendSecured
       never delivers. */
    uint32_t    trustedCertCount;

    /* Previous keypairs kept past a RotateIdentity, so a peer whose
       certificate has not caught up can still open toward this socket. 0 is a
       socket that never rotates. Init refuses more than the transport holds. */
    uint32_t    identityHistory;

    FluxKnockConfig knock;
    FluxBackend backend;
    uint16_t    port;
    uint8_t     enableMigration;      /* a session survives its peer's address changing */
    uint8_t     reserved[1];
} FluxConfig;

/* What LayoutCheck fills in, so a binding can prove its hand-written structs
   agree with the ones this library was compiled against. Every field is a byte
   count from the library's own point of view. */
typedef struct {
    uint32_t sizeofConfig;
    uint32_t sizeofFlowsConfig;
    uint32_t sizeofTimersConfig;
    uint32_t sizeofLivenessConfig;
    uint32_t sizeofEventsConfig;
    uint32_t sizeofTransferView;
    uint32_t sizeofApiTable;
    uint32_t offsetofConfigFlows;
    uint32_t offsetofConfigLiveness;
    uint32_t offsetofConfigEvents;
    uint32_t offsetofConfigTimers;
    uint32_t offsetofConfigPort;
    uint32_t sizeofKnockConfig;
    uint32_t offsetofConfigKnock;
    uint32_t reserved[2];
} FluxLayout;

/* The table. One struct per version, frozen when it ships; a later version is
   a new struct behind the same getter, and both point at the same functions
   underneath, so there is no duplicated logic to keep in step.

   Errors come back as the return value. A call that produces a number returns
   it directly and reports FLUX_NONE for failure, because a number needs no
   out-parameter and an out-parameter is one more thing a binding can get
   wrong. */
typedef struct {
    uint32_t version;

    /* Fills in this library's own sizes and offsets. Call it first and refuse
       to run if anything disagrees with the binding's own structs; the
       alternative is a silently mis-marshalled config and a socket built from
       garbage. */
    void (FLUX_CALL *LayoutCheck)(FluxLayout* out);

    /* The middle ground the C++ Config starts from. Fill a config with this
       before changing anything, since zero is a meaningful value in most of
       its fields and rarely the one wanted. */
    void (FLUX_CALL *DefaultConfig)(FluxConfig* out);

    /* The socket's life. Create makes an uninitialized one, Init arms it and
       is the last thing on its path that allocates, Shutdown is idempotent
       teardown after which Init is legal again, Destroy frees what Create
       made. Every number handed out by a socket dies with it. No other thread
       may be anywhere in the socket during Shutdown or Destroy, since both
       free what the other calls read. */
    FluxSocket* (FLUX_CALL *CreateSocket)  (void);
    FluxError   (FLUX_CALL *InitSocket)    (FluxSocket*, const FluxConfig*);
    void        (FLUX_CALL *ShutdownSocket)(FluxSocket*);
    void        (FLUX_CALL *DestroySocket) (FluxSocket*);

    /* The loop. Flux owns no thread, so the socket only works when it is
       called: Update runs the timers, Poll hands over what arrived, Flush puts
       what was sent on the wire. All three are safe from any threads at any
       cadence. NextTimeout is the soonest deadline across every flow, in
       absolute monotonic microseconds, or 0 when nothing is pending, for an
       application that would rather block than spin. */
    void     (FLUX_CALL *Update)     (FluxSocket*);
    void     (FLUX_CALL *Flush)      (FluxSocket*);
    uint64_t (FLUX_CALL *NextTimeout)(FluxSocket*);

    /* Peers.

       Peer resolves a host and port and hands back the number that names that
       peer from here on. It registers the peer and starts its handshake, which
       is the one place this API is more eager than the C++ one: there a peer
       appears on the first send, here it appears when you ask for its number.
       The two round trips are paid at a moment the caller picks either way.

       A number survives the peer moving to a new address, and dies when the
       peer does. Compare two for equality to tell whether they are the same
       peer; a number from a peer that has gone never compares equal to a
       later one, so a stale key in a binding's dictionary stays stale.

       PeerText writes a printable form and returns its length, or 0 if it did
       not fit. PeerAlive answers whether the number still names anything.
       PeerReady answers whether the handshake has finished. */
    FluxPeer  (FLUX_CALL *Peer)      (FluxSocket*, const char* host, uint16_t port);
    uint32_t  (FLUX_CALL *PeerText)  (FluxSocket*, FluxPeer, char* out, uint32_t cap);
    uint32_t  (FLUX_CALL *PeerAlive) (FluxSocket*, FluxPeer);
    uint32_t  (FLUX_CALL *PeerReady) (FluxSocket*, FluxPeer);
    FluxError (FLUX_CALL *RemovePeer)(FluxSocket*, FluxPeer);

    /* What this socket lets one peer occupy of its receive pool, and what that
       peer lets us occupy of its own. The two grant events announce that these
       moved; these are how a handler reads and answers. 0 means no limit. */
    FluxError (FLUX_CALL *SetRecvGrant)(FluxSocket*, FluxPeer, uint32_t slots);
    uint32_t  (FLUX_CALL *RecvGrant)   (FluxSocket*, FluxPeer);

    /* Advances this side's migration tag for every established peer, so
       packets after a deliberate local address change wear unlinkable tags.
       Nothing calls this on its own: a socket that never calls it never
       rotates. Returns how many peers rotated. */
    uint32_t  (FLUX_CALL *RotateTags)(FluxSocket*);

    /* Flows. Opening one is local and immediate: nothing goes on the wire, and
       it can be sent on before any handshake has finished. A flow is not bound
       to a peer, so the same number serves every peer with its own sequence,
       its own retransmits and its own failures for each. Closing is local too,
       and frees everything the flow held.

       FlowState is the flow's own: OPEN until closed, whatever any one peer is
       doing. FlowStateFor is this flow with ONE peer, which is where failure
       lives: a peer that refused the flow or stopped answering reads FAILED
       there while the flow stays OPEN for everybody else. */
    FluxFlow      (FLUX_CALL *OpenFlow)    (FluxSocket*, uint16_t flowId, FluxFlowMode);
    FluxError     (FLUX_CALL *CloseFlow)   (FluxSocket*, FluxFlow);
    FluxFlowState (FLUX_CALL *FlowState)   (FluxSocket*, FluxFlow);
    FluxFlowState (FLUX_CALL *FlowStateFor)(FluxSocket*, FluxFlow, FluxPeer);

    /* Receiving.

       Poll fills the caller's array with packet numbers and returns how many.
       lane is in and out: pass back what the last Poll left there and a
       thread keeps its lane, which is what makes one peer's traffic reach one
       thread in sequence; a single-threaded caller passes a pointer to a zero
       and never thinks about it. FLUX_NO_LANE coming back means every lane
       was busy and nothing was drained.

       Messages empties one packet in one call: it fills the message array
       (one datagram can carry several), reports the sender, the flow and the
       part through info, and returns the message count. One packet costs one
       lock however much is asked. The bytes pointers aim into the receive
       pool and stay valid until that packet's ReleasePacket — holding a
       packet is legal and cheap, it is one pool slot.

       Every packet number Poll returned owes exactly one ReleasePacket. A
       stale or repeated release is refused with NOT_FOUND and frees nothing,
       but the debt is real: packets never released drain the receive pool
       until the socket goes deaf, which reads as a network fault rather than
       the leak it is.

       EndPoll hands the lane back and belongs in whatever a binding uses for
       'finally'; a lane never ended is never drained again by anyone. End it
       after the reading if strict per-peer ordering matters: packets held
       past EndPoll keep their bytes, but another thread may then take the
       lane and read that peer's LATER traffic concurrently. */
    uint32_t  (FLUX_CALL *Poll)         (FluxSocket*, uint32_t* lane,
                                         FluxPacket* out, uint32_t max);
    uint32_t  (FLUX_CALL *Messages)     (FluxSocket*, FluxPacket,
                                         FluxMessage* out, uint32_t max,
                                         FluxPacketInfo* info);
    FluxError (FLUX_CALL *ReleasePacket)(FluxSocket*, FluxPacket);
    void      (FLUX_CALL *EndPoll)      (FluxSocket*, uint32_t lane);

    /* Sending.

       A packet under construction belongs to ONE thread from BuildPacket or
       Reply until Send or Abandon ends it. Two threads may build different
       packets at once, each gets its own; but the number for a single
       half-built packet must not be shared, the same way a string being
       edited is not handed to a second thread mid-edit. Passing one number
       to the puts on two threads at once is a use-after-free the number
       scheme does not, and is not meant to, catch.

       BuildPacket starts one aimed by the caller; Reply starts one already
       aimed at the sender of a received packet, so a reply never rebuilds the
       pairing by hand — hand it a packet number Poll returned and not yet
       released. Both hand back a number, or FLUX_NONE when no builder was
       free, which is what packetBuilders bounds.

       Exactly one of NoFlow or WithFlow must be called before the first put,
       because that choice is what decides which pool the body is written into
       and it cannot change once writing has started. NoFlow is traffic outside
       any flow: no sequence, no acknowledgement, no retransmission, the
       cheapest packet flux sends. WithFlow carries the flow's id and next
       sequence number, both stamped at send time.

       Security is one setting rather than a flag per level, so asking for two
       is a conflict. Unsecured opts out of protection entirely, plaintext with
       no tag, forgeable by anyone, and cannot carry a flow, since a forged
       packet could then name any sequence it liked and poison the receiver's
       ordering. MacOnly leaves the payload readable but keeps the tag over the
       whole packet, so anyone can read it and nobody without the key can
       change a byte: roughly half the crypto cost, the same bytes on the wire.

       The puts write little-endian, which is the wire's order. A chain reports
       one reason at the end and it is the first thing that went wrong, since
       everything after that is a consequence.

       Send is best-effort, encrypted always and authenticated when the peer
       is. SendSecured refuses any peer not authenticated against a pinned
       certificate, which without a trust store means it never delivers. Reply
       chains end with Respond or RespondSecured instead, which need no peer.

       All four ends free the packet number, and so does Abandon. Exactly one
       of the five, on every path out, or that builder is gone until the socket
       is. A number used after it was ended reports invalid state rather than
       reaching whatever took its place.

       A send on a flow is packed with others going the same way and waits for
       Flush, so the moment bytes leave is the caller's to pick. Miss it and
       they sit there. */
    FluxPacket (FLUX_CALL *BuildPacket)(FluxSocket*);
    FluxPacket (FLUX_CALL *Reply)      (FluxSocket*, FluxPacket received);
    FluxError  (FLUX_CALL *NoFlow)     (FluxSocket*, FluxPacket);
    FluxError  (FLUX_CALL *WithFlow)   (FluxSocket*, FluxPacket, FluxFlow, FluxFlowPart);
    FluxError  (FLUX_CALL *Unsecured)  (FluxSocket*, FluxPacket);
    FluxError  (FLUX_CALL *MacOnly)    (FluxSocket*, FluxPacket);
    FluxError  (FLUX_CALL *PutU8)      (FluxSocket*, FluxPacket, uint8_t);
    FluxError  (FLUX_CALL *PutU16)     (FluxSocket*, FluxPacket, uint16_t);
    FluxError  (FLUX_CALL *PutU32)     (FluxSocket*, FluxPacket, uint32_t);
    FluxError  (FLUX_CALL *PutU64)     (FluxSocket*, FluxPacket, uint64_t);
    FluxError  (FLUX_CALL *PutBytes)   (FluxSocket*, FluxPacket, const uint8_t*, uint16_t);
    FluxError  (FLUX_CALL *Send)       (FluxSocket*, FluxPacket, FluxPeer);
    FluxError  (FLUX_CALL *SendSecured)(FluxSocket*, FluxPacket, FluxPeer);
    FluxError  (FLUX_CALL *Respond)    (FluxSocket*, FluxPacket);
    FluxError  (FLUX_CALL *RespondSecured)(FluxSocket*, FluxPacket);
    FluxError  (FLUX_CALL *Abandon)    (FluxSocket*, FluxPacket);

    /* Events, readable only from inside the hook. EventHas answers nonzero
       while any of the bits asked for are set. EventPeer names the entity, and
       for PEER_LOST that number is already dead, which is the point: it is the
       key a binding removes from its own table. */
    uint32_t (FLUX_CALL *EventHas) (const FluxEvent*, FluxEventBits);
    FluxPeer (FLUX_CALL *EventPeer)(FluxSocket*, const FluxEvent*);
    uint16_t (FLUX_CALL *EventFlow)(const FluxEvent*);

    /* Transfers. One run of bytes whose length is known up front, beside the
       flows rather than inside them, with no chunking and nothing staged per
       packet. The source buffer is the retransmit store, so it must stay alive
       and unmodified until PollTransfers reports it finished; that is what
       lets a gigabyte and a kilobyte cost the same state.

       On the receiving side, TransferLength is what the announcement a
       TRANSFER_INCOMING event spoke of claims, and 0 when nothing is pending.
       AllowTransfer accepts it into a buffer of at least that many bytes,
       which is written at packet offsets rather than front to back, so only
       TransferProgress says how much of it means anything yet. RejectTransfer
       tells the peer no. Both are legal from inside the hook.

       CompleteTransfer releases a finished incoming transfer, and holding it
       is deliberate backpressure: the peer cannot start another on that id
       until the application says it is done with the last. */
    FluxError (FLUX_CALL *SendTransfer)    (FluxSocket*, uint16_t transferId, FluxPeer,
                                            const void* buffer, uint64_t length);
    uint64_t  (FLUX_CALL *TransferLength)  (FluxSocket*, uint16_t transferId, FluxPeer);
    FluxError (FLUX_CALL *AllowTransfer)   (FluxSocket*, uint16_t transferId, FluxPeer,
                                            void* buffer);
    FluxError (FLUX_CALL *RejectTransfer)  (FluxSocket*, uint16_t transferId, FluxPeer);
    uint64_t  (FLUX_CALL *TransferProgress)(FluxSocket*, uint16_t transferId, FluxPeer);
    uint32_t  (FLUX_CALL *PollTransfers)   (FluxSocket*, FluxTransferView* out, uint32_t max);
    FluxError (FLUX_CALL *CompleteTransfer)(FluxSocket*, uint16_t transferId, FluxPeer);

    /* Identity and certificates.

       IdentityGenerate makes a fresh keypair carrying tag and writes the
       private form. IdentityCertificate derives the public form from it, which
       is the artifact handed to whoever should trust this socket. Neither
       needs a socket, so a tool can mint an identity without starting one.

       LoadCertificate pins a key to a tag, and loading again for a tag already
       held replaces it in place, which is how a peer's rotation is adopted and
       how a revoked tag is trusted again. RemoveCertificate withdraws one: the
       entry stays with its key wiped, so every later check on that tag fails
       hard rather than falling back to unauthenticated, which is stronger than
       never having pinned it. NotFound when the tag was never pinned. */
    FluxError (FLUX_CALL *IdentityGenerate)   (const uint8_t tag[FLUX_TAG_SIZE],
                                               uint8_t out[FLUX_IDENTITY_SIZE]);
    FluxError (FLUX_CALL *IdentityCertificate)(const uint8_t identity[FLUX_IDENTITY_SIZE],
                                               uint8_t out[FLUX_CERT_SIZE]);
    FluxError (FLUX_CALL *LoadCertificate)    (FluxSocket*, const uint8_t cert[FLUX_CERT_SIZE]);
    FluxError (FLUX_CALL *RemoveCertificate)  (FluxSocket*, const uint8_t tag[FLUX_TAG_SIZE]);

    /* Replaces the keypair this socket proves its tag with, under live
       traffic. The tag does not change, so peer relationships survive and
       sessions already running are untouched, their keys having come from the
       handshake rather than from this one. Previous keypairs are kept as
       Config::identityHistory allows, so a peer still holding the old
       certificate can open toward this socket while its copy catches up.
       InvalidParam when the identity carries a different tag.

       ForgetPreviousIdentities wipes those retained keys, so an opener naming
       one stops being answerable and its sender falls back to the plain
       handshake. That is the answer to a leaked key.

       IdentityTag writes this socket's tag and returns its length, or 0 when
       the socket is anonymous. */
    FluxError (FLUX_CALL *RotateIdentity)     (FluxSocket*,
                                               const uint8_t identity[FLUX_IDENTITY_SIZE]);
    void      (FLUX_CALL *ForgetPreviousIdentities)(FluxSocket*);
    uint32_t  (FLUX_CALL *IdentityTag)        (FluxSocket*, uint8_t out[FLUX_TAG_SIZE]);

    /* Moves one peer's session key along its chain. Nothing is announced: the
       far side discovers the change when a packet opens under the next link.
       Config::rotateAfterBytes does the same on a byte threshold. */
    FluxError (FLUX_CALL *RotateKeys)         (FluxSocket*, FluxPeer);

    /* The first-flight opener.

       PeerExpecting is Peer with the identity expected at that address named,
       so the first send can carry data encrypted toward that identity's pinned
       certificate. The certificate must already be loaded. Without this a
       first send takes the plain handshake. FLUX_NONE when no loaded
       certificate carries the tag, or when knocking is off.

       MaxPayload is how many payload bytes the next packet to this peer can
       carry, as a caller may put them: smaller while the first packet must
       still open a session, full once it has. A send past it is refused rather
       than truncated, so a binding either asks or sizes to
       FLUX_SAFE_PAYLOAD_BYTES. 0 means the peer is gone.

       PacketIsKnock says a received packet arrived on an opener, before its
       sender's address was proven. Such a packet can be presented twice by a
       replayed opener in one narrow case, so an application that must not act
       twice reads this and decides what it accepts there. */
    FluxPeer  (FLUX_CALL *PeerExpecting)      (FluxSocket*, const char* host, uint16_t port,
                                               const uint8_t tag[FLUX_TAG_SIZE]);
    uint32_t  (FLUX_CALL *MaxPayload)         (FluxSocket*, FluxPeer);
    uint32_t  (FLUX_CALL *PacketIsKnock)     (FluxSocket*, FluxPacket);
} FluxApiV1;

/* The one symbol anybody has to find. Cast what comes back to the struct for
   the version asked for; null means this library has no such version. */
const void* FLUX_CALL flux_get_api(uint32_t version);

#ifdef __cplusplus
}
#endif

#endif /* FLUX_API_V1_H */
