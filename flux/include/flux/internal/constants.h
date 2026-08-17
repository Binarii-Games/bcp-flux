#pragma once

#include <cstdint>

#include <common/crypto/crypto.h>

namespace bcp::flux::internal
{
    // --- Version ---
    static constexpr uint16_t VERSION                       = 0;  ///< 0 until 1.0; nothing negotiates on it
    static constexpr uint8_t  VERSION_CAPS_SIZE             = 4;
    static constexpr uint8_t  VERSION_SIZE                  = 2;

    // --- Wire ---
    static constexpr uint16_t MAX_WIRE_PACKET_SIZE          = 1200;  ///< under the IPv6 minimum MTU less IP+UDP, with room for tunnels
    static constexpr uint8_t  WIRE_CONTROLLER_SIZE          = 1;
    static constexpr uint8_t  WIRE_TAG_SIZE                 = 16;
    static constexpr uint8_t  WIRE_NONCE_SIZE               = 8;  ///< counter half only; the rest is derived locally
    static constexpr uint8_t  WIRE_FLOW_ID_SIZE             = 2;
    static constexpr uint8_t  WIRE_FLOW_SEQ_SIZE            = 4;
    static constexpr uint8_t  WIRE_FLOW_DATA_SIZE           = 1;  ///< mode, epoch, message framing (see flow.h)
    static constexpr uint8_t  WIRE_FLOW_HEADER_SIZE         =
        WIRE_FLOW_ID_SIZE + WIRE_FLOW_SEQ_SIZE + WIRE_FLOW_DATA_SIZE;
    static constexpr uint8_t  WIRE_PEER_TAG_SIZE            = 4;  ///< present when CTRL_TAGGED is set

    /** Length in front of each message when CTRL_BATCH is set. Two bytes covers
        anything that fits a datagram, and a fixed width keeps the walk a bounds
        check rather than a decode. The lengths must consume the content
        exactly: a walk that overruns or leaves a tail means the framing cannot
        be trusted, so the whole packet is dropped rather than partly
        delivered. */
    static constexpr uint8_t  WIRE_BATCH_LEN_SIZE           = 2;

    /** Controller bit 5, saying the content is that list rather than one
        message. Named here as well as in Controls because the packer sets it
        while building a batch, and the flow table has no business reaching into
        the socket's headers for a wire constant. Controls takes its value from
        this one, so there is a single definition. */
    static constexpr uint8_t  WIRE_CTRL_BATCH               = 0x20;

    static constexpr uint8_t  WIRE_SECURE_CHANNEL_SIZE      = 1;
    static constexpr uint8_t  MIN_WIRE_SIZE                 = WIRE_CONTROLLER_SIZE;
    /** What a secure packet puts in front of the content: controller and the
        masked counter, plus the peer tag when CTRL_TAGGED is set. The
        authentication tag is not here. It goes after the payload, so that
        everything a MAC has to cover is one unbroken run of bytes rather than
        pieces on either side of it. */
    static constexpr uint8_t  WIRE_SECURE_HEAD_SIZE        = WIRE_CONTROLLER_SIZE + WIRE_NONCE_SIZE;
    /** Total a secure packet spends on framing, front and back. */
    static constexpr uint8_t  MIN_SECURE_WIRE_SIZE          = WIRE_SECURE_HEAD_SIZE + WIRE_TAG_SIZE;

    /** First plaintext byte of a secure packet, so which kind it is shows only
        after decrypting. CTRL_HAS_FLOW stays cleartext, but packet size gives
        the same away. */
    static constexpr uint8_t  SECURE_CHANNEL_APP            = 0x00;
    static constexpr uint8_t  SECURE_CHANNEL_PATH_CHLG      = 0x01;
    static constexpr uint8_t  SECURE_CHANNEL_PATH_RESP      = 0x02;
    static constexpr uint8_t  SECURE_CHANNEL_FLOW_REJECT    = 0x03;
    static constexpr uint8_t  SECURE_CHANNEL_FLOW_ACK       = 0x04;
    static constexpr uint8_t  SECURE_CHANNEL_GRANT           = 0x05;
    static constexpr uint8_t  SECURE_CHANNEL_GRANT_ACK       = 0x06;

    /** A transfer's own channels, which is what keeps the mechanism parallel
        to flows rather than threaded through them. A transfer carries no flow
        header, no mode bits and no message framing, so it demuxes here, before
        any flow decode runs, and the flow path never learns it exists.

        TRANSFER carries both the announcement and the bytes, told apart by a
        flag in its own header. TRANSFER_ACK reports what has arrived.
        TRANSFER_REJECT is the receiver declining, which is a refusal of one
        transfer rather than of the channel it came on, so it is its own op and
        not a reuse of FLOW_REJECT. */
    /** A resume note travelling to its holder, and the acknowledgement that
        stops the issuer resending it. The issuer seals the note for its own
        future self and keeps nothing, so the memory of a session travels with
        the side that will want it back. Same contract as GRANT and GRANT_ACK.
        These two op numbers were used by an earlier attempt at resumption that
        was reverted, and nothing on the wire outlived it, so reusing them
        collides with nothing. */
    static constexpr uint8_t  SECURE_CHANNEL_TICKET          = 0x0A;
    static constexpr uint8_t  SECURE_CHANNEL_TICKET_ACK      = 0x0B;

    static constexpr uint8_t  SECURE_CHANNEL_TRANSFER        = 0x07;
    static constexpr uint8_t  SECURE_CHANNEL_TRANSFER_ACK    = 0x08;
    static constexpr uint8_t  SECURE_CHANNEL_TRANSFER_REJECT = 0x09;

    /** Grant payload: the receive slots the sender of this op will hold for the
        peer it is addressed to, and a generation so an op that overtakes an
        older one cannot be undone by it. */
    static constexpr uint8_t  WIRE_GRANT_PAYLOAD_SIZE        = 8;

    /** Grant ack payload: the generation being acknowledged, nothing else. */
    static constexpr uint8_t  WIRE_GRANT_ACK_PAYLOAD_SIZE    = 4;

    static_assert(WIRE_TAG_SIZE == common::crypto::TAG_SIZE,
                  "The wire tag field carries the AEAD tag verbatim");

    // --- Handshake ---
    static constexpr uint8_t  WIRE_HS_SALT_SIZE             = 16;
    static constexpr uint8_t  WIRE_HS_TAG_SIZE              = 32;  ///< responder's announced identity tag
    static constexpr uint8_t  WIRE_HS_MAC_SIZE              = 16;

    /** Role-ordered so both ends assemble identical bytes. BuildTranscript is
        the authoritative layout:
          initiatorPk responderPk initiatorEph responderEph saltI saltR
          initiatorCaps responderCaps initiatorVersion responderVersion tag
        Everything negotiated is inside the MAC, so tampering fails key
        confirmation. */
    static constexpr size_t   HS_TRANSCRIPT_SIZE            =
        4*common::crypto::KEY_SIZE + 2*WIRE_HS_SALT_SIZE + 2*VERSION_SIZE + 2*VERSION_CAPS_SIZE + WIRE_HS_TAG_SIZE;

    static_assert(WIRE_HS_MAC_SIZE == common::crypto::MAC_SIZE,
                  "The wire confirmation field carries a ComputeMac output verbatim");

    /** Bytes sealed to one peer before the session key rotates itself, when
        Config::rotateAfterBytes is left at zero. Rotation is hygiene rather
        than a cryptographic necessity (XChaCha20 has no practical volume
        limit), so the default only has to bound how much traffic one key
        ever covers. */
    static constexpr uint64_t KEY_ROTATE_AFTER_BYTES_DEFAULT = 1ull << 30;

    /** The labels that split one secret into purpose-specific keys. Fixed and
        public; each only has to differ from every other input its source key
        is ever fed, so no two derivations share a domain. Here rather than in
        one translation unit because the handshake, the rotation and the knock
        all derive with them. */
    static constexpr uint8_t HEADER_KEY_LABEL[16] = {
        'f','l','u','x','-','h','d','r','-','m','a','s','k',0,0,0
    };
    static constexpr uint8_t MAC_KEY_LABEL[16] = {
        'f','l','u','x','-','m','a','c','-','o','n','l','y',0,0,0
    };
    static constexpr uint8_t KEY_ROTATE_LABEL[16] = {
        'f','l','u','x','-','k','e','y','-','r','o','t','a','t','e',0
    };
    static constexpr uint8_t KNOCK_KEY_LABEL[16] = {
        'f','l','u','x','-','k','n','o','c','k',0,0,0,0,0,0
    };
    static constexpr uint8_t KNOCK_STATIC_LABEL[16] = {
        'f','l','u','x','-','k','n','k','-','s','t','a','t','i','c',0
    };
    static constexpr uint8_t TICKET_SEAL_LABEL[16] = {
        'f','l','u','x','-','t','k','t','-','s','e','a','l',0,0,0
    };

    // --- Resume notes ---

    /** What the issuer seals for its own future self: the holder's identity
        tag, so the issuer can re-check it against its trust store rather than
        take the note's word, and the wall clock it was issued at, so an old
        one stops being honoured.

        The holder's public key is NOT in here. It rides the note's associated
        data instead, so a note only opens against the key the opener already
        proved, which binds the two together and costs nothing to carry. */
    static constexpr size_t   TICKET_SEALED_SIZE = WIRE_HS_TAG_SIZE + 8;

    /** The note as it travels and as the holder stores it: nonce, sealed body,
        tag. The holder never parses any of it. */
    static constexpr size_t   TICKET_WIRE_SIZE =
        common::crypto::NONCE_SIZE + TICKET_SEALED_SIZE + common::crypto::TAG_SIZE;

    /** TICKET payload: the note, nothing else. The holder needs no id to
        acknowledge, because a note replaces whatever it held for that issuer. */
    static constexpr size_t   WIRE_TICKET_PAYLOAD_SIZE = TICKET_WIRE_SIZE;

    /** Validity stamped into a note when Config leaves it at zero. Two days
        covers a deploy, a crash and an overnight reboot, which is what the
        mechanism is for. Nothing secret is in a note, so a longer life costs
        no confidentiality: what actually bounds it is the issuer rotating its
        identity, since the seal key comes from that. */
    static constexpr uint32_t TICKET_LIFETIME_SECONDS_DEFAULT = 48u * 3600u;

    /** How long an unacknowledged note waits before the tick resends it. */
    static constexpr uint64_t TICKET_RESEND_MICROS = 500'000;

    // --- Identity ---

    /** Previous keypairs a socket may keep past a rotation. The bound exists
        because a retained key is one more an opener can name, and the table
        is searched linearly. Config leaves it at zero, which is a socket that
        never rotates. */
    static constexpr uint8_t  MAX_IDENTITY_HISTORY = 8;

    /** Bytes naming which of a receiver's keys an opener was encrypted
        toward. Four is enough that two keys one socket holds at once are not
        going to collide, and short enough to cost nothing on the wire. */
    static constexpr size_t   WIRE_KEY_ID_SIZE = 4;

    // --- Knock (the 0-RTT opener) ---

    /** Cleartext knock header: controller, opcode, version, caps, masked
        counter, sender ephemeral, salt, sender wall clock, the receiver key
        id, and the identity region. Every field is fixed width, so every
        offset is constant and MaxPayload has one answer per state.

        The key id says which of the receiver's keys the rest was encrypted
        toward. It is present whatever either end has configured, because a
        header whose size depended on that would leave two differently
        configured peers unable to read each other.

        The identity region is the sender's own public key sealed under a key
        only the named receiver can rebuild, plus its tag. Nothing in the
        header is stable across two knocks from one sender, so an observer
        cannot tell them apart or recognise a sender it has seen before. */
    static constexpr size_t   KNOCK_IDENTITY_SIZE =
        common::crypto::KEY_SIZE + common::crypto::TAG_SIZE;
    static constexpr size_t   KNOCK_HEADER_SIZE   =
        1 + 1 + VERSION_SIZE + VERSION_CAPS_SIZE + WIRE_NONCE_SIZE
        + common::crypto::KEY_SIZE + WIRE_HS_SALT_SIZE + 8 + WIRE_KEY_ID_SIZE
        + KNOCK_IDENTITY_SIZE;

    /** Fixed field offsets inside the knock header. */
    static constexpr size_t   KNOCK_OFF_VERSION  = 2;
    static constexpr size_t   KNOCK_OFF_CAPS     = KNOCK_OFF_VERSION + VERSION_SIZE;
    static constexpr size_t   KNOCK_OFF_COUNTER  = KNOCK_OFF_CAPS + VERSION_CAPS_SIZE;
    static constexpr size_t   KNOCK_OFF_EPH      = KNOCK_OFF_COUNTER + WIRE_NONCE_SIZE;
    static constexpr size_t   KNOCK_OFF_SALT     = KNOCK_OFF_EPH + common::crypto::KEY_SIZE;
    static constexpr size_t   KNOCK_OFF_CLOCK    = KNOCK_OFF_SALT + WIRE_HS_SALT_SIZE;
    static constexpr size_t   KNOCK_OFF_KEYID    = KNOCK_OFF_CLOCK + 8;
    static constexpr size_t   KNOCK_OFF_IDENTITY = KNOCK_OFF_KEYID + WIRE_KEY_ID_SIZE;

    /** The interior leads with the sender's real controller byte, a flags
        byte, and the payload length. A resume note follows when the flags say
        so, and then the payload. Everything after the header is inside the
        seal, so an observer cannot tell a resume from a first contact.

        The flags byte is here rather than in the cleartext header for that
        reason, and it is spent from the interior's budget rather than the
        header's so a knock carrying no note stays the size it was. */
    static constexpr uint8_t  KNOCK_INNER_HAS_TICKET = 0x01;
    static constexpr size_t   KNOCK_INNER_PREFIX  = 1 + 1 + 2;
    static constexpr size_t   KNOCK_INNER_SIZE    =
        MAX_WIRE_PACKET_SIZE - KNOCK_HEADER_SIZE - WIRE_TAG_SIZE;
    static constexpr size_t   KNOCK_PAYLOAD_MAX   = KNOCK_INNER_SIZE - KNOCK_INNER_PREFIX;

    /** In-pool marker on a delivered packet that rode the first flight, so
        the application's replay contract is per message. Never travels: set
        after the open, on this socket's copy alone. */
    static constexpr uint8_t  WIRE_CTRL_KNOCKED = 0x40;

    /** Clock disagreement past which a knock is stale. Bounds what a replayed
        first flight can achieve when the seen-ring was wiped by a restart. */
    static constexpr uint32_t KNOCK_TTL_WINDOW_SECONDS_DEFAULT = 30;

    /** Knock validations one tick pays for, each costing key agreement.
        Excess knocks are dropped and the sender's retry covers them. */
    static constexpr uint32_t KNOCK_BUDGET_PER_TICK_DEFAULT = 32;

    /** Peers allowed to exist before their address is proven. */
    static constexpr uint32_t KNOCK_MAX_UNPROVEN_DEFAULT = 64;

    /** Packets accepted from one unproven peer before further ones are
        ejected unbuffered until its cookie echo lands. */
    static constexpr uint32_t KNOCK_UNPROVEN_PACKET_LIMIT_DEFAULT = 256;

    // --- Flow ---
    static constexpr uint16_t INVALID_FLOW_ID               = 0xFFFF;

    /** Sender's ring capacity and receiver's seen-bitmap width, chosen per mode
        by WindowFor. Nothing carries it on the wire, so deriving it from the
        mode bits is what makes both ends agree. Powers of two: both index by
        seq & (window - 1). */
    static constexpr uint16_t FLOW_WINDOW                   = 256;
    static constexpr uint16_t FLOW_WINDOW_BULK              = 1024;


    /** Ceiling for the configurable waiting and reorder rings: the largest
        power of two fitting the uint16_t caps they are stored in. */
    static constexpr uint16_t FLOW_RING_MAX                 = 32768;

    /** Paced by Config::timers::retryIntervalMicros, so 8 is about 1.6 seconds
        before whatever parked behind the handshake fails visibly. */
    static constexpr uint8_t  HANDSHAKE_MAX_ATTEMPTS        = 8;
    static constexpr uint32_t HANDSHAKE_RETRY_DEFAULT       = 200000;  ///< used when Config leaves it at zero

    /** Bytes in front of a FLOW_ACK entry's ranges:
        [flowId(2)][epoch(1)][rangeCount(1)][recvNext(4)][ackDelay(2)].

        ackDelay is how long this reply was held after the newest sequence it
        reports arrived. The sender takes it back out of the round trip, which
        then measures the path instead of the path plus the far side's ack
        cadence. Microseconds, saturating, so the ceiling is about 65 ms against
        a cadence measured in single milliseconds. */
    static constexpr uint8_t  WIRE_ACK_ENTRY_HEAD_SIZE      = 10;

    /** Ranges per flow, per FLOW_ACK packet, bounding wire bytes. The list is
        built from the newest seq downward, so what a cap discards is always the
        oldest run. That is why the entry carries recvNext: the cursor is the
        part the sender cannot afford to lose, and it is one fixed field rather
        than a list that can be cut short. */
    static constexpr uint8_t  FLOW_ACK_RANGE_COUNT          = 16;

    // --- Transfer ---
    // A transfer moves one length-announced run of bytes between buffers the
    // application owns, on its own secure channels, with no flow header and no
    // message framing. Its packets are all one size, which is what lets a
    // packet's place in the destination buffer be arithmetic rather than
    // bookkeeping.

    /** Header inside the seal on every transfer packet, after the channel
        byte: [transferId(2)][seq(4)][flags(1)]. The id names which transfer on
        this peer, the sequence places the packet, and the flag says whether
        this one announces or carries bytes. */
    static constexpr uint8_t  TRANSFER_WIRE_HEADER_SIZE      = 7;

    /** The announcing packet's payload: [totalLen(8)][stride(2)].

        The stride is sent even though both ends derive the same constant,
        because the receiver refuses a value it did not expect rather than
        trusting one. That refusal is load bearing: an announced stride would
        otherwise be an attacker-chosen multiplier on every offset the receiver
        computes into the application's buffer.

        The announcing packet carries no bytes of the transfer. Letting it
        carry a short first chunk would put a special case in the offset
        arithmetic, and that arithmetic is the one thing standing between a
        hostile sender and a write past the end of a buffer flux does not
        own. */
    static constexpr uint8_t  TRANSFER_ANNOUNCE_SIZE         = 10;

    /** Flag bit in the transfer header saying this packet announces rather
        than carries. A transfer runs one after another on the same id, so the
        receiver cannot infer a start from the sequence alone. */
    static constexpr uint8_t  TRANSFER_FLAG_ANNOUNCE         = 0x01;

    /** Payload one transfer packet carries, and every packet but the last
        carries exactly this. A packet at sequence s writes at
        (s - firstDataSeq) * TRANSFER_STRIDE_BYTES.

        The peer tag is subtracted whether or not a given packet carries one. A
        stride that moved with a per-packet flag would move every offset behind
        it, so the four bytes are spent on every transfer packet to keep the
        multiply exact. */
    static constexpr uint16_t TRANSFER_STRIDE_BYTES          =
        MAX_WIRE_PACKET_SIZE - WIRE_SECURE_HEAD_SIZE - WIRE_PEER_TAG_SIZE
        - WIRE_TAG_SIZE - WIRE_SECURE_CHANNEL_SIZE - TRANSFER_WIRE_HEADER_SIZE;

    /** A transfer's in-flight window, and it is this large because it can
        afford to be. Every reliable flow mode holds a full copy of each
        unacknowledged packet, so its window costs the packet size times its
        depth, and a window able to fill a fast long path costs more memory
        than the path carries. Measured on a 1 Gbit link at 40 ms, which holds
        about 5 MB in flight: the bulk window tops out near 1.2 MB, so the flow
        ran out of window rather than out of path and moved 1024 MB in 42.34 s
        against msquic's 12.65.

        A transfer stages nothing, because a retransmit is re-read from the
        application's own buffer, so an outstanding packet costs its ring entry
        alone, and the depth this could afford is far greater than a flow's.

        It is held at a bulk flow's depth anyway, because depth is only worth
        having if what is put at risk can be repaired. Measured on a link
        losing two percent in bursts of twenty, moving 20 MB: 33 s at this
        depth against 68 s at eight times it, with ten times the loss events,
        because the wider window overflowed the queue faster than the repair
        logic could recover it. Raising this is the last step of matching the
        flow path's acknowledgement detail, not the first. */
    static constexpr uint16_t TRANSFER_WINDOW                = 1024;

    /** Bytes of window state an acknowledgement carries, one bit per sequence
        from the cursor forward.

        A transfer's receiver writes each packet at its own offset and needs no
        order, so what the sender wants back is not a cursor but the set of
        sequences that have landed. Sending the whole window says that exactly:
        no blind spot beyond a peephole, no cap on how many gaps can be
        described, and self-healing, because a lost acknowledgement costs
        nothing when the next one carries the entire state again.

        At a 1024 window it is 128 bytes against a 1163 byte data packet, and
        acknowledgements go out on a cadence rather than per packet, so the
        reverse path pays a few percent for perfect information. A cursor with
        a 64 bit peephole was measured first: packets that had arrived but sat
        beyond the peephole stayed counted as outstanding, held the window
        shut, and were only timed when the cursor eventually reached them,
        which put a 1.37 second round trip into the estimate. */
    static constexpr uint16_t TRANSFER_ACK_BITMAP_BYTES      = TRANSFER_WINDOW / 8;

    /** Packets a receiving transfer holds while it waits for the application
        to answer the announcement. The sender does not stop to wait, so what
        is already on the path has somewhere to land. Past this the rest are
        dropped and retransmitted, which throttles the sender to the speed the
        application answers rather than wasting the link. */
    static constexpr uint16_t TRANSFER_PREATTACH_SLOTS       = 16;

    /** Largest transfer this socket accepts an announcement for when Config
        leaves maxTransferBytes at zero. Nothing inside flux is sized by it,
        because the tracking is window sized rather than transfer sized. It
        bounds what a remote may ask the application to find room for. */
    static constexpr uint64_t TRANSFER_MAX_BYTES_DEFAULT     = 1ull << 30;   // 1 GiB

    // --- Congestion control ---
    // Per peer, in bytes, spent only by flow packets. Grows on acknowledgement,
    // trims to CC_LOSS_RETAIN_PERCENT on loss, never below the Config floor.
    static constexpr uint32_t CC_INITIAL_WINDOW_BYTES       = 10u * MAX_WIRE_PACKET_SIZE;

    /** How many round trips a standing queue must hold, with the budget held
        flat, before slow start ends on it.

        Slow start doubles for as long as the path shows no standing queue.
        Doubling cannot know the ceiling until it passes it, and the overshoot
        is the size of the last step. Measured on a 100 ms path holding 625 KB:
        the budget went from 517 KB to 1032 KB in one round trip, 407 KB past
        what the path holds, overflowed the buffer and took 21 percent
        self-inflicted loss with 18.2 MB on the wire to move 10 MB. A flat
        reduction of the ramp fixes that by taxing every link, clean or not,
        so the ramp reacts to the queue instead and pays only where one forms.

        A sighting opens on the newest sample and the confirmation holds the
        budget flat until the smoothed figure agrees or both read clean again.
        Each half of that came from a measured failure. Growing a quarter per
        round trip during the check carried the budget into the buffer's drop
        ceiling before the verdict arrived. Releasing on the newest sample
        alone let one clean reading per round resume the doubling against a
        real queue, so the budget climbed past the ceiling in steps and the
        exit never fired.

        Two round trips, because one sighting can be scheduling jitter or a
        coalesced acknowledgement, and ending the ramp on it strands the
        budget far below what the path carries. A queue that outlives two
        round trips with the budget flat is a queue this sender is building. */
    static constexpr uint32_t CC_SLOW_START_CONFIRM_ROUNDS  = 2;

    /** What the budget keeps on a congestion event. 70 percent is CUBIC's
        figure, and it is deeper than the 85 that came before it. Two reasons it
        is affordable now. The curve returns to the previous window in a fraction
        of the time a straight line took, so the cut costs far less than it used
        to. And every other controller sharing a bottleneck uses roughly this,
        so a sender that keeps more than they do takes more than its share on
        every loss, permanently, and that is a property of the sender rather
        than of the network. */
    static constexpr uint8_t  CC_LOSS_RETAIN_PERCENT        = 70;

    /** What the budget keeps when a loss arrives with no queue behind it.

        Loss is only evidence of congestion when something was actually
        queueing. A wireless link drops for radio reasons with the path empty,
        and the queue estimate can see the difference: at the moment of these
        losses it reads a few hundred microseconds against a multi-millisecond
        target. Trimming 30 percent there settles the window at the textbook
        AIMD equilibrium, about sixteen packets at one percent loss, which
        measured 19x slower than the link allows.

        Still a trim rather than an exemption. The queue estimate can be
        stale for up to a bucket rotation after a route change, and a sender
        that ignores loss outright for that long is a flood. Five percent
        keeps the response proportional: noise costs a little, real
        congestion, corroborated by the queue, costs the full cut. */
    static constexpr uint8_t  CC_NOISE_RETAIN_PERCENT       = 95;

    /** The delivery estimate's memory: how long one bucket spans and how many
        are kept. Four quarter seconds, so a rate has to be absent for a full
        second before it is forgotten. Long enough that a burst cannot erase
        the estimate it is about to be judged against, short enough that a path
        which genuinely slowed is not judged against what it used to carry. */
    static constexpr uint32_t DELIVERY_BUCKETS              = 4;
    static constexpr uint32_t DELIVERY_BUCKET_MICROS        = 250000;

    /** The share of loss this path may sustain before loss is believed as a
        congestion signal at all.

        A flow at its fair share of a congested link loses a fraction of a
        percent, because that is all it takes for the feedback to work. A link
        losing whole percentages steadily is not telling a sender to slow down,
        it is telling it what the link is: interference, a fade, a bad cable.
        Reacting to that as congestion settles the window at the equilibrium
        for the loss rate, which is a small fraction of what the path carries
        and is where seven seconds of a ten second transfer went.

        Below this figure the delay signal is the whole congestion detector,
        which it is designed to be: the queue estimate sees a bottleneck
        filling before anything is dropped, and the governor stops growth on
        it. Loss only regains its vote once the link is losing more than a
        congested link ever needs to.

        Two percent is the figure BBRv2 uses for the same judgement, arrived at
        from the same reasoning. */
    static constexpr uint32_t CC_LOSS_TOLERANCE_PERCENT     = 2;

    /** How close to the path's measured capacity a sender must be before a
        burst of losses may be read as its own buffer overflow.

        An overflow is self-inflicted, so it cannot happen to a sender that is
        not filling the path, while interference takes packets at any rate.
        Measured on a link losing two percent in bursts of twenty: forty four
        of eighty trims were charged as overflow while the sender sat at thirty
        one percent of capacity, holding it there for the whole transfer.

        Seventy five rather than a hundred because the estimate is a floor. It
        is the largest rate recently observed, and a sender that has been held
        below capacity has never observed the whole of it, so demanding the
        full figure would gate out real overflows on exactly the paths that
        need the check. A shallow buffer overflows above the path's capacity
        rather than below it, so the true positives sit well clear of this. */
    static constexpr uint32_t CC_OVERFLOW_GATE_PERCENT      = 75;

    /** Ceiling on the budget for a starvation verdict to be considered.

        A sender that answers a standing queue by holding back can be starved
        by a neighbour that answers the same queue by filling further. The
        queue keeps the governor engaged, every loss trims, and the budget
        pins at a handful of packets while the path carries a hundred times
        that. The budget is what tells this apart from healthy sharing,
        because the queue cannot: it stands above target in both. Measured on
        one 50 Mbit link at 40 ms, two of these sharing sat at 145 to 167 KB
        each, one beside CUBIC never fell below 52 KB, and one starved by BBR
        was pinned between 4 and 10 KB. Ten packets sits above the starved
        band and four times under the worst healthy reading. */
    static constexpr uint32_t CC_STARVED_BUDGET_BYTES       = CC_INITIAL_WINDOW_BYTES;

    /** How long the starved conditions must hold before the verdict is
        taken, in round trips, with a floor for short paths. Loss trims put
        the budget at the floor transiently on any busy path, and a verdict
        taken on a transient would engage against ordinary congestion.
        Sixteen round trips of continuous starvation is not a transient. */
    static constexpr uint32_t CC_STARVED_CONFIRM_ROUNDS     = 16;
    static constexpr uint32_t CC_STARVED_CONFIRM_MIN_MICROS = 250000;

    /** How long the queue must read under the ordinary target, while the
        verdict holds, before it is lifted. Exit watches the queue rather
        than the recovered share, because a competitor still present starves
        the share again at once and the mode would oscillate. The floor is
        what keeps a BBR competitor's periodic probe drain, a fifth of a
        second every ten seconds, from reading as a departure. */
    static constexpr uint32_t CC_STARVED_EXIT_ROUNDS        = 8;
    static constexpr uint32_t CC_STARVED_EXIT_MIN_MICROS    = 500000;

    /** How long after the verdict lifts a relapse re-engages it immediately,
        with the references kept from the episode that just ended.

        The exit can be faked: a competitor's probe cycle drains the queue
        long enough to read as a departure, the verdict lifts, and the sender
        is starved again within seconds. Measured over five continuous
        minutes beside BBR, every collapse to zero followed such an exit.
        Re-entering through the full confirmation window costs a second of
        starvation each time, and re-freezing the references mid-contention
        captures a minimum the standing queue has already corrupted, so the
        relapse path skips the confirmation and keeps the references from the
        episode that just ended. Only a path that stays clean for this long
        after an exit forgets them and earns a fresh capture. */
    static constexpr uint32_t CC_STARVED_REENTRY_WINDOW_MICROS = 30000000;

    /** Slack over the frozen queue level, as a divisor of the queue target,
        folded into the bound when it is frozen.

        The level at the verdict is the level the competitors maintain, so a
        bound frozen exactly there sits on its own boundary: every later
        reading lands within noise of it, and whether the budget may ever
        grow is decided by measurement luck. Measured with two starved
        senders beside one BBR, the one whose bound fell 76 microseconds
        under the standing level was pinned at the floor for seven seconds
        while the other recovered. Half a target is above that noise and
        stays a fraction of the queue already standing, and because each
        sender freezes its own slack once, two of them cannot ratchet each
        other upward with it. */
    static constexpr uint32_t CC_STARVED_CAP_SLACK_DIVISOR  = 2;

    /** CUBIC's aggression, scaled by 100 so the curve stays in integers. The
        window follows C*(t - K)^3 + wMax with t in seconds, where K is how long
        the curve takes to climb back to wMax. 0.4 is the standard value. */
    static constexpr uint32_t CC_CUBIC_C_SCALED             = 40;
    static constexpr uint32_t CC_CUBIC_C_SCALE              = 100;
    static constexpr uint32_t CC_MIN_BUDGET_DEFAULT         = 2u * MAX_WIRE_PACKET_SIZE;

    /** Pacing. The window says how much may be outstanding, not how fast it may
        leave, and releasing it all at once is what overflows a queue that the
        average rate would never have troubled. So the send gate also refuses a
        packet that is within every other limit but ahead of the clock.

        The rate is the congestion budget over the round trip, which is the
        definition of the window: as much in flight as the path holds. The gain
        is the headroom the window needs to grow, since pacing exactly at the
        current rate means never sending more than the current window and never
        discovering there is room for more.

        The burst is how much may go back to back, which absorbs the coarseness
        of releasing on a tick rather than on a timer, and the granularity of a
        tick is why this is not the fine pacing a dedicated timer would give.

        Nothing is paced before the first round-trip sample, because there is no
        rate to pace at. The initial window bounds that opening burst instead,
        which is what it is for. */
    /** How many acknowledged packets with higher sequences it takes to call an
        unacknowledged one lost, without waiting for its timeout. The receiver
        already reports which sequences it holds, so this costs nothing on the
        wire and saves most of a timeout.

        Three is the long-standing figure, and the reason it is not one or two
        is reordering: a packet overtaken by one or two others is late rather
        than gone, and declaring it lost would cost a needless retransmit and,
        worse, a congestion reaction on a path that was fine. */
    static constexpr uint32_t LOSS_PACKET_THRESHOLD         = 3;

    /** Smallest the variance half of the retransmit timeout may be.

        Variance is what separates the timeout from the average round trip, and
        on a steady path it decays towards nothing. The average is the middle of
        the distribution, so a timeout that sits on it expires on about half of
        all acknowledgements, every one of which is then read as congestion.
        Measured on a clean 40 ms link the margin fell to 256 microseconds and
        the sender declared 582 losses in eight seconds without a single packet
        being dropped.

        One millisecond is the same lower bound the timeout already had on its
        own, and the same granularity RFC 9002 gives QUIC. */
    /** The retransmit deadline's margin as a fraction of the round trip,
        taken when it exceeds the variance term. Eight matches the spare
        eighth LossDelayMicros grants for reordering, and it exists for the
        same reason: a deadline that hugs the average duplicates whatever
        honestly runs a few percent late. */
    static constexpr uint32_t RTO_MARGIN_DIVISOR = 8;

    static constexpr uint32_t RTO_VARIANCE_MIN_MICROS       = 1000;

    /** Largest round trip that can be a measurement rather than a mistake.

        Ten seconds is more than an order of magnitude past the worst real path,
        including a geostationary hop with a full buffer in front of it. A
        sample beyond it did not come from the network, it came from subtracting
        something that was never a timestamp, and folding it into the smoothed
        value poisons every decision built on that value afterwards. One such
        sample once produced a smoothed round trip of 54 hours, which put the
        retransmit timeout past any clock and stopped the flow without failing
        it. Out of band samples are dropped, and an assert reports them, because
        a clamp that quietly corrects a wrong number means the next one is never
        found. */
    static constexpr uint32_t RTT_SAMPLE_MAX_MICROS         = 10000000;

    /** Largest the retransmit timeout may be.

        RTT_SAMPLE_MAX_MICROS already bounds everything the timeout derives from
        the network. This bounds the other input: the Config fallback used
        before the first sample arrives, which is whatever the application set
        and is not otherwise checked. Sixty seconds is the same ceiling TCP
        uses. Its job is to make a silent flow eventually try again rather than
        wait forever, so the worst outcome of a bad number is slow instead of
        dead. */
    static constexpr uint32_t RTO_MAX_MICROS                = 60000000;

    /** Most the timeout may be doubled while a peer stays silent.

        Three, so eight times the base, and the ceiling is low on purpose. A
        give-up count sits behind the timeout, so the shift multiplies the time
        to give up exponentially rather than just spacing the probes out. At six
        the tail of a transfer, which is the one case a probe exists for because
        no acknowledgement can ever reveal it, becomes the slowest thing in the
        system: nothing is outstanding but the last packet, so nothing arrives
        to reset the silence, and each attempt waits 64 times the round trip.
        Measured on a 25 percent loss link that stalled a transfer outright. */
    static constexpr uint32_t RTO_MAX_BACKOFF_SHIFT         = 3;

    /** Round trips of silence before a sending association is declared dead.

        A time, not a count of attempts. A count spends itself in a burst on a
        lossy but living link and stretches over minutes on a slow one, and
        both are the wrong verdict. Sixteen because on a link losing a quarter
        of everything the chance of that many consecutive probes all failing is
        about one in ten billion, so it is a conclusion rather than a guess.

        Deliberately NOT the flow stall timeout. That one is the receiver
        reclaiming buffer it is pinning for a gap nobody is filling, and it is
        generous on purpose because it is about memory. This asks whether the
        far side has stopped answering, which is a question about the path, so
        it is measured in the path's own units. */
    static constexpr uint32_t FLOW_DEATH_ROUNDS             = 16;

    /** Fewest probes that must go unanswered before that verdict is allowed.

        The backoff and the deadline have to agree about the same silence. Left
        independent they multiply: the interval grows, the window collapses
        beside it, and the offered rate falls far enough that the deadline
        expires having asked two or three times. A verdict of death taken on
        three questions is a guess, so the interval is capped at the deadline
        divided by this, and the doubling is spent inside the window instead of
        eating it. */
    static constexpr uint32_t FLOW_DEATH_MIN_PROBES         = 8;

    /** Unanswered probes before the path is treated as gone rather than
        congested. Three is the same count RFC 9002 uses. At that point trimming
        a percentage off the budget is arithmetic on a number that no longer
        describes anything, so it goes straight to the floor. */
    static constexpr uint32_t PERSISTENT_CONGESTION_PROBES  = 3;

    /** The windowed minimum round trip: how many buckets, and how long each
        covers. Three at four seconds gives between eight and twelve seconds of
        memory, which is long enough that a busy path still contains one quiet
        moment and short enough that a route change is noticed. */
    static constexpr uint32_t MIN_RTT_BUCKETS               = 3;
    static constexpr uint32_t MIN_RTT_BUCKET_MICROS         = 4000000;

    /** How much standing queue the sender will tolerate before it stops growing
        the window, as a fraction of the minimum round trip.

        A fraction rather than a fixed figure, because a millisecond count that
        is right on one link is wrong on every other. An eighth of the path's
        own delay is small enough to keep the queue out of the way of anything
        latency-sensitive sharing the link, and large enough that ordinary
        jitter does not read as congestion.

        This is what stops a loss-based controller resting at a full buffer.
        Growth waits while the queue is above it, whatever the curve wants. */
    static constexpr uint32_t QUEUE_TARGET_DIVISOR          = 8;

    /** Floor under that target, because a fraction of a very short path lands
        below the noise. On loopback the minimum round trip is tens of
        microseconds, an eighth of it is single digits, and ordinary scheduling
        jitter is larger than that, so the sender reads a standing queue that
        does not exist and never grows again. A millisecond is above the jitter
        on any path and far below the point where a queue starts mattering. */
    static constexpr uint32_t QUEUE_TARGET_MIN_MICROS       = 1000;

    /** Acknowledge at least this often, in packets, rather than only when the
        delay expires. Holding a reply is worth it on a quiet link, where it
        turns several replies into one. On a link with data flowing it is pure
        delay: two packets arrive in microseconds, and the sender is sitting
        there timing the pause and concluding the path is slow.

        Two is the long-standing figure and it keeps the saving where the saving
        is real, since a lone packet still waits for the timer. */
    static constexpr uint32_t ACK_EVERY_PACKETS             = 2;

    static constexpr uint32_t CC_PACING_GAIN_PERCENT        = 125;
    static constexpr uint32_t CC_PACING_BURST_BYTES         = 2u * MAX_WIRE_PACKET_SIZE;

    // --- I/O ---
    static constexpr uint32_t  MAX_READ_PER_TICK            = 258;

    // --- Migration ---
    /** Unknown-address tag lookups, and their trial decrypts, per Poll pass. A
        burst past this is a flood; a genuine mover retries on its next packet. */
    static constexpr uint32_t  MIGRATE_BUDGET_PER_POLL      = 64;

    // --- Liveness ---
    /** Monotonic micros are stored right-shifted by this, giving ~1.024 ms units
        in 32 bits and a ~49.7-day wrap. Wrapped subtraction stays exact under
        one wrap, so a peer past a full wrap evicts late, never early. */
    static constexpr uint32_t  SEEN_STAMP_SHIFT             = 10;
    static constexpr uint32_t  MAX_EVICT_PER_UPDATE         = 16;  ///< the rest ride the next tick

    /** A peer heard from for this long is dead and its entry is reclaimed. Used
        when Config leaves idleTimeoutMicros at zero. Idle eviction is not
        optional: a live peer refreshes the clock on every packet, so only a
        genuinely silent one is evicted, and reclaiming it is what frees the slot
        for a restarted process to reconnect. */
    static constexpr uint32_t  PEER_IDLE_TIMEOUT_DEFAULT    = 30000000;   // 30 s

    /** A receiving ordered flow whose cursor has not advanced for this long
        while it holds a gap is jammed, and the tick reclaims it. Used when
        Config leaves flowStallTimeoutMicros at zero. Comfortably past the
        longest a legitimate flow stalls while a lost cursor packet is
        retransmitted, which the sender bounds by its own give-up. */
    static constexpr uint32_t  FLOW_STALL_TIMEOUT_DEFAULT   = 5000000;   // 5 s

    // --- Pool ---
    static constexpr uint32_t SOCK_KERNEL_ZLOCKPCKT_COUNT   = 2048;

    /** Share of the receive pool kept clear of buffering when Config leaves the
        reserve at zero. Reception itself needs somewhere to land, and a pool
        consumed entirely by buffered packets leaves the kernel nothing to read
        into, which makes the socket deaf to every peer rather than throttling
        one. A fraction rather than a count, because what the reserve has to
        absorb is arrivals per tick, which tracks pool size and peer count
        rather than any fixed number. */
    /** Handles one drain chunk holds on the stack. The batch a tick takes is
        configured and may be far larger, so it is drained in chunks of this. */
    static constexpr uint32_t RECV_CHUNK                    = 64;

    /** Buffer reclaims a peer is allowed before its grant is cut. A lossy path
        costs a peer the occasional one, so this is high enough that ordinary
        loss never reaches it and low enough that a peer holding buffer it never
        uses is answered quickly. */
    static constexpr uint32_t GRANT_STRIKES_BEFORE_CUT      = 4;

    /** What a cut leaves, as a divisor. Halving rather than closing, because a
        peer that recovers should still be able to work, and repeated cuts reach
        the floor soon enough. */
    /** How recent the strikes have to be to count as a pattern.

        Without a window the count is a peer's whole lifetime, so four stalls an
        hour apart read the same as four in a row, and the grant is halved for
        something that is a lossy link rather than a peer holding buffer it does
        not use. Nothing ever raises a grant back, so that verdict is permanent.
        Thirty seconds is the same order as the idle timeout: four stalls inside
        it is a pattern, four spread past it is weather. */
    static constexpr uint64_t GRANT_STRIKE_WINDOW_MICROS    = 30000000;

    static constexpr uint32_t GRANT_CUT_DIVISOR             = 2;
    static constexpr uint32_t GRANT_CUT_FLOOR               = 2;

    static constexpr uint32_t RECV_RESERVE_DIVISOR          = 16;
    static constexpr uint32_t RECV_RESERVE_FLOOR            = 64;
    static constexpr uint32_t SOCK_KERNEL_SENDSLOT_COUNT    = 2048;
}
