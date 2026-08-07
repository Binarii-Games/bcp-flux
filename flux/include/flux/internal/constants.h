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

    // --- Congestion control ---
    // Per peer, in bytes, spent only by flow packets. Grows on acknowledgement,
    // trims to CC_LOSS_RETAIN_PERCENT on loss, never below the Config floor.
    static constexpr uint32_t CC_INITIAL_WINDOW_BYTES       = 10u * MAX_WIRE_PACKET_SIZE;

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
    static constexpr uint32_t GRANT_CUT_DIVISOR             = 2;
    static constexpr uint32_t GRANT_CUT_FLOOR               = 2;

    static constexpr uint32_t RECV_RESERVE_DIVISOR          = 16;
    static constexpr uint32_t RECV_RESERVE_FLOOR            = 64;
    static constexpr uint32_t SOCK_KERNEL_SENDSLOT_COUNT    = 2048;
}
