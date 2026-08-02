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

    /** Per flow, per FLOW_ACK packet. Bounds wire bytes only: acks are
        cumulative, so a range that misses one report rides the next. */
    static constexpr uint8_t  FLOW_ACK_RANGE_COUNT          = 16;

    // --- Congestion control ---
    // Per peer, in bytes, spent only by flow packets. Grows on acknowledgement,
    // trims to CC_LOSS_RETAIN_PERCENT on loss, never below the Config floor.
    static constexpr uint32_t CC_INITIAL_WINDOW_BYTES       = 10u * MAX_WIRE_PACKET_SIZE;
    static constexpr uint8_t  CC_LOSS_RETAIN_PERCENT        = 85;
    static constexpr uint32_t CC_MIN_BUDGET_DEFAULT         = 2u * MAX_WIRE_PACKET_SIZE;

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
    static constexpr uint32_t SOCK_KERNEL_SENDSLOT_COUNT    = 2048;
}
