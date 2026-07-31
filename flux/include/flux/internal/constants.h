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
    static constexpr uint8_t  WIRE_SECURE_CHANNEL_SIZE      = 1;
    static constexpr uint8_t  MIN_WIRE_SIZE                 = WIRE_CONTROLLER_SIZE;
    static constexpr uint8_t  MIN_SECURE_WIRE_SIZE          = WIRE_CONTROLLER_SIZE + WIRE_TAG_SIZE + WIRE_NONCE_SIZE;

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
    /** The in-flight window, in packets: the sender's ring capacity and the
        receiver's seen-bitmap width, one number for every flow in both
        directions. Fixed rather than configurable, because nothing carries it
        on the wire and nothing negotiates it, so two sockets that disagreed
        would have no way to find out. A constant makes them agree by
        construction.

        A power of two, since both the ring and the bitmap index by
        seq & (window - 1). 256 is a whole number of 64-bit bitmap words, and
        bounds a reliable association's ring at 6 KB. */
    static constexpr uint16_t FLOW_WINDOW                   = 256;

    /** Ceiling for the waiting and reorder rings, which stay configurable. The
        largest power of two that fits the uint16_t caps they are stored in. */
    static constexpr uint16_t FLOW_RING_MAX                 = 32768;

    /** Handshake attempts before a peer is judged unreachable and dropped.
        Paced by Config::timers::retryIntervalMicros, so 8 gives a peer about
        1.6 seconds of silence before whatever parked behind the handshake
        fails visibly, rather than waiting on an idle timeout that may be off. */
    static constexpr uint8_t  HANDSHAKE_MAX_ATTEMPTS        = 8;

    /** Used when Config leaves the retry interval at zero, which would
        otherwise make every tick a retry. */
    static constexpr uint32_t HANDSHAKE_RETRY_DEFAULT        = 200000;
    /** Ack ranges one flow contributes to a single FLOW_ACK packet, emitted
        newest-first from its seen bitmap. A cap on wire bytes, not on memory:
        acks are cumulative, so ranges that miss one report ride the next. */
    static constexpr uint8_t  FLOW_ACK_RANGE_COUNT          = 16;

    // --- Congestion control ---
    /** The in-flight budget is per peer, measured in BYTES, spent only by flow
        packets (the non-flow tier is untracked). It starts at
        CC_INITIAL_WINDOW_BYTES (ten full packets' worth), grows on
        acknowledgement, and trims to CC_LOSS_RETAIN_PERCENT of itself on loss,
        never below the Config floor (default CC_MIN_BUDGET_DEFAULT). Every value
        here is bytes; none is on the wire. */
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

    // --- Workers ---
    static constexpr uint8_t   SOCK_WORKER_COUNT            = 8;

    // --- Pool ---
    static constexpr uint32_t SOCK_KERNEL_ZLOCKPCKT_COUNT   = 2048;
    static constexpr uint32_t SOCK_KERNEL_SENDSLOT_COUNT    = 2048;
}