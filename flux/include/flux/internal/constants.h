#pragma once

#include <cstdint>

#include <common/crypto/crypto.h>

namespace bcp::flux::internal
{
    // --- Version ---
    static constexpr uint16_t VERSION                       = 2; ///< 2: flows register from data packets; the flow header gained its data byte
    static constexpr uint8_t  VERSION_CAPS_SIZE             = 4; ///< Fixed; changing it breaks older versions.
    static constexpr uint8_t  VERSION_SIZE                  = 2; 


    // --- Wire ---
    static constexpr uint16_t MAX_WIRE_PACKET_SIZE          = 1200; ///< Conservative floor: under the IPv6 min MTU (1280) less IP+UDP headers, with margin for tunnels/VPNs. MTU discovery probes upward from here.
    static constexpr uint8_t  WIRE_CONTROLLER_SIZE          = 1;
    static constexpr uint8_t  WIRE_TAG_SIZE                 = 16;
    static constexpr uint8_t  WIRE_NONCE_SIZE               = 8;  ///< Send-counter half of the nonce; the rest is derived locally.
    static constexpr uint8_t  WIRE_FLOW_ID_SIZE             = 2;
    static constexpr uint8_t  WIRE_FLOW_SEQ_SIZE            = 4;
    static constexpr uint8_t  WIRE_FLOW_DATA_SIZE           = 1;  ///< mode + window exponent, after the sequence
    /** The whole flow header, inside the seal: id, sequence, data byte. */
    static constexpr uint8_t  WIRE_FLOW_HEADER_SIZE         =
        WIRE_FLOW_ID_SIZE + WIRE_FLOW_SEQ_SIZE + WIRE_FLOW_DATA_SIZE;
    static constexpr uint8_t  WIRE_PEER_TAG_SIZE            = 4;  ///< Migration tag; present when CTRL_TAGGED is set.
    static constexpr uint8_t  WIRE_SECURE_CHANNEL_SIZE      = 1;  ///< First encrypted byte; splits app data from control.
    static constexpr uint8_t  MIN_WIRE_SIZE                 = WIRE_CONTROLLER_SIZE;
    static constexpr uint8_t  MIN_SECURE_WIRE_SIZE          = WIRE_CONTROLLER_SIZE + WIRE_TAG_SIZE + WIRE_NONCE_SIZE;

    /** In-band secure channel: the first byte of every secure packet's
        plaintext, encrypted and never visible on the wire. 0 is application
        data; anything else is internal control (path validation). A validation
        packet is byte-for-byte indistinguishable from data to any observer,
        even one that knows Flux's header. The receiver learns which only after
        a successful decrypt. */
    static constexpr uint8_t  SECURE_CHANNEL_APP            = 0x00;
    static constexpr uint8_t  SECURE_CHANNEL_PATH_CHLG      = 0x01;
    static constexpr uint8_t  SECURE_CHANNEL_PATH_RESP      = 0x02;
    static constexpr uint8_t  SECURE_CHANNEL_FLOW_REJECT    = 0x03; ///< receiver refused to register a flow (caps)
    // 0x04 is unassigned: it carried FLOW_OPEN_ACK when opening was a wire
    // exchange, and reusing it too soon would make two protocol generations
    // ambiguous on capture.
    // 0x05 and 0x06 are retired: they carried FLOW_CLOSE and FLOW_CLOSE_ACK
    // when closing was negotiated. Closing is local now, and a flow is not tied
    // to a peer, so a remote dropping its receive state cannot end the flow.
    // Left unassigned so a capture from either generation stays unambiguous.
    static constexpr uint8_t  SECURE_CHANNEL_FLOW_ACK       = 0x07;

    static_assert(WIRE_TAG_SIZE == common::crypto::TAG_SIZE,
                  "The wire tag field carries the AEAD tag verbatim");

    // --- Handshake ---
    static constexpr uint8_t  WIRE_HS_SALT_SIZE             = 16; ///< Each side's KDF salt contribution.
    static constexpr uint8_t  WIRE_HS_TAG_SIZE              = 32; ///< Responder's announced identity tag.
    static constexpr uint8_t  WIRE_HS_MAC_SIZE              = 16; ///< Key-confirmation MAC over the transcript.

    /** The handshake transcript both sides bind into the session key and the
        confirmation MAC, role-ordered so both ends assemble identical bytes:
          initiatorPk ‖ responderPk ‖ saltI ‖ saltR
          ‖ initiatorCaps ‖ responderCaps ‖ initiatorVersion ‖ responderVersion ‖ tag
        Version and caps sit inside the MAC'd transcript; a tampered or
        mismatched negotiation fails key confirmation. BuildTranscript is the
        authoritative field order. */
    static constexpr size_t   HS_TRANSCRIPT_SIZE            =
        2*common::crypto::KEY_SIZE + 2*WIRE_HS_SALT_SIZE + 2*VERSION_SIZE + 2*VERSION_CAPS_SIZE + WIRE_HS_TAG_SIZE;

    static_assert(WIRE_HS_MAC_SIZE == common::crypto::MAC_SIZE,
                  "The wire confirmation field carries a ComputeMac output verbatim");

    // --- Flow ---
    static constexpr uint16_t INVALID_FLOW_ID               = 0xFFFF;
    /** The flow window (out-ring capacity and in-bitmap width) rounds to a
        power of two within these bounds. Floor 64 keeps the seen bitmap a whole
        number of 64-bit words; the ceiling is the largest power of two that fits
        the uint16_t window field, so the rounded value never overflows it. */
    static constexpr uint16_t FLOW_WINDOW_MIN               = 64;
    static constexpr uint16_t FLOW_WINDOW_MAX               = 32768;
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
    /** Ceiling on unknown-address tag lookups (and their trial decrypts) per
        Poll pass. Genuine moves are rare; a burst beyond this smells like a
        flood, and a legit mover past the budget just retries next packet. */
    static constexpr uint32_t  MIGRATE_BUDGET_PER_POLL      = 64;

    // --- Liveness ---
    /** Peer seen-stamps store monotonic microseconds right-shifted by this,
        giving ~1.024 ms units in 32 bits (a ~49.7-day wrap). Wrapped
        subtraction keeps elapsed time exact under one wrap, so an idle peer
        past a full wrap can only be evicted late, never early. */
    static constexpr uint32_t  SEEN_STAMP_SHIFT             = 10;
    /** Evictions one Update call will perform; the rest ride the next tick.
        Bounds the burst of RemovePeer teardowns when many peers idle out
        together. Same shape as MIGRATE_BUDGET_PER_POLL, smaller because a
        teardown (flow sweep + pending drain) far outweighs a tag lookup. */
    static constexpr uint32_t  MAX_EVICT_PER_UPDATE         = 16;

    // --- Workers ---
    static constexpr uint8_t   SOCK_WORKER_COUNT            = 8;

    // --- Pool ---
    static constexpr uint32_t SOCK_KERNEL_ZLOCKPCKT_COUNT   = 2048;
    static constexpr uint32_t SOCK_KERNEL_SENDSLOT_COUNT    = 2048;
}