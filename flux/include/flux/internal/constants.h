#pragma once

#include <cstdint>

#include <common/crypto/crypto.h>

namespace bcp::flux::internal
{
    // --- Version ---
    static constexpr uint16_t VERSION                       = 0; ///< Stays 0 until 1.0: the wire is not frozen, so nothing negotiates on it
    static constexpr uint8_t  VERSION_CAPS_SIZE             = 4; ///< Fixed; changing it breaks older versions.
    static constexpr uint8_t  VERSION_SIZE                  = 2; 


    // --- Wire ---
    static constexpr uint16_t MAX_WIRE_PACKET_SIZE          = 1200; ///< Conservative floor: under the IPv6 min MTU (1280) less IP+UDP headers, with margin for tunnels/VPNs. MTU discovery probes upward from here.
    static constexpr uint8_t  WIRE_CONTROLLER_SIZE          = 1;
    static constexpr uint8_t  WIRE_TAG_SIZE                 = 16;
    static constexpr uint8_t  WIRE_NONCE_SIZE               = 8;  ///< Send-counter half of the nonce; the rest is derived locally.
    static constexpr uint8_t  WIRE_FLOW_ID_SIZE             = 2;
    static constexpr uint8_t  WIRE_FLOW_SEQ_SIZE            = 4;
    static constexpr uint8_t  WIRE_FLOW_DATA_SIZE           = 1;  ///< mode, after the sequence
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
    static constexpr uint8_t  SECURE_CHANNEL_FLOW_ACK       = 0x04;

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