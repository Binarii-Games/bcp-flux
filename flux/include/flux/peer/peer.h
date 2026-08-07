#pragma once

#include <array>
#include <type_traits>

#include <common/crypto/crypto.h>

#include <flux/address.h>
#include <flux/internal/constants.h>
#include <flux/internal/rtt.h>
#include <flux/peer/peer_id.h>

namespace bcp::flux
{
    /** Rotating migration tag on a peer's secure packets, an address-independent
        connection handle. Derived from the session key on both ends, never sent.
        All-zero is reserved. */
    using PeerTag = std::array<uint8_t, internal::WIRE_PEER_TAG_SIZE>;

    /** Handshake progress. The AWAITING states are initiator-only. The responder
        stays stateless through the challenge and creates a peer only after it
        verifies, so responder-side peers start ESTABLISHED. */
    enum class HandshakeState : uint8_t
    {
        AWAITING_CHALLENGE = 0,   ///< HS_INIT sent, waiting for the challenge
        AWAITING_FINISH    = 1,   ///< HS_RES sent, waiting for the remote's key
        ESTABLISHED        = 2,   ///< proven and keyed; the peer is valid
    };

    /** Liveness stamp: monotonic micros shifted to ~1 ms units (SEEN_STAMP_SHIFT),
        wrapping about every 49.7 days. Compute elapsed with wrapped uint32_t
        subtraction (now - then). Stays exact for gaps under one wrap. */
    inline uint32_t SeenStamp(uint64_t micros) noexcept
    {
        return static_cast<uint32_t>(micros >> internal::SEEN_STAMP_SHIFT);
    }

    /** Stored in PeerTable's SlotPool, which hands back raw bytes and runs no
        constructor or destructor. Must stay trivially copyable: no vector, no
        atomic, no vtable, nothing that owns heap memory.

        A recycled slot keeps the previous peer's bytes (SlotPool zeroes once, at
        Init), so registration must write every field. */
    struct Peer
    {
        Address addr;
        BcpId   id;

        common::crypto::PublicKey  theirPk;   ///< remote's key; id == blake2b(theirPk)
        common::crypto::SessionKey session;   ///< DH(our secret, theirPk) through the KDF,
                                              ///< salted per handshake

        /** Masks the counter field of every secure packet, so the counter is
            not readable on the wire. Split from `session` rather than reused:
            XChaCha20 derives its own internal subkey the same way, and a
            separate key keeps the two derivations from ever sharing a domain.
            Derived with the session, discarded with it. */
        common::crypto::SessionKey headerKey;

        /** Authenticates a MAC-only packet, which is not encrypted and so has
            no AEAD tag to be covered by. Separate from `session` because the
            obvious later optimisation is to swap BLAKE2b for the Poly1305 the
            AEAD already computes, and a Poly1305 key must never be reused
            across messages. Sharing the session key would make that change
            silently forgeable rather than merely wrong. Derived with the
            session, discarded with it. */
        common::crypto::SessionKey macKey;

        /** Nonce counter for packets we encrypt to this peer. Travels in each
            packet, so the remote never tracks it.

            @pre Bumped under the slot write lock, per send. */
        uint64_t sendCounter;

        /** Migration tag state. myTagStep is the step we stamp on outgoing
            secure packets; myTag caches that step's tag so the send path copies
            4 bytes instead of running the KDF. theirTagStep is the base of the
            remote's bound tag window [base, base + 2]. All of it resets to
            step 0 on every (re)key, since tags derive from the session key. */
        uint32_t myTagStep;
        uint32_t theirTagStep;
        PeerTag  myTag;

        /** Path validation in flight: the address the peer seems to have moved
            to, the challenge sent there, and the tag step the mover presented
            (where the window slides on success). It either completes (the mover
            answers, the peer rebinds) or never does. An unproven address never
            tears down the proven session. pathAddr unset means nothing pending.

            @pre Claimed and cleared under the slot write lock, so two workers
                 cannot finish the same validation. */
        Address  pathAddr;
        uint8_t  pathChallenge[16];
        uint32_t pathStep;

        /** Our salt contribution while the handshake is in flight: saltI on the
            initiator (held until HS_FINISH arrives), saltR on the responder
            (held so a duplicate HS_RES resends the same FINISH instead of
            re-keying). */
        uint8_t hsSalt[internal::WIRE_HS_SALT_SIZE];

        /** Identity tag the peer announced in HS_FINISH. Opaque to Flux, passed
            up to the layer above. All zeros for an anonymous peer and on the
            responder side, which gets no announcement. */
        uint8_t announcedTag[internal::WIRE_HS_TAG_SIZE];

        /** Handshake ephemeral state, and the whole point of it is that the
            secret half does not outlive the exchange. It is wiped the moment
            the session is derived, which is what stops a later theft of the
            long-lived key from opening traffic recorded today.

            hsEphSecret is the initiator's, held between HS_RES and HS_FINISH.
            The other three are the responder's, and exist so a duplicate
            HS_RES can be answered with the identical HS_FINISH rather than
            re-keyed: the responder cannot re-derive its old answer once its
            secret is gone, and the initiator cannot accept a re-key once its
            own is gone either. hsPeerEph is what tells the two apart. */
        common::crypto::SecretKey hsEphSecret;
        common::crypto::PublicKey hsPeerEph;    ///< initiator's ephemeral, as accepted
        common::crypto::PublicKey hsEphPub;     ///< our ephemeral, to repeat the answer
        uint8_t hsConfirm[internal::WIRE_HS_MAC_SIZE];

        /** Packets queued before the handshake finished, as an intrusive list
            in the socket's pending pool: each slot holds the next index, so the
            peer keeps only the ends. UINT32_MAX (SlotPool::INVALID) means empty;
            head == tail is one packet. */
        uint32_t pendingHead;
        uint32_t pendingTail;

        /** Liveness, in SeenStamp units. firstSeenAt is set once at
            registration. lastSeenAt refreshes only on packets RECEIVED from the
            peer (our own sends say nothing about the remote), lazily on the
            configured grain, and drives idle eviction. */
        uint32_t firstSeenAt;
        uint32_t lastSeenAt;

        /** Per-peer congestion control: the budget of unacked flow bytes we may
            keep on the path, plus the state that sizes it. None of it goes on
            the wire, and only flow packets spend the budget (the non-flow tier
            is untracked).

            @pre Read and written under the slot write lock, like sendCounter. */
        uint32_t congestionBudget;        ///< ceiling on in-flight flow bytes
        uint32_t bytesInFlight;           ///< flow bytes sent, not yet resolved

        /** Recv slots this remote said it will hold for us at once. Bounds what
            we may leave outstanding to it, alongside the congestion window.
            Zero means it has named no limit. */
        uint32_t theirGrant;

        /** Packets sent to this remote that it has not yet resolved. Compared
            against theirGrant, so this side stops sending what the far side
            would only throw away.

            An estimate rather than the truth. It cannot see what the remote has
            delivered but its application has not polled, so it reads low. The
            remote's own enforcement is authoritative and this only spares the
            bandwidth of sending into a refusal. */
        uint32_t outstandingToPeer;

        /** Generation of the newest grant applied from this remote, so an op
            that arrives out of order is ignored rather than undoing a newer
            one. */
        uint32_t theirGrantGeneration;

        /** Generation of the last grant this side sent, incremented when the
            value changes so the remote can order them. */
        uint32_t ourGrantGeneration;

        /** Set while this peer still owes us an acknowledgement for our current
            grant. Raised when a session commits and again whenever the value
            changes, cleared by an ack naming ourGrantGeneration. The tick
            resends while it is set, which is what makes an announcement
            survive a lost packet. */
        bool grantSendPending;

        /** When the pending grant last went out. The tick paces the resend
            against this, because a flag alone would put one op on the wire per
            tick for as long as the ack takes. Zero sends at the first
            opportunity. */
        uint64_t grantSentAtMicros;

        uint32_t slowStartThreshold;      ///< below it the budget doubles per round-trip;
                                          ///< at or above, the curve decides

        /** The budget this peer held when congestion was last detected, and
            when that happened. The curve climbs back toward the first as a
            function of time since the second, which is what makes recovery
            independent of how long the path is. */
        uint32_t wMaxBytes;
        uint64_t congestionEpochMicros;

        /** Which congestion event the packets now in flight belong to.
            Incremented on every reaction, and stamped onto each packet as it is
            sent, so a loss reported afterwards can be told apart: one carrying
            an older epoch was already on the path when we reacted and is part
            of the event we already answered, while one carrying the current
            epoch left after it and is news. Bounds the reaction to one per
            event exactly, where a clock could only ever approximate it. */
        uint8_t congestionEpoch;

        /** The path to this peer, and the deadline built from it. Every flow
            to this peer shares it, because they all cross the same wire. */
        internal::RttEstimate rtt;

        HandshakeState state;
        uint8_t attempts;      ///< handshake attempts so far; retry policy is the caller's
        bool    hasId;         ///< id is only meaningful once the handshake proves it
        bool    authenticated; ///< announced tag matched a trusted certificate AND the
                               ///< peer proved it owns that certificate's key

        /** Whether a packet from this peer has ever opened under the session
            key. A responder establishes from HS_RES alone, and nothing in that
            message is authenticated, so until this is set the identity bound
            here is only what the message claimed. */
        bool    confirmed;

        /** Pacing. `pacingTokens` is how many bytes may still leave right now,
            topped up from the rate since `pacingRefilledAt` and capped at a
            small burst. Zero tokens with a live round-trip sample is the gate
            saying wait, not saying no: the packet goes to a flow's waiting ring
            and the tick releases it when the clock has caught up.

            Untouched until a round trip has been measured, since there is no
            rate to pace at before that. */
        uint32_t pacingTokens;
        uint64_t pacingRefilledAt;

        /** An event about this peer has been recorded and nobody has read it
            yet. Removal leaves the slot leased while it is set, so a later peer
            cannot land on the entry the event is sitting in, and whoever
            delivers it releases the slot instead. `freeWhenRead` is how the
            deferred removal is remembered, since unlike an association there is
            no lifecycle value already meaning it. Both written under this
            peer's write lock. */
        bool emitting;
        bool freeWhenRead;

        bool IsValid() const { return state == HandshakeState::ESTABLISHED; }
    };

    static_assert(std::is_trivially_copyable_v<Peer>,
                  "Peer is stored in a SlotPool by raw cast, so it must stay trivially copyable");
}
