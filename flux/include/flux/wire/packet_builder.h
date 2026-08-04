#pragma once

#include <cstdint>
#include <utility>

#include <common/error.h>
#include <flux/flow/flow.h>
#include <flux/socket/packet_slot.h>

namespace bcp::flux
{
    class Socket;
    class SocketSender;
    struct Address;
    class FlowHandle;
}

namespace bcp::flux::wire
{
    class PacketContentStage
    {
    private:
        SocketSender* sender_ = nullptr;
        PacketSlotWriter writer_;

        Address respondTo_{};   ///< Reply target; set only on a PrepareResponse chain.

        common::Error failReason_{common::Error::Ok}; ///< Set only if construction or an action failed.
        bool failed_{false};

        /** Records the first failure and keeps it.

            A chain reports one reason at the end, and the useful one is what
            went wrong first: everything after it is a consequence. A later
            overflow must not overwrite the reason a builder was already dead. */
        void Fail(common::Error reason) noexcept
        {
            if (failed_) return;
            failed_     = true;
            failReason_ = reason;
        }

    public:
        explicit PacketContentStage(SocketSender& sender, PacketSlotWriter writer,
                                    Address respondTo = {}) :
                sender_(&sender), writer_(std::move(writer)), respondTo_(respondTo) {}

        /** The stage a failed builder hands back: holds no slot, refuses to
            send, and reports why. */
        explicit PacketContentStage(common::Error failReason) :
                writer_(PacketSlotHandle::Invalid()),
                failReason_(failReason), failed_(true) {}

        PacketContentStage& PutU8(uint8_t in);
        PacketContentStage& PutU16(uint16_t in);
        PacketContentStage& PutU32(uint32_t in);
        PacketContentStage& PutU64(uint64_t in);
        PacketContentStage& PutBytes(const uint8_t* data, size_t len);

        /** Best-effort delivery: authenticated when the peer is, opportunistic
            otherwise.

            The socket keeps a route to the peer alive (handshaking on first
            contact, surviving address changes, revalidating a moved path while
            packets keep arriving), but makes no per-packet promise. A packet
            lost to ordinary drop stays lost, and a route the network refuses
            to validate stalls rather than being guessed at. Per-packet
            reliability and liveness of a silent route belong to reliable
            flows. */
        common::Error Send(Address address);

        /** Delivered only to a peer authenticated against a trusted
            certificate. NotAuthenticated if the peer is established but
            unauthenticated; a packet parked behind a fresh handshake is
            dropped at flush time unless the peer comes out authenticated. */
        common::Error SendSecured(Address address);

        /** Sends to the source of the packet this chain replies to, with the
            same contract as Send(Address). The address rides the chain from
            PacketSlotHandle::PrepareResponse, so a reply never rebuilds the
            pairing by hand. InvalidState on a chain that did not start
            there. */
        common::Error Respond();

        /** Respond(), delivered only to an authenticated peer: the
            SendSecured(Address) contract on the carried address. */
        common::Error RespondSecured();
    };

    /** Declares what kind of packet this is, then hands over a writer for the
        payload. The declaration comes first because it decides which pool the
        packet body is written into, and that cannot change once the app
        starts writing.

        A reliable flow's body must survive being sent (it is the retransmit
        source, re-encrypted under a fresh counter if the packet is lost), so
        it goes into a retained staging slot. Everything else (unreliable
        flows, non-flow traffic) goes into a kernel send slot, encrypted in
        place, and released the moment it is on the wire. No slot is acquired
        until NoFlow/WithFlow says which of the two this is. */
    class PacketBuilder
    {
    public:
        /** How a packet is protected. One setting rather than a flag per level,
            so asking for two is a conflict the builder can see instead of an
            order-dependent outcome. Selected through Unsecured or MacOnly, not
            by naming this. */
        enum class Security : uint8_t
        {
            Encrypted,   ///< default: payload is ciphertext, tag covers it
            MacOnly,     ///< payload readable, tag still covers it
            Unsecured,   ///< no tag, no nonce, no protection of any kind
        };

    private:
        /** PrepareResponse aims the builder it mints at the received packet's
            source. Private, so aiming stays that path's job alone and every
            other chain ends in Send(Address) as it always has. */
        friend class bcp::flux::PacketSlotHandle;

    private:
        Socket*       socket_ = nullptr;
        SocketSender* sender_ = nullptr;

        Address respondTo_{};  ///< Reply target on a PrepareResponse chain.

        common::Error failReason_;

        Security security_{Security::Encrypted};
        bool     securityChosen_{false};   ///< a second, different choice conflicts

        bool tagged_{false};   ///< Socket-migration setting: secure packets
                               ///< carry the 4-byte peer tag.
        bool spent_{false};    ///< the first Put takes the slot; a second chain
                               ///< off the same builder has none to give.

        /** What NoFlow or WithFlow recorded. Nothing is acquired when they are
            called, so anything else the packet needs can still be declared
            afterwards and the order stops mattering. */
        enum class Target : uint8_t { Unset, NoFlow, Flow };
        Target            target_{Target::Unset};
        const FlowHandle* flow_{nullptr};   ///< borrowed for the chain only
        FlowPart          part_{FlowPart::Whole};

        void Aim(const Address& target) { respondTo_ = target; }

        /** Takes the slot, writes the header, and hands over the writer. Called
            by the first Put, or by a Send that had nothing to put. */
        PacketContentStage Begin();

    public:
        explicit PacketBuilder(Socket& socket, SocketSender& sender,
                               bool tagged = false)
        : socket_(&socket), sender_(&sender),
          failReason_(common::Error::Ok), tagged_(tagged) {}

        /** The builder a handle without a socket hands back: NoFlow and
            WithFlow yield a stage that refuses to send, carrying the reason. */
        explicit PacketBuilder(common::Error failReason)
        : failReason_(failReason) {}

        /** One chain, one packet. The builder borrows the flow handle until the
            first Put takes a slot, and a copy would either duplicate that
            borrow or quietly carry a builder whose slot is already spent. */
        PacketBuilder(const PacketBuilder&)            = delete;
        PacketBuilder& operator=(const PacketBuilder&) = delete;
        PacketBuilder(PacketBuilder&&)                 = default;

        /** Opts this packet out of encryption and authentication entirely: on
            the wire in plaintext with no tag, and any party can forge or alter
            one. Cannot carry a flow, because a forged packet could then name
            any sequence number it liked and poison the receiver's ordering. */
        PacketBuilder& Unsecured();

        /** Readable on the wire, but not alterable. The payload is sent as it
            is and the tag still covers the whole packet, so anyone can read it
            and nobody without the key can change a byte of it.

            Roughly half the crypto cost of encrypting, and the same bytes on
            the wire, so it buys CPU rather than space. For traffic that is
            public anyway and sent often, which on a game server is most of the
            state replication.

            Composes with every flow mode. The sequence number is inside the
            authenticated range, so ordering and acknowledgement stay
            trustworthy even though they are readable. */
        PacketBuilder& MacOnly();

        /** Traffic outside any flow: no sequence number, no acknowledgement,
            no retransmission. The cheapest packet Flux sends. */
        PacketBuilder& NoFlow();

        /** Traffic on `flow`, which must be OPEN. The packet carries the
            flow's id and its next sequence number, both stamped at send time;
            a reliable flow additionally retains the body for retransmission.
            A failed or stale handle, or a flow not yet OPEN, yields a stage
            that refuses to send.

            `part` places the packet in a message spanning several of them, and
            defaults to a message of one, which is what every send that does not
            care about framing already is. Anything else needs
            RELIABLE_ORDERED, since ordered delivery is what lets two bits carry
            the framing, and yields a refusing stage on the other modes.

            The transport never assembles the run. It carries the framing and
            the receiver reads it off each packet, so a message has no size
            limit and nothing is allocated to hold one. */
        PacketBuilder& WithFlow(const FlowHandle& flow,
                                FlowPart part = FlowPart::Whole);

        /** The first of these takes the slot and writes the header, so
            everything the packet needs must be declared before it. `flow` is
            borrowed until then, which one chained expression always satisfies.

            After the first, the stage owns the writer and the rest of the Puts
            are its own. */
        PacketContentStage PutU8(uint8_t in);
        PacketContentStage PutU16(uint16_t in);
        PacketContentStage PutU32(uint32_t in);
        PacketContentStage PutU64(uint64_t in);
        PacketContentStage PutBytes(const uint8_t* data, size_t len);

        /** A packet with no payload still has to be built before it can go. */
        common::Error Send(Address address);
        common::Error SendSecured(Address address);
        common::Error Respond();
        common::Error RespondSecured();

        inline bool Failed()
        {
            return failReason_ != common::Error::Ok;
        }
    };
}