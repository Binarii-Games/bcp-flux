#pragma once

#include <cstdint>
#include <utility>

#include <common/error.h>
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
        /** PrepareResponse aims the builder it mints at the received packet's
            source. Private, so aiming stays that path's job alone and every
            other chain ends in Send(Address) as it always has. */
        friend class bcp::flux::PacketSlotHandle;

    private:
        Socket*       socket_ = nullptr;
        SocketSender* sender_ = nullptr;

        Address respondTo_{};  ///< Reply target on a PrepareResponse chain.

        common::Error failReason_;
        bool secure_{true};
        bool tagged_{false};   ///< Socket-migration setting: secure packets
                               ///< carry the 4-byte peer tag.
        bool spent_{false};    ///< NoFlow/WithFlow are one-shot: the second
                               ///< call has no slot to give.

        void Aim(const Address& target) { respondTo_ = target; }

    public:
        explicit PacketBuilder(Socket& socket, SocketSender& sender,
                               bool tagged = false)
        : socket_(&socket), sender_(&sender),
          failReason_(common::Error::Ok), tagged_(tagged) {}

        /** The builder a handle without a socket hands back: NoFlow and
            WithFlow yield a stage that refuses to send, carrying the reason. */
        explicit PacketBuilder(common::Error failReason)
        : failReason_(failReason) {}

        /** Opts this packet out of encryption and authentication: it goes on
            the wire in plaintext with no tag, and any party can forge or
            alter one. Encrypted is the default; call this before
            NoFlow/WithFlow. */
        PacketBuilder& Unsecured();

        /** Traffic outside any flow: no sequence number, no acknowledgement,
            no retransmission. The cheapest packet Flux sends. */
        PacketContentStage NoFlow();

        /** Traffic on `flow`, which must be OPEN. The packet carries the
            flow's id and its next sequence number, both stamped at send time;
            a reliable flow additionally retains the body for retransmission.
            A failed or stale handle, or a flow not yet OPEN, yields a stage
            that refuses to send. */
        PacketContentStage WithFlow(const FlowHandle& flow);

        inline bool Failed()
        {
            return failReason_ != common::Error::Ok;
        }
    };
}