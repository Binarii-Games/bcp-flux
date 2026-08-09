#pragma once

#include <common/error.h>

namespace bcp::flux
{
    class Socket;
    class ISocketKernel;
    class PacketSlotHandle;

    class SocketSender
    {
    private:
        Socket* sock_;
        ISocketKernel* sockKernel_;

    public:
        common::Error Init (Socket* socket, ISocketKernel* socketKernel);

        /** When requireAuth is set, the packet is deliverable only to a peer that
            authenticated against a trusted certificate. Refused on an unauthenticated
            established peer (NotAuthenticated); when parked behind a handshake, dropped
            at flush time unless the peer came out authenticated.

            A flow packet is offered to its flow's open batch first and only
            reaches the wire when that batch seals, so a caller must Flush for
            anything to leave. Everything else goes straight out. */
        [[nodiscard]] common::Error Send (PacketSlotHandle pHandle, bool requireAuth = false);

        /** Admits, seals and puts one packet on the wire, with no batching
            considered. This is the path a sealed batch takes, and going back
            through Send would offer it to the batch it just came out of. */
        [[nodiscard]] common::Error SendNow (PacketSlotHandle pHandle, bool requireAuth = false);

        /** Everything SendNow does except the send: takes the packet through
            the outbound gate and hands back the sealed wire slot.

            For a caller with several packets to put out that would rather give
            them to the kernel together. An invalid handle back means the packet
            was consumed on the way through, either parked behind a handshake or
            refused, and `status` says which. */
        [[nodiscard]] PacketSlotHandle SealForSend(PacketSlotHandle pHandle,
                                                   common::Error& status,
                                                   bool requireAuth = false);
    };
}