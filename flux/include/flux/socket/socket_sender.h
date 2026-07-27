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
            at flush time unless the peer came out authenticated. */
        common::Error Send (PacketSlotHandle pHandle, bool requireAuth = false);
    };
}