#include <flux/socket/socket_sender.h>
#include <flux/socket/socket.h>
#include <flux/socket/i_socket_kernel.h>
#include <flux/socket/packet_slot.h>

namespace bcp::flux
{
    common::Error SocketSender::Init(Socket* socket, ISocketKernel* socketKernel)
    {
        sock_ = socket;
        sockKernel_ = socketKernel;
        return common::Error::Ok;
    }

    common::Error SocketSender::Send(PacketSlotHandle pHandle, bool requireAuth)
    {
        // A flow packet is a message for its flow's open batch, and only the
        // batch reaches the wire. Anything the batch cannot take right now, a
        // peer still handshaking or a flow with no association yet, falls
        // through and goes out on its own as it always did.
        common::Error status = common::Error::Ok;
        if (sock_->OfferToBatch(pHandle, requireAuth, status))
            return status;

        return SendNow(std::move(pHandle), requireAuth);
    }

    common::Error SocketSender::SendNow(PacketSlotHandle pHandle, bool requireAuth)
    {
        common::Error status = common::Error::Ok;
        pHandle = sock_->PreProcessOut(std::move(pHandle), status, requireAuth);

        const PacketSlot* packet = pHandle.Read();
        if (!packet)
            return status;   // Ok = accepted and parked behind a handshake

        return sockKernel_->SendTo(packet->address.addr, packet->data, packet->dataSize);
    }
}