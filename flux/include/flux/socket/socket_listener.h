#pragma once

#include <cstdint>
#include <array>

#include <common/error.h>
#include <common/collections/fifo_queue.h>
#include <flux/socket/i_socket_kernel.h>
#include <flux/socket/packet_slot.h>

namespace bcp::flux
{
    class SocketListener
    {
    private:
        ISocketKernel* sockKernel_ = nullptr;

    public:
        SocketListener() = default;
        
        [[nodiscard]] common::Error Init(ISocketKernel* packetSource);
        uint32_t Poll(PacketSlotHandle* out, size_t max);
    };
}