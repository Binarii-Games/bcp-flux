#pragma once

#include <cstdint>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
#endif

#include <common/error.h>
#include <common/result.h>
#include <common/platform.h>
#include <common/collections/slot_pool.h>

#include <flux/socket/packet_slot.h>


namespace bcp::flux 
{              
    namespace wire { class PacketBuilder; }

    /** Platform-agnostic UDP socket interface.
        Implementations own the memory. */
    class ISocketKernel 
    {
    protected:
        common::collections::SlotPool recvSlotPool_;
        common::collections::SlotPool sendSlotPool_;
    public:
        virtual ~ISocketKernel() = default;

        [[nodiscard]] virtual common::Error Init(int port, uint32_t recvSlotCount = 4096, uint32_t sendSlotCount = 4096) = 0;
        virtual void Close() = 0;

        /** Copies data into internal buffer and sends. Caller keeps ownership of data. */
        [[nodiscard]] virtual common::Error SendTo
        (
            const sockaddr_storage& target, 
            const uint8_t* data, 
            uint16_t size
        ) = 0;

        /** Fills outPackets with pointers into socket-owned memory. */
        [[nodiscard]] virtual common::Result<uint32_t> ReceiveFrom
        (
            PacketSlotHandle* outPackets, 
            uint32_t maxCount
        ) = 0;

        /** Returns packets to the socket. */
        virtual void ReleasePacket
        (
            uint8_t** addresses, 
            uint32_t count
        ) = 0;

        virtual uint8_t* GetBufferBase() = 0;
        virtual uint32_t GetBufferSize() = 0;

        /** Pool every received packet is leased from. The flow receive path
            parks out-of-order packets by bare slot index (hold-back) and needs
            this to rebuild a handle at delivery time. Stable for the kernel's
            life; cached once at Init. */
        common::collections::SlotPool* GetRecvPool() { return &recvSlotPool_; }

        /** Pool outgoing packets are written into. The flow send path parks an
            over-budget unreliable body by bare slot index (the waiting ring)
            and needs this to rebuild a handle over it, or release it, at drain
            time. Stable for the kernel's life; cached once at Init. */
        common::collections::SlotPool* GetSendPool() { return &sendSlotPool_; }

        common::Result<PacketSlotWriter> Write();
        void Unlock(uint32_t idx);

    protected:
        common::Result<PacketSlotHandle> PopPacketHandle();
    };
}