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
#include <flux/platform.h>
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

        /** One datagram in a batch send. Points at the caller's bytes and does
            not own them, so the caller keeps every slot alive until SendBatch
            returns. */
        struct Outgoing
        {
            const sockaddr_storage* target;
            const uint8_t*          data;
            uint16_t                size;
        };

        /** Sends several datagrams with as few trips into the kernel as the
            platform allows.

            Linux takes the whole array in one sendmmsg. Everywhere else this is
            a loop over SendTo, which is what those platforms did anyway, so the
            caller sees one behaviour and one cost model either way.

            Best effort per datagram, like SendTo: a failure on one does not
            stop the rest, because the alternative is a single bad address
            holding up every other peer in the batch.

            @return how many left the machine. Less than `count` means the
                    remainder failed, and they are the ones at the end. */
        [[nodiscard]] virtual uint32_t SendBatch(const Outgoing* items,
                                                 uint32_t count) = 0;

        /** Fills outPackets with pointers into socket-owned memory. */
        [[nodiscard]] virtual common::Result<uint32_t> ReceiveFrom
        (
            PacketSlotHandle* outPackets, 
            uint32_t maxCount
        ) = 0;

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
    };
}