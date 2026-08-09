// --- win_socket.h ---

#pragma once

#include <flux/platform.h>
#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>

#include <flux/socket/i_socket_kernel.h>

#include <common/error.h>
#include <common/result.h>
#include <common/collections/slot_pool.h>

namespace bcp::flux::platform {

    /** Standard Windows UDP socket using recvfrom/sendto.

        Non-blocking, no threads: the caller drives receives via ReceiveFrom.
        SlotPool manages receive buffers. */
    class WinSocket : public ISocketKernel {
    private:
        SOCKET handle_ = INVALID_SOCKET;

        static constexpr size_t WINDOW_HEADER_SIZE = sizeof(PacketSlot);

    public:
        WinSocket() = default;
        ~WinSocket() override { Close(); }

        [[nodiscard]] common::Error Init(int port, uint32_t recvSlotCount = 4096, uint32_t sendSlotCount = 4096) override;
        void Close() override;

        [[nodiscard]] uint32_t SendBatch(const Outgoing* items, uint32_t count) override;

        [[nodiscard]] common::Error SendTo(const sockaddr_storage& target, const uint8_t* data, uint16_t size) override;
        [[nodiscard]] common::Result<uint32_t> ReceiveFrom(PacketSlotHandle* outPackets, uint32_t maxCount) override;


    private:
        PacketSlot* GetRecvSlot(uint32_t slotIndex);
        uint32_t GetSlotIndexFromPtr(const uint8_t* address);
    };
}

#endif