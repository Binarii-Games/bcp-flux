// --- posix_socket.h ---

#pragma once
#ifndef _WIN32

#include <cstdint>

#include <flux/socket/i_socket_kernel.h>

#include <common/error.h>
#include <common/result.h>
#include <common/collections/slot_pool.h>

namespace bcp::flux::platform {

    /** Standard POSIX UDP socket using recvfrom/sendto, the direct sibling of
        WinSocket. Covers macOS and Linux in one implementation because both
        speak the same Berkeley sockets API that Winsock descends from.

        Mechanism matches WinSocket: one dual-stack IPv6 datagram socket, set
        non-blocking so Pump-style callers never stall, receive buffers owned
        by a SlotPool. No threads; the caller drives receives via ReceiveFrom.

        What differs from WinSocket is plumbing, not design:
          handle        int fd, -1 invalid      vs  SOCKET, INVALID_SOCKET
          non-blocking  fcntl(O_NONBLOCK)       vs  ioctlsocket(FIONBIO)
          errors        errno                   vs  WSAGetLastError()
          teardown      close()                 vs  closesocket()
          addr length   socklen_t               vs  int
          startup       none                    vs  WSAStartup once per process */
    class PosixSocket : public ISocketKernel {
    private:
        int handle_ = -1;

        static constexpr size_t WINDOW_HEADER_SIZE = sizeof(PacketSlot);

    public:
        PosixSocket() = default;
        ~PosixSocket() override { Close(); }

        [[nodiscard]] common::Error Init(int port, uint32_t recvSlotCount = 4096, uint32_t sendSlotCount = 4096) override;
        void Close() override;

        [[nodiscard]] common::Error SendTo(const sockaddr_storage& target, const uint8_t* data, uint16_t size) override;
        [[nodiscard]] common::Result<uint32_t> ReceiveFrom(PacketSlotHandle* outPackets, uint32_t maxCount) override;
        void ReleasePacket(uint8_t** addresses, uint32_t count) override;

        uint8_t* GetBufferBase() override { return nullptr; }
        uint32_t GetBufferSize() override { return 0; }

    private:
        uint32_t GetSlotIndexFromPtr(const uint8_t* address);
    };
}

#endif
