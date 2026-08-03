// --- win_socket.cpp ---

#ifdef _WIN32
#include <flux/socket/platform/win_socket.h>

#include <string>

#include <flux/internal/constants.h>
#include <common/log.h>

namespace bcp::flux::platform {
    
    common::Error WinSocket::Init(int port, uint32_t recvSlotCount, uint32_t sendSlotCount) 
    {
        handle_ = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (handle_ == INVALID_SOCKET) return common::Error::IoFailed;

        int optTrue = 1;
        int optFalse = 0;
        int bufSize = 8 * 1024 * 1024;
        setsockopt(handle_, SOL_SOCKET, SO_RCVBUF, (char*)&bufSize, sizeof(bufSize));
        setsockopt(handle_, SOL_SOCKET, SO_SNDBUF, (char*)&bufSize, sizeof(bufSize));
        setsockopt(handle_, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&optFalse, sizeof(optFalse));
        setsockopt(handle_, SOL_SOCKET, SO_REUSEADDR, (char*)&optTrue, sizeof(optTrue));

        u_long mode = 1;
        if (ioctlsocket(handle_, FIONBIO, &mode) != 0) 
        {
            Close();
            return common::Error::IoFailed;
        }

        sockaddr_in6 addr = {};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(static_cast<u_short>(port));
        addr.sin6_addr = in6addr_any;
        if (bind(handle_, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) 
        {
            Close();
            return common::Error::BindFailed;
        }

        uint32_t stride = WINDOW_HEADER_SIZE + internal::MAX_WIRE_PACKET_SIZE;
        stride = (stride + 15) & ~15;

        if (!recvSlotPool_.Init(recvSlotCount, stride)) 
        {
            Close();
            return common::Error::AllocFailed;
        }

        if (!sendSlotPool_.Init(sendSlotCount, stride))
        {
            Close();
            return common::Error::AllocFailed;
        }

        return common::Error::Ok;
    }

    void WinSocket::Close() 
    {
        if (handle_ != INVALID_SOCKET) 
        {
            closesocket(handle_);
            handle_ = INVALID_SOCKET;
        }
        recvSlotPool_.Shutdown();
        sendSlotPool_.Shutdown();
    }

    common::Error WinSocket::SendTo(const sockaddr_storage& dest, const uint8_t* data, uint16_t size) 
    {
        if (handle_ == INVALID_SOCKET) return common::Error::IoFailed;
        if (size > internal::MAX_WIRE_PACKET_SIZE) return common::Error::TooLarge;

        int destLen = (dest.ss_family == AF_INET)
            ? sizeof(sockaddr_in)
            : sizeof(sockaddr_in6);

        int result = sendto(handle_, (const char*)data, size, 0,
                            (const sockaddr*)&dest, destLen);

        if (result == SOCKET_ERROR) 
        {
            int errCode = WSAGetLastError();
            // raw address family, for debugging
            LogF(common::LogLevel::Error, "WinSocket sendto failed with error code: %d, address family: %d", errCode, dest.ss_family);
        }

        return (result > 0) ? common::Error::Ok : common::Error::SendFailed;
    }

    /** Drains all available packets from the kernel buffer in one call.
        Non-blocking, returns immediately when no more data is available. */
    common::Result<uint32_t> WinSocket::ReceiveFrom(PacketSlotHandle* outPackets, uint32_t maxCount) 
    {
        if (handle_ == INVALID_SOCKET)
            return common::Result<uint32_t>::Fail(common::Error::IoFailed);

        uint32_t count = 0;

        while (count < maxCount) 
        {
            // TODO: MSG_PEEK first to skip the Acquire when no data is waiting, saving atomic ops.
            uint32_t slotIdx = recvSlotPool_.Acquire();
            if (slotIdx == common::collections::SlotPool::INVALID)
                break;


            // PacketSlot used directly; not part of any multi-threaded queue yet.
            // PacketSlot* recvSlot = reinterpret_cast<PacketSlot*>(recvSlotPool_.WriteLock(slotIdx)); // Lock
            PacketSlotHandle h = {slotIdx, &recvSlotPool_};
            PacketSlot* recvSlot = h.Write();
            int addrLen = sizeof(sockaddr_storage);

            int bytes = recvfrom(
                handle_,
                (char*)recvSlot->data,
                internal::MAX_WIRE_PACKET_SIZE,
                0,
                (sockaddr*)&recvSlot->address.addr,
                &addrLen
            );

            if (bytes <= 0) 
                break;

            recvSlot->dataSize = static_cast<uint16_t>(bytes);

            outPackets[count++] = std::move(h);
        }

        return common::Result<uint32_t>::Success(count);
    }

    PacketSlot* WinSocket::GetRecvSlot(uint32_t slotIndex) 
    {
        return reinterpret_cast<PacketSlot*>(recvSlotPool_.GetSlotPtr(slotIndex));
    }

    uint32_t WinSocket::GetSlotIndexFromPtr(const uint8_t* address) 
    {
        uintptr_t base = reinterpret_cast<uintptr_t>(recvSlotPool_.GetSlotPtr(0));
        uintptr_t offset = reinterpret_cast<uintptr_t>(address) - base;
        return static_cast<uint32_t>(offset / recvSlotPool_.GetStride());
    }
}

#endif