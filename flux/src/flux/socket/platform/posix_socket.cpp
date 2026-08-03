// --- posix_socket.cpp ---

#ifndef _WIN32
#include <flux/socket/platform/posix_socket.h>

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#include <flux/internal/constants.h>
#include <common/log.h>

namespace bcp::flux::platform {

    common::Error PosixSocket::Init(int port, uint32_t recvSlotCount, uint32_t sendSlotCount)
    {
        // AF_INET6 + SOCK_DGRAM = one UDP socket. IPV6_V6ONLY off makes it
        // dual-stack: IPv4 senders arrive as ::ffff:a.b.c.d mapped addresses,
        // the single form the rest of the codebase uses (ResolveAddress
        // produces the same mapping on the send side).
        handle_ = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (handle_ < 0) return common::Error::IoFailed;

        int optTrue  = 1;
        int optFalse = 0;
        // 8 MB kernel buffers: at ~1400 B per datagram that is ~6000 packets
        // of headroom between Pump calls before the OS starts dropping.
        // Best-effort like the Windows side. The OS may clamp (Linux caps at
        // net.core.rmem_max), and a smaller buffer only means earlier drops.
        int bufSize = 8 * 1024 * 1024;
        setsockopt(handle_, SOL_SOCKET,   SO_RCVBUF,    &bufSize,  sizeof(bufSize));
        setsockopt(handle_, SOL_SOCKET,   SO_SNDBUF,    &bufSize,  sizeof(bufSize));
        setsockopt(handle_, IPPROTO_IPV6, IPV6_V6ONLY,  &optFalse, sizeof(optFalse));
        setsockopt(handle_, SOL_SOCKET,   SO_REUSEADDR, &optTrue,  sizeof(optTrue));

        // Non-blocking lets ReceiveFrom drain-and-return instead of stalling
        // the polling thread: recvfrom on an empty socket fails with
        // EWOULDBLOCK immediately rather than sleeping. POSIX sets it as a
        // descriptor flag via fcntl (read-modify-write to preserve other
        // flags); Windows expresses the same bit via ioctlsocket(FIONBIO).
        const int flags = fcntl(handle_, F_GETFL, 0);
        if (flags < 0 || fcntl(handle_, F_SETFL, flags | O_NONBLOCK) < 0)
        {
            Close();
            return common::Error::IoFailed;
        }

        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port   = htons(static_cast<uint16_t>(port));
        addr.sin6_addr   = in6addr_any;
        if (::bind(handle_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
        {
            Close();
            return common::Error::BindFailed;
        }

        uint32_t stride = WINDOW_HEADER_SIZE + internal::MAX_WIRE_PACKET_SIZE;
        stride = (stride + 15) & ~15u;

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

    void PosixSocket::Close()
    {
        if (handle_ >= 0)
        {
            ::close(handle_);
            handle_ = -1;
        }
        recvSlotPool_.Shutdown();
        sendSlotPool_.Shutdown();
    }

    uint32_t PosixSocket::SendBatch(const Outgoing* items, uint32_t count)
    {
        if (handle_ < 0 || count == 0) return 0;

#if defined(__linux__)
        // One trip into the kernel for the whole array. Linux reports how many
        // it accepted and stops at the first refusal, so the loop below picks
        // up from there rather than assuming all or nothing.
        uint32_t done = 0;
        while (done < count)
        {
            constexpr uint32_t MAX_PER_CALL = 64;
            const uint32_t take = (count - done) < MAX_PER_CALL
                                ? (count - done) : MAX_PER_CALL;

            mmsghdr msgs[MAX_PER_CALL]{};
            iovec   iov [MAX_PER_CALL]{};
            for (uint32_t i = 0; i < take; ++i)
            {
                const Outgoing& item = items[done + i];
                iov[i].iov_base = const_cast<uint8_t*>(item.data);
                iov[i].iov_len  = item.size;
                msgs[i].msg_hdr.msg_name    = const_cast<sockaddr_storage*>(item.target);
                msgs[i].msg_hdr.msg_namelen = item.target->ss_family == AF_INET
                    ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
                msgs[i].msg_hdr.msg_iov     = &iov[i];
                msgs[i].msg_hdr.msg_iovlen  = 1;
            }

            const int sent = ::sendmmsg(handle_, msgs, take, 0);
            if (sent <= 0)
            {
                common::LogF(common::LogLevel::Error,
                             "PosixSocket sendmmsg failed: %s (errno %d)",
                             std::strerror(errno), errno);
                break;
            }
            done += static_cast<uint32_t>(sent);
            // A short count is the kernel refusing the next one, so stop rather
            // than spinning on the same datagram.
            if (static_cast<uint32_t>(sent) < take) break;
        }
        return done;
#else
        // No sendmmsg here, so this is the loop these platforms already ran.
        // Same syscalls in the same order, reached through one call.
        uint32_t done = 0;
        for (uint32_t i = 0; i < count; ++i)
        {
            if (SendTo(*items[i].target, items[i].data, items[i].size)
                != common::Error::Ok) break;
            ++done;
        }
        return done;
#endif
    }

    common::Error PosixSocket::SendTo(const sockaddr_storage& dest, const uint8_t* data, uint16_t size)
    {
        if (handle_ < 0) return common::Error::IoFailed;
        if (size > internal::MAX_WIRE_PACKET_SIZE) return common::Error::TooLarge;

        // The kernel wants the exact sockaddr size for the family, not
        // sizeof(sockaddr_storage); some stacks reject the padded length.
        const socklen_t destLen = (dest.ss_family == AF_INET)
            ? sizeof(sockaddr_in)
            : sizeof(sockaddr_in6);

        const ssize_t result = ::sendto(handle_, data, size, 0,
                                        reinterpret_cast<const sockaddr*>(&dest), destLen);

        if (result < 0)
        {
            common::LogF(common::LogLevel::Error,
                         "PosixSocket sendto failed: %s (errno %d), address family: %d",
                         std::strerror(errno), errno, dest.ss_family);
        }

        return (result > 0) ? common::Error::Ok : common::Error::SendFailed;
    }

    /** Drains all available packets from the kernel buffer in one call.
        Non-blocking: returns immediately when no more data is available. */
    common::Result<uint32_t> PosixSocket::ReceiveFrom(PacketSlotHandle* outPackets, uint32_t maxCount)
    {
        if (handle_ < 0)
            return common::Result<uint32_t>::Fail(common::Error::IoFailed);

        uint32_t count = 0;

        while (count < maxCount)
        {
            const uint32_t slotIdx = recvSlotPool_.Acquire();
            if (slotIdx == common::collections::SlotPool::INVALID)
                break;

            PacketSlotHandle h = {slotIdx, &recvSlotPool_};
            PacketSlot* recvSlot = h.Write();
            socklen_t addrLen = sizeof(sockaddr_storage);

            const ssize_t bytes = ::recvfrom(
                handle_,
                recvSlot->data,
                internal::MAX_WIRE_PACKET_SIZE,
                0,
                reinterpret_cast<sockaddr*>(&recvSlot->address.addr),
                &addrLen
            );

            // <= 0 covers both "socket empty" (EWOULDBLOCK, the normal exit)
            // and real errors; either way there is nothing more this call. The
            // just-acquired slot goes back via h's destructor.
            if (bytes <= 0)
                break;

            recvSlot->dataSize = static_cast<uint16_t>(bytes);

            outPackets[count++] = std::move(h);
        }

        return common::Result<uint32_t>::Success(count);
    }

    uint32_t PosixSocket::GetSlotIndexFromPtr(const uint8_t* address)
    {
        const uintptr_t base   = reinterpret_cast<uintptr_t>(recvSlotPool_.GetSlotPtr(0));
        const uintptr_t offset = reinterpret_cast<uintptr_t>(address) - base;
        return static_cast<uint32_t>(offset / recvSlotPool_.GetStride());
    }
}

#endif
