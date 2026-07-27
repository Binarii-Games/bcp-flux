#pragma once

// Raw UDP sockets for middlebox tests. Some tests interpose a relay between two
// Flux sockets to simulate a hostile or lossy network — an address change
// (migration) or packet reordering (flows). Those relays are built from bare OS
// sockets, and this is that layer: create a bound non-blocking UDP socket, send
// a datagram, and classify one by its cleartext controller byte the way any
// on-path observer could. The Flux-socket scaffolding is one layer up, in
// flux_net.h.
#include <common/platform.h>   // OS socket headers, incl. Winsock on Windows

#include <cstdint>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#include <flux/address.h>

namespace udp_raw
{
#ifdef _WIN32
    using Socket = SOCKET;
    inline bool Bad(Socket fd)   { return fd == INVALID_SOCKET; }
    inline void Close(Socket fd) { closesocket(fd); }
#else
    using Socket = int;
    inline bool Bad(Socket fd)   { return fd < 0; }
    inline void Close(Socket fd) { ::close(fd); }
#endif

    // A non-blocking UDP socket bound to `port` on the loopback interface.
    inline Socket MakeBound(uint16_t port)
    {
        Socket fd = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (Bad(fd)) return fd;
        int off = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&off), sizeof(off));
#ifdef _WIN32
        u_long nonBlocking = 1; ioctlsocket(fd, FIONBIO, &nonBlocking);
#else
        int flags = fcntl(fd, F_GETFL, 0); fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port   = htons(port);
        addr.sin6_addr   = in6addr_any;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) { Close(fd); return static_cast<Socket>(-1); }
        return fd;
    }

    inline void SendTo(Socket fd, const uint8_t* data, int len, const bcp::flux::Address& to)
    {
        const sockaddr_storage& storage = to;
        ::sendto(fd, reinterpret_cast<const char*>(data), len, 0,
                 reinterpret_cast<const sockaddr*>(&storage), sizeof(sockaddr_in6));
    }

    // Controller-byte bits, mirrored from the wire so a relay can classify a
    // datagram (handshake vs secure) exactly as any on-path observer could.
    inline constexpr uint8_t BIT_INTERNAL = 0x01;
    inline constexpr uint8_t BIT_UNSECURE = 0x04;
    inline bool IsHandshake(const uint8_t* bytes, int n) { return n >= 1 && (bytes[0] & BIT_INTERNAL) && (bytes[0] & BIT_UNSECURE); }
    inline bool IsSecure(const uint8_t* bytes, int n)    { return n >= 1 && !(bytes[0] & BIT_UNSECURE); }
}
