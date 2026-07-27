#pragma once

// Shared scaffolding for tests and benches that drive real Flux sockets over
// the loopback interface. The platform boilerplate — which backend to use, and
// starting Winsock on Windows — lives here once so each test reads as the
// scenario it exercises, not as setup. All helpers are header-inline; every
// test binary links its own copy.
#include <common/platform.h>   // OS socket headers, incl. Winsock on Windows

#include <flux/socket/socket.h>
#include <flux/address.h>

#include <chrono>
#include <thread>

namespace flux_net
{
    // Native UDP backend per platform; on Windows, Winsock must be up first.
#ifdef _WIN32
    inline constexpr bcp::flux::Socket::BackendType BACKEND = bcp::flux::Socket::BackendType::STD_WIN;
    struct WinsockBoot { WinsockBoot() { WSADATA data; WSAStartup(MAKEWORD(2, 2), &data); } };
    inline WinsockBoot g_winsockBoot;
#else
    inline constexpr bcp::flux::Socket::BackendType BACKEND = bcp::flux::Socket::BackendType::STD_UNX;
#endif

    // A loopback address on the given UDP port.
    inline bcp::flux::Address Loopback(uint16_t port)
    {
        return bcp::flux::Address::From("::1", port).Take();
    }

    // True once `socket` holds an established, valid session with `addr`.
    inline bool Established(bcp::flux::Socket& socket, const bcp::flux::Address& addr)
    {
        bcp::flux::PeerHandle peer = socket.GetPeer(addr);
        return !peer.Failed() && peer.Read() && peer.Read()->IsValid();
    }

    // Pumps both sockets (processing and discarding any delivered packets) until
    // each has an established session with the other, or the budget runs out.
    // The caller triggers the handshake first (Connect or a Send). Returns true
    // when both sides are established.
    inline bool PumpUntilEstablished(bcp::flux::Socket& socketA, const bcp::flux::Address& addrA,
                                     bcp::flux::Socket& socketB, const bcp::flux::Address& addrB,
                                     int maxIterations = 200)
    {
        bcp::flux::PacketSlotHandle sink[64];
        for (int i = 0; i < maxIterations; ++i)
        {
            socketA.Poll(sink, 64);
            socketB.Poll(sink, 64);
            socketA.Update();
            socketB.Update();
            if (Established(socketA, addrB) && Established(socketB, addrA))
                return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return false;
    }
}
