// A process that dies and restarts on the same address reconnects once its
// stale entry idles out. This is the reconnection path the confirmed-session
// re-key guard depends on: the server refuses a new handshake for an address it
// still holds a confirmed peer for (the newcomer does not hold the old session,
// and a confirmed peer is not re-keyed), so the newcomer waits until mandatory
// idle eviction reclaims the dead entry, after which a fresh handshake lands.
//
// The server uses a short idle timeout so the wait fits a test; the default is
// the same mechanism at 30 s. Real loopback UDP, so the address behaves as it
// would on a network. UBSan (ASan aborts on init on this toolchain).
#include <flux/socket/socket.h>
#include <flux/address.h>
#include <flux/wire/packet_builder.h>
#include <flux/socket/packet_slot.h>
#include <flux/flow/flow_handle.h>

#include "flux_net.h"
#include "harness.h"

#include <chrono>
#include <thread>

namespace flux   = bcp::flux;
namespace common = bcp::common;

namespace
{
    common::Error Init(flux::Socket& s, uint16_t port, uint32_t idleMicros)
    {
        flux::Socket::Config c{};
        c.type = flux_net::BACKEND;
        c.port = port;
        c.maxPeers = 8;
        c.pendingPacketCount = 64;
        c.flows.outCount = 4;
        c.flows.inCount  = 4;
        c.flows.stagingCount = 256;
        c.liveness.idleTimeoutMicros = idleMicros;   // 0 on the client, default
        return s.Init(c);
    }

    void Pump(flux::Socket& a, flux::Socket& b, int rounds)
    {
        flux::PacketSlotHandle sink[64];
        for (int i = 0; i < rounds; ++i)
        {
            a.Poll(sink, 64); b.Poll(sink, 64);
            a.Flush(); b.Flush();
            a.Update(); b.Update();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        for (auto& h : sink) h = flux::PacketSlotHandle::Invalid();
    }

    // Sends one value on a fresh flow and returns true once the server delivers
    // it. Also proves the server's peer is confirmed, since the packet opened
    // under the session key.
    bool SendAndReceive(flux::Socket& client, flux::Socket& server,
                        const flux::Address& serverAddr, uint32_t value)
    {
        flux::FlowHandle flow = client.OpenFlow(7, flux::FlowMode::RELIABLE_ORDERED);
        if (flow.Failed()) return false;
        if (client.BuildPacket().WithFlow(flow).PutU32(value).Send(serverAddr) != common::Error::Ok)
            return false;

        flux::PacketSlotHandle inbox[64];
        bool got = false;
        for (int i = 0; i < 500 && !got; ++i)
        {
            client.Flush(); server.Flush();
            client.Update(); server.Update();
            flux::PollCursor cursor = server.Poll(inbox, 64);
            while (cursor.Next())
            {
                flux::PacketSlotReader& r = cursor.Message();
                uint32_t v = 0;
                if (r.TakeU32(v) && v == value) got = true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        for (auto& h : inbox) h = flux::PacketSlotHandle::Invalid();
        return got;
    }
}

int main()
{
    const uint16_t CLIENT = 20960, SERVER = 20961;
    const flux::Address serverAddr = flux_net::Loopback(SERVER);
    const flux::Address clientAddr = flux_net::Loopback(CLIENT);
    constexpr uint32_t IDLE = 1'000'000;   // 1 s, so eviction fires well inside the run

    flux::Socket server;
    CHECK(Init(server, SERVER, IDLE) == common::Error::Ok);

    // The first process establishes and drives the server's peer to confirmed.
    {
        flux::Socket client1;
        CHECK(Init(client1, CLIENT, 0) == common::Error::Ok);
        CHECK(client1.Connect(serverAddr) == common::Error::Ok);
        CHECK(flux_net::PumpUntilEstablished(client1, clientAddr, server, serverAddr));
        CHECK(SendAndReceive(client1, server, serverAddr, 0xABCD));   // confirms the server peer
        CHECK(flux_net::Established(server, clientAddr));
        client1.Shutdown();   // the process dies
    }

    // A new process starts on the same address. Fresh identity, same port.
    flux::Socket client2;
    CHECK(Init(client2, CLIENT, 0) == common::Error::Ok);
    CHECK(client2.Connect(serverAddr) == common::Error::Ok);

    // While the server still holds the confirmed stale peer it refuses the new
    // handshake. Checked on a wall-clock bound comfortably under the idle
    // timeout, so eviction cannot have fired yet.
    const auto blockStart = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - blockStart < std::chrono::milliseconds(300))
        Pump(client2, server, 10);
    CHECK(!flux_net::Established(client2, serverAddr));

    // Given time, the stale entry idles out and the new process gets in. If the
    // client's handshake gives up before eviction fires, the app re-connects,
    // which is the real reconnection loop.
    bool reconnected = false;
    const auto start = std::chrono::steady_clock::now();
    while (!reconnected && std::chrono::steady_clock::now() - start < std::chrono::seconds(15))
    {
        if (client2.GetPeer(serverAddr).Failed())
            (void)client2.Connect(serverAddr);
        Pump(client2, server, 20);
        reconnected = flux_net::Established(client2, serverAddr)
                   && flux_net::Established(server, clientAddr);
    }
    CHECK(reconnected);

    // The reconnected session carries data, so it is a real session and not just
    // a half-open handshake.
    CHECK(SendAndReceive(client2, server, serverAddr, 0x1234));

    client2.Shutdown();
    server.Shutdown();
    return test::report();
}
