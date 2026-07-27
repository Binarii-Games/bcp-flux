// Address migration, end to end over real UDP. A connection must survive its
// peer's address changing — no re-handshake, same keys — without letting an
// attacker hijack it by replaying a captured packet from a spoofed address.
//
// The setup is a two-port UDP relay standing between client and server. The
// client always talks to the relay's port A and always sees the server there;
// the relay chooses whether the server sees the client arrive from port A or
// port B. Flipping that is exactly a client address change (WiFi->cellular, NAT
// rebind, IP rotation) from the server's vantage, which is the only thing
// migration has to survive.
//
// Three scenarios: a plain move survives with no handshake, a spoofed replay
// never reroutes the stream, and a deliberately rotated tag is still recognized
// at the new address.
#include "flux_net.h"   // BACKEND, Loopback, Established, Winsock boot
#include "udp_raw.h"    // raw UDP relay sockets

#include <flux/wire/packet_builder.h>
#include <flux/socket/packet_slot.h>

#include "harness.h"

#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

namespace flux = bcp::flux;
namespace common = bcp::common;

using flux_net::BACKEND;
using flux_net::Established;
using flux_net::Loopback;
using RawSocket = udp_raw::Socket;
using udp_raw::IsHandshake;
using udp_raw::IsSecure;

// The relay. The client always reaches the server via port A; the server sees
// the client on A, or on B once `forwardViaB` is set. Replies always go back to
// the client from A, so the client's own view never changes.
struct Relay
{
    RawSocket socketA{}, socketB{};
    uint16_t  portA{}, portB{}, clientPort{}, serverPort{};
    flux::Address clientAddr, serverAddr;

    bool forwardViaB       = false;   ///< route client->server out of port B (the move)
    bool watching          = false;   ///< count handshake datagrams toward the client
    int  handshakesToClient = 0;

    std::vector<uint8_t> lastClientSecure;   ///< last secure client->server datagram seen

    bool Init(uint16_t pa, uint16_t pb, uint16_t pc, uint16_t ps)
    {
        portA = pa; portB = pb; clientPort = pc; serverPort = ps;
        clientAddr = Loopback(pc); serverAddr = Loopback(ps);
        socketA = udp_raw::MakeBound(pa); socketB = udp_raw::MakeBound(pb);
        return !udp_raw::Bad(socketA) && !udp_raw::Bad(socketB);
    }
    void DrainOne(RawSocket fd)
    {
        uint8_t buffer[2048];
        for (;;)
        {
            sockaddr_in6 source{}; socklen_t len = sizeof(source);
            int n = static_cast<int>(::recvfrom(fd, reinterpret_cast<char*>(buffer), sizeof(buffer), 0,
                                                reinterpret_cast<sockaddr*>(&source), &len));
            if (n <= 0) break;
            const uint16_t sourcePort = ntohs(source.sin6_port);

            if (sourcePort == clientPort)         // client -> server
            {
                if (IsSecure(buffer, n)) lastClientSecure.assign(buffer, buffer + n);
                udp_raw::SendTo(forwardViaB ? socketB : socketA, buffer, n, serverAddr);
            }
            else if (sourcePort == serverPort)    // server -> client, always via A
            {
                if (watching && IsHandshake(buffer, n)) ++handshakesToClient;
                udp_raw::SendTo(socketA, buffer, n, clientAddr);
            }
        }
    }
    void Pump() { DrainOne(socketA); DrainOne(socketB); }
    void Close() { if (!udp_raw::Bad(socketA)) udp_raw::Close(socketA); if (!udp_raw::Bad(socketB)) udp_raw::Close(socketB); }
};

// One application byte carried on a non-flow packet, and how many of each op a
// socket has delivered.
static common::Error SendOp(flux::Socket& socket, const flux::Address& to, uint8_t op)
{
    auto stage = socket.BuildPacket().NoFlow();
    stage.PutU8(op);
    return stage.Send(to);
}
static int CollectOp(flux::Socket& socket, uint8_t op)
{
    flux::PacketSlotHandle handles[64];
    uint32_t count = socket.Poll(handles, 64);
    int seen = 0;
    for (uint32_t i = 0; i < count; ++i)
    {
        flux::PacketSlotReader reader{std::move(handles[i])};
        uint8_t got = 0;
        if (reader.TakeU8(got) && got == op) ++seen;
    }
    return seen;
}

// A client, a server, and a relay, driven to an established session.
struct World
{
    flux::Socket client, server;
    Relay        relay;
    uint16_t     portA, portB, clientPort, serverPort;

    bool Boot(uint16_t base)
    {
        portA = base; portB = base + 1; clientPort = base + 2; serverPort = base + 3;
        if (server.Init({ .type = BACKEND, .port = serverPort, .maxPeers = 8, .pendingPacketCount = 8 }) != common::Error::Ok) return false;
        if (client.Init({ .type = BACKEND, .port = clientPort, .maxPeers = 8, .pendingPacketCount = 8 }) != common::Error::Ok) return false;
        if (!relay.Init(portA, portB, clientPort, serverPort)) return false;
        if (SendOp(client, Loopback(portA), 0x01) != common::Error::Ok) return false;

        int received = 0;
        for (int i = 0; i < 200; ++i)
        {
            relay.Pump();
            received += CollectOp(server, 0x01);
            CollectOp(client, 0x00);
            client.Update();
            server.Update();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            if (Established(client, Loopback(portA)) && Established(server, Loopback(portA))) break;
        }
        return Established(client, Loopback(portA)) && Established(server, Loopback(portA));
    }
    void Drive(int ticks)
    {
        for (int i = 0; i < ticks; ++i)
        {
            relay.Pump();
            CollectOp(client, 0xFF);   // drain, count nothing
            CollectOp(server, 0xFF);
            client.Update();
            server.Update();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    void Close() { relay.Close(); }
};

// A move mid-session: the server recognizes the peer at its new address, rebinds
// to it, and keeps the same keys — no handshake anywhere.
static void move_survives_with_same_keys()
{
    World world;
    CHECK(world.Boot(9700));

    world.relay.forwardViaB = true;    // the client's apparent address changes
    world.relay.watching    = true;

    int delivered = 0;
    for (int round = 0; round < 4; ++round)
    {
        CHECK(SendOp(world.client, Loopback(world.portA), 0x20) == common::Error::Ok);
        for (int i = 0; i < 25; ++i)
        {
            world.relay.Pump();
            delivered += CollectOp(world.server, 0x20);
            CollectOp(world.client, 0xFF);
            world.client.Update();
            world.server.Update();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    CHECK(delivered >= 1);                                        // data crossed the move
    CHECK(Established(world.server, Loopback(world.portB)));      // rebound to the new address
    CHECK(!Established(world.server, Loopback(world.portA)));     // old address released
    CHECK(world.relay.handshakesToClient == 0);                  // no re-handshake: same session
    world.Close();
}

// A replayed secure packet forged from a victim address never reroutes the
// stream: the server does not rebind to the victim, and the real client keeps
// receiving.
static void spoofed_replay_never_redirects()
{
    World world;
    CHECK(world.Boot(9710));

    // Capture a genuine secure client->server datagram.
    CHECK(SendOp(world.client, Loopback(world.portA), 0x30) == common::Error::Ok);
    world.Drive(30);
    CHECK(!world.relay.lastClientSecure.empty());

    // Replay it to the server straight from a victim address the attacker forges.
    const uint16_t victimPort = 9715;
    RawSocket victim = udp_raw::MakeBound(victimPort);
    CHECK(!udp_raw::Bad(victim));
    for (int i = 0; i < 3; ++i)
        udp_raw::SendTo(victim, world.relay.lastClientSecure.data(),
                static_cast<int>(world.relay.lastClientSecure.size()), Loopback(world.serverPort));
    world.Drive(40);

    // The real route is untouched: the server never rebound to the victim.
    CHECK(Established(world.server, Loopback(world.portA)));
    CHECK(!Established(world.server, Loopback(victimPort)));

    // Prove replies still reach the real client, not the victim.
    int atClient = 0;
    for (int round = 0; round < 5; ++round)
    {
        CHECK(SendOp(world.server, Loopback(world.portA), 0x31) == common::Error::Ok);
        for (int i = 0; i < 15; ++i)
        {
            world.relay.Pump();
            atClient += CollectOp(world.client, 0x31);
            CollectOp(world.server, 0xFF);
            world.client.Update();
            world.server.Update();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    CHECK(atClient >= 1);

    // The victim saw at most a bounded challenge or two, never the stream.
    int victimPackets = 0;
    uint8_t buffer[2048];
    for (;;)
    {
        sockaddr_in6 source{}; socklen_t len = sizeof(source);
        int n = static_cast<int>(::recvfrom(victim, reinterpret_cast<char*>(buffer), sizeof(buffer), 0,
                                            reinterpret_cast<sockaddr*>(&source), &len));
        if (n <= 0) break;
        ++victimPackets;
    }
    CHECK(victimPackets <= 2);

    udp_raw::Close(victim);
    world.Close();
}

// RotateTags before a move: the new address wears a fresh, unlinkable tag and is
// still recognized, still with no re-handshake.
static void rotated_tag_is_recognized_after_move()
{
    World world;
    CHECK(world.Boot(9720));

    CHECK(world.client.RotateTags() == 1);   // deliberate rotation, as before an IP change
    world.relay.forwardViaB = true;
    world.relay.watching    = true;

    int delivered = 0;
    for (int round = 0; round < 5; ++round)
    {
        CHECK(SendOp(world.client, Loopback(world.portA), 0x60) == common::Error::Ok);
        for (int i = 0; i < 25; ++i)
        {
            world.relay.Pump();
            delivered += CollectOp(world.server, 0x60);
            CollectOp(world.client, 0xFF);
            world.client.Update();
            world.server.Update();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    CHECK(delivered >= 1);
    CHECK(Established(world.server, Loopback(world.portB)));
    CHECK(world.relay.handshakesToClient == 0);
    world.Close();
}

int main()
{
    move_survives_with_same_keys();
    spoofed_replay_never_redirects();
    rotated_tag_is_recognized_after_move();
    return test::report();
}
