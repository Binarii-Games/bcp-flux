// Each flow mode's delivery contract, end to end over real UDP. A flow is
// opened locally, with nothing on the wire, the receiver registers its half
// from the first packet that arrives, and a burst of numbered packets is sent
// on it. RELIABLE_ORDERED must deliver every one in send order,
// RELIABLE_UNORDERED must deliver every one in whatever order they arrive, and
// UNRELIABLE must deliver newest only, dropping a packet that arrives after a
// newer one was delivered.
//
// Arrival order is what separates the contracts, so every burst is routed
// through a relay that swaps adjacent datagrams before they reach the server.
// Over plain loopback nothing reorders, and without the relay none of these
// assertions could fail: the resequencing check needs a gap to hold back, and
// the newest-only check needs a stale packet to arrive late.
#include "flux_net.h"
#include "udp_raw.h"

#include <flux/wire/packet_builder.h>
#include <flux/socket/packet_slot.h>
#include <flux/flow/flow_handle.h>

#include "harness.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

namespace flux = bcp::flux;
namespace common = bcp::common;

using flux_net::BACKEND;
using flux_net::Established;
using flux_net::Loopback;

// A relay between client and server. It forwards both directions, and while
// `reorderActive` is set it swaps each adjacent pair of client->server datagrams
// (holding the first until the second arrives, then sending the second first).
// Reordering is turned on only for the data burst, never during the handshake
// or the flow-open exchange, which must stay in order.
struct ReorderRelay
{
    udp_raw::Socket socket{};
    uint16_t        relayPort{}, clientPort{}, serverPort{};
    flux::Address   clientAddr, serverAddr;

    bool    reorderActive = false;
    uint8_t held[2048];
    int     heldLen = 0;
    int     swaps   = 0;   ///< adjacent-pair swaps actually performed

    bool Init(uint16_t rp, uint16_t cp, uint16_t sp)
    {
        relayPort = rp; clientPort = cp; serverPort = sp;
        clientAddr = Loopback(cp); serverAddr = Loopback(sp);
        socket = udp_raw::MakeBound(rp);
        return !udp_raw::Bad(socket);
    }

    void Pump()
    {
        uint8_t buffer[2048];
        for (;;)
        {
            sockaddr_in6 source{}; socklen_t len = sizeof(source);
            int n = static_cast<int>(::recvfrom(socket, reinterpret_cast<char*>(buffer), sizeof(buffer), 0,
                                                reinterpret_cast<sockaddr*>(&source), &len));
            if (n <= 0) break;
            const uint16_t sourcePort = ntohs(source.sin6_port);

            if (sourcePort == clientPort)          // client -> server
            {
                if (!reorderActive)
                {
                    udp_raw::SendTo(socket, buffer, n, serverAddr);
                }
                else if (heldLen == 0)
                {
                    std::memcpy(held, buffer, n); heldLen = n;   // hold the first of a pair
                }
                else
                {
                    udp_raw::SendTo(socket, buffer, n, serverAddr);       // second first...
                    udp_raw::SendTo(socket, held, heldLen, serverAddr);   // ...then the held first
                    heldLen = 0;
                    ++swaps;
                }
            }
            else if (sourcePort == serverPort)     // server -> client (acks)
            {
                udp_raw::SendTo(socket, buffer, n, clientAddr);
            }
        }
    }

    // Release a straggler left held when the burst had an odd count.
    void Flush()
    {
        if (heldLen) { udp_raw::SendTo(socket, held, heldLen, serverAddr); heldLen = 0; }
    }
    void Close() { if (!udp_raw::Bad(socket)) udp_raw::Close(socket); }
};

// A socket configured with flow pools on both directions.
static common::Error InitWithFlows(flux::Socket& socket, uint16_t port)
{
    flux::Socket::Config config{};
    config.type               = BACKEND;
    config.port               = port;
    config.maxPeers           = 16;
    config.pendingPacketCount = 32;
    config.flows.outCount     = 16;
    config.flows.inCount      = 16;
    return socket.Init(config);
}

static void reliable_ordered_flow_delivers_in_order()
{
    flux::Socket client, server;
    CHECK(InitWithFlows(client, 9430) == common::Error::Ok);
    CHECK(InitWithFlows(server, 9431) == common::Error::Ok);

    ReorderRelay relay;
    CHECK(relay.Init(9432, 9430, 9431));
    const flux::Address relayAddr = Loopback(9432);   // both peers see each other here

    flux::PacketSlotHandle sink[64];

    // Establish through the relay (in order — reordering is still off).
    CHECK(client.Connect(relayAddr) == common::Error::Ok);
    bool established = false;
    for (int i = 0; i < 300 && !established; ++i)
    {
        relay.Pump();
        client.Poll(sink, 64);
        server.Poll(sink, 64);
        client.Update();
        server.Update();
        established = Established(client, relayAddr) && Established(server, relayAddr);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(established);

    // Opening is local: the flow is OPEN and sendable the instant it exists,
    // with nothing on the wire and nothing to wait for. The server has never
    // heard of flow 7 and will register it from the first packet that arrives.
    flux::FlowHandle flow = client.OpenFlow(7, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!flow.Failed());
    CHECK(client.GetFlowState(flow) == flux::FlowLifecycle::OPEN);

    // Now shuffle the wire, and send a numbered burst.
    relay.reorderActive = true;
    constexpr uint32_t BURST = 32;
    for (uint32_t seq = 0; seq < BURST; ++seq)
        CHECK(client.BuildPacket().WithFlow(flow).PutU32(seq).Send(relayAddr) == common::Error::Ok);

    // Collect what the server delivers, in delivery order. No per-tick flush:
    // a held packet waits for its pair so the swap actually happens; the tail
    // flush below releases a lone straggler if the on-wire count was odd.
    std::vector<uint32_t> delivered;
    auto drain = [&](int ticks)
    {
        for (int i = 0; i < ticks && delivered.size() < BURST; ++i)
        {
            relay.Pump();
            flux::PacketSlotHandle handles[64];
            uint32_t count = server.Poll(handles, 64);
            for (uint32_t h = 0; h < count; ++h)
            {
                flux::PacketSlotReader reader{std::move(handles[h])};
                uint32_t seq = 0;
                if (reader.TakeU32(seq)) delivered.push_back(seq);
            }
            client.Poll(sink, 64);   // drain acks back to the sender
            client.Update();
            server.Update();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    };
    drain(500);
    relay.Flush();   // release a straggler held from an odd on-wire count
    drain(100);

    // The relay really did reorder (otherwise the ordering check proves nothing),
    // every packet arrived despite it, and delivery was in send order.
    CHECK(relay.swaps > 0);
    CHECK(delivered.size() == BURST);
    bool inOrder = delivered.size() == BURST;
    for (uint32_t i = 0; i < delivered.size(); ++i)
        if (delivered[i] != i) inOrder = false;
    CHECK(inOrder);

    relay.Close();
}

// The shared shape of the unordered-mode cases: establish through a swapping
// relay, send a numbered burst on one flow of the given mode, and collect what
// the server delivers, in delivery order. The caller asserts its contract on
// the result. `expected` only bounds the drain: draining stops early once that
// many arrived, so a correct run does not sit out the full tick count.
static bool RunSwappedBurst(flux::FlowMode mode, uint16_t clientPort, uint16_t serverPort,
                            uint16_t relayPort, uint32_t burst, size_t expected,
                            std::vector<uint32_t>& delivered, int& swaps)
{
    flux::Socket client, server;
    CHECK(InitWithFlows(client, clientPort) == common::Error::Ok);
    CHECK(InitWithFlows(server, serverPort) == common::Error::Ok);

    ReorderRelay relay;
    CHECK(relay.Init(relayPort, clientPort, serverPort));
    const flux::Address relayAddr = Loopback(relayPort);

    flux::PacketSlotHandle sink[64];

    CHECK(client.Connect(relayAddr) == common::Error::Ok);
    bool established = false;
    for (int i = 0; i < 300 && !established; ++i)
    {
        relay.Pump();
        client.Poll(sink, 64);
        server.Poll(sink, 64);
        client.Update();
        server.Update();
        established = Established(client, relayAddr) && Established(server, relayAddr);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(established);
    if (!established) { relay.Close(); return false; }

    flux::FlowHandle flow = client.OpenFlow(9, mode);
    CHECK(!flow.Failed());

    relay.reorderActive = true;
    for (uint32_t seq = 0; seq < burst; ++seq)
        CHECK(client.BuildPacket().WithFlow(flow).PutU32(seq).Send(relayAddr) == common::Error::Ok);

    for (int i = 0; i < 300 && delivered.size() < expected; ++i)
    {
        relay.Pump();
        flux::PacketSlotHandle handles[64];
        uint32_t count = server.Poll(handles, 64);
        for (uint32_t h = 0; h < count; ++h)
        {
            flux::PacketSlotReader reader{std::move(handles[h])};
            uint32_t seq = 0;
            if (reader.TakeU32(seq)) delivered.push_back(seq);
        }
        client.Poll(sink, 64);
        client.Update();
        server.Update();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    swaps = relay.swaps;
    relay.Close();
    return true;
}

static void reliable_unordered_flow_delivers_everything()
{
    // The relay swaps adjacent pairs, so packets arrive out of order. The
    // contract is delivery exactly once per packet, in whatever order they
    // came: nothing held back, nothing dropped, duplicates filtered.
    constexpr uint32_t BURST = 32;
    std::vector<uint32_t> delivered;
    int swaps = 0;
    if (!RunSwappedBurst(flux::FlowMode::RELIABLE_UNORDERED, 9433, 9434, 9435,
                         BURST, BURST, delivered, swaps))
        return;

    CHECK(swaps > 0);
    CHECK(delivered.size() == BURST);
    bool eachOnce = true;
    uint32_t seenCount[BURST] = {};
    for (uint32_t payload : delivered)
        if (payload < BURST) ++seenCount[payload]; else eachOnce = false;
    for (uint32_t i = 0; i < BURST; ++i)
        if (seenCount[i] != 1) eachOnce = false;
    CHECK(eachOnce);
}

static void unreliable_flow_delivers_newest_only()
{
    // Same swapped wire, opposite contract: when the newer of a swapped pair
    // arrives first, the older one is stale on arrival and must be dropped.
    // Newest-only delivery is exactly "the delivered sequence is strictly
    // increasing", and the swaps guarantee at least one stale drop, so a full
    // delivery count would mean the drop never happened.
    constexpr uint32_t BURST = 32;
    std::vector<uint32_t> delivered;
    int swaps = 0;
    if (!RunSwappedBurst(flux::FlowMode::UNRELIABLE, 9436, 9437, 9438,
                         BURST, BURST / 2, delivered, swaps))
        return;

    CHECK(swaps > 0);
    CHECK(!delivered.empty());
    CHECK(delivered.size() < BURST);
    bool strictlyIncreasing = true;
    for (size_t i = 1; i < delivered.size(); ++i)
        if (delivered[i] <= delivered[i - 1]) strictlyIncreasing = false;
    CHECK(strictlyIncreasing);
}

int main()
{
    reliable_ordered_flow_delivers_in_order();
    reliable_unordered_flow_delivers_everything();
    unreliable_flow_delivers_newest_only();
    return test::report();
}
