// A flow needs no opening exchange: it is usable the instant OpenFlow returns,
// and the receiver registers its half from whichever packet arrives first.
// Covers the three things that behaviour rests on: the flow is OPEN and
// sendable immediately, an unknown flow is registered from a data packet, and
// a flow the receiver cannot take is rejected so the sender stops rather than
// retransmitting into silence.
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>
#include <flux/socket/packet_slot.h>

#include "flux_net.h"
#include "harness.h"

#include <chrono>
#include <thread>
#include <vector>

namespace flux = bcp::flux;
namespace common = bcp::common;

static constexpr uint16_t PORT_A = 9810;
static constexpr uint16_t PORT_B = 9811;

// Pumps both sockets, collecting the u32 payload of every flow packet the
// server delivers.
static void Drive(flux::Socket& client, flux::Socket& server,
                  std::vector<uint32_t>& delivered, int ticks)
{
    flux::PacketSlotHandle handles[64];
    for (int i = 0; i < ticks; ++i)
    {
        client.Flush();
        client.Update();
        server.Flush();
        server.Update();
        client.Poll(handles, 64);

        const uint32_t count = server.Poll(handles, 64);
        for (uint32_t h = 0; h < count; ++h)
        {
            flux::PacketSlotReader reader{ std::move(handles[h]) };
            uint32_t value = 0;
            if (reader.TakeU32(value))
                delivered.push_back(value);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

static flux::Socket::Config MakeConfig(uint16_t port, uint32_t maxInPerPeer)
{
    flux::Socket::Config config{};
    config.type     = flux_net::BACKEND;
    config.port     = port;
    config.maxPeers = 8;

    config.flows.outCount     = 8;
    config.flows.inCount      = 8;
    config.flows.maxOutPerPeer = 4;
    config.flows.maxInPerPeer  = maxInPerPeer;
    return config;
}

// A flow is sendable the moment it exists, and the receiver builds its half
// from the traffic itself.
static void RegistersFromFirstPacket()
{
    flux::Socket client, server;
    CHECK(client.Init(MakeConfig(PORT_A, 4)) == common::Error::Ok);
    CHECK(server.Init(MakeConfig(PORT_B, 4)) == common::Error::Ok);

    const flux::Address addrB = flux_net::Loopback(PORT_B);

    // No handshake yet, no wire traffic from the open, nothing to wait on.
    flux::FlowHandle flow = client.OpenFlow(7, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!flow.Failed());
    CHECK(client.GetFlowState(flow) == flux::FlowLifecycle::OPEN);

    // Sending is allowed straight away. The peer handshake happens underneath
    // and these park behind it.
    constexpr uint32_t BURST = 8;
    for (uint32_t seq = 0; seq < BURST; ++seq)
        CHECK(client.BuildPacket().WithFlow(flow).PutU32(seq).Send(addrB)
              == common::Error::Ok);

    std::vector<uint32_t> delivered;
    Drive(client, server, delivered, 400);

    // The server never called OpenFlow and never acked an open, yet every
    // packet arrived, in order, because the flow header carried everything
    // registration needed.
    CHECK(delivered.size() == BURST);
    for (uint32_t i = 0; i < delivered.size() && i < BURST; ++i)
        CHECK(delivered[i] == i);

    CHECK(client.GetFlowState(flow) == flux::FlowLifecycle::OPEN);
}

// A receiver at its per-peer flow cap refuses, and the sender's flow dies
// rather than retransmitting forever.
static void RejectedWhenTheReceiverIsFull()
{
    flux::Socket client, server;
    CHECK(client.Init(MakeConfig(PORT_A, 4)) == common::Error::Ok);
    // One in-flow per peer: the second flow this client opens cannot be taken.
    CHECK(server.Init(MakeConfig(PORT_B, 1)) == common::Error::Ok);

    const flux::Address addrB = flux_net::Loopback(PORT_B);

    flux::FlowHandle accepted = client.OpenFlow(1, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!accepted.Failed());
    CHECK(client.BuildPacket().WithFlow(accepted).PutU32(100).Send(addrB)
          == common::Error::Ok);

    std::vector<uint32_t> delivered;
    Drive(client, server, delivered, 300);
    CHECK(delivered.size() == 1);

    // Second flow to the same peer: locally fine, but the server has no room
    // for it. Nothing about OpenFlow can know that, so it still succeeds.
    flux::FlowHandle refused = client.OpenFlow(2, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!refused.Failed());
    CHECK(client.GetFlowState(refused) == flux::FlowLifecycle::OPEN);

    CHECK(client.BuildPacket().WithFlow(refused).PutU32(200).Send(addrB)
          == common::Error::Ok);

    delivered.clear();
    Drive(client, server, delivered, 300);

    // Never delivered, and the flow is FAILED rather than still trying: the
    // reject told the sender to stop. The app reads that off its handle.
    CHECK(delivered.empty());
    CHECK(client.GetFlowState(refused, addrB) == flux::FlowLifecycle::FAILED);
    // The FLOW itself is untouched: only that one target failed.
    CHECK(client.GetFlowState(refused) == flux::FlowLifecycle::OPEN);

    // The rejection is scoped to the one flow. The accepted flow to the same
    // peer keeps working, which is what makes a caps refusal survivable.
    CHECK(client.GetFlowState(accepted, addrB) == flux::FlowLifecycle::OPEN);
    CHECK(client.BuildPacket().WithFlow(accepted).PutU32(101).Send(addrB)
          == common::Error::Ok);

    delivered.clear();
    Drive(client, server, delivered, 300);
    CHECK(delivered.size() == 1);
    if (delivered.size() == 1)
        CHECK(delivered[0] == 101);
}

int main()
{
    RegistersFromFirstPacket();
    RejectedWhenTheReceiverIsFull();

    return test::report();
}
