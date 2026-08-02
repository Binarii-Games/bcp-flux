// A flow is not bound to a peer. One OpenFlow serves every address it is sent
// to, each target getting its own sequence, its own in-flight state and its own
// failure. Covers what that buys: several peers on one flow with independent
// ordering, a failure scoped to the target that caused it, and closing the flow
// tearing down every target at once.
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

static constexpr uint16_t PORT_CLIENT = 9820;
static constexpr uint16_t PORT_B      = 9821;
static constexpr uint16_t PORT_C      = 9822;
static constexpr uint16_t PORT_D      = 9823;

static flux::Socket::Config MakeConfig(uint16_t port, uint32_t maxInPerPeer = 4)
{
    flux::Socket::Config config{};
    config.type     = flux_net::BACKEND;
    config.port     = port;
    config.maxPeers = 8;

    config.flows.flowCount     = 8;
    config.flows.outCount      = 8;
    config.flows.inCount       = 8;
    config.flows.maxOutPerPeer = 4;
    config.flows.maxInPerPeer  = maxInPerPeer;
    return config;
}

// Pumps every socket and appends what each server delivered to its own bucket.
static void Drive(flux::Socket& client,
                  flux::Socket** servers, std::vector<uint32_t>* buckets,
                  size_t serverCount, int ticks)
{
    flux::PacketSlotHandle handles[64];
    for (int i = 0; i < ticks; ++i)
    {
        client.Flush();
        client.Update();
        client.Poll(handles, 64);

        for (size_t s = 0; s < serverCount; ++s)
        {
            servers[s]->Update();
            const uint32_t count = servers[s]->Poll(handles, 64);
            for (uint32_t h = 0; h < count; ++h)
            {
                flux::PacketSlotReader reader{ std::move(handles[h]) };
                uint32_t value = 0;
                if (reader.TakeU32(value))
                    buckets[s].push_back(value);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

// One flow, three peers, independent sequences.
static void OneFlowManyPeers()
{
    flux::Socket client, b, c, d;
    CHECK(client.Init(MakeConfig(PORT_CLIENT)) == common::Error::Ok);
    CHECK(b.Init(MakeConfig(PORT_B)) == common::Error::Ok);
    CHECK(c.Init(MakeConfig(PORT_C)) == common::Error::Ok);
    CHECK(d.Init(MakeConfig(PORT_D)) == common::Error::Ok);

    const flux::Address addrB = flux_net::Loopback(PORT_B);
    const flux::Address addrC = flux_net::Loopback(PORT_C);
    const flux::Address addrD = flux_net::Loopback(PORT_D);

    // No address here: the flow belongs to the socket, not to a peer.
    flux::FlowHandle flow = client.OpenFlow(7, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!flow.Failed());
    CHECK(client.GetFlowState(flow) == flux::FlowLifecycle::OPEN);

    // No target has been sent to yet, so no association exists for any of them.
    CHECK(client.GetFlowState(flow, addrB) == flux::FlowLifecycle::CLOSED);

    // The same handle addresses all three. Each target's state is created by
    // the first send that names it.
    constexpr uint32_t BURST = 6;
    for (uint32_t seq = 0; seq < BURST; ++seq)
    {
        CHECK(client.BuildPacket().WithFlow(flow).PutU32(seq).Send(addrB) == common::Error::Ok);
        CHECK(client.BuildPacket().WithFlow(flow).PutU32(seq).Send(addrC) == common::Error::Ok);
        CHECK(client.BuildPacket().WithFlow(flow).PutU32(seq).Send(addrD) == common::Error::Ok);
    }

    flux::Socket* servers[3] = { &b, &c, &d };
    std::vector<uint32_t> buckets[3];
    Drive(client, servers, buckets, 3, 500);

    // Every peer got the whole burst, in order. Ordering is per target, so
    // three independent sequences ran at once under one flow id.
    for (size_t s = 0; s < 3; ++s)
    {
        CHECK(buckets[s].size() == BURST);
        for (uint32_t i = 0; i < buckets[s].size() && i < BURST; ++i)
            CHECK(buckets[s][i] == i);
    }

    // Each target now has its own association, and the flow is open to all.
    CHECK(client.GetFlowState(flow, addrB) == flux::FlowLifecycle::OPEN);
    CHECK(client.GetFlowState(flow, addrC) == flux::FlowLifecycle::OPEN);
    CHECK(client.GetFlowState(flow, addrD) == flux::FlowLifecycle::OPEN);

    // Closing the flow reaches every target through the flow's association
    // list, which is the only index that answers flow to peers.
    CHECK(client.CloseFlow(flow) == common::Error::Ok);
    CHECK(client.GetFlowState(flow) == flux::FlowLifecycle::CLOSED);
    CHECK(client.GetFlowState(flow, addrB) == flux::FlowLifecycle::CLOSED);
    CHECK(client.GetFlowState(flow, addrC) == flux::FlowLifecycle::CLOSED);
    CHECK(client.GetFlowState(flow, addrD) == flux::FlowLifecycle::CLOSED);

    // The slot went back to the pool, so the id is free to open again.
    flux::FlowHandle reopened = client.OpenFlow(7, flux::FlowMode::UNRELIABLE);
    CHECK(!reopened.Failed());

    // The closed handle is stale and must not address the new flow, even
    // though both name id 7.
    CHECK(client.GetFlowState(flow) == flux::FlowLifecycle::CLOSED);
    CHECK(client.CloseFlow(reopened) == common::Error::Ok);
}

// A target that refuses the flow fails alone; the others keep working.
static void FailureIsPerTarget()
{
    flux::Socket client, b, c;
    CHECK(client.Init(MakeConfig(PORT_CLIENT)) == common::Error::Ok);
    // B takes one flow per peer, C takes four.
    CHECK(b.Init(MakeConfig(PORT_B, 1)) == common::Error::Ok);
    CHECK(c.Init(MakeConfig(PORT_C, 4)) == common::Error::Ok);

    const flux::Address addrB = flux_net::Loopback(PORT_B);
    const flux::Address addrC = flux_net::Loopback(PORT_C);

    flux::FlowHandle first  = client.OpenFlow(1, flux::FlowMode::RELIABLE_ORDERED);
    flux::FlowHandle second = client.OpenFlow(2, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!first.Failed());
    CHECK(!second.Failed());

    flux::Socket* servers[2] = { &b, &c };
    std::vector<uint32_t> buckets[2];

    // Fill B's single in-flow slot with flow 1.
    CHECK(client.BuildPacket().WithFlow(first).PutU32(10).Send(addrB) == common::Error::Ok);
    Drive(client, servers, buckets, 2, 300);
    CHECK(buckets[0].size() == 1);

    // Flow 2 to B has nowhere to go, but flow 2 to C is fine. Same flow, two
    // targets, opposite outcomes.
    buckets[0].clear();
    buckets[1].clear();
    CHECK(client.BuildPacket().WithFlow(second).PutU32(20).Send(addrB) == common::Error::Ok);
    CHECK(client.BuildPacket().WithFlow(second).PutU32(21).Send(addrC) == common::Error::Ok);
    Drive(client, servers, buckets, 2, 400);

    CHECK(buckets[0].empty());        // B refused
    CHECK(buckets[1].size() == 1);    // C accepted
    if (buckets[1].size() == 1)
        CHECK(buckets[1][0] == 21);

    // The failure is confined to the B association. The flow is still open, and
    // still working with C.
    CHECK(client.GetFlowState(second, addrB) == flux::FlowLifecycle::FAILED);
    CHECK(client.GetFlowState(second, addrC) == flux::FlowLifecycle::OPEN);
    CHECK(client.GetFlowState(second) == flux::FlowLifecycle::OPEN);

    buckets[1].clear();
    CHECK(client.BuildPacket().WithFlow(second).PutU32(22).Send(addrC) == common::Error::Ok);
    Drive(client, servers, buckets, 2, 300);
    CHECK(buckets[1].size() == 1);
}

// The id space is the socket's, not the peer's.
static void FlowIdsAreSocketWide()
{
    flux::Socket client;
    CHECK(client.Init(MakeConfig(PORT_CLIENT)) == common::Error::Ok);

    flux::FlowHandle flow = client.OpenFlow(5, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!flow.Failed());

    // A flow id names one flow on this socket. Two flows sharing an id would be
    // indistinguishable to a remote, which reads only the id off the wire.
    flux::FlowHandle clash = client.OpenFlow(5, flux::FlowMode::UNRELIABLE);
    CHECK(clash.Failed());
    CHECK(clash.FailReason() == common::Error::AlreadyInUse);

    // The reserved sentinel is never a usable id.
    CHECK(client.OpenFlow(0xFFFF, flux::FlowMode::UNRELIABLE).Failed());

    // A mode that does not exist is refused at open, so no flow can stamp one
    // onto every packet it sends. RELIABLE_ORDERED_BULK does exist but draws
    // from a pool this socket never asked for, and that is refused at the open
    // too rather than at the first send.
    CHECK(client.OpenFlow(6, flux::FlowMode::RELIABLE_ORDERED_BULK).Failed());
    CHECK(client.OpenFlow(6, static_cast<flux::FlowMode>(4)).Failed());
    CHECK(client.OpenFlow(6, static_cast<flux::FlowMode>(0xFF)).Failed());

    // A real mode on a free id opens.
    flux::FlowHandle second = client.OpenFlow(6, flux::FlowMode::UNRELIABLE);
    CHECK(!second.Failed());

    CHECK(client.CloseFlow(flow) == common::Error::Ok);

    // Closing frees the id.
    flux::FlowHandle reused = client.OpenFlow(5, flux::FlowMode::UNRELIABLE);
    CHECK(!reused.Failed());
}

int main()
{
    OneFlowManyPeers();
    FailureIsPerTarget();
    FlowIdsAreSocketWide();

    return test::report();
}
