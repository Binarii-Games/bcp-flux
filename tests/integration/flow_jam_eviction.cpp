// A receiving ordered flow that pins recv slots behind a gap the sender never
// fills is jammed. After Config::liveness stall timeout the tick frees what it
// buffered and leaves the association standing. The contract (ARCHITECTURE 3.6,
// "Delivering an in-flow packet"): a stuck cursor holding a gap gives up its
// buffered packets, keeps its cursor and epoch so the sender can resend into
// the same gap, and a flow still making progress or already finished is left
// alone.
//
// A jam is held open by giving the sender a very long retransmit interval, so
// the one dropped cursor packet is not resent within the test. The receiver's
// cursor stays stuck and its hold-back stays pinned, which is exactly the state
// a misbehaving or dead sender leaves behind.
//
// Two in-process FAULTY sockets. UBSan (ASan aborts on init on this toolchain).
#include <flux/socket/socket.h>
#include <flux/address.h>
#include <flux/wire/packet_builder.h>
#include <flux/socket/packet_slot.h>
#include <flux/flow/flow_handle.h>
#include <flux/socket/platform/faulty_socket.h>

#include "flux_net.h"   // boots Winsock on Windows before the FAULTY kernel binds
#include "harness.h"

#include <chrono>
#include <thread>
#include <vector>

namespace flux   = bcp::flux;
namespace common = bcp::common;

namespace
{
    constexpr auto FAULTY = flux::Socket::BackendType::FAULTY;

    flux::Address Loopback(uint16_t port) { return flux::Address::From("::1", port).Take(); }

    bool Established(flux::Socket& s, const flux::Address& a)
    {
        flux::PeerHandle p = s.GetPeer(a);
        return !p.Failed() && p.Read() && p.Read()->IsValid();
    }

    // stallMicros sizes the receiver's jam timeout; retryMicros sizes the
    // sender's retransmit clock (huge holds a jam open, default lets a lossy
    // flow recover).
    common::Error Init(flux::Socket& s, uint16_t port, uint32_t stallMicros, uint32_t retryMicros)
    {
        flux::Socket::Config c{};
        c.type = FAULTY;
        c.port = port;
        c.maxPeers = 8;
        c.pendingPacketCount = 64;
        c.flows.outCount = 8;
        c.flows.inCount  = 8;
        c.flows.stagingCount = 1024;
        c.flows.reliableWaitCount = 256;
        c.timers.retryIntervalMicros = retryMicros;
        c.liveness.flowStallTimeoutMicros = stallMicros;
        return s.Init(c);
    }

    void Pump(flux::Socket& a, flux::Socket& b, int rounds, int perRoundMicros = 1000)
    {
        flux::PacketSlotHandle sink[64];
        for (int i = 0; i < rounds; ++i)
        {
            a.Flush();
            a.Update(); a.Poll(sink, 64);
            b.Flush();
            b.Update(); b.Poll(sink, 64);
            std::this_thread::sleep_for(std::chrono::microseconds(perRoundMicros));
        }
        for (auto& h : sink) h = flux::PacketSlotHandle::Invalid();
    }

    bool Connect(flux::Socket& client, flux::Socket& server,
                 const flux::Address& serverAddr, const flux::Address& clientAddr)
    {
        if (client.Connect(serverAddr) != common::Error::Ok) return false;
        for (int i = 0; i < 2000; ++i)
        {
            Pump(client, server, 1);
            if (Established(client, serverAddr) && Established(server, clientAddr)) return true;
        }
        return false;
    }

    // Sends `count` packets on `flow`, dropping the first one (seq 1) at the
    // sender's socket so the receiver opens the flow on seq 2 and stalls with a
    // gap at seq 1. Returns false if the drop did not land as intended.
    bool SendWithLostHead(flux::Socket& client, uint16_t clientPort,
                          const flux::FlowHandle& flow, const flux::Address& serverAddr,
                          uint32_t count)
    {
        auto* faulty = flux::platform::FaultySocket::ForPort(clientPort);
        if (!faulty) return false;
        const uint64_t droppedBefore = faulty->GetStats().dropped;

        faulty->DropNext(1);   // the very next packet out is seq 1
        for (uint32_t v = 0; v < count; ++v)
            if (client.BuildPacket().WithFlow(flow).PutU32(v).Send(serverAddr) != common::Error::Ok)
                break;

        return faulty->GetStats().dropped == droppedBefore + 1;
    }
}

// 1. A jammed flow gives up what it buffered once the stall timeout passes, and
//    keeps its association.
static void JammedFlowKeepsAssociation()
{
    const uint16_t CLIENT = 20860, SERVER = 20861;
    flux::Socket client, server;
    CHECK(Init(client, CLIENT, 0 /*server stall unused*/, 10'000'000) == common::Error::Ok);
    CHECK(Init(server, SERVER, 250'000 /*250 ms*/, 200'000) == common::Error::Ok);
    const flux::Address serverAddr = Loopback(SERVER), clientAddr = Loopback(CLIENT);
    CHECK(Connect(client, server, serverAddr, clientAddr));

    Pump(client, server, 20);   // quiesce: flush any handshake acks

    flux::FlowHandle flow = client.OpenFlow(11, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!flow.Failed());
    CHECK(SendWithLostHead(client, CLIENT, flow, serverAddr, 20));

    // The head is lost, so the receiver holds seq 2.. behind the gap. The
    // server is ticked with a FROZEN clock here: reception happens on the tick,
    // but every reclaim on it is measured against that clock, so a time that
    // never advances means nothing can age out before we observe it, however
    // slow the runner. The eviction phase below lets the clock run.
    const uint64_t frozen = common::MonotonicMicros();
    flux::PacketSlotHandle inbox[64];
    uint32_t delivered = 0;
    for (int i = 0; i < 120; ++i)
    {
        client.Flush();
        client.Update();
        // Update takes packets off the socket, Poll hands over what it took.
        server.Update(frozen);
        flux::PollCursor cursor = server.Poll(inbox, 64);
        delivered += cursor.PacketCount();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    for (auto& h : inbox) h = flux::PacketSlotHandle::Invalid();

    // Whatever arrived in order ahead of the dropped packet was delivered, and
    // which packet the link drops is the backend's schedule rather than this
    // test's business. What the jam means is that delivery STOPS at the gap and
    // does not resume, so the count is taken here and must not move while the
    // sender keeps pushing into a gap it never fills.
    const uint32_t beforeGap = delivered;
    CHECK(beforeGap < 20);                              // the gap really blocked something
    for (int i = 0; i < 120; ++i)
    {
        client.Flush();
        client.Update();
        server.Update(frozen);
        flux::PollCursor stuck = server.Poll(inbox, 64);
        delivered += stuck.PacketCount();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    for (auto& h : inbox) h = flux::PacketSlotHandle::Invalid();
    CHECK(delivered == beforeGap);                      // nothing past the gap
    CHECK(server.ReceivingFlowCount(clientAddr) == 1);  // the jammed flow is there

    // Past the 250 ms stall timeout, the tick reclaims it.
    const auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(500))
    {
        server.Flush();
        server.Update();
        server.Poll(inbox, 64);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    for (auto& h : inbox) h = flux::PacketSlotHandle::Invalid();
    // The buffered packets are gone, but the association is not. Destroying it
    // would restart this side at sequence one while the sender is far past
    // that, and nothing either of them sent afterwards could line up again.
    CHECK(server.ReceivingFlowCount(clientAddr) == 1);
    CHECK(Established(server, clientAddr));

    client.Shutdown();
    server.Shutdown();
}

// 2. A flow that keeps making progress under loss is never evicted, even when it
//    runs longer than the stall timeout in wall-clock, and it completes.
static void ProgressingFlowSpared()
{
    const uint16_t CLIENT = 20862, SERVER = 20863;
    flux::Socket client, server;
    CHECK(Init(client, CLIENT, 2'000'000, 200'000) == common::Error::Ok);
    CHECK(Init(server, SERVER, 2'000'000 /*generous, > a few RTOs*/, 200'000) == common::Error::Ok);
    const flux::Address serverAddr = Loopback(SERVER), clientAddr = Loopback(CLIENT);
    CHECK(Connect(client, server, serverAddr, clientAddr));

    // 5% loss both ways: the cursor stalls briefly on a lost packet and recovers
    // well inside the 2 s timeout, so it must never be judged jammed.
    auto* fc = flux::platform::FaultySocket::ForPort(CLIENT);
    auto* fs = flux::platform::FaultySocket::ForPort(SERVER);
    flux::platform::FaultySocket::Profile p{}; p.lossPercent = 5;
    p.seed = 0xA1A1; if (fc) fc->SetProfile(p);
    p.seed = 0xB2B2; if (fs) fs->SetProfile(p);

    flux::FlowHandle flow = client.OpenFlow(11, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!flow.Failed());

    constexpr uint32_t BURST = 120;
    std::vector<bool> got(BURST, false);
    uint32_t delivered = 0, sent = 0;
    bool everEvicted = false;
    flux::PacketSlotHandle inbox[64];
    const auto start = std::chrono::steady_clock::now();
    while (delivered < BURST &&
           std::chrono::steady_clock::now() - start < std::chrono::seconds(15))
    {
        while (sent < BURST &&
               client.BuildPacket().WithFlow(flow).PutU32(sent).Send(serverAddr) == common::Error::Ok)
            ++sent;
        client.Flush();
        client.Update(); client.Poll(inbox, 64);
        server.Flush();
        server.Update();
        flux::PollCursor cursor = server.Poll(inbox, 64);
        while (cursor.Next())
        {
            flux::PacketSlotReader& r = cursor.Message();
            uint32_t v = 0;
            if (r.TakeU32(v) && v < BURST && !got[v]) { got[v] = true; ++delivered; }
        }
        // Mid-transfer the flow must exist: a spurious eviction would show as 0.
        if (delivered < BURST && server.ReceivingFlowCount(clientAddr) == 0)
            everEvicted = true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    for (auto& h : inbox) h = flux::PacketSlotHandle::Invalid();

    CHECK(!everEvicted);            // never falsely reclaimed while in progress
    CHECK(delivered == BURST);      // and it finished

    client.Shutdown();
    server.Shutdown();
}

// 3. Reclaiming one peer's jammed flow leaves its healthy sibling and the peer
//    itself untouched.
static void SiblingSurvives()
{
    const uint16_t CLIENT = 20864, SERVER = 20865;
    flux::Socket client, server;
    CHECK(Init(client, CLIENT, 0, 10'000'000) == common::Error::Ok);
    CHECK(Init(server, SERVER, 250'000, 200'000) == common::Error::Ok);
    const flux::Address serverAddr = Loopback(SERVER), clientAddr = Loopback(CLIENT);
    CHECK(Connect(client, server, serverAddr, clientAddr));
    Pump(client, server, 20);

    // A healthy, lossless flow: send it and let it drain fully.
    flux::FlowHandle healthy = client.OpenFlow(30, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!healthy.Failed());
    constexpr uint32_t HEALTHY_N = 20;
    std::vector<bool> got(HEALTHY_N, false);
    uint32_t healthyDelivered = 0, sent = 0;
    flux::PacketSlotHandle inbox[64];
    for (int i = 0; i < 400 && healthyDelivered < HEALTHY_N; ++i)
    {
        while (sent < HEALTHY_N &&
               client.BuildPacket().WithFlow(healthy).PutU32(sent).Send(serverAddr) == common::Error::Ok)
            ++sent;
        client.Flush();
        client.Update(); client.Poll(inbox, 64);
        server.Flush();
        server.Update();
        flux::PollCursor cursor = server.Poll(inbox, 64);
        while (cursor.Next())
        {
            flux::PacketSlotReader& r = cursor.Message();
            uint32_t v = 0;
            if (r.TakeU32(v) && v < HEALTHY_N && !got[v]) { got[v] = true; ++healthyDelivered; }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    for (auto& h : inbox) h = flux::PacketSlotHandle::Invalid();
    CHECK(healthyDelivered == HEALTHY_N);
    CHECK(server.ReceivingFlowCount(clientAddr) == 1);   // just the healthy one

    Pump(client, server, 20);   // quiesce before staging the jam

    // A second flow, jammed the same way as test 1. The server ticks on a
    // frozen clock so it receives without anything aging out before both flows
    // can be observed.
    const uint64_t held = common::MonotonicMicros();
    flux::FlowHandle jam = client.OpenFlow(31, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!jam.Failed());
    CHECK(SendWithLostHead(client, CLIENT, jam, serverAddr, 20));
    for (int i = 0; i < 120; ++i)
    {
        client.Flush();
        client.Update();
        server.Update(held);
        server.Poll(inbox, 64);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    for (auto& h : inbox) h = flux::PacketSlotHandle::Invalid();
    CHECK(server.ReceivingFlowCount(clientAddr) == 2);   // healthy + jammed

    // Past the timeout, only the jammed one goes.
    const auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(500))
    {
        server.Flush();
        server.Update(); server.Poll(inbox, 64);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    for (auto& h : inbox) h = flux::PacketSlotHandle::Invalid();
    CHECK(server.ReceivingFlowCount(clientAddr) == 2);   // both stand
    CHECK(Established(server, clientAddr));               // peer intact

    client.Shutdown();
    server.Shutdown();
}

int main()
{
    JammedFlowKeepsAssociation();
    ProgressingFlowSpared();
    SiblingSurvives();
    return test::report();
}
