// A receiving ordered flow that pins recv slots behind a gap the sender never
// fills is jammed. After the Config::liveness stall timeout the tick frees what
// it buffered and leaves the association standing. The contract (ARCHITECTURE
// 3.6, "Delivering an in-flow packet"): a stuck cursor holding a gap gives up
// its buffered packets, keeps its cursor and epoch so the sender can resend
// into the same gap, and a flow still making progress or already finished is
// left alone.
//
// HOLDING A JAM OPEN. Dropping the flow's head once is not enough: a reliable
// flow whose head is lost retransmits it within a round trip once it has an RTT
// sample, and on loopback that sample arrives at once, so the gap fills and no
// jam forms. The sender's configured retry interval does not hold it either,
// because that interval is only the fallback before an RTT sample exists. So
// the jam is made real by keeping the head lost: the sender's socket is set to
// drop everything once the burst is on the wire, which discards every
// retransmit of the head. The rest of the burst was already sent, so it reaches
// the receiver and pins the hold-back, and the cursor stays stuck for good.
//
// WHAT PROVES THE RECLAIM. The receiver subscribes to PEER_FLOW_JAMMED, which
// fires exactly when the sweep finds a jam and takes something back. Watching
// for it is what turns "the association still exists" into "the jam was
// actually reclaimed" rather than "nothing happened". The event is silent for a
// flow that keeps progressing, which the second phase relies on.
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

#include <atomic>
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

    // Counts the flow-jammed events a socket delivers, so a test can tell that a
    // reclaim actually fired rather than only that a flow still exists.
    struct JamWatch { std::atomic<int> jammed{0}; };

    void OnFlowEvent(void* context, const flux::EventInfo& info)
    {
        if (context != nullptr && info.Has(flux::SocketEvent::PEER_FLOW_JAMMED))
            static_cast<JamWatch*>(context)->jammed.fetch_add(1, std::memory_order_relaxed);
    }

    // stallMicros sizes the receiver's jam timeout; retryMicros sizes the
    // sender's retransmit clock. A non-null watch subscribes the socket to
    // PEER_FLOW_JAMMED, which is how the reclaim is observed.
    common::Error Init(flux::Socket& s, uint16_t port, uint32_t stallMicros, uint32_t retryMicros,
                       JamWatch* watch = nullptr)
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
        if (watch != nullptr)
        {
            c.events.hook       = &OnFlowEvent;
            c.events.context    = watch;
            c.events.subscribed = flux::ToBits(flux::SocketEvent::PEER_FLOW_JAMMED);
        }
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

    // Opens a persistent gap at a flow's head. The head (seq 1) is dropped as it
    // leaves, then the sender's socket is blacked out so every retransmit of it
    // is discarded too. seq 2..count are already on the wire by then, so they
    // reach the receiver and pin the hold-back behind the gap. Returns false if
    // the head was not the datagram dropped, which would leave no gap.
    bool JamHead(flux::Socket& client, uint16_t clientPort,
                 const flux::FlowHandle& flow, const flux::Address& serverAddr,
                 uint32_t count)
    {
        auto* faulty = flux::platform::FaultySocket::ForPort(clientPort);
        if (!faulty) return false;

        // Drain anything owed first, so the head is the only datagram in flight
        // when the drop is armed. The tick that receives also produces the acks
        // this side owes, and one of those leaving first would eat the drop.
        for (int i = 0; i < 8; ++i) { client.Update(); client.Flush(); }

        const uint64_t droppedBefore = faulty->GetStats().dropped;

        // The head alone, flushed with the drop armed, so it is unambiguously
        // the datagram discarded rather than a batched control packet.
        faulty->DropNext(1);
        if (client.BuildPacket().WithFlow(flow).PutU32(0).Send(serverAddr) != common::Error::Ok)
            return false;
        // Push until the head actually leaves and is discarded. Owed acks were
        // drained above and the server is not ticked here, so nothing new to
        // ack is produced and the head is the only datagram this raises; a
        // prior flow can otherwise defer a new flow's first packet to the next
        // tick, where a bare Flush never sends it.
        for (int i = 0; i < 16 && faulty->GetStats().dropped == droppedBefore; ++i)
        {
            client.Flush();
            client.Update();
        }
        if (faulty->GetStats().dropped != droppedBefore + 1)
            return false;   // the head was not the datagram dropped

        // The rest reach the receiver and pile up behind the gap. Push until
        // they actually leave, for the same reason the head needed pushing: a
        // new flow's first datagram can be deferred a tick. The head has no ack
        // and no RTT sample of its own yet, so it does not retransmit inside
        // this short window and reach the receiver ahead of the blackout.
        const uint64_t sentBefore = faulty->GetStats().sent;
        for (uint32_t v = 1; v < count; ++v)
            if (client.BuildPacket().WithFlow(flow).PutU32(v).Send(serverAddr) != common::Error::Ok)
                break;
        for (int i = 0; i < 16 && faulty->GetStats().sent == sentBefore; ++i)
        {
            client.Flush();
            client.Update();
        }

        // Keep the head lost. From here every packet the sender puts out, which
        // is its retransmits of the head, is discarded, so the gap never fills.
        flux::platform::FaultySocket::Profile blackout{};
        blackout.lossPercent = 100;
        blackout.applyTo     = flux::platform::FaultySocket::Direction::Send;
        faulty->SetProfile(blackout);
        return true;
    }

    // 1. A jammed flow gives up what it buffered once the stall timeout passes,
    //    and keeps its association.
    void JammedFlowKeepsAssociation()
    {
        const uint16_t CLIENT = 20860, SERVER = 20861;
        JamWatch watch;
        flux::Socket client, server;
        CHECK(Init(client, CLIENT, 0 /*server stall unused*/, 10'000'000) == common::Error::Ok);
        CHECK(Init(server, SERVER, 250'000 /*250 ms*/, 200'000, &watch) == common::Error::Ok);
        const flux::Address serverAddr = Loopback(SERVER), clientAddr = Loopback(CLIENT);
        CHECK(Connect(client, server, serverAddr, clientAddr));

        Pump(client, server, 20);   // quiesce: flush any handshake acks

        flux::FlowHandle flow = client.OpenFlow(11, flux::FlowMode::RELIABLE_ORDERED);
        CHECK(!flow.Failed());
        CHECK(JamHead(client, CLIENT, flow, serverAddr, 20));

        // The head stays lost, so the receiver holds seq 2.. behind the gap and
        // delivers nothing. The 250 ms stall has not elapsed in this window, so
        // nothing is reclaimed yet.
        flux::PacketSlotHandle inbox[64];
        uint32_t delivered = 0;
        for (int i = 0; i < 120; ++i)
        {
            client.Flush();
            client.Update();
            server.Update();
            flux::PollCursor cursor = server.Poll(inbox, 64);
            delivered += cursor.PacketCount();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        for (auto& h : inbox) h = flux::PacketSlotHandle::Invalid();
        CHECK(delivered == 0);                              // nothing past the gap
        CHECK(server.ReceivingFlowCount(clientAddr) == 1);  // the jammed flow is there

        // Past the stall timeout the tick reclaims the buffer, which fires the
        // event and frees what the gap pinned.
        const auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(500))
        {
            server.Flush();
            server.Update();
            server.Poll(inbox, 64);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        for (auto& h : inbox) h = flux::PacketSlotHandle::Invalid();
        CHECK(watch.jammed.load() >= 1);                    // the jam was actually taken back
        // The buffered packets are gone, but the association is not. Destroying
        // it would restart this side at sequence one while the sender is far
        // past that, and nothing either of them sent afterwards could line up.
        CHECK(server.ReceivingFlowCount(clientAddr) == 1);
        CHECK(Established(server, clientAddr));

        client.Shutdown();
        server.Shutdown();
    }

    // 2. A flow that keeps making progress under loss is never evicted, even when
    //    it runs longer than the stall timeout in wall-clock, and it completes.
    void ProgressingFlowSpared()
    {
        const uint16_t CLIENT = 20862, SERVER = 20863;
        JamWatch watch;
        flux::Socket client, server;
        CHECK(Init(client, CLIENT, 2'000'000, 200'000) == common::Error::Ok);
        CHECK(Init(server, SERVER, 2'000'000 /*generous, > a few RTOs*/, 200'000, &watch) == common::Error::Ok);
        const flux::Address serverAddr = Loopback(SERVER), clientAddr = Loopback(CLIENT);
        CHECK(Connect(client, server, serverAddr, clientAddr));

        // 5% loss both ways: the cursor stalls briefly on a lost packet and
        // recovers well inside the 2 s timeout, so it must never be judged jammed.
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
        CHECK(watch.jammed.load() == 0); // and never reported jammed
        CHECK(delivered == BURST);      // and it finished

        client.Shutdown();
        server.Shutdown();
    }

    // 3. Reclaiming one peer's jammed flow leaves its healthy sibling and the
    //    peer itself untouched.
    void SiblingSurvives()
    {
        const uint16_t CLIENT = 20864, SERVER = 20865;
        JamWatch watch;
        flux::Socket client, server;
        CHECK(Init(client, CLIENT, 0, 10'000'000) == common::Error::Ok);
        CHECK(Init(server, SERVER, 250'000, 200'000, &watch) == common::Error::Ok);
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

        // A second flow, jammed the same way as phase 1. The healthy flow has
        // drained and been acked, so the sender blackout that holds the jam open
        // leaves nothing of it to resend.
        flux::FlowHandle jam = client.OpenFlow(31, flux::FlowMode::RELIABLE_ORDERED);
        CHECK(!jam.Failed());
        CHECK(JamHead(client, CLIENT, jam, serverAddr, 20));
        for (int i = 0; i < 120; ++i)
        {
            client.Flush();
            client.Update();
            server.Update();
            server.Poll(inbox, 64);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        for (auto& h : inbox) h = flux::PacketSlotHandle::Invalid();
        CHECK(server.ReceivingFlowCount(clientAddr) == 2);   // healthy + jammed

        // Past the timeout, the jammed flow's buffer is taken back. Both
        // associations stand, and only the jammed one is reported.
        const auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(500))
        {
            server.Flush();
            server.Update(); server.Poll(inbox, 64);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        for (auto& h : inbox) h = flux::PacketSlotHandle::Invalid();
        CHECK(watch.jammed.load() == 1);                     // exactly one flow reclaimed
        CHECK(server.ReceivingFlowCount(clientAddr) == 2);   // both stand
        CHECK(Established(server, clientAddr));               // peer intact

        client.Shutdown();
        server.Shutdown();
    }
}

int main()
{
    JammedFlowKeepsAssociation();
    ProgressingFlowSpared();
    SiblingSurvives();
    return test::report();
}
