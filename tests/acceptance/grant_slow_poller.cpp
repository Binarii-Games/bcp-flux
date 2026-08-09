// A peer sending cleanly must not take the receive pool from a slow reader.
//
// The companion test drives its abusive peer through the reorder hold-back, by
// losing that peer's own packets so its cursor sticks. That is one of the ways a
// packet enters the pool, not the only one. A peer whose packets all arrive in
// order buffers nothing: each is delivered straight to the ready queue and holds
// its slot there until the application polls it. So an application that polls
// slowly turns an ordinary sender into the same pressure, with no loss, no
// reordering, and nothing unusual on the wire.
//
// The contract is the same whichever door a packet came through: a peer holds
// what it was granted and no more.
//
// The flooder sends on an UNRELIABLE flow deliberately. A reliable one pins a
// staging slot per unacked packet and stalls on its own accounting long before a
// receiver feels anything, which is how an earlier version of this test came to
// pass while measuring nothing. Unreliable retains no copy, so the sender keeps
// pushing and the pressure is real.
//
// The reserve is set to one slot in both phases. It is a second, independent
// defence, and leaving it at its default would protect the receiver even with no
// grant, which would hide whether the grant works at all.
//
// THE TEST CONTAINS ITS OWN CONTROL. It runs the same scenario twice, once with
// no grant and once with one, and requires the ungranted run to starve. If both
// runs deliver everything, the setup is not producing pressure and the test
// fails rather than reporting a success it did not earn.
#include <flux/socket/socket.h>
#include <flux/address.h>
#include <flux/wire/packet_builder.h>
#include <flux/socket/packet_slot.h>
#include <flux/flow/flow_handle.h>

#include "flux_net.h"
#include "harness.h"

#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>

namespace flux   = bcp::flux;
namespace common = bcp::common;

namespace
{
    constexpr uint32_t RECV_SLOTS     = 128;
    constexpr uint32_t QUIET_MESSAGES = 16;
    constexpr uint32_t POLL_EVERY     = 60;   // rounds between drains
    constexpr uint32_t FLOOD_PER_ROUND = 24;

    using flux_net::Loopback;
    using flux_net::Established;

    void Pump(flux::Socket& socket)
    {
        flux::PacketSlotHandle inbox[64];
        socket.Update();
        { flux::PollCursor cursor = socket.Poll(inbox, 64); while (cursor.Next()) {} }
        socket.Flush();
    }

    bool Connect(flux::Socket& from, flux::Socket& to,
                 const flux::Address& toAddr, const flux::Address& fromAddr)
    {
        (void)from.BuildPacket().NoFlow().PutU8(1).Send(toAddr);
        const auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::seconds(10))
        {
            Pump(from);
            Pump(to);
            if (Established(from, toAddr) && Established(to, fromAddr)) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return false;
    }

    // How many of the quiet peer's messages reached the application.
    uint32_t RunPhase(uint32_t grant, uint16_t basePort)
    {
        const uint16_t receiverPort = basePort;
        const uint16_t flooderPort  = static_cast<uint16_t>(basePort + 1);
        const uint16_t quietPort    = static_cast<uint16_t>(basePort + 2);

        flux::Socket receiver, flooder, quiet;

        flux::Socket::Config rc{};
        rc.type             = flux_net::BACKEND;
        rc.port             = receiverPort;
        rc.maxPeers         = 8;
        rc.recvSlotCount    = RECV_SLOTS;
        rc.recvReserveSlots = 1;   // the grant is what is under test, not this
        rc.flows.outCount      = 8;
        rc.flows.inCount       = 8;
        rc.flows.stagingCount  = 256;
        rc.flows.recvGrant     = grant;
        if (receiver.Init(rc) != common::Error::Ok) return 0;

        flux::Socket::Config sc{};
        sc.type     = flux_net::BACKEND;
        sc.maxPeers = 8;
        sc.flows.outCount = 8;
        sc.flows.inCount  = 8;
        sc.flows.stagingCount        = 1024;
        sc.flows.reliableWaitCount   = 1024;
        sc.flows.unreliableWaitCount = 4096;
        sc.flows.minCongestionBudget = 64u * 1024u * 1024u;
        sc.port = flooderPort;
        if (flooder.Init(sc) != common::Error::Ok) return 0;
        sc.port = quietPort;
        if (quiet.Init(sc) != common::Error::Ok) return 0;

        const flux::Address receiverAddr = Loopback(receiverPort);
        if (!Connect(flooder, receiver, receiverAddr, Loopback(flooderPort))) return 0;
        if (!Connect(quiet,   receiver, receiverAddr, Loopback(quietPort)))   return 0;

        flux::FlowHandle floodFlow = flooder.OpenFlow(41, flux::FlowMode::UNRELIABLE);
        flux::FlowHandle quietFlow = quiet.OpenFlow(42, flux::FlowMode::RELIABLE_ORDERED);
        if (floodFlow.Failed() || quietFlow.Failed()) return 0;

        const std::vector<uint8_t> body(400, 0x77);
        std::vector<bool> arrived(QUIET_MESSAGES, false);
        uint32_t delivered = 0, sent = 0, round = 0;

        const auto start = std::chrono::steady_clock::now();
        while (delivered < QUIET_MESSAGES &&
               std::chrono::steady_clock::now() - start < std::chrono::seconds(12))
        {
            for (uint32_t i = 0; i < FLOOD_PER_ROUND; ++i)
                (void)flooder.BuildPacket().WithFlow(floodFlow)
                             .PutBytes(body.data(), body.size()).Send(receiverAddr);
            flooder.Flush();

            if (sent < QUIET_MESSAGES)
            {
                const uint32_t tag = sent;
                if (quiet.BuildPacket().WithFlow(quietFlow).PutU32(tag)
                         .Send(receiverAddr) == common::Error::Ok)
                    ++sent;
            }
            quiet.Flush();

            receiver.Update();   // takes packets off the socket every round
            if (++round % POLL_EVERY == 0)   // but the application collects rarely
            {
                flux::PacketSlotHandle inbox[64];
                flux::PollCursor cursor = receiver.Poll(inbox, 64);
                while (cursor.Next())
                {
                    flux::PacketSlotReader& reader = cursor.Message();
                    uint32_t tag = 0;
                    if (reader.TakeU32(tag) && tag < QUIET_MESSAGES && !arrived[tag])
                    {
                        arrived[tag] = true;
                        ++delivered;
                    }
                }
            }
            receiver.Flush();
            Pump(quiet);
            Pump(flooder);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        quiet.CloseFlow(quietFlow);
        flooder.CloseFlow(floodFlow);
        receiver.Shutdown();
        flooder.Shutdown();
        quiet.Shutdown();
        return delivered;
    }
}

int main()
{
    const uint32_t ungranted = RunPhase(0,  24330);
    const uint32_t granted   = RunPhase(16, 24340);

    std::printf("quiet peer delivered: %u/%u ungranted, %u/%u granted\n",
                ungranted, QUIET_MESSAGES, granted, QUIET_MESSAGES);

    // The control. Without a grant the flooder must take the pool and starve the
    // quiet peer. If this passes, the scenario is not applying pressure and
    // nothing below means anything.
    CHECK(ungranted < QUIET_MESSAGES);

    // And with one, every message arrives.
    CHECK(granted == QUIET_MESSAGES);
    return test::report();
}
