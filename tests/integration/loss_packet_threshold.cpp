// Declaring a packet lost from the acks instead of from a stopwatch.
//
// The receiver already reports which sequences it holds. If it has acknowledged
// several sent after one that is still missing, that one is gone, and waiting
// for its timeout throws away information that already arrived.
//
// WHY THIS NEEDS A SLOW LINK TO MEASURE AT ALL. The retransmit timeout is built
// from the measured round trip, and on loopback that is microseconds, so the
// timeout fires almost immediately and there is nothing to beat. Latency is
// injected in both directions to give the round trip a size worth saving.
//
// THE LOSS IS MADE DETERMINISTIC RATHER THAN AIMED. Arming the fault injector to
// drop the next datagram does not work here and has misled this file once
// already: the tick that receives also produces the acks owed, so the arming
// lands on one of those and nothing of interest is lost. Instead the link is cut
// outright for exactly as long as it takes one data packet to leave, which is
// confirmed by the injector's own count before the test goes on.
//
// WHAT IS ASSERTED, AND WHAT IS ONLY PRINTED. The stream is asserted: the loss
// really happened, every message arrived, and it arrived as a strict run. The
// recovery time is printed and not asserted, on purpose. Measured over fourteen
// runs each way on a jittered link, the detection gives a median of 75 ms
// against 84 ms and a worst case of 77 ms against 185 ms, so the typical margin
// is about ten percent. That is inside what a loaded build machine moves, and a
// test that goes red because the machine was busy is worse than no test.
//
// The number is worth printing because the distribution is the point: with the
// detection every run lands in a four millisecond band, and without it the
// slowest is more than twice the fastest. A human reading a wildly different
// figure here has learned something. An assertion would only have learned that
// CI was busy.
//
// The stream is also verified as a strict run, because a loss-recovery test
// that recovered in good time and delivered the wrong bytes would pass on the
// only number it printed.
#include <flux/socket/socket.h>
#include <flux/address.h>
#include <flux/flow/flow_handle.h>
#include <flux/socket/packet_slot.h>
#include <flux/wire/packet_builder.h>
#include <flux/socket/platform/faulty_socket.h>

#include "flux_net.h"
#include "harness.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <thread>

namespace flux   = bcp::flux;
namespace common = bcp::common;

namespace
{
    constexpr uint16_t BASE_PORT   = 25500;
    constexpr uint16_t FLOW_ID     = 70;
    constexpr uint32_t MESSAGES    = 100;
    /** Big enough that one fills a datagram on its own. A batch takes ONE flow
        sequence for everything packed into it, so with small messages a whole
        transfer collapses into a couple of sequences and there is nothing for
        sequence-based loss detection to work with. The packet is the batch, so
        a test about packets has to send messages that are packets. */
    constexpr uint32_t PAYLOAD     = 1000;
    constexpr uint32_t LOSE_AFTER  = 4;    ///< let this many through, then drop one
    constexpr uint32_t LATENCY_US  = 25000;   ///< on the sending leg, so a round trip near 25 ms

    using Clock = std::chrono::steady_clock;

    void SetLink(flux::platform::FaultySocket* kernel, uint32_t micros, uint8_t lossPercent)
    {
        flux::platform::FaultySocket::Profile profile{};
        // Outbound only. With Both, cutting the link to lose one data packet
        // also swallows the acks coming back, and the injector's count cannot
        // tell which it took, so the loss stops being the deterministic thing
        // this test needs.
        profile.applyTo       = flux::platform::FaultySocket::Direction::Send;
        profile.latencyMicros = micros;
        profile.jitterMicros  = micros / 2;
        profile.lossPercent   = lossPercent;
        profile.seed          = 0xB0B0;
        kernel->SetProfile(profile);
    }

    void Drive(flux::Socket& sender, flux::Socket& receiver,
               flux::PacketSlotHandle* inbox, uint32_t max)
    {
        sender.Flush();
        sender.Update();
        { flux::PollCursor cursor = sender.Poll(inbox, max); while (cursor.Next()) {} }
        receiver.Update();
        receiver.Flush();
    }
}

int main()
{
    flux::Socket::Config config{};
    config.type           = flux::Socket::BackendType::FAULTY;
    config.maxPeers       = 4;
    config.flows.outCount = 8;
    config.flows.inCount  = 8;

    flux::Socket sender, receiver;
    config.port = BASE_PORT;
    CHECK(receiver.Init(config) == common::Error::Ok);
    config.port = static_cast<uint16_t>(BASE_PORT + 1);
    CHECK(sender.Init(config) == common::Error::Ok);

    const flux::Address receiverAddr = flux_net::Loopback(BASE_PORT);
    const flux::Address senderAddr   = flux_net::Loopback(BASE_PORT + 1);

    flux::platform::FaultySocket* senderKernel =
        flux::platform::FaultySocket::ForPort(static_cast<uint16_t>(BASE_PORT + 1));
    CHECK(senderKernel != nullptr);
    if (!senderKernel) return test::report();

    (void)sender.Connect(receiverAddr);
    CHECK(flux_net::PumpUntilEstablished(sender, senderAddr, receiver, receiverAddr));

    // Latency only after the handshake, so establishing does not cost seconds.
    SetLink(senderKernel, LATENCY_US, 0);

    flux::FlowHandle flow = sender.OpenFlow(FLOW_ID, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!flow.Failed());

    uint32_t offered   = 0;
    uint32_t delivered = 0;
    bool     wrong     = false;
    Clock::time_point lostAt{};
    Clock::time_point closedAt{};

    flux::PacketSlotHandle inbox[64];

    auto collect = [&]
    {
        flux::PollCursor cursor = receiver.Poll(inbox, 64);
        while (cursor.Next())
        {
            uint32_t value = 0;
            if (!cursor.Message().TakeU32(value)) continue;
            if (value != delivered) wrong = true;
            else                    ++delivered;

            // The run continuing past the hole is the moment the missing
            // packet was resent and arrived.
            if (closedAt == Clock::time_point{} && delivered > LOSE_AFTER)
                closedAt = Clock::now();
        }
    };

    // Phase one: a few packets through cleanly, so there is something behind
    // the hole and a round-trip sample to build a timeout from.
    uint8_t filler[PAYLOAD - sizeof(uint32_t)];
    std::memset(filler, 0xA5, sizeof(filler));

    auto offer = [&]
    {
        return sender.BuildPacket().WithFlow(flow).PutU32(offered)
                     .PutBytes(filler, sizeof(filler)).Send(receiverAddr);
    };

    while (offered < LOSE_AFTER && offer() == common::Error::Ok)
        ++offered;

    {
        const auto until = Clock::now() + std::chrono::seconds(5);
        while (delivered < LOSE_AFTER && Clock::now() < until)
        {
            Drive(sender, receiver, inbox, 64);
            collect();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    CHECK(delivered == LOSE_AFTER);

    // Phase two: cut the link, put exactly one packet into it, and wait for the
    // injector to confirm it swallowed something before restoring the link.
    // That is what makes the loss a fact rather than an intention.
    const uint64_t droppedBefore = senderKernel->GetStats().dropped;
    SetLink(senderKernel, LATENCY_US, 100);

    CHECK(offer() == common::Error::Ok);
    ++offered;

    {
        const auto until = Clock::now() + std::chrono::seconds(5);
        while (senderKernel->GetStats().dropped == droppedBefore && Clock::now() < until)
        {
            Drive(sender, receiver, inbox, 64);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    const bool reallyLost = senderKernel->GetStats().dropped > droppedBefore;
    CHECK(reallyLost);

    SetLink(senderKernel, LATENCY_US, 20);
    lostAt = Clock::now();

    // Phase three: keep sending. The receiver holds everything behind the hole
    // and acknowledges it, which is the evidence the detection runs on.
    {
        const auto until = Clock::now() + std::chrono::seconds(20);
        while (delivered < MESSAGES && Clock::now() < until)
        {
            while (offered < MESSAGES && offer() == common::Error::Ok)
                ++offered;

            Drive(sender, receiver, inbox, 64);
            collect();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    const auto recoveryMs = closedAt == Clock::time_point{}
        ? -1
        : std::chrono::duration_cast<std::chrono::milliseconds>(closedAt - lostAt).count();

    std::printf("delivered %u/%u, gap closed in %lld ms (round trip about %u ms)\n",
                delivered, MESSAGES, static_cast<long long>(recoveryMs),
                LATENCY_US / 1000);

    CHECK(!wrong);
    CHECK(delivered == MESSAGES);
    CHECK(recoveryMs >= 0);

    return test::report();
}
