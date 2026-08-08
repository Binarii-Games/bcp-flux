// The last packet of a stream is lost and nothing follows it.
//
// WHY THIS ONE NEEDS THE TIMER. Every other loss in the suite is found from
// the acknowledgements: the receiver reports sequences above the hole, and
// three of them, or one outstanding past the reordering allowance, is proof
// the missing one is gone. A tail loss produces none of that evidence. The
// receiver's cursor sits below the hole, there is nothing above it to
// acknowledge, and no reply the receiver could possibly send names the packet
// that vanished. The only thing that can recover it is the sender's own
// deadline expiring and putting a probe on the wire.
//
// So this is the one test where the timeout is the mechanism under test rather
// than the slow path being beaten. If the probe timer stops firing, or backs
// off past the flow's patience, or a refused pacing allowance silently
// swallows the retransmit, this is what goes red.
//
// THE LOSS IS CONFIRMED, NOT ASSUMED. The link is cut outright, exactly one
// packet is offered into it, and the injector's own count is checked before
// the test goes on. Arming a drop and hoping it lands on the packet of
// interest does not work here, because the tick that receives also produces
// the acknowledgements owed, and the arming lands on one of those instead.
//
// The recovery time is printed and not asserted. What is asserted is that the
// stream completes and completes in order, which is the contract.
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
    constexpr uint16_t BASE_PORT  = 25600;
    constexpr uint16_t FLOW_ID    = 71;
    constexpr uint32_t MESSAGES   = 12;
    /** One message fills a datagram. A batch takes ONE flow sequence for
        everything packed into it, so small messages would put the whole
        stream into a couple of sequences and there would be no distinct tail
        packet to lose. */
    constexpr uint32_t PAYLOAD    = 1000;
    constexpr uint32_t LATENCY_US = 15000;

    using Clock = std::chrono::steady_clock;

    void SetLink(flux::platform::FaultySocket* kernel, uint8_t lossPercent)
    {
        flux::platform::FaultySocket::Profile profile{};
        // Outbound only, so cutting the link to lose one data packet does not
        // also swallow the acknowledgements coming back. The injector's count
        // could not tell which it had taken.
        profile.applyTo       = flux::platform::FaultySocket::Direction::Send;
        profile.latencyMicros = LATENCY_US;
        profile.jitterMicros  = LATENCY_US / 4;
        profile.lossPercent   = lossPercent;
        profile.seed          = 0x7A11;
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
    SetLink(senderKernel, 0);

    flux::FlowHandle flow = sender.OpenFlow(FLOW_ID, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!flow.Failed());

    uint32_t offered   = 0;
    uint32_t delivered = 0;
    bool     wrong     = false;

    flux::PacketSlotHandle inbox[64];

    uint8_t filler[PAYLOAD - sizeof(uint32_t)];
    std::memset(filler, 0xC3, sizeof(filler));

    auto offer = [&]
    {
        return sender.BuildPacket().WithFlow(flow).PutU32(offered)
                     .PutBytes(filler, sizeof(filler)).Send(receiverAddr);
    };

    auto collect = [&]
    {
        flux::PollCursor cursor = receiver.Poll(inbox, 64);
        while (cursor.Next())
        {
            uint32_t value = 0;
            if (!cursor.Message().TakeU32(value)) continue;
            if (value != delivered) wrong = true;
            else                    ++delivered;
        }
    };

    // Everything but the last message, delivered cleanly, so the path has a
    // measured round trip to build a deadline from.
    while (offered < MESSAGES - 1 && offer() == common::Error::Ok)
        ++offered;

    {
        const auto until = Clock::now() + std::chrono::seconds(10);
        while (delivered < MESSAGES - 1 && Clock::now() < until)
        {
            Drive(sender, receiver, inbox, 64);
            collect();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    CHECK(delivered == MESSAGES - 1);

    // The tail. Cut the link, offer exactly one, and wait for the injector to
    // confirm it swallowed something before restoring.
    const uint64_t droppedBefore = senderKernel->GetStats().dropped;
    SetLink(senderKernel, 100);

    CHECK(offer() == common::Error::Ok);
    ++offered;
    sender.Flush();

    {
        const auto until = Clock::now() + std::chrono::seconds(10);
        while (senderKernel->GetStats().dropped == droppedBefore && Clock::now() < until)
        {
            Drive(sender, receiver, inbox, 64);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    CHECK(senderKernel->GetStats().dropped > droppedBefore);

    SetLink(senderKernel, 0);
    const auto lostAt = Clock::now();

    // Nothing more is offered from here. The receiver has no sequence above
    // the hole to report, so no acknowledgement can name the missing packet
    // and only the sender's own deadline can recover it.
    {
        const auto until = Clock::now() + std::chrono::seconds(20);
        while (delivered < MESSAGES && Clock::now() < until)
        {
            Drive(sender, receiver, inbox, 64);
            collect();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    const auto recoveredMs = delivered == MESSAGES
        ? std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - lostAt).count()
        : -1;
    std::printf("tail recovered in %lld ms (round trip about %u ms)\n",
                static_cast<long long>(recoveredMs), LATENCY_US / 1000);

    CHECK(!wrong);
    CHECK(delivered == MESSAGES);

    return test::report();
}
