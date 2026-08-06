// Four peers, one receiver, every link losing packets.
//
// flow_fault_recovery already puts one client on ten damaged links, which asks
// whether recovery works. This asks something that only appears with several
// peers at once: whether it works for all of them, independently, while they
// compete for the same receiver.
//
// Every sender uses THE SAME FLOW ID. Flow ids are each peer's own choice, so
// two peers picking 60 is ordinary, and it is the case where a receiver that
// keyed anything on the id alone rather than on the peer would mix two streams
// together and nobody would notice until the bytes were wrong.
//
// THE CONTRACT, checked per peer rather than in total. Reliable ordered means
// every message arrives, once, in send order. So each sender's stream is
// verified as a strict run from zero: a repeat, a gap or a swap all fail, and a
// total that happens to add up cannot cover for a stream that did not.
//
// It also has to be all four. Three finishing and one starving satisfies any
// count of delivered messages and is precisely the failure worth catching here,
// which is why each is asserted on its own.
//
// THE CONTROL. Loopback loses nothing, so the run is only meaningful if the
// injected faults actually fired. The test requires packets to have been
// dropped, and fails rather than passing over an undamaged link.
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
#include <thread>

namespace flux   = bcp::flux;
namespace common = bcp::common;

namespace
{
    constexpr uint16_t BASE_PORT = 25480;
    constexpr uint32_t SENDERS   = 4;
    constexpr uint32_t MESSAGES  = 120;
    constexpr uint16_t FLOW_ID   = 60;   // the same id from every peer, on purpose
    constexpr uint8_t  LOSS_PCT  = 8;

    struct Sender
    {
        flux::Socket     socket;
        flux::Address    addr;
        flux::FlowHandle flow;
        uint32_t         offered   = 0;   ///< accepted by Send, so owed delivery
        uint32_t         delivered = 0;   ///< seen by the receiver, in order
        bool             wrong     = false;
    };
}

int main()
{
    flux::Socket::Config receiverConfig{};
    receiverConfig.type               = flux::Socket::BackendType::FAULTY;
    receiverConfig.port               = BASE_PORT;
    receiverConfig.maxPeers           = 8;
    receiverConfig.flows.outCount     = 16;
    receiverConfig.flows.inCount      = 16;
    receiverConfig.flows.maxInPerPeer = 2;

    flux::Socket receiver;
    CHECK(receiver.Init(receiverConfig) == common::Error::Ok);
    const flux::Address receiverAddr = flux_net::Loopback(BASE_PORT);

    Sender senders[SENDERS];
    for (uint32_t i = 0; i < SENDERS; ++i)
    {
        const uint16_t port = static_cast<uint16_t>(BASE_PORT + 1 + i);
        flux::Socket::Config config{};
        config.type           = flux::Socket::BackendType::FAULTY;
        config.port           = port;
        config.maxPeers       = 4;
        config.flows.outCount = 8;
        config.flows.inCount  = 8;
        if (senders[i].socket.Init(config) != common::Error::Ok)
        {
            CHECK(false);
            return test::report();
        }
        senders[i].addr = flux_net::Loopback(port);

        // A seed each, so the four links lose different packets rather than
        // four copies of one pattern, and so a failure replays exactly.
        flux::platform::FaultySocket* kernel = flux::platform::FaultySocket::ForPort(port);
        CHECK(kernel != nullptr);
        if (!kernel) return test::report();
        flux::platform::FaultySocket::Profile profile{};
        profile.applyTo     = flux::platform::FaultySocket::Direction::Both;
        profile.lossPercent = LOSS_PCT;
        profile.seed        = static_cast<uint32_t>(0xF10A0001u + i);
        kernel->SetProfile(profile);
    }

    for (uint32_t i = 0; i < SENDERS; ++i)
    {
        (void)senders[i].socket.Connect(receiverAddr);
        senders[i].flow = senders[i].socket.OpenFlow(FLOW_ID, flux::FlowMode::RELIABLE_ORDERED);
        CHECK(!senders[i].flow.Failed());
    }

    // Scoped, so every delivered handle is released before the sockets are shut
    // down below. A handle outliving its socket releases a slot back into a pool
    // that has been freed.
    {
    flux::PacketSlotHandle inbox[64];
    const auto start = std::chrono::steady_clock::now();

    while (std::chrono::steady_clock::now() - start < std::chrono::seconds(30))
    {
        for (uint32_t i = 0; i < SENDERS; ++i)
        {
            Sender& sender = senders[i];

            // Offer until the transport pushes back. TooManyPending is the
            // backpressure signal, not a failure, so the value is only counted
            // as owed once Send accepted it.
            while (sender.offered < MESSAGES
                   && sender.socket.BuildPacket().WithFlow(sender.flow)
                            .PutU32(sender.offered).Send(receiverAddr) == common::Error::Ok)
                ++sender.offered;

            sender.socket.Flush();
            sender.socket.Update();
            { flux::PollCursor cursor = sender.socket.Poll(inbox, 64);
              while (cursor.Next()) {} }
        }

        receiver.Update();
        {
            flux::PollCursor cursor = receiver.Poll(inbox, 64);
            while (cursor.Next())
            {
                const flux::PacketSlot* packet = cursor.Packet().Read();
                if (!packet) continue;

                // Attributed by peer, never by flow id, because all four use
                // the same one.
                Sender* from = nullptr;
                for (uint32_t i = 0; i < SENDERS; ++i)
                    if (senders[i].addr == packet->address) from = &senders[i];
                if (!from) continue;

                uint32_t value = 0;
                if (!cursor.Message().TakeU32(value)) continue;

                // Strict run from zero. A repeat, a gap or a swap all land here.
                if (value != from->delivered) from->wrong = true;
                else                          ++from->delivered;
            }
        }
        receiver.Flush();

        bool allDone = true;
        for (uint32_t i = 0; i < SENDERS; ++i)
            if (senders[i].delivered < MESSAGES) allDone = false;
        if (allDone) break;

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    }

    uint64_t dropped = 0;
    for (uint32_t i = 0; i < SENDERS; ++i)
    {
        const flux::platform::FaultySocket* kernel = flux::platform::FaultySocket::ForPort(
            static_cast<uint16_t>(BASE_PORT + 1 + i));
        if (kernel) dropped += kernel->GetStats().dropped;
    }

    for (uint32_t i = 0; i < SENDERS; ++i)
    {
        std::printf("peer %u: offered %u, delivered %u%s\n",
                    i, senders[i].offered, senders[i].delivered,
                    senders[i].wrong ? ", OUT OF ORDER" : "");

        // Each on its own. A total would let one starving peer hide behind
        // three fast ones.
        CHECK(!senders[i].wrong);
        CHECK(senders[i].delivered == MESSAGES);
    }

    std::printf("dropped %llu packets across the four links\n",
                static_cast<unsigned long long>(dropped));

    // The control. With an undamaged link none of the recovery ran and the run
    // says nothing about it.
    CHECK(dropped > 0);

    for (uint32_t i = 0; i < SENDERS; ++i) senders[i].socket.Shutdown();
    receiver.Shutdown();
    return test::report();
}
