// Events under several threads polling one socket at once.
//
// Update and Poll are both documented as safe to call concurrently, and events
// are dispatched from Poll, so everything the event table does to stay correct
// under contention only runs in this shape. Single-threaded runs never take the
// compare-exchange retry, never take an entry from a previous occupant, and
// never have two threads walking entries at the same time. This test is what
// puts those paths in front of a thread sanitizer.
//
// Two things are asserted, and the first is the one that matters.
//
// EVENTS MATCH STATE. Every receiving flow the socket registers raises exactly
// one INCOMING_FLOW_OPENED, so the number of events delivered for a peer has to
// equal the number of flows the socket says that peer holds. Events are a nudge
// toward state, and a nudge that does not agree with the state it points at is
// worthless. This is the assertion that fails if a race loses one.
//
// ONE PEER, ONE HANDLER AT A TIME. Delivery is split into lanes so a peer's
// traffic reaches one thread, and events are stamped with their peer's lane so
// they follow it. An application is told it may hold per-peer state without a
// lock, so two handlers running for the same peer at once would break a promise
// the library makes rather than merely being untidy.
//
// THE TEST CONTAINS ITS OWN CONTROL. It requires that flows actually registered
// and events actually arrived. Without that a run where nothing connected would
// satisfy every assertion above by having nothing to check.
#include <flux/socket/socket.h>
#include <flux/address.h>
#include <flux/flow/flow_handle.h>
#include <flux/socket/packet_slot.h>
#include <flux/wire/packet_builder.h>

#include "flux_net.h"
#include "harness.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>

namespace flux   = bcp::flux;
namespace common = bcp::common;

namespace
{
    constexpr uint16_t BASE_PORT      = 25400;
    constexpr uint32_t SENDERS        = 4;
    constexpr uint32_t FLOWS_PER      = 4;
    constexpr uint32_t RECEIVER_LANES = 4;

    struct SenderView
    {
        flux::Address         addr;
        std::atomic<uint32_t> events{0};
        /** Raised while a handler for this peer is running. A second handler
            finding it already raised is the lane guarantee broken. */
        std::atomic<bool>     inHandler{false};
    };

    struct Watch
    {
        SenderView            senders[SENDERS];
        std::atomic<uint32_t> overlaps{0};
        std::atomic<uint32_t> unknown{0};
    };

    void OnReceiverEvent(void* context, const flux::EventInfo& info)
    {
        Watch& watch = *static_cast<Watch*>(context);
        if (!info.Has(flux::SocketEvent::INCOMING_FLOW_OPENED)) return;

        for (uint32_t i = 0; i < SENDERS; ++i)
        {
            if (!(watch.senders[i].addr == info.Peer())) continue;

            if (watch.senders[i].inHandler.exchange(true))
                watch.overlaps.fetch_add(1);

            watch.senders[i].events.fetch_add(1);
            watch.senders[i].inHandler.store(false);
            return;
        }
        watch.unknown.fetch_add(1);
    }
}

int main()
{
    Watch watch;

    flux::Socket::Config receiverConfig{};
    receiverConfig.type               = flux_net::BACKEND;
    receiverConfig.port               = BASE_PORT;
    receiverConfig.maxPeers           = 16;
    receiverConfig.pollLanes          = RECEIVER_LANES;
    receiverConfig.flows.inCount      = 64;
    receiverConfig.flows.outCount     = 64;
    receiverConfig.flows.maxInPerPeer = FLOWS_PER;
    receiverConfig.events.hook        = OnReceiverEvent;
    receiverConfig.events.context     = &watch;
    receiverConfig.events.subscribed  = flux::ToBits(flux::SocketEvent::INCOMING_FLOW_OPENED);

    flux::Socket receiver;
    CHECK(receiver.Init(receiverConfig) == common::Error::Ok);

    const flux::Address receiverAddr = flux_net::Loopback(BASE_PORT);

    flux::Socket senders[SENDERS];
    for (uint32_t i = 0; i < SENDERS; ++i)
    {
        const uint16_t port = static_cast<uint16_t>(BASE_PORT + 1 + i);
        flux::Socket::Config config{};
        config.type            = flux_net::BACKEND;
        config.port            = port;
        config.maxPeers        = 4;
        config.flows.outCount  = 16;
        config.flows.inCount   = 16;
        if (senders[i].Init(config) != common::Error::Ok)
        {
            CHECK(false);
            return test::report();
        }
        watch.senders[i].addr = flux_net::Loopback(port);
    }

    // Four threads drive the receiver at once, each preferring its own lane.
    // This is the shape the event table exists to survive.
    std::atomic<bool> stop{false};
    std::thread pollers[RECEIVER_LANES];
    for (uint32_t lane = 0; lane < RECEIVER_LANES; ++lane)
    {
        pollers[lane] = std::thread([&receiver, &stop, lane]
        {
            flux::PacketSlotHandle inbox[32];
            flux::ThreadIdentity identity{lane};
            while (!stop.load(std::memory_order_relaxed))
            {
                receiver.Update();
                flux::PollCursor cursor = receiver.Poll(inbox, 32, identity);
                while (cursor.Next()) {}
            }
        });
    }

    // Every sender opens its flows and keeps offering on them, on its own
    // thread, so registrations land on the receiver while every poller is busy.
    std::thread senderThreads[SENDERS];
    for (uint32_t i = 0; i < SENDERS; ++i)
    {
        senderThreads[i] = std::thread([&senders, &stop, receiverAddr, i]
        {
            flux::FlowHandle flows[FLOWS_PER];
            for (uint32_t f = 0; f < FLOWS_PER; ++f)
                flows[f] = senders[i].OpenFlow(static_cast<uint16_t>(40 + f),
                                               flux::FlowMode::RELIABLE_ORDERED);

            flux::PacketSlotHandle inbox[16];
            while (!stop.load(std::memory_order_relaxed))
            {
                for (uint32_t f = 0; f < FLOWS_PER; ++f)
                    (void)senders[i].BuildPacket().WithFlow(flows[f])
                                    .PutU32(f).Send(receiverAddr);
                senders[i].Flush();
                senders[i].Update();
                flux::PollCursor cursor = senders[i].Poll(inbox, 16);
                while (cursor.Next()) {}
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }

            for (uint32_t f = 0; f < FLOWS_PER; ++f)
                (void)senders[i].CloseFlow(flows[f]);
        });
    }

    std::this_thread::sleep_for(std::chrono::seconds(3));
    stop.store(true, std::memory_order_relaxed);
    for (std::thread& thread : senderThreads) thread.join();

    // The pollers run on a little longer, so anything recorded by the last
    // registrations has a poll to come out on.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    for (std::thread& thread : pollers) thread.join();

    // Every event named a peer this test created.
    CHECK(watch.unknown.load() == 0);

    // Two handlers never ran for one peer at the same time.
    CHECK(watch.overlaps.load() == 0);

    // The assertion that matters: what was reported equals what the socket
    // holds, per peer.
    uint32_t registeredTotal = 0;
    uint32_t eventTotal      = 0;
    for (uint32_t i = 0; i < SENDERS; ++i)
    {
        const uint32_t registered = receiver.ReceivingFlowCount(watch.senders[i].addr);
        const uint32_t events     = watch.senders[i].events.load();
        CHECK(events == registered);
        registeredTotal += registered;
        eventTotal      += events;
    }

    std::printf("registered %u flows across %u peers, %u events delivered\n",
                registeredTotal, SENDERS, eventTotal);

    // The control. If nothing connected, every check above passes on empty
    // counts and the run proves nothing.
    CHECK(registeredTotal == SENDERS * FLOWS_PER);
    CHECK(eventTotal > 0);

    for (uint32_t i = 0; i < SENDERS; ++i) senders[i].Shutdown();
    receiver.Shutdown();
    return test::report();
}
