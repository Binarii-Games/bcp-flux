// Every flow-scoped event, made to fire on purpose.
//
// The event table can be right and still report nothing, because an event that
// no code path reaches is indistinguishable from one that works. This walks the
// four flow events through the situation each is meant to describe and requires
// that each arrives, once, naming the right flow.
//
// It runs as four phases against one pair of sockets, in an order the phases
// depend on. The receiver takes one flow per remote, which is what makes the
// third phase a refusal, and the receiver is shut down for the fourth, which is
// what makes the sender run out of retransmits.
//
// A refusal is final for the generation it refused, so each phase uses ids the
// earlier ones did not, except where reusing one is the point.
#include <flux/socket/socket.h>
#include <flux/address.h>
#include <flux/flow/flow_handle.h>
#include <flux/socket/packet_slot.h>
#include <flux/wire/packet_builder.h>

#include "flux_net.h"
#include "harness.h"

#include <chrono>
#include <cstdint>
#include <thread>

namespace flux   = bcp::flux;
namespace common = bcp::common;

namespace
{
    constexpr uint16_t BASE_PORT  = 25440;
    constexpr uint16_t FLOW_MAIN  = 30;
    constexpr uint16_t FLOW_EXTRA = 31;

    // What a hook saw. Counted per event, with the flow id of the last one, so a
    // test can require both that it fired and that it named the right flow.
    struct Seen
    {
        uint32_t opened = 0, reopened = 0, refused = 0, lost = 0;
        uint16_t lastOpened = 0, lastReopened = 0, lastRefused = 0, lastLost = 0;
    };

    void OnReceiverEvent(void* context, const flux::EventInfo& info)
    {
        Seen& seen = *static_cast<Seen*>(context);
        if (info.Has(flux::SocketEvent::INCOMING_FLOW_OPENED))
        {
            ++seen.opened;
            seen.lastOpened = info.Flow();
        }
        if (info.Has(flux::SocketEvent::INCOMING_FLOW_REOPENED))
        {
            ++seen.reopened;
            seen.lastReopened = info.Flow();
        }
    }

    void OnSenderEvent(void* context, const flux::EventInfo& info)
    {
        Seen& seen = *static_cast<Seen*>(context);
        if (info.Has(flux::SocketEvent::OUTGOING_FLOW_REFUSED))
        {
            ++seen.refused;
            seen.lastRefused = info.Flow();
        }
        if (info.Has(flux::SocketEvent::OUTGOING_FLOW_LOST))
        {
            ++seen.lost;
            seen.lastLost = info.Flow();
        }
    }

    void Drive(flux::Socket& sender, flux::Socket* receiver)
    {
        flux::PacketSlotHandle inbox[16];
        sender.Update();
        { flux::PollCursor cursor = sender.Poll(inbox, 16); while (cursor.Next()) {} }
        sender.Flush();
        if (!receiver) return;
        receiver->Update();
        { flux::PollCursor cursor = receiver->Poll(inbox, 16); while (cursor.Next()) {} }
        receiver->Flush();
    }

    // Offers on one flow and drives both sides until `done` says so, or the
    // budget runs out. Returns whether it got there, so a phase that did not
    // reach its situation fails as itself rather than as the event it wanted.
    template <typename Done>
    bool OfferUntil(flux::Socket& sender, flux::Socket* receiver,
                    const flux::Address& to, flux::FlowHandle& flow, Done done)
    {
        const auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::seconds(5))
        {
            (void)sender.BuildPacket().WithFlow(flow).PutU32(1).Send(to);
            sender.Flush();
            Drive(sender, receiver);
            if (done()) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return false;
    }
}

int main()
{
    Seen receiverSeen, senderSeen;

    flux::Socket::Config receiverConfig{};
    receiverConfig.type               = flux_net::BACKEND;
    receiverConfig.port               = BASE_PORT;
    receiverConfig.maxPeers           = 4;
    receiverConfig.flows.outCount     = 8;
    receiverConfig.flows.inCount      = 8;
    // One flow per remote, which is what makes the third phase a refusal
    // rather than a second registration.
    receiverConfig.flows.maxInPerPeer = 1;
    receiverConfig.events.hook        = OnReceiverEvent;
    receiverConfig.events.context     = &receiverSeen;
    receiverConfig.events.subscribed  = flux::ToBits(flux::SocketEvent::INCOMING_FLOW_OPENED)
                                      | flux::ToBits(flux::SocketEvent::INCOMING_FLOW_REOPENED);

    flux::Socket::Config senderConfig{};
    senderConfig.type           = flux_net::BACKEND;
    senderConfig.port           = static_cast<uint16_t>(BASE_PORT + 1);
    senderConfig.maxPeers       = 4;
    senderConfig.flows.outCount = 8;
    senderConfig.flows.inCount  = 8;
    // Short enough that the flow's death happens inside the test rather than
    // inside the five second default. The flow dies when it resolves nothing
    // for this long while owing packets, which is exactly what the shutdown
    // below produces.
    senderConfig.timers.retryIntervalMicros      = 20000;
    senderConfig.liveness.flowStallTimeoutMicros = 300000;
    senderConfig.events.hook       = OnSenderEvent;
    senderConfig.events.context    = &senderSeen;
    senderConfig.events.subscribed = flux::ToBits(flux::SocketEvent::OUTGOING_FLOW_REFUSED)
                                   | flux::ToBits(flux::SocketEvent::OUTGOING_FLOW_LOST);

    flux::Socket receiver, sender;
    CHECK(receiver.Init(receiverConfig) == common::Error::Ok);
    CHECK(sender.Init(senderConfig) == common::Error::Ok);

    const flux::Address receiverAddr = flux_net::Loopback(BASE_PORT);
    const flux::Address senderAddr   = flux_net::Loopback(BASE_PORT + 1);

    (void)sender.Connect(receiverAddr);
    CHECK(flux_net::PumpUntilEstablished(sender, senderAddr, receiver, receiverAddr));

    // --- INCOMING_FLOW_OPENED -------------------------------------------------

    flux::FlowHandle main = sender.OpenFlow(FLOW_MAIN, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!main.Failed());
    CHECK(OfferUntil(sender, &receiver, receiverAddr, main,
                     [&] { return receiverSeen.opened > 0; }));
    CHECK(receiverSeen.opened == 1);
    CHECK(receiverSeen.lastOpened == FLOW_MAIN);

    // --- INCOMING_FLOW_REOPENED -----------------------------------------------
    //
    // Closing puts nothing on the wire, so the receiver still holds the old
    // association. Opening the same id again advances the generation, and the
    // first packet of the new one is what tells the receiver everything it was
    // holding is void.

    CHECK(sender.CloseFlow(main) == common::Error::Ok);
    flux::FlowHandle again = sender.OpenFlow(FLOW_MAIN, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!again.Failed());
    CHECK(OfferUntil(sender, &receiver, receiverAddr, again,
                     [&] { return receiverSeen.reopened > 0; }));
    CHECK(receiverSeen.reopened == 1);
    CHECK(receiverSeen.lastReopened == FLOW_MAIN);

    // The reopen is not a second registration, so the count above must not have
    // moved. This is what separates the two events rather than letting one
    // stand in for the other.
    CHECK(receiverSeen.opened == 1);

    // --- OUTGOING_FLOW_REFUSED ------------------------------------------------
    //
    // The receiver takes one flow per remote and that one is spoken for, so a
    // second id is answered with a rejection rather than being seated.

    flux::FlowHandle extra = sender.OpenFlow(FLOW_EXTRA, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!extra.Failed());
    CHECK(OfferUntil(sender, &receiver, receiverAddr, extra,
                     [&] { return senderSeen.refused > 0; }));
    CHECK(senderSeen.refused == 1);
    CHECK(senderSeen.lastRefused == FLOW_EXTRA);

    // --- OUTGOING_FLOW_LOST ---------------------------------------------------
    //
    // A different failure from a refusal, and the reason they are two events. The
    // flow was accepted and working; the peer simply stops being there, so a
    // packet on it runs out of retransmits.

    receiver.Shutdown();
    CHECK(OfferUntil(sender, nullptr, receiverAddr, again,
                     [&] { return senderSeen.lost > 0; }));
    CHECK(senderSeen.lost == 1);
    CHECK(senderSeen.lastLost == FLOW_MAIN);

    // A give-up is not a refusal. If these ran together the two events would be
    // reporting the same thing under two names.
    CHECK(senderSeen.refused == 1);

    std::printf("opened %u, reopened %u, refused %u, lost %u\n",
                receiverSeen.opened, receiverSeen.reopened,
                senderSeen.refused, senderSeen.lost);

    sender.Shutdown();
    return test::report();
}
