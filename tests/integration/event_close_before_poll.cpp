// An association torn down while it still owes an event.
//
// A slot carrying an unread event keeps its lease until somebody reads it, so a
// later occupant cannot land on the entry that event is sitting in. That is what
// makes delivery reliable rather than likely, and every other test walks past
// it: they poll continuously, so events are delivered long before anything is
// closed and teardown always takes the ordinary release.
//
// WHAT WOULD NOT PROVE ANYTHING. Tearing an association down and then polling
// proves nothing, because teardown never touches the entry. The event survives
// and the slot comes back whether or not the lease was ever held. A test built
// that way passes against code with no pin in it at all.
//
// So this measures the thing that is only true with the pin: while a slot is
// owed an event, it is genuinely unavailable to anybody else.
//
// The receiving pool holds exactly two associations. The first peer takes both
// and is never polled for, so both slots owe an event. It is then removed. A
// second peer arrives and asks for two flows, and must be REFUSED, because both
// slots are still held for events nobody has read. That refusal is the pin. Then
// one poll delivers the two events, both slots come back, and the second peer
// gets them on its next attempt.
//
// Three ways the pin could be wrong, each caught here. Slots that never come
// back leave the second peer refused forever. Slots released twice hand the same
// association to two peers. Events dropped at teardown never arrive at all.
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
    constexpr uint16_t BASE_PORT = 25420;
    constexpr uint32_t FLOWS     = 2;   // and the receiving pool holds exactly this

    struct Seen
    {
        uint32_t count = 0;
        uint16_t flows[8]{};
    };

    void OnEvent(void* context, const flux::EventInfo& info)
    {
        Seen& seen = *static_cast<Seen*>(context);
        if (!info.Has(flux::SocketEvent::INCOMING_FLOW_OPENED)) return;
        if (seen.count < 8) seen.flows[seen.count] = info.Flow();
        ++seen.count;
    }

    // Drives both sockets. The receiver takes packets off the wire in Update,
    // and Poll is what hands events over, so leaving Poll out is how this test
    // gets an association that owes one.
    void Drive(flux::Socket& sender, flux::Socket& receiver, bool pollReceiver)
    {
        flux::PacketSlotHandle inbox[16];
        sender.Update();
        { flux::PollCursor cursor = sender.Poll(inbox, 16); while (cursor.Next()) {} }
        sender.Flush();

        receiver.Update();
        if (pollReceiver)
        {
            flux::PollCursor cursor = receiver.Poll(inbox, 16);
            while (cursor.Next()) {}
        }
        receiver.Flush();
    }

    // Establishment without ever polling the receiver. flux_net's helper polls
    // both sides, which would hand over the very events this test needs left
    // unread. Reception happens on the tick, so Update alone is enough.
    bool EstablishQuietly(flux::Socket& sender, const flux::Address& senderAddr,
                          flux::Socket& receiver, const flux::Address& receiverAddr)
    {
        for (int i = 0; i < 400; ++i)
        {
            Drive(sender, receiver, false);
            if (flux_net::Established(sender, receiverAddr)
                && flux_net::Established(receiver, senderAddr)) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return false;
    }

    struct Attempt
    {
        flux::FlowHandle flows[FLOWS];
        uint32_t         registered = 0;
        uint32_t         refused    = 0;
    };

    // Offers on two flows until the receiver has either registered both or
    // refused both, reading STATE on each side rather than events. Refused is a
    // positive answer, not a timeout: the receiver sends FLOW_REJECT when it
    // cannot seat a flow, and the sender marks that association FAILED.
    Attempt OfferFlows(flux::Socket& sender, flux::Socket& receiver,
                       const flux::Address& receiverAddr, const flux::Address& senderAddr,
                       uint16_t firstFlowId, bool pollReceiver)
    {
        Attempt attempt;
        for (uint32_t i = 0; i < FLOWS; ++i)
            attempt.flows[i] = sender.OpenFlow(static_cast<uint16_t>(firstFlowId + i),
                                               flux::FlowMode::RELIABLE_ORDERED);

        const auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::seconds(5))
        {
            for (uint32_t i = 0; i < FLOWS; ++i)
                (void)sender.BuildPacket().WithFlow(attempt.flows[i])
                            .PutU32(i).Send(receiverAddr);
            sender.Flush();
            Drive(sender, receiver, pollReceiver);

            attempt.registered = receiver.ReceivingFlowCount(senderAddr);
            attempt.refused    = 0;
            for (uint32_t i = 0; i < FLOWS; ++i)
                if (sender.GetFlowState(attempt.flows[i], receiverAddr)
                    == flux::FlowLifecycle::FAILED) ++attempt.refused;

            if (attempt.registered == FLOWS || attempt.refused == FLOWS) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return attempt;
    }
}

int main()
{
    Seen seen;

    flux::Socket::Config receiverConfig{};
    receiverConfig.type               = flux_net::BACKEND;
    receiverConfig.port               = BASE_PORT;
    receiverConfig.maxPeers           = 4;
    receiverConfig.flows.outCount     = 8;
    receiverConfig.flows.inCount      = FLOWS;   // exactly enough for one peer
    receiverConfig.flows.maxInPerPeer = FLOWS;
    receiverConfig.events.hook        = OnEvent;
    receiverConfig.events.context     = &seen;
    receiverConfig.events.subscribed  = flux::ToBits(flux::SocketEvent::INCOMING_FLOW_OPENED);

    flux::Socket receiver;
    CHECK(receiver.Init(receiverConfig) == common::Error::Ok);

    flux::Socket::Config senderConfig{};
    senderConfig.type           = flux_net::BACKEND;
    senderConfig.maxPeers       = 4;
    senderConfig.flows.outCount = 8;
    senderConfig.flows.inCount  = 8;

    flux::Socket first, second;
    senderConfig.port = static_cast<uint16_t>(BASE_PORT + 1);
    CHECK(first.Init(senderConfig) == common::Error::Ok);
    senderConfig.port = static_cast<uint16_t>(BASE_PORT + 2);
    CHECK(second.Init(senderConfig) == common::Error::Ok);

    const flux::Address receiverAddr = flux_net::Loopback(BASE_PORT);
    const flux::Address firstAddr    = flux_net::Loopback(BASE_PORT + 1);
    const flux::Address secondAddr   = flux_net::Loopback(BASE_PORT + 2);

    (void)first.Connect(receiverAddr);
    CHECK(EstablishQuietly(first, firstAddr, receiver, receiverAddr));

    // Both slots taken, and the receiver is never polled, so both owe an event.
    CHECK(OfferFlows(first, receiver, receiverAddr, firstAddr, 30, false).registered == FLOWS);

    // Recording happens on the tick, handing over happens on the poll, and
    // there has been no poll.
    CHECK(seen.count == 0);

    // Silence the first peer before removing it, or its retransmits would start
    // a fresh handshake and take the slots straight back.
    first.Shutdown();
    CHECK(receiver.RemovePeer(firstAddr) == common::Error::Ok);

    // THE ASSERTION THAT NEEDS THE PIN. Both associations are gone, but their
    // slots are still held because their events have not been read. A second
    // peer asking for two flows has to be refused. Without the pin those slots
    // would be back in the pool, this peer would be seated, and the two unread
    // events would be written over.
    (void)second.Connect(receiverAddr);
    CHECK(EstablishQuietly(second, secondAddr, receiver, receiverAddr));

    const Attempt blocked = OfferFlows(second, receiver, receiverAddr, secondAddr, 40, false);
    CHECK(blocked.registered == 0);
    CHECK(blocked.refused == FLOWS);
    CHECK(receiver.ReceivingFlowCount(secondAddr) == 0);

    // The poll that was owed. Both events come out here, and releasing the two
    // slots is the last thing each delivery does.
    {
        flux::PacketSlotHandle inbox[16];
        flux::PollCursor cursor = receiver.Poll(inbox, 16);
        while (cursor.Next()) {}
    }

    // The first peer's events, not the second's, and neither written over.
    const uint32_t afterTeardown = seen.count;
    CHECK(afterTeardown == FLOWS);
    CHECK(seen.flows[0] == 30 || seen.flows[0] == 31);
    CHECK(seen.flows[1] == 30 || seen.flows[1] == 31);
    CHECK(seen.flows[0] != seen.flows[1]);

    // And now the slots are back. Fresh flow ids, because the refused ones were
    // told no and a refusal is final for that generation.
    const Attempt seated = OfferFlows(second, receiver, receiverAddr, secondAddr, 42, true);
    CHECK(seated.registered == FLOWS);

    std::printf("held slots refused %u flows, then delivered %u events and seated %u\n",
                blocked.refused, afterTeardown, seated.registered);

    second.Shutdown();
    receiver.Shutdown();
    return test::report();
}
