// Being told what happened instead of asking every tick.
//
// A socket can answer two kinds of question. State is always readable: ask what
// a flow's lifecycle is, or how many flows a peer has opened here, and it tells
// you. Events are the other half, and they carry nothing the state does not
// already have. They only say which entity is worth looking at, so a program
// stops walking every peer and every flow on the off chance something moved.
//
// That is why the handlers below keep no counters. They log, and where they
// want detail they ask the socket, which is safe because a handler runs with
// nothing locked. The loop at the bottom decides it is finished the same way,
// by reading state rather than by trusting a tally a callback kept.
//
// Hooks are registered in Config and called from Poll, for the peers whose
// packets that Poll is about to hand over. Delivery is split into lanes so one
// peer's traffic reaches one thread, and events follow the same split, so an
// application holding per-peer state on a polling thread can touch it from a
// handler without a lock.
//
// The two sides want different events, which is the point.
//
// THE RECEIVER wants INCOMING_FLOW_OPENED. A remote can open a flow here
// without asking, and nothing else reports it.
//
// THE SENDER wants OUTGOING_FLOW_REFUSED. It opens more flows to one peer than
// that peer allows, and the refusals come back long after the Send that caused
// them returned Ok. A flow refused by one peer stays open for every other, so
// the event names an address as well as a flow.
//
//     ./events

#include <common/log.h>

#include <flux/address.h>
#include <flux/flow/flow_handle.h>
#include <flux/socket/packet_slot.h>
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>

#include <chrono>
#include <cstdint>
#include <thread>

#include "setup.h"

namespace common = bcp::common;
namespace flux   = bcp::flux;

constexpr uint16_t PORT_SENDER   = 9580;
constexpr uint16_t PORT_RECEIVER = 9581;

// The receiver accepts two flows from any one remote. The sender opens four, so
// two of them have to be refused.
constexpr uint32_t FLOWS_ALLOWED = 2;
constexpr uint32_t FLOWS_OPENED  = 4;

// --- Receiver side ------------------------------------------------------------

// The context is whatever the application registered. Here it is the socket
// itself, because the handler wants to ask it something.
static void OnReceiverEvent(void* context, const flux::EventInfo& info)
{
    flux::Socket& socket = *static_cast<flux::Socket*>(context);

    // A peer event carries no flow, so it reports INVALID_FLOW_ID. Asking per
    // event rather than switching is what lets one call report both.
    if (info.Has(flux::SocketEvent::PEER_ESTABLISHED))
        common::LogF(common::LogLevel::Info, "receiver: a peer completed its handshake");

    if (!info.Has(flux::SocketEvent::INCOMING_FLOW_OPENED)) return;

    // Calling back into the socket from inside a handler is the reason this
    // runs where it does. The event said which peer to look at and the socket
    // holds the detail.
    common::LogF(common::LogLevel::Info,
                 "receiver: flow %u opened here, that peer now holds %u",
                 info.Flow(), socket.ReceivingFlowCount(info.Peer()));
}

// --- Sender side --------------------------------------------------------------

static void OnSenderEvent(void* context, const flux::EventInfo& info)
{
    (void)context;

    // Two different answers, which is why they are two events. A refusal means
    // that peer is at a limit and asking again changes nothing. A loss means
    // the flow was accepted and later stopped reaching it, so trying again
    // later is reasonable.
    if (info.Has(flux::SocketEvent::OUTGOING_FLOW_REFUSED))
        common::LogF(common::LogLevel::Info,
                     "sender: flow %u refused, that peer is at its limit", info.Flow());

    if (info.Has(flux::SocketEvent::OUTGOING_FLOW_LOST))
        common::LogF(common::LogLevel::Info,
                     "sender: flow %u stopped reaching that peer", info.Flow());
}

// --- Both ---------------------------------------------------------------------

static void Tick(flux::Socket& socket)
{
    flux::PacketSlotHandle inbox[32];
    socket.Update();
    // Hooks fire from here, before the packets are handed over.
    { flux::PollCursor cursor = socket.Poll(inbox, 32); while (cursor.Next()) {} }
    socket.Flush();
}

// The state, asked directly. This is what the events point at, and it is
// readable whether or not anybody registered a hook.
static uint32_t FailedFlows(flux::Socket& socket, const flux::FlowHandle* flows,
                            const flux::Address& peer)
{
    uint32_t failed = 0;
    for (uint32_t i = 0; i < FLOWS_OPENED; ++i)
        if (socket.GetFlowState(flows[i], peer) == flux::FlowLifecycle::FAILED) ++failed;
    return failed;
}

int main()
{
    flux::Socket receiver, sender;

    flux::Socket::Config receiverConfig{};
    receiverConfig.type               = examples::BACKEND;
    receiverConfig.port               = PORT_RECEIVER;
    receiverConfig.maxPeers           = 8;
    receiverConfig.flows.inCount      = 16;
    receiverConfig.flows.outCount     = 16;
    // What one remote may create here. The refusals the sender sees come from
    // this.
    receiverConfig.flows.maxInPerPeer = FLOWS_ALLOWED;
    receiverConfig.events.hook        = OnReceiverEvent;
    receiverConfig.events.context     = &receiver;
    receiverConfig.events.subscribed  = flux::ToBits(flux::SocketEvent::INCOMING_FLOW_OPENED)
                                      | flux::ToBits(flux::SocketEvent::PEER_ESTABLISHED);

    flux::Socket::Config senderConfig{};
    senderConfig.type              = examples::BACKEND;
    senderConfig.port              = PORT_SENDER;
    senderConfig.maxPeers          = 8;
    senderConfig.flows.inCount     = 16;
    senderConfig.flows.outCount    = 16;
    senderConfig.events.hook       = OnSenderEvent;
    senderConfig.events.context    = nullptr;
    senderConfig.events.subscribed = flux::ToBits(flux::SocketEvent::OUTGOING_FLOW_REFUSED)
                                   | flux::ToBits(flux::SocketEvent::OUTGOING_FLOW_LOST);

    if (receiver.Init(receiverConfig) != common::Error::Ok) return 1;
    if (sender.Init(senderConfig) != common::Error::Ok) return 1;

    const flux::Address receiverAddr = flux::Address::From("::1", PORT_RECEIVER).Take();
    const flux::Address senderAddr   = flux::Address::From("::1", PORT_SENDER).Take();

    // Opening is local and costs nothing on the wire. The receiver hears about
    // a flow from the first packet sent on it, not from the open.
    flux::FlowHandle flows[FLOWS_OPENED];
    for (uint32_t i = 0; i < FLOWS_OPENED; ++i)
    {
        flows[i] = sender.OpenFlow(static_cast<uint16_t>(20 + i),
                                   flux::FlowMode::RELIABLE_ORDERED);
        if (flows[i].Failed()) return 1;
    }

    const auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < std::chrono::seconds(5))
    {
        // Keep offering: a flow opened before the session exists has its first
        // packet parked, and the refusals only come once traffic lands.
        for (uint32_t i = 0; i < FLOWS_OPENED; ++i)
            (void)sender.BuildPacket().WithFlow(flows[i]).PutU32(i).Send(receiverAddr);
        sender.Flush();

        Tick(sender);
        Tick(receiver);

        if (FailedFlows(sender, flows, receiverAddr) >= FLOWS_OPENED - FLOWS_ALLOWED)
            break;

        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    common::LogF(common::LogLevel::Info,
                 "state says: receiver holds %u flows from the sender, and %u of the "
                 "sender's flows failed",
                 receiver.ReceivingFlowCount(senderAddr),
                 FailedFlows(sender, flows, receiverAddr));

    for (uint32_t i = 0; i < FLOWS_OPENED; ++i)
        (void)sender.CloseFlow(flows[i]);
    sender.Shutdown();
    receiver.Shutdown();
    return 0;
}
