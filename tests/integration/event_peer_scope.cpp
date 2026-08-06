// Every peer-scoped event except migration, made to fire on purpose.
//
// Migration lives in migration.cpp, which already owns the relay needed to move
// a peer's apparent address. Everything else is here.
//
// Five phases, in an order that builds on itself. A session opens. The receiver
// names a grant and the sender is told. One flow is made to jam by losing a
// packet the sender will not resend soon enough, so its buffer is taken back.
// That is repeated until the receiver decides this peer is not worth its
// current grant and cuts it. Finally the peer is removed.
//
// THE LAST PHASE ALSO COVERS THE PEER PIN. PEER_LOST is recorded and the peer is
// then removed, with no poll in between, so the slot is held by the event rather
// than returned. The peer table holds exactly one peer, so a second one can only
// be seated after the event has been read and the slot given back, which is
// what proves the lease was held rather than merely that the event survived.
//
// The timers are deliberately upside down: a long retransmit interval and a
// short stall timeout, so a gap outlives the patience of the receiver instead of
// being filled before it matters. That is the whole trick to making a jam
// happen on demand.
#include <flux/socket/socket.h>
#include <flux/address.h>
#include <flux/flow/flow_handle.h>
#include <flux/internal/constants.h>
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
    constexpr uint16_t BASE_PORT   = 25460;
    constexpr uint16_t FLOW_ID     = 50;
    constexpr uint32_t START_GRANT = 64;
    constexpr uint32_t NEW_GRANT   = 32;

    struct Seen
    {
        uint32_t established = 0, lost = 0, grantChanged = 0, grantCut = 0, jammed = 0;
        uint32_t lastGrant = 0;
    };

    void OnReceiverEvent(void* context, const flux::EventInfo& info)
    {
        Seen& seen = *static_cast<Seen*>(context);
        if (info.Has(flux::SocketEvent::PEER_ESTABLISHED)) ++seen.established;
        if (info.Has(flux::SocketEvent::PEER_FLOW_JAMMED)) ++seen.jammed;
        if (info.Has(flux::SocketEvent::PEER_GRANT_CUT))   ++seen.grantCut;
        if (info.Has(flux::SocketEvent::PEER_LOST))        ++seen.lost;
    }

    // The grant is what the REMOTE says we may occupy, so a change in it is news
    // on the sending side.
    void OnSenderEvent(void* context, const flux::EventInfo& info)
    {
        Seen& seen = *static_cast<Seen*>(context);
        if (info.Has(flux::SocketEvent::PEER_GRANT_CHANGED)) ++seen.grantChanged;
    }

    void Drive(flux::Socket& sender, flux::Socket* receiver, bool pollReceiver = true)
    {
        flux::PacketSlotHandle inbox[16];
        sender.Update();
        { flux::PollCursor cursor = sender.Poll(inbox, 16); while (cursor.Next()) {} }
        sender.Flush();
        if (!receiver) return;
        receiver->Update();
        if (pollReceiver)
        {
            flux::PollCursor cursor = receiver->Poll(inbox, 16);
            while (cursor.Next()) {}
        }
        receiver->Flush();
    }

    template <typename Done>
    bool DriveUntil(flux::Socket& sender, flux::Socket* receiver, Done done,
                    int millis = 4000)
    {
        const auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(millis))
        {
            Drive(sender, receiver);
            if (done()) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return false;
    }

    void SetLoss(flux::platform::FaultySocket* kernel, uint8_t percent)
    {
        flux::platform::FaultySocket::Profile profile{};
        profile.applyTo     = flux::platform::FaultySocket::Direction::Send;
        profile.lossPercent = percent;
        profile.seed        = 0x5A5A;
        kernel->SetProfile(profile);
    }

    // Opens a gap and holds it open long enough to count as abandoned.
    //
    // Two things have to be true at once, and the second is the one that is easy
    // to get wrong. A packet has to go missing so the receiver holds later ones
    // behind it, AND the retransmit has to not arrive before the stall timeout.
    // Config::timers::retryIntervalMicros does not help with the second: that
    // paces opens and closes, while a flow's retransmit timeout comes from the
    // measured round trip and floors at a millisecond, so on loopback the gap is
    // refilled almost at once.
    //
    // So the link is cut entirely for the wait. Nothing new arrives, the
    // retransmit does not either, and the cursor sits where it is until the
    // receiver gives up on it.
    //
    // Targeting one exact datagram was tried and is not reliable: DropNext takes
    // whichever packet leaves next, and the tick that receives also produces the
    // acks this side owes, so a control packet eats the arming. The acceptance
    // test that depends on precise targeting says the same about itself.
    bool ProvokeJam(flux::Socket& sender, flux::Socket& receiver,
                    const flux::Address& to, flux::FlowHandle& flow,
                    flux::platform::FaultySocket* senderKernel, Seen& seen)
    {
        const uint32_t before  = seen.jammed;
        const uint64_t dropped = senderKernel->GetStats().dropped;

        SetLoss(senderKernel, 40);
        for (uint32_t i = 0; i < 16; ++i)
        {
            (void)sender.BuildPacket().WithFlow(flow).PutU32(i).Send(to);
            sender.Flush();
        }

        // The control for this helper: with nothing lost there is no gap, and a
        // jam that then failed to appear would be measuring the harness.
        const bool lost = senderKernel->GetStats().dropped > dropped;

        SetLoss(senderKernel, 100);
        const bool jammed =
            lost && DriveUntil(sender, &receiver, [&] { return seen.jammed > before; }, 800);
        SetLoss(senderKernel, 0);

        // Let the retransmits through again, so the next round starts from a
        // flow that is moving rather than one still stuck on the last gap.
        for (int i = 0; i < 40; ++i) Drive(sender, &receiver);
        return jammed;
    }
}

int main()
{
    Seen receiverSeen, senderSeen;

    flux::Socket::Config receiverConfig{};
    receiverConfig.type               = flux::Socket::BackendType::FAULTY;
    receiverConfig.port               = BASE_PORT;
    // One peer at a time, so the last phase can only seat a second one after the
    // first one's slot comes back.
    receiverConfig.maxPeers           = 1;
    receiverConfig.flows.outCount     = 8;
    receiverConfig.flows.inCount      = 8;
    receiverConfig.flows.recvGrant    = START_GRANT;
    // Short, so a gap counts as abandoned inside the test.
    receiverConfig.liveness.flowStallTimeoutMicros = 120000;
    receiverConfig.events.hook        = OnReceiverEvent;
    receiverConfig.events.context     = &receiverSeen;
    receiverConfig.events.subscribed  = flux::ToBits(flux::SocketEvent::PEER_ESTABLISHED)
                                      | flux::ToBits(flux::SocketEvent::PEER_FLOW_JAMMED)
                                      | flux::ToBits(flux::SocketEvent::PEER_GRANT_CUT)
                                      | flux::ToBits(flux::SocketEvent::PEER_LOST);

    flux::Socket::Config senderConfig{};
    senderConfig.type           = flux::Socket::BackendType::FAULTY;
    senderConfig.port           = static_cast<uint16_t>(BASE_PORT + 1);
    senderConfig.maxPeers       = 4;
    senderConfig.flows.outCount = 8;
    senderConfig.flows.inCount  = 8;
    // Long on purpose. A gap the sender refills promptly never becomes a jam.
    senderConfig.timers.retryIntervalMicros = 30000000;
    // The link is cut outright while a gap is being left to go stale, and every
    // retransmit that leaves during that spends an attempt. Without headroom the
    // flow gives up partway through and there is nothing left to jam.
    senderConfig.timers.maxAttempts         = 200;
    senderConfig.events.hook       = OnSenderEvent;
    senderConfig.events.context    = &senderSeen;
    senderConfig.events.subscribed = flux::ToBits(flux::SocketEvent::PEER_GRANT_CHANGED);

    flux::Socket receiver, sender;
    CHECK(receiver.Init(receiverConfig) == common::Error::Ok);
    CHECK(sender.Init(senderConfig) == common::Error::Ok);

    flux::platform::FaultySocket* senderKernel =
        flux::platform::FaultySocket::ForPort(static_cast<uint16_t>(BASE_PORT + 1));
    CHECK(senderKernel != nullptr);
    if (!senderKernel) return test::report();

    const flux::Address receiverAddr = flux_net::Loopback(BASE_PORT);
    const flux::Address senderAddr   = flux_net::Loopback(BASE_PORT + 1);

    // --- PEER_ESTABLISHED -----------------------------------------------------

    (void)sender.Connect(receiverAddr);
    CHECK(flux_net::PumpUntilEstablished(sender, senderAddr, receiver, receiverAddr));
    CHECK(DriveUntil(sender, &receiver, [&] { return receiverSeen.established > 0; }));
    CHECK(receiverSeen.established == 1);

    // --- PEER_GRANT_CHANGED ---------------------------------------------------
    //
    // The receiver names a new figure, it goes out over the channel, and the
    // SENDER is the side that learns something: this is what bounds how much it
    // may have in flight.

    // The grant named in Config is announced when the session opens, and that
    // first announcement is itself a change from nothing. So this measures the
    // move rather than the total.
    const uint32_t grantsBefore = senderSeen.grantChanged;
    CHECK(receiver.SetRecvGrant(senderAddr, NEW_GRANT) == common::Error::Ok);
    CHECK(DriveUntil(sender, &receiver,
                     [&] { return senderSeen.grantChanged > grantsBefore; }));

    // --- PEER_FLOW_JAMMED -----------------------------------------------------

    flux::FlowHandle flow = sender.OpenFlow(FLOW_ID, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!flow.Failed());
    CHECK(ProvokeJam(sender, receiver, receiverAddr, flow, senderKernel, receiverSeen));
    CHECK(receiverSeen.jammed >= 1);

    // --- PEER_GRANT_CUT -------------------------------------------------------
    //
    // One jam is a bad moment. Enough of them is a peer holding buffer it never
    // uses, and the receiver lowers what it will hold for it.

    while (receiverSeen.jammed <= flux::internal::GRANT_STRIKES_BEFORE_CUT
           && receiverSeen.grantCut == 0)
    {
        if (!ProvokeJam(sender, receiver, receiverAddr, flow, senderKernel, receiverSeen))
            break;
    }
    CHECK(DriveUntil(sender, &receiver, [&] { return receiverSeen.grantCut > 0; }));
    CHECK(receiverSeen.grantCut >= 1);
    CHECK(receiver.RecvGrantFor(senderAddr) < NEW_GRANT);

    // --- PEER_LOST, and the peer pin ------------------------------------------
    //
    // Removed with no poll in between, so the event is recorded and the slot is
    // held by it rather than returned.

    sender.Shutdown();
    CHECK(receiverSeen.lost == 0);
    CHECK(receiver.RemovePeer(senderAddr) == common::Error::Ok);

    // The table holds one peer and that one is gone, but its slot is not back
    // yet, so nothing can take it.
    flux::Socket::Config secondConfig = senderConfig;
    secondConfig.port           = static_cast<uint16_t>(BASE_PORT + 2);
    secondConfig.events.hook    = nullptr;
    secondConfig.events.context = nullptr;
    // The long retry above exists to keep a gap open, and this peer needs the
    // opposite: to knock again quickly once there is room.
    secondConfig.timers.retryIntervalMicros = 20000;
    flux::Socket second;
    CHECK(second.Init(secondConfig) == common::Error::Ok);
    const flux::Address secondAddr = flux_net::Loopback(BASE_PORT + 2);

    (void)second.Connect(receiverAddr);
    for (int i = 0; i < 40; ++i) Drive(second, &receiver, false);   // no poll: still held
    CHECK(!flux_net::Established(receiver, secondAddr));

    // The poll that was owed. PEER_LOST comes out, and the slot goes back.
    {
        flux::PacketSlotHandle inbox[16];
        flux::PollCursor cursor = receiver.Poll(inbox, 16);
        while (cursor.Next()) {}
    }
    CHECK(receiverSeen.lost == 1);

    // And now there is room again.
    CHECK(DriveUntil(second, &receiver,
                     [&] { return flux_net::Established(receiver, secondAddr); }));

    std::printf("established %u, grant changed %u, jammed %u, grant cut %u, lost %u\n",
                receiverSeen.established, senderSeen.grantChanged,
                receiverSeen.jammed, receiverSeen.grantCut, receiverSeen.lost);

    second.Shutdown();
    receiver.Shutdown();
    return test::report();
}
