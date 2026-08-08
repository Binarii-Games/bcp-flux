// A flow whose target stops answering dies, and it dies on a clock rather
// than on a count of attempts.
//
// WHAT IS DIFFERENT FROM event_flow_scope. That test shuts the receiver down
// and checks the flow is eventually reported lost, which is the event. This
// one leaves the peer running and blacks out the link, then checks the two
// BOUNDS on when the report arrives, which is the policy.
//
// Both bounds matter and they fail in opposite directions.
//
// The ceiling is the obvious one. A target that has stopped answering must
// produce a clear death rather than an indefinite stall, because a flow that
// probes into silence forever holds its in-flight ring, its staging copies and
// its share of the peer's budget, and the application is never told.
//
// The floor is the one that used to break. Deaths were once counted in
// attempts, and a count spends itself in a burst: eight retransmits on a link
// that is merely lossy can elapse in a few milliseconds while the peer is
// perfectly alive, killing a healthy flow. The bound is now a multiple of the
// measured round trip with a guaranteed number of probes inside it, so a death
// cannot arrive before the path has genuinely been given time to answer.
// Asserting only the ceiling would pass an implementation that killed every
// flow on its first timeout.
//
// The link is blacked out in both directions, so this is a peer that has
// vanished rather than one that is slow.
#include <flux/socket/socket.h>
#include <flux/address.h>
#include <flux/flow/flow_handle.h>
#include <flux/socket/packet_slot.h>
#include <flux/wire/packet_builder.h>
#include <flux/internal/constants.h>
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
    constexpr uint16_t BASE_PORT  = 25620;
    constexpr uint16_t FLOW_ID    = 72;
    constexpr uint32_t PAYLOAD    = 1000;
    constexpr uint32_t WARMUP     = 6;        ///< delivered first, so a round trip is measured
    constexpr uint32_t LATENCY_US = 15000;

    /** The forced acknowledgement cadence, which is the lower bound on the
        hold term in the deadline. Config's default, restated because the
        floor below is computed from it. */
    constexpr uint32_t ACK_CADENCE_US = 5000;

    /** The spec these bounds encode, written out rather than read from the
        implementation.

        Deliberately literals and NOT flux::internal::FLOW_DEATH_ROUNDS and
        RTO_MARGIN_DIVISOR. A floor computed from the constant it is meant to
        bound moves with that constant and can never catch a change to it:
        with the constant read from the header, regressing it from sixteen to
        two dropped the floor to below zero and the test stayed green on a
        death eight times too early. So the intended figures live here, and
        changing the implementation to disagree with them fails this test,
        which is the point. If the policy is meant to change, this changes
        too, as a decision rather than as a side effect. */
    constexpr int64_t EXPECTED_DEATH_ROUNDS  = 16;   // FLOW_DEATH_ROUNDS
    constexpr int64_t EXPECTED_RTO_MARGIN_DIV = 8;   // RTO_MARGIN_DIVISOR

    /** No death may arrive sooner than this.

        One timeout is at least the round trip plus its margin plus the hold,
        and the deadline is that many of them. Injected jitter is additive, so
        the measured round trip can never come in below LATENCY_US, which
        makes every term a floor and the product a floor. A slower host
        measures a longer round trip and dies later, so this cannot flake
        upward.

        It also has to clear 200 ms to mean anything, because the deadline is
        clamped up to Config's retry interval and this test does not override
        it. Any figure below that is satisfied by the clamp alone. This test
        shipped with a hand-picked 100 and was therefore unfalsifiable. */
    constexpr int64_t FLOOR_MS =
        EXPECTED_DEATH_ROUNDS
            * (LATENCY_US + LATENCY_US / EXPECTED_RTO_MARGIN_DIV + ACK_CADENCE_US)
            / 1000
        - 50;   // one tick of slack against granularity

    /** Well past the bound at this round trip, so only a flow that never dies
        at all reaches it. */
    constexpr int64_t CEILING_MS = 15000;

    using Clock = std::chrono::steady_clock;

    struct Seen
    {
        uint32_t lost     = 0;
        uint16_t lastLost = 0;
    };

    void OnSenderEvent(void* context, const flux::EventInfo& info)
    {
        Seen& seen = *static_cast<Seen*>(context);
        if (info.Has(flux::SocketEvent::OUTGOING_FLOW_LOST))
        {
            ++seen.lost;
            seen.lastLost = info.Flow();
        }
    }

    void SetLink(flux::platform::FaultySocket* kernel, uint8_t lossPercent,
                 flux::platform::FaultySocket::Direction direction)
    {
        flux::platform::FaultySocket::Profile profile{};
        profile.applyTo       = direction;
        profile.latencyMicros = LATENCY_US;
        profile.jitterMicros  = LATENCY_US / 4;
        profile.lossPercent   = lossPercent;
        profile.seed          = 0xDEAD;
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
    Seen senderSeen{};

    flux::Socket::Config receiverConfig{};
    receiverConfig.type           = flux::Socket::BackendType::FAULTY;
    receiverConfig.maxPeers       = 4;
    receiverConfig.flows.outCount = 8;
    receiverConfig.flows.inCount  = 8;
    receiverConfig.port           = BASE_PORT;

    flux::Socket::Config senderConfig = receiverConfig;
    senderConfig.port              = static_cast<uint16_t>(BASE_PORT + 1);
    senderConfig.events.hook       = OnSenderEvent;
    senderConfig.events.context    = &senderSeen;
    senderConfig.events.subscribed = flux::ToBits(flux::SocketEvent::OUTGOING_FLOW_LOST);

    flux::Socket sender, receiver;
    CHECK(receiver.Init(receiverConfig) == common::Error::Ok);
    CHECK(sender.Init(senderConfig) == common::Error::Ok);

    const flux::Address receiverAddr = flux_net::Loopback(BASE_PORT);
    const flux::Address senderAddr   = flux_net::Loopback(BASE_PORT + 1);

    flux::platform::FaultySocket* senderKernel =
        flux::platform::FaultySocket::ForPort(static_cast<uint16_t>(BASE_PORT + 1));
    CHECK(senderKernel != nullptr);
    if (!senderKernel) return test::report();

    (void)sender.Connect(receiverAddr);
    CHECK(flux_net::PumpUntilEstablished(sender, senderAddr, receiver, receiverAddr));

    SetLink(senderKernel, 0, flux::platform::FaultySocket::Direction::Send);

    flux::FlowHandle flow = sender.OpenFlow(FLOW_ID, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!flow.Failed());

    uint32_t offered   = 0;
    uint32_t delivered = 0;

    flux::PacketSlotHandle inbox[64];
    uint8_t filler[PAYLOAD - sizeof(uint32_t)];
    std::memset(filler, 0x5C, sizeof(filler));

    auto offer = [&]
    {
        return sender.BuildPacket().WithFlow(flow).PutU32(offered)
                     .PutBytes(filler, sizeof(filler)).Send(receiverAddr);
    };

    // Warm up, so the death bound is built from a measured round trip rather
    // than from the configured fallback.
    while (offered < WARMUP && offer() == common::Error::Ok)
        ++offered;

    {
        const auto until = Clock::now() + std::chrono::seconds(10);
        while (delivered < WARMUP && Clock::now() < until)
        {
            Drive(sender, receiver, inbox, 64);
            flux::PollCursor cursor = receiver.Poll(inbox, 64);
            while (cursor.Next()) ++delivered;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    CHECK(delivered == WARMUP);
    CHECK(senderSeen.lost == 0);   // nothing has gone wrong yet

    // The peer vanishes. Both directions, so no acknowledgement can arrive and
    // no probe can land.
    SetLink(senderKernel, 100, flux::platform::FaultySocket::Direction::Both);
    const auto blackoutAt = Clock::now();

    // Owe the flow something, otherwise there is nothing outstanding to die on.
    for (uint32_t i = 0; i < 4 && offer() == common::Error::Ok; ++i)
        ++offered;

    int64_t deathMs = -1;
    {
        const auto until = blackoutAt + std::chrono::milliseconds(CEILING_MS);
        while (senderSeen.lost == 0 && Clock::now() < until)
        {
            Drive(sender, receiver, inbox, 64);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (senderSeen.lost > 0)
            deathMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                Clock::now() - blackoutAt).count();
    }

    std::printf("flow died %lld ms after the blackout (round trip about %u ms)\n",
                static_cast<long long>(deathMs), LATENCY_US / 1000);

    // The ceiling: a vanished target produces a clear death.
    CHECK(senderSeen.lost == 1);
    CHECK(senderSeen.lastLost == FLOW_ID);

    // The floor: it is not the first timeout that kills the flow.
    CHECK(deathMs >= FLOOR_MS);

    return test::report();
}
