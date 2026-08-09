// A peer that holds buffer it never uses gets less of it, and nobody else pays.
//
// Loss costs a peer nothing here. A gap its sender fills is ordinary, and the
// reclaim that follows a gap nobody fills is what counts against it. So the
// signal is not damage on the path, it is buffer taken and left to time out,
// which a well-behaved remote never does however lossy its link.
//
// The jammer loses its own packets on the way out and never retransmits, so its
// receiving cursor sticks on the first loss and stays there. Everything it sends
// afterwards piles up behind that gap and is thrown away when the stall timeout
// passes, and each of those is a strike. One flow kept alive rather than a fresh
// one per round, because a new flow has to re-jam from scratch and an earlier
// shape of this test produced two strikes in twelve rounds that way.
//
// The second peer shares the link and the socket and behaves normally
// throughout. Its grant must not move, because a cut is a judgement about one
// remote and must never be collateral.
//
// The exact figure the jammer lands on varies with how many strikes accumulate
// before the run ends. What is asserted is that it was cut at all, and that the
// other peer was not.
#include <flux/socket/socket.h>
#include <flux/address.h>
#include <flux/wire/packet_builder.h>
#include <flux/socket/packet_slot.h>
#include <flux/flow/flow_handle.h>
#include <flux/socket/platform/faulty_socket.h>
#include "flux_net.h"
#include "harness.h"
#include <chrono>
#include <thread>
#include <cstdio>
#include <vector>
namespace flux = bcp::flux; namespace common = bcp::common;
namespace {
    constexpr uint16_t RECV = 24470, JAMMER = 24471, GOOD = 24472;
    void Pump(flux::Socket& s)
    { flux::PacketSlotHandle in[32]; s.Update();
      { flux::PollCursor c = s.Poll(in, 32); while (c.Next()) {} } s.Flush(); }
}
int main()
{
    flux::Socket recv, jammer, good;
    flux::Socket::Config rc{};
    rc.type = flux_net::BACKEND; rc.port = RECV; rc.maxPeers = 8;
    rc.flows.outCount = 8; rc.flows.inCount = 8; rc.flows.stagingCount = 256;
    rc.flows.recvGrant = 64;
    rc.liveness.flowStallTimeoutMicros = 60'000;   // 60 ms, so strikes come fast
    CHECK(recv.Init(rc) == common::Error::Ok);

    flux::Socket::Config sc{};
    sc.maxPeers = 8; sc.flows.outCount = 8; sc.flows.inCount = 8;
    sc.flows.stagingCount = 512; sc.timers.retryIntervalMicros = 600'000'000;
    sc.type = flux::Socket::BackendType::FAULTY; sc.port = JAMMER;
    CHECK(jammer.Init(sc) == common::Error::Ok);
    sc.type = flux_net::BACKEND; sc.port = GOOD;
    sc.timers.retryIntervalMicros = 200'000;
    CHECK(good.Init(sc) == common::Error::Ok);

    const flux::Address rAddr = flux_net::Loopback(RECV);
    (void)jammer.BuildPacket().NoFlow().PutU8(1).Send(rAddr);
    (void)good.BuildPacket().NoFlow().PutU8(1).Send(rAddr);
    for (int i = 0; i < 300; ++i) { Pump(jammer); Pump(good); Pump(recv);
        std::this_thread::sleep_for(std::chrono::milliseconds(2)); }

    if (auto* f = flux::platform::FaultySocket::ForPort(JAMMER))
    { flux::platform::FaultySocket::Profile p{}; p.seed = 0x77; p.lossPercent = 40; f->SetProfile(p); }

    const uint32_t jamStart  = recv.RecvGrantFor(flux_net::Loopback(JAMMER));
    const uint32_t goodStart = recv.RecvGrantFor(flux_net::Loopback(GOOD));
    const std::vector<uint8_t> body(300, 0x5A);

    // One flow each, kept alive. The jammer's cursor sticks on its first loss
    // and never moves, so every batch it sends afterwards piles up behind that
    // gap and is thrown away when the stall timeout passes. Each of those is a
    // strike. A fresh flow per round would have to re-jam every time, which is
    // why an earlier shape of this test produced two strikes in twelve rounds.
    flux::FlowHandle jf = jammer.OpenFlow(60, flux::FlowMode::RELIABLE_ORDERED);
    flux::FlowHandle gf = good.OpenFlow(90, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!jf.Failed()); CHECK(!gf.Failed());

    for (int round = 0; round < 16; ++round)
    {
        for (int k = 0; k < 10; ++k) {
            (void)jammer.BuildPacket().WithFlow(jf).PutBytes(body.data(), body.size()).Send(rAddr);
            (void)good.BuildPacket().WithFlow(gf).PutBytes(body.data(), body.size()).Send(rAddr);
        }
        for (int i = 0; i < 60; ++i) { Pump(jammer); Pump(good); Pump(recv);
            std::this_thread::sleep_for(std::chrono::milliseconds(2)); }
    }
    jammer.CloseFlow(jf); good.CloseFlow(gf);

    const uint32_t jamEnd  = recv.RecvGrantFor(flux_net::Loopback(JAMMER));
    const uint32_t goodEnd = recv.RecvGrantFor(flux_net::Loopback(GOOD));
    std::printf("jammer %u -> %u | well-behaved %u -> %u\n",
                jamStart, jamEnd, goodStart, goodEnd);
    CHECK(jamEnd < jamStart);      // the jammer was cut
    CHECK(goodEnd == goodStart);   // and the other peer untouched
    recv.Shutdown(); jammer.Shutdown(); good.Shutdown();
    return test::report();
}
