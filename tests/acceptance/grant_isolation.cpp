// One peer must not be able to make a socket deaf to every other peer.
//
// A receiving ordered flow buffers packets that arrive ahead of a gap, and each
// buffered packet pins a slot in the socket-wide receive pool. Nothing today
// bounds how much of that pool one remote may pin, so a single flow behind a
// gap it never fills can take all of it, and once the pool is dry the kernel
// has nowhere to receive into for anybody. The socket goes deaf until the stall
// timeout frees the buffer.
//
// The contract this test states: what one peer pins is bounded by what the
// receiver granted that peer, so traffic from every other peer is delivered
// untouched no matter what the first one does.
//
// The setup puts the damage on one sender rather than on the receiver, because
// the FAULTY kernel is per socket. The abusive sender loses its own packets on
// the way out and never retransmits (retry interval far past the test), so the
// receiver's cursor for that flow sticks at the first gap while later packets
// keep arriving and piling into its hold-back. The receiver's stall timeout is
// set well past the test so the jam is held open throughout. The quiet sender
// uses the ordinary kernel and sends a small, exact number of messages that all
// have to arrive.
//
// Worth being precise about what the abusive peer does, because it is nothing.
// It breaks no rule and forges nothing. It is configured for high throughput, a
// deep waiting ring and a large congestion budget, which is what a peer on a fat
// pipe legitimately has. Every packet it sends is one this socket accepted and
// acknowledged. The pressure comes from a sender whose own limits are set high,
// so the receiver cannot be defended by anything the sender chooses to do, which
// is the whole reason the bound has to be issued and enforced by the receiver.
//
// This test fails until per-peer receive grants exist.
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
#include <vector>

namespace flux   = bcp::flux;
namespace common = bcp::common;

namespace
{
    constexpr uint16_t RECEIVER = 24310;
    constexpr uint16_t ABUSER   = 24311;
    constexpr uint16_t QUIET    = 24312;

    // Small enough that one unbounded hold-back can swallow it. The real
    // default is 2048, which one bulk flow at a 1024 window still takes half
    // of, so the shape of the failure is the same either way.
    constexpr uint32_t RECV_SLOTS = 256;

    // What the quiet peer sends. Every one of these must arrive.
    constexpr uint32_t QUIET_MESSAGES = 24;

    // Enough to overrun RECV_SLOTS many times over if nothing bounds it.
    constexpr uint32_t ABUSE_PACKETS = 12000;

    using flux_net::Loopback;
    using flux_net::Established;

    common::Error InitReceiver(flux::Socket& socket)
    {
        flux::Socket::Config config{};
        config.type          = flux_net::BACKEND;
        config.port          = RECEIVER;
        config.maxPeers      = 8;
        config.recvSlotCount = RECV_SLOTS;
        config.flows.outCount    = 8;
        config.flows.inCount     = 8;
        config.flows.bulkInCount = 4;
        config.flows.stagingCount = 512;
        // Far past the run, so the jam is never reclaimed underneath the test
        // and the pressure on the pool is sustained throughout.
        config.liveness.flowStallTimeoutMicros = 120'000'000;
        return socket.Init(config);
    }

    common::Error InitSender(flux::Socket& socket, uint16_t port,
                             flux::Socket::BackendType backend, uint32_t retryMicros)
    {
        flux::Socket::Config config{};
        config.type     = backend;
        config.port     = port;
        config.maxPeers = 8;
        config.flows.outCount     = 8;
        config.flows.inCount      = 8;
        config.flows.bulkOutCount = 4;
        config.flows.stagingCount = 2048;
        // High throughput rather than misbehaviour. These are the sender's own
        // limits, so a remote sets them however it likes and the receiver never
        // sees the choice.
        config.flows.reliableWaitCount   = 8192;
        config.flows.minCongestionBudget = 64u * 1024u * 1024u;
        config.timers.retryIntervalMicros = retryMicros;
        return socket.Init(config);
    }

    void Pump(flux::Socket& socket)
    {
        flux::PacketSlotHandle inbox[64];
        socket.Update();
        { flux::PollCursor cursor = socket.Poll(inbox, 64); while (cursor.Next()) {} }
        socket.Flush();
    }

    bool Connect(flux::Socket& from, flux::Socket& to,
                 const flux::Address& toAddr, const flux::Address& fromAddr)
    {
        (void)from.BuildPacket().NoFlow().PutU8(1).Send(toAddr);
        const auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::seconds(10))
        {
            Pump(from);
            Pump(to);
            if (Established(from, toAddr) && Established(to, fromAddr)) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return false;
    }
}

int main()
{
    flux::Socket receiver, abuser, quiet;
    CHECK(InitReceiver(receiver) == common::Error::Ok);
    // The abuser never resends, so its gaps stay open for the whole run.
    CHECK(InitSender(abuser, ABUSER, flux::Socket::BackendType::FAULTY,
                     600'000'000) == common::Error::Ok);
    CHECK(InitSender(quiet, QUIET, flux_net::BACKEND,
                     200'000) == common::Error::Ok);

    const flux::Address receiverAddr = Loopback(RECEIVER);
    CHECK(Connect(abuser, receiver, receiverAddr, Loopback(ABUSER)));
    CHECK(Connect(quiet,  receiver, receiverAddr, Loopback(QUIET)));

    // Lose a quarter of what the abuser sends, so its receiving cursor sticks
    // almost immediately and every later packet lands in the hold-back.
    if (auto* faulty = flux::platform::FaultySocket::ForPort(ABUSER))
    {
        flux::platform::FaultySocket::Profile profile{};
        profile.seed        = 0xC3C3;
        profile.lossPercent = 25;
        faulty->SetProfile(profile);
    }

    flux::FlowHandle abusiveFlow =
        abuser.OpenFlow(21, flux::FlowMode::RELIABLE_ORDERED_BULK);
    CHECK(!abusiveFlow.Failed());
    flux::FlowHandle quietFlow =
        quiet.OpenFlow(22, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!quietFlow.Failed());

    const std::vector<uint8_t> body(600, 0xEE);

    // Fill the receiver's hold-back first, so the quiet peer's traffic meets a
    // pool that is already under whatever pressure the abuser can apply.
    for (uint32_t i = 0; i < ABUSE_PACKETS; ++i)
    {
        (void)abuser.BuildPacket().WithFlow(abusiveFlow)
                    .PutBytes(body.data(), body.size()).Send(receiverAddr);
        abuser.Flush();
        if ((i & 15) == 0) Pump(receiver);
    }
    for (int i = 0; i < 200; ++i) { Pump(receiver); Pump(abuser); }

    // Now the quiet peer speaks. Every message it sends must be delivered.
    std::vector<bool> arrived(QUIET_MESSAGES, false);
    uint32_t delivered = 0, sent = 0;

    const auto start = std::chrono::steady_clock::now();
    while (delivered < QUIET_MESSAGES &&
           std::chrono::steady_clock::now() - start < std::chrono::seconds(20))
    {
        if (sent < QUIET_MESSAGES)
        {
            const uint32_t tag = sent;
            if (quiet.BuildPacket().WithFlow(quietFlow).PutU32(tag)
                     .Send(receiverAddr) == common::Error::Ok)
                ++sent;
        }
        quiet.Flush();

        // Keep the abuser pushing, so the pressure does not let up while the
        // quiet peer is trying to be heard.
        (void)abuser.BuildPacket().WithFlow(abusiveFlow)
                    .PutBytes(body.data(), body.size()).Send(receiverAddr);
        abuser.Flush();

        receiver.Update();
        {
            flux::PacketSlotHandle inbox[64];
            flux::PollCursor cursor = receiver.Poll(inbox, 64);
            while (cursor.Next())
            {
                flux::PacketSlotReader& reader = cursor.Message();
                uint32_t tag = 0;
                if (reader.TakeU32(tag) && tag < QUIET_MESSAGES && !arrived[tag])
                {
                    arrived[tag] = true;
                    ++delivered;
                }
            }
        }
        receiver.Flush();
        Pump(quiet);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // The whole point. One peer misbehaving does not cost another peer a single
    // message.
    CHECK(delivered == QUIET_MESSAGES);
    for (uint32_t i = 0; i < QUIET_MESSAGES; ++i)
        CHECK(arrived[i]);

    receiver.Shutdown();
    abuser.Shutdown();
    quiet.Shutdown();
    return test::report();
}
