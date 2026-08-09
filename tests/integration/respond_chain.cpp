// A polled packet can build its own reply: PrepareResponse hands back the
// ordinary builder aimed at the packet's source, and the chain ends with
// Respond() or RespondSecured() instead of Send(address). Covers the refusals
// (a handle Poll never delivered, a chain that was never aimed, a moved-from
// handle), the reply round trip over real UDP, answering one packet twice, and
// the secured terminal enforcing the SendSecured contract.
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>
#include <flux/socket/packet_slot.h>

#include "flux_net.h"
#include "harness.h"

#include <chrono>
#include <cstring>
#include <thread>

namespace flux = bcp::flux;
namespace common = bcp::common;

static constexpr uint16_t PORT_A = 9800;
static constexpr uint16_t PORT_B = 9801;

static constexpr uint8_t PING[] = "ping";
static constexpr uint8_t PONG[] = "pong";
static constexpr uint8_t EXTRA  = 0x7;

int main()
{
    // A handle that never went through Poll has no socket to reply through, so
    // the whole chain refuses rather than sending via a socket it was never
    // given.
    {
        flux::PacketSlotHandle unstamped;
        CHECK(unstamped.PrepareResponse().NoFlow().PutU8(1).Respond()
              == common::Error::InvalidState);
    }

    flux::Socket::Config config;
    config.type = flux_net::BACKEND;

    flux::Socket a, b;
    config.port = PORT_A;
    CHECK(a.Init(config) == common::Error::Ok);
    config.port = PORT_B;
    CHECK(b.Init(config) == common::Error::Ok);

    // Respond is only reachable on an aimed chain. A plain BuildPacket chain
    // has no reply target, and must refuse instead of guessing one.
    CHECK(a.BuildPacket().NoFlow().PutU8(1).Respond() == common::Error::InvalidState);

    const flux::Address addrB = flux_net::Loopback(PORT_B);
    CHECK(a.BuildPacket().NoFlow().PutBytes(PING, sizeof(PING) - 1).Send(addrB)
          == common::Error::Ok);

    // Pump both sides: B answers the ping the moment it arrives, A collects
    // what comes back. The loop ends when both replies landed.
    bool answered = false;
    bool gotPong  = false;
    bool gotExtra = false;

    flux::PacketSlotHandle inbox[8];

    for (int spin = 0; spin < 2000 && !(gotPong && gotExtra); ++spin)
    {
        b.Flush();
        b.Update();
        flux::PollCursor cursorB = b.Poll(inbox, 8);
        while (cursorB.Next())
        {
            if (answered)
                continue;
            answered = true;

            // The reply chain: no address anywhere, the handle carries it.
            CHECK(cursorB.Packet().PrepareResponse().NoFlow()
                      .PutBytes(PONG, sizeof(PONG) - 1).Respond()
                  == common::Error::Ok);

            // Each PrepareResponse mints a fresh one-shot builder, so one
            // packet can be answered more than once.
            CHECK(cursorB.Packet().PrepareResponse().NoFlow().PutU8(EXTRA).Respond()
                  == common::Error::Ok);

            // The secured terminal carries the SendSecured contract: nothing
            // pinned A's identity, so the reply is refused, not delivered.
            CHECK(cursorB.Packet().PrepareResponse().NoFlow().PutU8(EXTRA).RespondSecured()
                  == common::Error::NotAuthenticated);

            // Moving the handle moves the reply capability with it; the
            // moved-from handle keeps nothing to send through.
            flux::PacketSlotHandle moved = std::move(cursorB.Packet());
            CHECK(cursorB.Packet().PrepareResponse().NoFlow().PutU8(1).Respond()
                  == common::Error::InvalidState);
            CHECK(!moved.PrepareResponse().Failed());
        }

        a.Flush();
        a.Update();
        flux::PollCursor cursorA = a.Poll(inbox, 8);
        while (cursorA.Next())
        {
            const flux::PacketSlot* packet = cursorA.Packet().Read();
            if (!packet)
                continue;

            const size_t length = cursorA.Message().ContentLength();

            if (length == sizeof(PONG) - 1 &&
                std::memcmp(cursorA.Message().Content(), PONG, length) == 0)
                gotPong = true;
            else if (length == 1 && cursorA.Message().Content()[0] == EXTRA)
                gotExtra = true;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    CHECK(answered);
    CHECK(gotPong);
    CHECK(gotExtra);

    return test::report();
}
