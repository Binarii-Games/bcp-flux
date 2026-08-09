// A sends one message, B answers it through the packet itself. The reply
// never names an address: a packet delivered by Poll can build its own
// response, already aimed at whoever sent it.
//
//     ./respond

#include <common/log.h>

#include <flux/address.h>
#include <flux/socket/packet_slot.h>
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>

#include "setup.h"

#include <atomic>
#include <chrono>
#include <thread>

namespace common = bcp::common;
namespace flux   = bcp::flux;

constexpr uint16_t PORT_A = 9530;
constexpr uint16_t PORT_B = 9531;

constexpr uint8_t PONG[] = "pong";

static std::atomic<bool> answered{false};

// B's loop: pump, and answer the first message that arrives.
static void Tick(flux::Socket& socket)
{
    flux::PacketSlotHandle inbox[8];

    for (;;)
    {
        socket.Flush();
        socket.Update();

        flux::PollCursor cursor = socket.Poll(inbox, 8);
        while (cursor.Next())
        {
            common::LogF(common::LogLevel::Info, "B got: %.*s",
                         int(cursor.Message().ContentLength()),
                         reinterpret_cast<const char*>(cursor.Message().Content()));

            // The reply comes from the packet, not the socket. PrepareResponse
            // hands back the ordinary builder already aimed at the sender, so
            // the chain is the usual one and ends with Respond() in place of
            // Send(address). RespondSecured() exists too, with the SendSecured
            // contract.
            cursor.Packet().PrepareResponse()
                .NoFlow()
                .PutBytes(PONG, sizeof(PONG) - 1)
                .Respond();

            answered = true;
            return;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

int main()
{
    flux::Socket::Config config;
    config.type = examples::BACKEND;

    flux::Socket a, b;

    config.port = PORT_A;
    if (a.Init(config) != common::Error::Ok) return 1;

    config.port = PORT_B;
    if (b.Init(config) != common::Error::Ok) return 1;

    const flux::Address addrB = flux::Address::From("::1", PORT_B).Take();

    std::thread responder(Tick, std::ref(b));

    constexpr uint8_t PING[] = "ping";

    // No connect step: this first send to an unknown address starts the
    // handshake and holds the message until the session is up.
    a.BuildPacket().NoFlow().PutBytes(PING, sizeof(PING) - 1).Send(addrB);

    // Pump A until B's answer lands, and print it.
    flux::PacketSlotHandle inbox[8];
    bool got = false;

    while (!got)
    {
        a.Flush();
        a.Update();
        flux::PollCursor cursor = a.Poll(inbox, 8);
        while (!got && cursor.Next())
        {
            common::LogF(common::LogLevel::Info, "A got: %.*s",
                         int(cursor.Message().ContentLength()),
                         reinterpret_cast<const char*>(cursor.Message().Content()));
            got = true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    responder.join();
    return answered ? 0 : 1;
}
