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

        const uint32_t count = socket.Poll(inbox, 8);
        for (uint32_t i = 0; i < count; ++i)
        {
            const flux::PacketSlot* packet = inbox[i].Read();
            const size_t            offset = packet->ContentOffset();

            common::LogF(common::LogLevel::Info, "B got: %.*s",
                         int(packet->ContentLength()),
                         reinterpret_cast<const char*>(packet->Content(offset)));

            // The reply comes from the packet, not the socket. PrepareResponse
            // hands back the ordinary builder already aimed at the sender, so
            // the chain is the usual one and ends with Respond() in place of
            // Send(address). RespondSecured() exists too, with the SendSecured
            // contract.
            inbox[i].PrepareResponse()
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
        const uint32_t count = a.Poll(inbox, 8);
        for (uint32_t i = 0; i < count && !got; ++i)
        {
            const flux::PacketSlot* packet = inbox[i].Read();
            const size_t            offset = packet->ContentOffset();

            common::LogF(common::LogLevel::Info, "A got: %.*s",
                         int(packet->ContentLength()),
                         reinterpret_cast<const char*>(packet->Content(offset)));
            got = true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    responder.join();
    return answered ? 0 : 1;
}
