// Two sockets in one process, a thread each, trading one message and one reply.
//
// Both send before either has heard anything, so both sides start a handshake
// at the same moment. The collision resolves on its own and the session comes
// up once.
//
// Each side opens with a message. Whoever receives a message answers it with
//     received: "<what arrived>"
// and whoever receives an answer is done.
//
//     ./simultaneous_handshake

#include <common/log.h>

#include <flux/address.h>
#include <flux/socket/packet_slot.h>
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>

#include "setup.h"

#include <chrono>
#include <cstring>
#include <thread>

namespace common = bcp::common;
namespace flux   = bcp::flux;

constexpr uint16_t PORT_A = 9500;
constexpr uint16_t PORT_B = 9501;

constexpr uint8_t REPLY[]    = "received: ";
constexpr uint8_t QUOTE[]    = "\"";
constexpr size_t  REPLY_SIZE = sizeof(REPLY) - 1;

// Flux owns no thread, so Update and Poll only happen because someone calls
// them. Update first: timers and handshake retries apply before the pass that
// reads what arrived.
static void Tick(flux::Socket& socket, const char* name)
{
    // Poll fills these with handles onto the socket's own receive slots. The
    // payload is never copied out, and a handle frees its slot when it dies.
    flux::PacketSlotHandle inbox[8];

    for (;;)
    {
        socket.Flush();
        socket.Update();

        const uint32_t count = socket.Poll(inbox, 8);
        for (uint32_t i = 0; i < count; ++i)
        {
            // ContentOffset is where the wire header ends and the payload starts.
            const flux::PacketSlot* packet  = inbox[i].Read();
            const size_t            offset  = packet->ContentOffset();
            const uint8_t*          content = packet->Content(offset);
            const size_t            length  = packet->ContentLength();

            common::LogF(common::LogLevel::Info, "%s got: %.*s",
                         name, int(length), reinterpret_cast<const char*>(content));

            // An answer to our own opening message: this side is finished.
            if (std::memcmp(content, REPLY, REPLY_SIZE) == 0)
                return;

            socket.BuildPacket().NoFlow()
                .PutBytes(REPLY, REPLY_SIZE)
                .PutBytes(QUOTE, 1)
                .PutBytes(content, length)
                .PutBytes(QUOTE, 1)
                .Send(packet->address);
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

    const flux::Address addrA = flux::Address::From("::1", PORT_A).Take();
    const flux::Address addrB = flux::Address::From("::1", PORT_B).Take();

    constexpr uint8_t HELLO_A[] = "hello from A";
    constexpr uint8_t HELLO_B[] = "hello from B";

    // NoFlow is a standalone packet: no sequence number, no ack, no
    // retransmission. And there is no connect step: a first send to an unknown
    // address starts the handshake and holds the message until the session is up.
    a.BuildPacket().NoFlow().PutBytes(HELLO_A, sizeof(HELLO_A) - 1).Send(addrB);
    b.BuildPacket().NoFlow().PutBytes(HELLO_B, sizeof(HELLO_B) - 1).Send(addrA);

    std::thread threadA(Tick, std::ref(a), "A");
    std::thread threadB(Tick, std::ref(b), "B");

    threadA.join();
    threadB.join();
    return 0;
}
