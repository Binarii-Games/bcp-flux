// A sends one message, B answers it. A never reads a packet.
//
// A still has to pump its own socket. The handshake is a four-message exchange
// and Poll is what processes it, so without A polling, A's message never
// reaches B. A just never looks at what comes out.
//
//     ./send_and_respond

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

constexpr uint16_t PORT_A = 9500;
constexpr uint16_t PORT_B = 9501;

constexpr uint8_t REPLY[] = "received: ";
constexpr uint8_t QUOTE[] = "\"";

static std::atomic<bool> answered{false};

// B's loop. Flux owns no thread, so Update and Poll only happen because someone
// calls them. Update first: timers and handshake retries apply before the pass
// that reads what arrived. Returns once it has answered one message.
static void Tick(flux::Socket& socket)
{
    // Poll fills these with handles onto the socket's own receive slots. The
    // payload is never copied out, and a handle frees its slot when it dies.
    flux::PacketSlotHandle inbox[8];

    for (;;)
    {
        socket.Update();

        const uint32_t count = socket.Poll(inbox, 8);
        for (uint32_t i = 0; i < count; ++i)
        {
            // A slot holds the whole wire packet. ContentOffset is where the
            // header ends and the application payload starts.
            const flux::PacketSlot* packet  = inbox[i].Read();
            const size_t            offset  = packet->ContentOffset();
            const uint8_t*          content = packet->Content(offset);
            const size_t            length  = packet->ContentLength();

            common::LogF(common::LogLevel::Info, "B got: %.*s",
                         int(length), reinterpret_cast<const char*>(content));

            // NoFlow is a standalone packet: no sequence number, no ack, no
            // retransmission. The cheapest thing Flux sends.
            socket.BuildPacket().NoFlow()
                .PutBytes(REPLY, sizeof(REPLY) - 1)
                .PutBytes(QUOTE, 1)
                .PutBytes(content, length)
                .PutBytes(QUOTE, 1)
                .Send(packet->address);

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

    constexpr uint8_t HELLO[] = "hello from A";

    // No connect step: this first send to an unknown address starts the
    // handshake and holds the message until the session is up.
    a.BuildPacket().NoFlow().PutBytes(HELLO, sizeof(HELLO) - 1).Send(addrB);

    // Carries A's side of the handshake. Nothing is read out of it.
    flux::PacketSlotHandle sink[8];
    while (!answered)
    {
        a.Update();
        a.Poll(sink, 8);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    responder.join();
    return 0;
}
