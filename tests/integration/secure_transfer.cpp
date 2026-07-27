// Secure application transfer, end to end over real UDP. Covers the two things
// Send promises for non-flow traffic: a message sent to a peer not yet known is
// parked behind the handshake and flushed intact once the session is up, and an
// established session carries messages both directions with every byte
// preserved (including an empty body).
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>
#include <flux/socket/packet_slot.h>

#include "flux_net.h"
#include "harness.h"

#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

namespace flux = bcp::flux;
namespace common = bcp::common;

// A small multi-field application message: an opcode, an id, and a byte body.
struct Message
{
    uint8_t              op;
    uint32_t             id;
    std::vector<uint8_t> body;

    common::Error Send(flux::Socket& socket, const flux::Address& to) const
    {
        return socket.BuildPacket().NoFlow()
            .PutU8(op).PutU32(id).PutU16(static_cast<uint16_t>(body.size()))
            .PutBytes(body.data(), body.size()).Send(to);
    }

    bool operator==(const Message& other) const
    {
        return op == other.op && id == other.id && body == other.body;
    }
};

// Drains everything a socket has ready, decoding each packet back into a
// Message, and appends them to `out`.
static void Collect(flux::Socket& socket, std::vector<Message>& out)
{
    flux::PacketSlotHandle handles[64];
    uint32_t count = socket.Poll(handles, 64);
    for (uint32_t i = 0; i < count; ++i)
    {
        flux::PacketSlotReader reader{std::move(handles[i])};
        Message message{};
        uint16_t length = 0;
        if (!reader.TakeU8(message.op))  continue;
        if (!reader.TakeU32(message.id)) continue;
        if (!reader.TakeU16(length))     continue;
        message.body.resize(length);
        if (length && !reader.TakeBytes(message.body.data(), length)) continue;
        out.push_back(std::move(message));
    }
}

static bool Received(const std::vector<Message>& all, const Message& wanted)
{
    for (const Message& message : all)
        if (message == wanted) return true;
    return false;
}

// A message to an unknown peer is parked behind the handshake and flushed
// intact, and once established both directions carry traffic byte-for-byte.
static void secure_messages_cross_intact()
{
    flux::Socket client, server;
    CHECK(client.Init({ .type = flux_net::BACKEND, .port = 9420,
                        .maxPeers = 16, .pendingPacketCount = 32 }) == common::Error::Ok);
    CHECK(server.Init({ .type = flux_net::BACKEND, .port = 9421,
                        .maxPeers = 16, .pendingPacketCount = 32 }) == common::Error::Ok);

    const flux::Address serverAddr = flux_net::Loopback(9421);
    const flux::Address clientAddr = flux_net::Loopback(9420);

    std::vector<Message> gotByServer, gotByClient;

    // Sent before the peer is known: must park behind the handshake, not drop.
    const Message parked{ 0x10, 1001, {'h', 'e', 'l', 'l', 'o'} };
    CHECK(parked.Send(client, serverAddr) == common::Error::Ok);
    CHECK(!flux_net::Established(client, serverAddr));   // handshake not done yet

    for (int i = 0; i < 200; ++i)
    {
        Collect(client, gotByClient);
        Collect(server, gotByServer);
        client.Update();
        server.Update();
        if (flux_net::Established(client, serverAddr) && Received(gotByServer, parked)) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(flux_net::Established(client, serverAddr));
    CHECK(flux_net::Established(server, clientAddr));
    CHECK(Received(gotByServer, parked));   // the parked message arrived intact

    // Established both directions, including an empty body.
    const Message toClient{ 0x20, 2001, {'l', 'i', 'v', 'e'} };
    const Message toServer{ 0x21, 2002, {} };   // empty-body edge
    CHECK(toClient.Send(server, clientAddr) == common::Error::Ok);
    CHECK(toServer.Send(client, serverAddr) == common::Error::Ok);

    for (int i = 0; i < 40; ++i)
    {
        Collect(client, gotByClient);
        Collect(server, gotByServer);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(Received(gotByClient, toClient));
    CHECK(Received(gotByServer, toServer));
}

int main()
{
    secure_messages_cross_intact();
    return test::report();
}
