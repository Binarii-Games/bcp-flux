// A packet with no flow and no encryption.
//
// The cheapest thing Flux sends. One controller byte in front of the payload,
// and nothing else: no sequence number, no acknowledgement, no retransmission,
// no tag, no nonce. A UDP datagram with a byte of framing.
//
// Nothing about it is protected. Any party can read it, forge one, or alter one
// in flight, so it is for traffic with nothing to keep and no need to trust the
// sender. By default a receiver still wants a peer it has handshaked with
// before it will accept one, which is hygiene rather than authentication.
//
//     ./unsecured

#include <common/log.h>

#include <flux/address.h>
#include <flux/socket/packet_slot.h>
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <thread>

#include "setup.h"

namespace common = bcp::common;
namespace flux   = bcp::flux;

constexpr uint16_t PORT_A = 9580;
constexpr uint16_t PORT_B = 9581;

int main()
{
    flux::Socket::Config config{};
    config.type     = examples::BACKEND;
    config.maxPeers = 8;

    flux::Socket a, b;
    config.port = PORT_A;
    if (a.Init(config) != common::Error::Ok) return 1;
    config.port = PORT_B;
    if (b.Init(config) != common::Error::Ok) return 1;

    const flux::Address addrB = flux::Address::From("::1", PORT_B).Take();

    flux::PacketSlotHandle inbox[8];
    auto pump = [&](int rounds) {
        for (int i = 0; i < rounds; ++i)
        {
            a.Update(); a.Poll(inbox, 8);
            b.Update(); b.Poll(inbox, 8);
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
    };

    // The handshake is for the peer relationship, not for this packet. An
    // unsecured send needs no session, but the receiver's default policy is to
    // take one only from an address it already knows.
    if (a.Connect(addrB) != common::Error::Ok) return 1;
    pump(400);

    uint8_t payload[32];
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = static_cast<uint8_t>(i * 7 + 1);

    const common::Error sent = a.BuildPacket()
        .Unsecured()
        .NoFlow()
        .PutBytes(payload, sizeof(payload))
        .Send(addrB);

    if (sent != common::Error::Ok)
    {
        common::LogF(common::LogLevel::Error, "send failed: %d", static_cast<int>(sent));
        return 1;
    }

    bool arrived = false;
    for (int i = 0; i < 200 && !arrived; ++i)
    {
        a.Update(); a.Poll(inbox, 8);
        b.Update();

        const uint32_t count = b.Poll(inbox, 8);
        for (uint32_t k = 0; k < count; ++k)
        {
            const flux::PacketSlot* packet = inbox[k].Read();
            if (!packet) continue;

            const size_t   offset = packet->ContentOffset();
            const uint8_t* body   = packet->Content(offset);
            const size_t   length = packet->dataSize - offset;

            const bool intact = length == sizeof(payload)
                             && std::memcmp(body, payload, length) == 0;

            common::LogF(common::LogLevel::Info,
                         "B received %zu bytes on the wire, %zu of payload, %s",
                         static_cast<size_t>(packet->dataSize), length,
                         intact ? "identical" : "CORRUPT");
            common::LogF(common::LogLevel::Info,
                         "framing overhead: %zu byte%s",
                         offset, offset == 1 ? "" : "s");
            arrived = intact;
        }
        std::this_thread::sleep_for(std::chrono::microseconds(200));
    }

    for (auto& h : inbox) h = flux::PacketSlotHandle::Invalid();
    a.Shutdown();
    b.Shutdown();

    if (!arrived) common::LogF(common::LogLevel::Error, "nothing arrived");
    return arrived ? 0 : 1;
}
