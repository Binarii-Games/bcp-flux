// Readable on the wire, but not alterable.
//
// Three levels of protection, chosen per packet:
//
//   default      encrypted and authenticated
//   MacOnly()    sent as it is, with a tag over the whole packet
//   Unsecured()  no tag at all, forgeable by anyone
//
// MacOnly is for traffic that is public anyway and sent often. A game's state
// replication is the case it exists for: nobody needs the positions hidden, but
// everybody needs them to be the ones the server actually sent. It costs the
// same bytes as encrypting and about half the CPU.
//
// It carries a flow like anything else, so ordering, acknowledgement and
// congestion control are unaffected. The sequence number is inside the
// authenticated range: readable, not forgeable.
//
//     ./mac_only

#include <common/log.h>

#include <flux/address.h>
#include <flux/flow/flow_handle.h>
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

constexpr uint16_t PORT_A  = 9600;
constexpr uint16_t PORT_B  = 9601;
constexpr uint16_t FLOW_ID = 3;

int main()
{
    flux::Socket::Config config{};
    config.type            = examples::BACKEND;
    config.maxPeers        = 8;
    config.flows.outCount  = 4;
    config.flows.inCount   = 4;
    config.flows.flowCount = 8;

    flux::Socket a, b;
    config.port = PORT_A;
    if (a.Init(config) != common::Error::Ok) return 1;
    config.port = PORT_B;
    if (b.Init(config) != common::Error::Ok) return 1;

    const flux::Address addrB = flux::Address::From("::1", PORT_B).Take();

    flux::PacketSlotHandle inbox[16];
    auto pump = [&](int rounds) {
        for (int i = 0; i < rounds; ++i)
        {
            a.Flush();
            a.Update(); a.Poll(inbox, 16);
            b.Flush();
            b.Update(); b.Poll(inbox, 16);
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
    };

    if (a.Connect(addrB) != common::Error::Ok) return 1;
    pump(400);

    uint8_t state[64];
    for (size_t i = 0; i < sizeof(state); ++i)
        state[i] = static_cast<uint8_t>(i * 3 + 7);

    // A flow, because state replication needs sequencing whether or not it
    // needs secrecy. Unreliable: a position update older than one already
    // delivered is worth nothing, so it is never resent.
    flux::FlowHandle flow = a.OpenFlow(FLOW_ID, flux::FlowMode::UNRELIABLE);
    if (flow.Failed()) return 1;

    const common::Error sent = a.BuildPacket()
        .MacOnly()
        .WithFlow(flow)
        .PutBytes(state, sizeof(state))
        .Send(addrB);

    if (sent != common::Error::Ok)
    {
        common::LogF(common::LogLevel::Error, "send failed: %d", static_cast<int>(sent));
        return 1;
    }

    bool arrived = false;
    for (int i = 0; i < 200 && !arrived; ++i)
    {
        a.Flush();
        a.Update(); a.Poll(inbox, 16);
        b.Flush();
        b.Update();

        const uint32_t count = b.Poll(inbox, 16);
        for (uint32_t k = 0; k < count; ++k)
        {
            const flux::PacketSlot* packet = inbox[k].Read();
            if (!packet) continue;

            const uint8_t* body   = packet->Content(packet->ContentOffset());
            const size_t   length = packet->ContentLength();
            const bool     intact = length == sizeof(state)
                                 && std::memcmp(body, state, length) == 0;

            common::LogF(common::LogLevel::Info,
                         "B received %zu bytes, %s, mac-only: %s",
                         length, intact ? "identical" : "CORRUPT",
                         packet->IsMacOnly() ? "yes" : "no");
            common::LogF(common::LogLevel::Info,
                         "  %zu on the wire, so %zu of framing, same as encrypting",
                         static_cast<size_t>(packet->dataSize),
                         static_cast<size_t>(packet->dataSize) - length);
            arrived = intact;
        }
        std::this_thread::sleep_for(std::chrono::microseconds(200));
    }

    // Anyone on the path can read those 64 bytes. Nobody without the session
    // key can change one of them: the tag covers the whole packet, so a flipped
    // bit is dropped on arrival rather than delivered.
    common::LogF(common::LogLevel::Info,
                 "payload was readable in flight, and unalterable");

    for (auto& h : inbox) h = flux::PacketSlotHandle::Invalid();
    (void)a.CloseFlow(flow);
    a.Shutdown();
    b.Shutdown();

    if (!arrived) common::LogF(common::LogLevel::Error, "nothing arrived");
    return arrived ? 0 : 1;
}
