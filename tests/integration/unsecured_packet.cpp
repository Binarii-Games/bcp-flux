// The plaintext opt-out, end to end.
//
// An unsecured packet carries the controller byte and nothing else Flux adds:
// no sequence, no acknowledgement, no retransmission, no tag, no nonce, no
// channel byte. A UDP datagram with one byte of framing, for traffic that has
// nothing to keep secret.
//
// Asserted here: the payload arrives byte for byte, the framing really is the
// one controller byte, and a flow cannot ride one, since everything a flow
// needs lives inside the seal an unsecured packet does not have.
#include "flux_net.h"

#include <flux/socket/packet_slot.h>
#include <flux/wire/packet_builder.h>

#include "harness.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <thread>

namespace flux   = bcp::flux;
namespace common = bcp::common;

using flux_net::BACKEND;
using flux_net::Loopback;
using flux_net::PumpUntilEstablished;

int main()
{
    flux::Socket::Config config{};
    config.type            = BACKEND;
    config.maxPeers        = 8;
    config.flows.outCount  = 4;
    config.flows.inCount   = 4;
    config.flows.flowCount = 4;

    flux::Socket a, b;
    config.port = 22400;
    CHECK(a.Init(config) == common::Error::Ok);
    config.port = 22401;
    CHECK(b.Init(config) == common::Error::Ok);

    const flux::Address addrA = Loopback(22400);
    const flux::Address addrB = Loopback(22401);

    CHECK(a.Connect(addrB) == common::Error::Ok);
    CHECK(PumpUntilEstablished(a, addrA, b, addrB, 400));

    uint8_t payload[32];
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = static_cast<uint8_t>(i * 7 + 1);

    CHECK(a.BuildPacket().Unsecured().NoFlow()
            .PutBytes(payload, sizeof(payload)).Send(addrB) == common::Error::Ok);

    bool   arrived   = false;
    size_t wireSize  = 0;
    size_t framing   = 0;
    uint8_t got[64]{};
    size_t  gotLen = 0;

    flux::PacketSlotHandle inbox[8];
    for (int i = 0; i < 200 && !arrived; ++i)
    {
        a.Update();
        a.Poll(inbox, 8);
        b.Update();

        const uint32_t count = b.Poll(inbox, 8);
        for (uint32_t k = 0; k < count; ++k)
        {
            const flux::PacketSlot* packet = inbox[k].Read();
            if (!packet) continue;

            framing  = packet->ContentOffset();
            wireSize = packet->dataSize;
            gotLen   = wireSize - framing;
            if (gotLen <= sizeof(got))
                std::memcpy(got, packet->Content(framing), gotLen);
            arrived = true;
        }
        std::this_thread::sleep_for(std::chrono::microseconds(200));
    }

    CHECK(arrived);
    CHECK(gotLen == sizeof(payload));
    CHECK(std::memcmp(got, payload, sizeof(payload)) == 0);

    // One controller byte in front of the payload, and that is the whole of
    // what Flux adds. Anything more means something crept into the cheap path.
    CHECK(framing == 1);
    CHECK(wireSize == sizeof(payload) + 1);

    // A flow needs its sequence and its acknowledgements, and both live inside
    // the seal, so the builder refuses the combination rather than sending
    // something the far side cannot place in order.
    flux::FlowHandle flow = a.OpenFlow(1, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(!flow.Failed());
    CHECK(a.BuildPacket().Unsecured().WithFlow(flow)
            .PutBytes(payload, sizeof(payload)).Send(addrB) != common::Error::Ok);
    (void)a.CloseFlow(flow);

    for (auto& h : inbox) h = flux::PacketSlotHandle::Invalid();
    a.Shutdown();
    b.Shutdown();
    return test::report();
}
