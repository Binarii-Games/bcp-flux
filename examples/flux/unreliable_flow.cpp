// A opens an UNRELIABLE flow and sends a numbered burst on it to B.
//
// One word different from reliable_flow: the mode passed to OpenFlow. Everything
// else about a flow is the same, so this one keeps to a single peer to isolate
// what the mode changes; reliable_flow is where one flow reaching several peers
// is shown.
//
// UNRELIABLE still numbers and acknowledges every packet, so loss is visible to
// congestion control, but nothing is ever retransmitted and nothing is held
// back to fix order. A lost packet stays lost and a late one is delivered late.
// Nothing is dropped or reordered on loopback, so the output here matches the
// reliable case; the difference is what happens on a path that misbehaves.
//
//     ./unreliable_flow

#include <common/log.h>

#include <flux/address.h>
#include <flux/flow/flow_handle.h>
#include <flux/socket/packet_slot.h>
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>

#include <atomic>
#include <chrono>
#include <thread>

#include "setup.h"

namespace common = bcp::common;
namespace flux   = bcp::flux;

constexpr uint16_t PORT_A  = 9500;
constexpr uint16_t PORT_B  = 9501;
constexpr uint16_t FLOW_ID = 7;
constexpr uint32_t BURST   = 8;

static std::atomic<uint32_t> delivered{0};

static void Tick(flux::Socket& socket)
{
    flux::PacketSlotHandle inbox[16];

    while (delivered < BURST)
    {
        socket.Update();

        const uint32_t count = socket.Poll(inbox, 16);
        for (uint32_t i = 0; i < count; ++i)
        {
            // The flow id and sequence number ride the wire header, so an
            // UNRELIABLE packet is still numbered, it just is not resent.
            const uint16_t flowId = inbox[i].Read()->FlowId();

            flux::PacketSlotReader reader{std::move(inbox[i])};
            uint32_t seq = 0;
            reader.TakeU32(seq);

            common::LogF(common::LogLevel::Info, "B got flow %u packet %u", flowId, seq);
            ++delivered;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

int main()
{
    flux::Socket::Config config;
    config.type             = examples::BACKEND;
    config.flows.outCount   = 16;
    config.flows.inCount    = 16;

    flux::Socket a, b;

    config.port = PORT_A;
    if (a.Init(config) != common::Error::Ok) return 1;

    config.port = PORT_B;
    if (b.Init(config) != common::Error::Ok) return 1;

    const flux::Address addrB = flux::Address::From("::1", PORT_B).Take();

    std::thread responder(Tick, std::ref(b));

    // Local, immediate, and not bound to B: this flow could be sent to any
    // number of peers, and each would get its own state. One is enough here.
    flux::FlowHandle flow = a.OpenFlow(FLOW_ID, flux::FlowMode::UNRELIABLE);

    flux::PacketSlotHandle sink[8];

    for (uint32_t seq = 0; seq < BURST; ++seq)
        a.BuildPacket().WithFlow(flow).PutU32(seq).Send(addrB);

    // A keeps pumping so the acks come back. They resolve the in-flight
    // accounting and feed congestion control; they never cause a resend.
    while (delivered < BURST)
    {
        a.Update();
        a.Poll(sink, 8);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // Good practice, not a requirement. This tells B the flow is finished and
    // lets the slot be recycled sooner. Flows are cleaned up on their own when
    // the peer is removed or the socket shuts down, so nothing leaks without it.
    (void)a.CloseFlow(flow);

    responder.join();
    return 0;
}
