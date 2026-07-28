// A opens a RELIABLE_ORDERED flow to B and sends a numbered burst on it.
//
// Opening a flow is local and costs nothing on the wire: OpenFlow returns a
// flow that is already OPEN and can be sent on immediately. B has never heard
// of it and registers its receiving half from the first packet that arrives.
// Flow storage is off by default, so Config::flows has to be given a pool on
// both directions.
//
// RELIABLE_ORDERED means every packet arrives and arrives in send order. Lost
// ones are retransmitted from a retained copy, and one that overtakes a gap is
// held back until the gap fills.
//
//     ./reliable_flow

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

// B's loop. Flow packets come out of Poll like any other packet; the flow id
// they carry is on the slot.
static void Tick(flux::Socket& socket)
{
    flux::PacketSlotHandle inbox[16];

    while (delivered < BURST)
    {
        socket.Update();

        const uint32_t count = socket.Poll(inbox, 16);
        for (uint32_t i = 0; i < count; ++i)
        {
            // A flow packet carries its flow id and sequence number in the wire
            // header, so the id is on the slot before anything is decoded.
            const uint16_t flowId = inbox[i].Read()->FlowId();

            // A reader takes the handle and gives a cursor over the payload;
            // TakeU32 mirrors the PutU32 that sent it.
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

    // Local and immediate: no wire exchange, nothing to wait for. The peer
    // handshake still happens underneath on first send, and the packets park
    // behind it.
    flux::FlowHandle flow = a.OpenFlow(addrB, FLOW_ID, flux::FlowMode::RELIABLE_ORDERED);

    flux::PacketSlotHandle sink[8];

    // WithFlow instead of NoFlow: the packet gets the flow's id and its next
    // sequence number, which is what makes acking, ordering and resending
    // possible at all.
    for (uint32_t seq = 0; seq < BURST; ++seq)
        a.BuildPacket().WithFlow(flow).PutU32(seq).Send(addrB);

    // A keeps pumping: the acks that resolve the in-flight packets come back
    // here, and an unacked reliable packet is retransmitted from Update.
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
