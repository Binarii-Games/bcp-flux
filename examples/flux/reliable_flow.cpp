// A opens ONE RELIABLE_ORDERED flow and sends a numbered burst on it to two
// different peers.
//
// A flow is not tied to a peer. OpenFlow takes no address: it declares what the
// flow IS (its id, its mode, how much it may keep in flight) and the per-target
// state is created by the first packet sent to each address. So one handle
// serves every peer, and each gets its own sequence numbering, its own
// retransmits and its own failures.
//
// Opening is also local and costs nothing on the wire: the flow comes back OPEN
// and can be sent on immediately. Neither B nor C has heard of it, and each
// registers its own receiving half from the first packet that reaches it.
//
// RELIABLE_ORDERED means every packet arrives and arrives in send order, per
// peer. Lost ones are retransmitted from a retained copy, and one that overtakes
// a gap is held back until the gap fills. Ordering is per target, so a stalled
// peer never holds up another.
//
// Flow storage is off by default, so Config::flows has to be given a pool.
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
constexpr uint16_t PORT_C  = 9502;
constexpr uint16_t FLOW_ID = 7;
constexpr uint32_t BURST   = 8;

// One counter per receiver, so the two conversations can be seen arriving
// independently.
static std::atomic<uint32_t> deliveredB{0};
static std::atomic<uint32_t> deliveredC{0};

// A receiver's loop, run by both B and C. Flow packets come out of Poll like any
// other packet; the flow id they carry is on the slot. Neither receiver opened
// anything: their side of the flow was created by the traffic itself.
static void Tick(flux::Socket& socket, const char* name, std::atomic<uint32_t>& delivered)
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

            common::LogF(common::LogLevel::Info, "%s got flow %u packet %u",
                         name, flowId, seq);
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

    flux::Socket a, b, c;

    config.port = PORT_A;
    if (a.Init(config) != common::Error::Ok) return 1;

    config.port = PORT_B;
    if (b.Init(config) != common::Error::Ok) return 1;

    config.port = PORT_C;
    if (c.Init(config) != common::Error::Ok) return 1;

    const flux::Address addrB = flux::Address::From("::1", PORT_B).Take();
    const flux::Address addrC = flux::Address::From("::1", PORT_C).Take();

    std::thread responderB(Tick, std::ref(b), "B", std::ref(deliveredB));
    std::thread responderC(Tick, std::ref(c), "C", std::ref(deliveredC));

    // No address here. The flow belongs to this socket, not to a peer, and it is
    // OPEN and sendable the moment it exists. The peer handshakes still happen
    // underneath on first send, and the packets park behind them.
    flux::FlowHandle flow = a.OpenFlow(FLOW_ID, flux::FlowMode::RELIABLE_ORDERED);

    // WithFlow instead of NoFlow: the packet gets the flow's id and its next
    // sequence number, which is what makes acking, ordering and resending
    // possible at all. The SAME handle addresses both peers, and the sequence
    // is counted separately for each, so both see 0..BURST-1.
    for (uint32_t seq = 0; seq < BURST; ++seq)
    {
        a.BuildPacket().WithFlow(flow).PutU32(seq).Send(addrB);
        a.BuildPacket().WithFlow(flow).PutU32(seq).Send(addrC);
    }

    // A keeps pumping: the acks that resolve the in-flight packets come back
    // here, and an unacked reliable packet is retransmitted from Update.
    flux::PacketSlotHandle sink[8];
    while (deliveredB < BURST || deliveredC < BURST)
    {
        a.Update();
        a.Poll(sink, 8);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // Two different questions. The flow's own state is whether it is open at
    // all; its state with one peer is where a failure shows up, so a target
    // that died would read FAILED there while the flow stayed OPEN for the
    // other. 0 is OPEN.
    common::LogF(common::LogLevel::Info, "flow=%d  toB=%d  toC=%d",
                 int(a.GetFlowState(flow)),
                 int(a.GetFlowState(flow, addrB)),
                 int(a.GetFlowState(flow, addrC)));

    // Good practice, not a requirement: this closes the flow with EVERY peer it
    // reached, releasing what each was holding. Flows are cleaned up on their
    // own when a peer is removed or the socket shuts down, so nothing leaks
    // without it.
    (void)a.CloseFlow(flow);

    responderB.join();
    responderC.join();
    return 0;
}
