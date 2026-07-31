// Message framing across several packets, and what happens when one is
// abandoned halfway.
//
// A message larger than a packet travels as a run on one ordered flow, each
// packet marked with where it sits. The transport carries the marks and never
// gathers the pieces, so what is asserted here is the contract those marks
// make: a run arrives in order, a complete run reassembles to exactly what was
// sent, and a run that is abandoned is recognisable as abandoned.
//
// The last of those is the one worth having. A flow closed and reopened
// mid-message leaves the receiver holding a partial that nothing will ever
// finish. Without a mark saying a new message starts, the next message would be
// appended to the wreckage of the old one and the receiver would hand the
// application bytes that were never sent, in an order that looks correct.
#include "flux_net.h"

#include <flux/flow/flow_handle.h>
#include <flux/internal/constants.h>
#include <flux/socket/packet_slot.h>
#include <flux/wire/packet_builder.h>

#include "harness.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

namespace flux   = bcp::flux;
namespace common = bcp::common;

using flux_net::BACKEND;
using flux_net::Loopback;
using flux_net::PumpUntilEstablished;

namespace
{
    constexpr uint16_t FLOW_ID = 3;
    constexpr size_t   CHUNK   = 400;

    /** The whole of the receiving side. Mirrors what examples/flux/big_message
        does, because that is the contract being asserted. */
    struct Reassembler
    {
        std::vector<uint8_t> partial;
        std::vector<uint8_t> latest;
        bool     holding   = false;
        uint32_t completed = 0;
        uint32_t abandoned = 0;

        void Take(flux::FlowPart part, const uint8_t* body, size_t length)
        {
            switch (part)
            {
            case flux::FlowPart::Whole:
                if (holding) { ++abandoned; partial.clear(); holding = false; }
                latest.assign(body, body + length);
                ++completed;
                break;
            case flux::FlowPart::First:
                if (holding) { ++abandoned; partial.clear(); }
                partial.assign(body, body + length);
                holding = true;
                break;
            case flux::FlowPart::Middle:
                if (!holding) return;
                partial.insert(partial.end(), body, body + length);
                break;
            case flux::FlowPart::Last:
                if (!holding) return;
                partial.insert(partial.end(), body, body + length);
                latest.swap(partial);
                partial.clear();
                holding = false;
                ++completed;
                break;
            }
        }
    };

    flux::FlowPart PartFor(size_t offset, size_t chunk, size_t total)
    {
        const bool first = offset == 0;
        const bool last  = offset + chunk >= total;
        if (first && last) return flux::FlowPart::Whole;
        if (first)         return flux::FlowPart::First;
        if (last)          return flux::FlowPart::Last;
        return flux::FlowPart::Middle;
    }

    uint8_t ByteAt(uint8_t seed, size_t offset)
    {
        return static_cast<uint8_t>((offset * 31u + (offset >> 8) + seed * 101u) & 0xFF);
    }

    void Pump(flux::Socket& a, flux::Socket& b, Reassembler& into, int rounds)
    {
        flux::PacketSlotHandle sink[64];
        for (int i = 0; i < rounds; ++i)
        {
            a.Update();
            a.Poll(sink, 64);
            b.Update();

            const uint32_t count = b.Poll(sink, 64);
            for (uint32_t k = 0; k < count; ++k)
            {
                const flux::PacketSlot* packet = sink[k].Read();
                if (!packet) continue;
                const size_t offset = packet->ContentOffset();
                into.Take(packet->Part(), packet->Content(offset),
                          packet->dataSize - offset);
            }
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
        for (auto& h : sink) h = flux::PacketSlotHandle::Invalid();
    }
}

int main()
{
    flux::Socket::Config config{};
    config.type               = BACKEND;
    config.maxPeers           = 8;
    config.pendingPacketCount = 128;
    config.flows.outCount     = 8;
    config.flows.inCount      = 8;
    config.flows.flowCount    = 16;

    flux::Socket a, b;
    config.port = 22200;
    CHECK(a.Init(config) == common::Error::Ok);
    config.port = 22201;
    CHECK(b.Init(config) == common::Error::Ok);

    const flux::Address addrB = Loopback(22201);
    const flux::Address addrA = Loopback(22200);
    CHECK(a.Connect(addrB) == common::Error::Ok);
    CHECK(PumpUntilEstablished(a, addrA, b, addrB, 400));

    Reassembler inbound;

    // --- A complete message spanning several packets reassembles exactly ---
    {
        flux::FlowHandle flow = a.OpenFlow(FLOW_ID, flux::FlowMode::RELIABLE_ORDERED);
        CHECK(!flow.Failed());

        const size_t total = CHUNK * 5;
        std::vector<uint8_t> payload(total);
        for (size_t i = 0; i < total; ++i) payload[i] = ByteAt(1, i);

        for (size_t sent = 0; sent < total; sent += CHUNK)
        {
            const size_t n = total - sent < CHUNK ? total - sent : CHUNK;
            CHECK(a.BuildPacket().WithFlow(flow, PartFor(sent, n, total))
                    .PutBytes(payload.data() + sent, n).Send(addrB) == common::Error::Ok);
        }
        Pump(a, b, inbound, 200);

        CHECK(inbound.completed == 1);
        CHECK(inbound.latest.size() == total);
        CHECK(std::memcmp(inbound.latest.data(), payload.data(), total) == 0);
        CHECK(inbound.abandoned == 0);

        (void)a.CloseFlow(flow);
        Pump(a, b, inbound, 40);
    }

    // --- A message abandoned partway is dropped, not spliced onto the next ---
    {
        // Open the id again and send only the opening packets of a message, so
        // the receiver is left holding a run with no end coming.
        flux::FlowHandle flow = a.OpenFlow(FLOW_ID, flux::FlowMode::RELIABLE_ORDERED);
        CHECK(!flow.Failed());

        std::vector<uint8_t> orphan(CHUNK * 3);
        for (size_t i = 0; i < orphan.size(); ++i) orphan[i] = ByteAt(2, i);

        CHECK(a.BuildPacket().WithFlow(flow, flux::FlowPart::First)
                .PutBytes(orphan.data(), CHUNK).Send(addrB) == common::Error::Ok);
        CHECK(a.BuildPacket().WithFlow(flow, flux::FlowPart::Middle)
                .PutBytes(orphan.data() + CHUNK, CHUNK).Send(addrB) == common::Error::Ok);
        Pump(a, b, inbound, 200);

        // The run is open on the receiving side and no Last is coming.
        CHECK(inbound.completed == 1);   // still only the first message

        // The sender gives up on that message and starts again under the same
        // id, which is what an application retrying actually does.
        (void)a.CloseFlow(flow);
        Pump(a, b, inbound, 40);

        flux::FlowHandle again = a.OpenFlow(FLOW_ID, flux::FlowMode::RELIABLE_ORDERED);
        CHECK(!again.Failed());

        const size_t total = CHUNK * 4;
        std::vector<uint8_t> payload(total);
        for (size_t i = 0; i < total; ++i) payload[i] = ByteAt(3, i);

        for (size_t sent = 0; sent < total; sent += CHUNK)
        {
            const size_t n = total - sent < CHUNK ? total - sent : CHUNK;
            CHECK(a.BuildPacket().WithFlow(again, PartFor(sent, n, total))
                    .PutBytes(payload.data() + sent, n).Send(addrB) == common::Error::Ok);
        }
        Pump(a, b, inbound, 300);

        // The abandoned run was recognised as abandoned, and the message that
        // followed is exactly what was sent rather than the two spliced.
        CHECK(inbound.abandoned == 1);
        CHECK(inbound.completed == 2);
        CHECK(inbound.latest.size() == total);
        CHECK(std::memcmp(inbound.latest.data(), payload.data(), total) == 0);

        (void)a.CloseFlow(again);
    }

    // --- Framing is refused on the modes that cannot carry it ---
    {
        flux::FlowHandle unordered = a.OpenFlow(4, flux::FlowMode::RELIABLE_UNORDERED);
        CHECK(!unordered.Failed());
        uint8_t byte = 0;
        CHECK(a.BuildPacket().WithFlow(unordered, flux::FlowPart::First)
                .PutBytes(&byte, 1).Send(addrB) != common::Error::Ok);
        // The same flow still carries an ordinary packet.
        CHECK(a.BuildPacket().WithFlow(unordered).PutBytes(&byte, 1).Send(addrB)
                == common::Error::Ok);
        (void)a.CloseFlow(unordered);

        flux::FlowHandle unreliable = a.OpenFlow(5, flux::FlowMode::UNRELIABLE);
        CHECK(!unreliable.Failed());
        CHECK(a.BuildPacket().WithFlow(unreliable, flux::FlowPart::Middle)
                .PutBytes(&byte, 1).Send(addrB) != common::Error::Ok);
        (void)a.CloseFlow(unreliable);
    }

    a.Shutdown();
    b.Shutdown();
    return test::report();
}
