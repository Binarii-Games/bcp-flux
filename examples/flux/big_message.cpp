// Sending a message bigger than a packet.
//
// Flux sends one packet per call, so a large message goes as a run of them on
// one ordered flow. Each packet says where it sits in the run, and that is the
// whole of the framing: the transport carries the marks and never gathers the
// pieces, so the size is unbounded and nothing is allocated to hold a message
// in transit. The receiver appends as they arrive.
//
//     ./big_message

#include <common/log.h>

#include <flux/address.h>
#include <flux/flow/flow_handle.h>
#include <flux/internal/constants.h>
#include <flux/socket/packet_slot.h>
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "setup.h"

namespace common = bcp::common;
namespace flux   = bcp::flux;

constexpr uint16_t PORT_A  = 9560;
constexpr uint16_t PORT_B  = 9561;
constexpr uint16_t FLOW_ID = 7;

constexpr size_t MESSAGE_BYTES = 256u * 1024u;

// What the application gets once every header has taken its share.
constexpr size_t CHUNK = flux::internal::MAX_WIRE_PACKET_SIZE
                       - flux::internal::MIN_SECURE_WIRE_SIZE
                       - flux::internal::WIRE_PEER_TAG_SIZE
                       - flux::internal::WIRE_SECURE_CHANNEL_SIZE
                       - flux::internal::WIRE_FLOW_HEADER_SIZE;

// First packet, last packet, both, or neither.
static flux::FlowPart PartFor(size_t offset, size_t chunk, size_t total)
{
    const bool first = offset == 0;
    const bool last  = offset + chunk >= total;
    if (first && last) return flux::FlowPart::Whole;
    if (first)         return flux::FlowPart::First;
    if (last)          return flux::FlowPart::Last;
    return flux::FlowPart::Middle;
}

int main()
{
    flux::Socket::Config config{};
    config.type               = examples::BACKEND;
    config.maxPeers           = 8;
    config.pendingPacketCount = 64;
    config.flows.outCount     = 8;
    config.flows.inCount      = 8;

    flux::Socket a, b;
    config.port = PORT_A;
    if (a.Init(config) != common::Error::Ok) return 1;
    config.port = PORT_B;
    if (b.Init(config) != common::Error::Ok) return 1;

    const flux::Address addrB = flux::Address::From("::1", PORT_B).Take();

    flux::FlowHandle flow = a.OpenFlow(FLOW_ID, flux::FlowMode::RELIABLE_ORDERED);
    if (flow.Failed()) return 1;

    std::vector<uint8_t> message(MESSAGE_BYTES);
    for (size_t i = 0; i < MESSAGE_BYTES; ++i)
        message[i] = static_cast<uint8_t>(i * 31 + (i >> 8));

    std::vector<uint8_t> received;
    flux::PacketSlotHandle inbox[64];
    size_t sent = 0;
    bool   complete = false;

    while (!complete)
    {
        // Send until the window pushes back, then let acks catch up and
        // offer the same chunk again.
        while (sent < MESSAGE_BYTES)
        {
            const size_t n = MESSAGE_BYTES - sent < CHUNK ? MESSAGE_BYTES - sent : CHUNK;

            if (a.BuildPacket().WithFlow(flow, PartFor(sent, n, MESSAGE_BYTES))
                  .PutBytes(message.data() + sent, n).Send(addrB) != common::Error::Ok)
                break;

            sent += n;
        }

        a.Flush();
        a.Update();
        a.Poll(inbox, 64);
        b.Flush();
        b.Update();

        flux::PollCursor cursor = b.Poll(inbox, 64);
        while (cursor.Next())
        {
            const flux::PacketSlot* packet = cursor.Packet().Read();
            if (!packet) continue;

            const uint8_t* body   = cursor.Message().Content();
            const size_t   length = cursor.Message().ContentLength();
            const flux::FlowPart part = packet->Part();

            // Three lines cover all four cases. Clearing on an opening packet
            // is what discards a message the sender abandoned partway, so the
            // next one is never appended to the remains of it.
            if (part == flux::FlowPart::First || part == flux::FlowPart::Whole)
                received.clear();

            received.insert(received.end(), body, body + length);

            if (part == flux::FlowPart::Last || part == flux::FlowPart::Whole)
                complete = true;
        }
    }

    const bool intact = received.size() == MESSAGE_BYTES
                     && std::memcmp(received.data(), message.data(), MESSAGE_BYTES) == 0;

    common::LogF(common::LogLevel::Info, "sent %zu bytes as %zu packets on one flow",
                 MESSAGE_BYTES, (MESSAGE_BYTES + CHUNK - 1) / CHUNK);
    common::LogF(common::LogLevel::Info, "received %zu bytes, %s",
                 received.size(), intact ? "identical" : "CORRUPT");

    return intact ? 0 : 1;
}
