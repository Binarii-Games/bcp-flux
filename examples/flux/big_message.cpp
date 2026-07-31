// Sending a message larger than a packet, and knowing where it ends.
//
// bulk_transfer moves a lot of bytes and leaves the framing to the reader: it
// knows the size in advance, so appending until the count is reached is enough.
// Most protocols do not have that luxury. This one marks each packet with where
// it sits in the message, so the receiver learns where one ends and the next
// begins without a length header of its own.
//
// The transport carries the marks and nothing else. It never gathers the pieces
// or holds a partial message, so the size is unbounded and the receive path
// allocates nothing to accommodate one.
//
// Reassembler::Take handles the failure case. A flow that gives up partway, or
// an id reopened for a fresh attempt, leaves the receiver holding a run that
// will never be finished. First says a new message starts here, so the stale
// partial is dropped instead of the next message being appended to it.
//
//     ./big_message

#include <common/log.h>

#include <flux/address.h>
#include <flux/flow/flow_handle.h>
#include <flux/internal/constants.h>
#include <flux/socket/packet_slot.h>
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

#include "setup.h"

namespace common = bcp::common;
namespace flux   = bcp::flux;

constexpr uint16_t PORT_A  = 9560;
constexpr uint16_t PORT_B  = 9561;
constexpr uint16_t FLOW_ID = 7;

constexpr size_t MESSAGE_BYTES = 512u * 1024u;
constexpr size_t MESSAGE_COUNT = 3;

constexpr size_t CHUNK = flux::internal::MAX_WIRE_PACKET_SIZE
                       - flux::internal::MIN_SECURE_WIRE_SIZE
                       - flux::internal::WIRE_PEER_TAG_SIZE
                       - flux::internal::WIRE_SECURE_CHANNEL_SIZE
                       - flux::internal::WIRE_FLOW_HEADER_SIZE;

static uint8_t ByteAt(size_t message, size_t offset)
{
    return static_cast<uint8_t>((offset * 31u + (offset >> 8) + message * 7u) & 0xFF);
}

// Everything the receiving side has to do. Four cases, no length header, no
// buffer sized ahead of time.
struct Reassembler
{
    std::vector<uint8_t> partial;
    std::vector<uint8_t> latest;
    bool     holding   = false;
    uint32_t completed = 0;
    uint32_t abandoned = 0;   ///< runs that never reached a Last

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
            // A run was already open, so nothing is ever going to finish it.
            if (holding) { ++abandoned; partial.clear(); }
            partial.assign(body, body + length);
            holding = true;
            break;

        case flux::FlowPart::Middle:
            if (!holding) return;   // arrived mid-run, nothing to append to
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

    Reassembler inbound;
    flux::PacketSlotHandle sink[64];
    bool intact = true;

    for (size_t message = 0; message < MESSAGE_COUNT; ++message)
    {
        std::vector<uint8_t> payload(MESSAGE_BYTES);
        for (size_t i = 0; i < MESSAGE_BYTES; ++i) payload[i] = ByteAt(message, i);

        size_t sent = 0;
        while (sent < MESSAGE_BYTES || inbound.completed <= message)
        {
            while (sent < MESSAGE_BYTES)
            {
                const size_t n = (MESSAGE_BYTES - sent) < CHUNK ? (MESSAGE_BYTES - sent) : CHUNK;

                const common::Error err = a.BuildPacket()
                    .WithFlow(flow, PartFor(sent, n, MESSAGE_BYTES))
                    .PutBytes(payload.data() + sent, n)
                    .Send(addrB);

                if (err == common::Error::Ok) { sent += n; continue; }

                // Backpressure only. Anything else and the flow or the peer is
                // gone, which ends this message rather than looping on it.
                if (err != common::Error::TooManyPending)
                {
                    common::LogF(common::LogLevel::Error, "send failed at %zu: %d",
                                 sent, static_cast<int>(err));
                    return 1;
                }
                break;
            }

            a.Update();
            a.Poll(sink, 64);
            b.Update();

            const uint32_t count = b.Poll(sink, 64);
            for (uint32_t i = 0; i < count; ++i)
            {
                const flux::PacketSlot* packet = sink[i].Read();
                if (!packet) continue;

                const size_t   offset = packet->ContentOffset();
                const uint8_t* body   = packet->Content(offset);
                inbound.Take(packet->Part(), body, packet->dataSize - offset);
            }

            if (count == 0) std::this_thread::sleep_for(std::chrono::microseconds(200));
        }

        if (inbound.latest.size() != MESSAGE_BYTES
         || std::memcmp(inbound.latest.data(), payload.data(), MESSAGE_BYTES) != 0)
            intact = false;

        common::LogF(common::LogLevel::Info,
                     "message %zu: %zu bytes in %zu packets, reassembled %zu, %s",
                     message, MESSAGE_BYTES, (MESSAGE_BYTES + CHUNK - 1) / CHUNK,
                     inbound.latest.size(), intact ? "identical" : "CORRUPT");
    }

    common::LogF(common::LogLevel::Info, "%u messages completed, %u runs abandoned",
                 inbound.completed, inbound.abandoned);

    return intact && inbound.completed == MESSAGE_COUNT ? 0 : 1;
}
