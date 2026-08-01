// Moving something large over one reliable ordered flow.
//
// Flux sends one packet per call, so a payload bigger than a packet is the
// application's to chunk. The flow does the rest: every chunk is numbered, a
// loss is retransmitted, and delivery is in send order, so the receiver can
// append what arrives and end up with the bytes it was sent.
//
// The window bounds what is in flight, not what can be sent. Past it Send
// returns TooManyPending, which is the backpressure signal: pump the socket so
// acks land, then offer the same chunk again. That loop is the whole trick, and
// it is why the transfer size is unbounded while memory is not.
//
// Both sides run in one process here, so the numbers say nothing about the
// network. What they do show is that the flow keeps its ordering promise across
// far more packets than its window holds.
//
//     ./bulk_transfer

#include <common/log.h>

#include <flux/address.h>
#include <flux/flow/flow_handle.h>
#include <flux/internal/constants.h>
#include <flux/socket/packet_slot.h>
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

#include "setup.h"

namespace common = bcp::common;
namespace flux   = bcp::flux;

constexpr uint16_t PORT_A  = 9540;
constexpr uint16_t PORT_B  = 9541;
constexpr uint16_t FLOW_ID = 11;

constexpr size_t PAYLOAD_BYTES = 4u * 1024u * 1024u;

// What is left for the application once the headers outside and inside the seal
// have taken their share.
constexpr size_t CHUNK = flux::internal::MAX_WIRE_PACKET_SIZE
                       - flux::internal::MIN_SECURE_WIRE_SIZE
                       - flux::internal::WIRE_PEER_TAG_SIZE
                       - flux::internal::WIRE_SECURE_CHANNEL_SIZE
                       - flux::internal::WIRE_FLOW_HEADER_SIZE;

static std::atomic<bool>   done{false};
static std::atomic<size_t> receivedBytes{0};

// A counting pattern rather than random bytes, so a gap or a reorder shows up as
// a wrong value at a known offset instead of a hash that merely differs.
static uint8_t ByteAt(size_t offset)
{
    return static_cast<uint8_t>((offset * 31u + (offset >> 8)) & 0xFF);
}

// B appends whatever arrives and checks it against the pattern as it goes.
// Ordered delivery is what makes appending correct: the next packet out of Poll
// is always the next packet that was sent.
static void Receive(flux::Socket& socket)
{
    flux::PacketSlotHandle inbox[64];
    size_t expected = 0;
    bool   intact   = true;

    while (expected < PAYLOAD_BYTES)
    {
        socket.Update();

        const uint32_t count = socket.Poll(inbox, 64);
        for (uint32_t i = 0; i < count; ++i)
        {
            const flux::PacketSlot* packet = inbox[i].Read();
            if (!packet) continue;

            const size_t   offset  = packet->ContentOffset();
            const uint8_t* content = packet->Content(offset);
            const size_t   length  = packet->ContentLength();

            for (size_t b = 0; b < length; ++b)
            {
                if (content[b] != ByteAt(expected + b)) intact = false;
            }
            expected += length;
        }
        receivedBytes = expected;

        if (count == 0) std::this_thread::sleep_for(std::chrono::microseconds(200));
    }

    common::LogF(common::LogLevel::Info, "B received %zu bytes, contents %s",
                 expected, intact ? "intact" : "CORRUPT");
    done = true;
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

    std::thread receiver(Receive, std::ref(b));

    flux::FlowHandle flow = a.OpenFlow(FLOW_ID, flux::FlowMode::RELIABLE_ORDERED);
    if (flow.Failed()) return 1;

    std::vector<uint8_t> payload(PAYLOAD_BYTES);
    for (size_t i = 0; i < PAYLOAD_BYTES; ++i) payload[i] = ByteAt(i);

    const auto started = std::chrono::steady_clock::now();

    flux::PacketSlotHandle sink[64];
    size_t   sent     = 0;
    uint64_t refusals = 0;

    while (sent < PAYLOAD_BYTES)
    {
        const size_t n = (PAYLOAD_BYTES - sent) < CHUNK ? (PAYLOAD_BYTES - sent) : CHUNK;

        const common::Error err = a.BuildPacket().WithFlow(flow)
                                   .PutBytes(payload.data() + sent, n)
                                   .Send(addrB);

        if (err == common::Error::Ok)
        {
            sent += n;
            continue;
        }

        // Anything other than backpressure ends the transfer: the flow is gone,
        // or the peer is. Backpressure just means the window and the waiting
        // ring are both full, so let the acks catch up.
        if (err != common::Error::TooManyPending)
        {
            common::LogF(common::LogLevel::Error, "send failed at %zu bytes: %d",
                         sent, static_cast<int>(err));
            break;
        }

        ++refusals;
        a.Update();
        a.Poll(sink, 64);
    }

    // Keep pumping until the receiver has it all: the last chunks are still in
    // flight, and their retransmits need the tick.
    while (!done)
    {
        a.Update();
        a.Poll(sink, 64);
        std::this_thread::sleep_for(std::chrono::microseconds(200));
    }

    const auto elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - started).count();

    receiver.join();

    common::LogF(common::LogLevel::Info,
                 "A sent %zu bytes in %zu chunks of %zu, %llu backpressure waits",
                 sent, (sent + CHUNK - 1) / CHUNK, CHUNK,
                 static_cast<unsigned long long>(refusals));
    common::LogF(common::LogLevel::Info, "%.2f MB in %.2f s, %.1f MB/s over loopback",
                 PAYLOAD_BYTES / 1048576.0, elapsed,
                 (PAYLOAD_BYTES / 1048576.0) / elapsed);

    (void)a.CloseFlow(flow);
    return receivedBytes == PAYLOAD_BYTES ? 0 : 1;
}
