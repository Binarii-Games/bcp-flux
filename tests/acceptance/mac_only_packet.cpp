// Authenticated, not encrypted.
//
// A MAC-only packet is sent as it is and carries a tag over the whole
// datagram, so anyone can read the payload and nobody without the key can
// change a byte of it. Same framing as an encrypted packet, so the only thing
// that differs is the transform.
//
// The two properties that make it worth having are checked here rather than
// reasoned about: the payload really does arrive readable and unchanged, and a
// single flipped bit really is refused rather than delivered. The second is the
// one that would fail silently if the tag stopped covering what it should,
// which is why the packet is corrupted deliberately rather than hoped about.
//
// It also has to carry a flow. Most of a game's traffic is state replication
// that nobody needs to hide but everybody needs sequenced, so a mode that could
// not be acknowledged or retransmitted would be useless for the case it exists
// for. The sequence sits inside the authenticated range: readable, not
// forgeable.
#include "flux_net.h"

#include <flux/flow/flow_handle.h>
#include <flux/internal/constants.h>
#include <flux/socket/packet_slot.h>
#include <flux/socket/platform/faulty_socket.h>
#include <flux/wire/packet_builder.h>

#include "harness.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

namespace flux   = bcp::flux;
namespace common = bcp::common;

using flux::platform::FaultySocket;
using flux_net::Loopback;

namespace
{
    constexpr uint16_t PORT_A = 22600;
    constexpr uint16_t PORT_B = 22601;

    struct Received
    {
        std::vector<uint8_t> body;
        size_t wireSize   = 0;
        size_t framing    = 0;
        bool   macOnlyBit = false;
        bool   arrived    = false;
    };

    /** Pumps both ends until the receiver delivers something, or the budget
        runs out. A budget that runs out is the answer when the packet was
        supposed to be refused. */
    Received PumpForOne(flux::Socket& from, flux::Socket& to, int rounds = 200)
    {
        Received got;
        flux::PacketSlotHandle sink[16];
        for (int i = 0; i < rounds && !got.arrived; ++i)
        {
            from.Flush();
            from.Update();
            from.Poll(sink, 16);
            to.Flush();
            to.Update();

            flux::PollCursor cursor = to.Poll(sink, 16);
            while (cursor.Next())
            {
                const flux::PacketSlot* packet = cursor.Packet().Read();
                if (!packet) continue;

                got.framing    = packet->ContentOffset();
                got.wireSize   = packet->dataSize;
                got.macOnlyBit = packet->IsMacOnly();
                const size_t length = cursor.Message().ContentLength();
                got.body.assign(cursor.Message().Content(),
                                cursor.Message().Content() + length);
                got.arrived = true;
            }
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
        for (auto& h : sink) h = flux::PacketSlotHandle::Invalid();
        return got;
    }

    flux::Socket::Config BaseConfig()
    {
        flux::Socket::Config config{};
        config.type                    = flux::Socket::BackendType::FAULTY;
        config.maxPeers                = 8;
        config.pendingPacketCount      = 128;
        config.flows.outCount          = 8;
        config.flows.inCount           = 8;
        config.flows.flowCount         = 16;
        config.flows.stagingCount      = 512;
        config.timers.ackDelayMicros   = 200;
        return config;
    }

    void Establish(flux::Socket& a, flux::Socket& b, const flux::Address& addrB)
    {
        flux::PacketSlotHandle sink[16];
        for (int i = 0; i < 400; ++i)
        {
            a.Flush();
            a.Update(); a.Poll(sink, 16);
            b.Flush();
            b.Update(); b.Poll(sink, 16);
        }
        for (auto& h : sink) h = flux::PacketSlotHandle::Invalid();
        (void)addrB;
    }
}

int main()
{
    uint8_t payload[48];
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = static_cast<uint8_t>(i * 13 + 5);

    flux::Socket::Config config = BaseConfig();
    flux::Socket a, b;
    config.port = PORT_A;
    CHECK(a.Init(config) == common::Error::Ok);
    config.port = PORT_B;
    CHECK(b.Init(config) == common::Error::Ok);

    FaultySocket* senderKernel = FaultySocket::ForPort(PORT_A);
    CHECK(senderKernel != nullptr);

    const flux::Address addrB = Loopback(PORT_B);
    CHECK(a.Connect(addrB) == common::Error::Ok);
    Establish(a, b, addrB);

    // --- Readable, unchanged, and marked as what it is ---
    {
        CHECK(a.BuildPacket().MacOnly().NoFlow()
                .PutBytes(payload, sizeof(payload)).Send(addrB) == common::Error::Ok);

        const Received got = PumpForOne(a, b);
        CHECK(got.arrived);
        CHECK(got.macOnlyBit);
        CHECK(got.body.size() == sizeof(payload));
        CHECK(std::memcmp(got.body.data(), payload, sizeof(payload)) == 0);

        // Same framing as encrypting, which is the trade: this buys CPU, not
        // space. Anything smaller here means the tag stopped being carried.
        CHECK(got.framing == flux::internal::WIRE_CONTROLLER_SIZE
                           + flux::internal::WIRE_NONCE_SIZE
                           + flux::internal::WIRE_PEER_TAG_SIZE
                           + flux::internal::WIRE_SECURE_CHANNEL_SIZE);
        CHECK(got.wireSize == got.framing + sizeof(payload) + flux::internal::WIRE_TAG_SIZE);
    }

    // --- One flipped bit is refused, not delivered ---
    {
        senderKernel->CorruptNext(1);
        CHECK(a.BuildPacket().MacOnly().NoFlow()
                .PutBytes(payload, sizeof(payload)).Send(addrB) == common::Error::Ok);

        const Received got = PumpForOne(a, b);
        CHECK(!got.arrived);   // the tag caught it
    }

    // --- Every flow mode carries one ---
    {
        struct Case { flux::FlowMode mode; uint16_t id; };
        const Case cases[] = {
            { flux::FlowMode::RELIABLE_ORDERED,   1 },
            { flux::FlowMode::RELIABLE_UNORDERED, 2 },
            { flux::FlowMode::UNRELIABLE,         3 },
        };

        for (const Case& c : cases)
        {
            flux::FlowHandle flow = a.OpenFlow(c.id, c.mode);
            CHECK(!flow.Failed());
            CHECK(a.BuildPacket().MacOnly().WithFlow(flow)
                    .PutBytes(payload, sizeof(payload)).Send(addrB) == common::Error::Ok);

            const Received got = PumpForOne(a, b);
            CHECK(got.arrived);
            CHECK(got.macOnlyBit);
            CHECK(got.body.size() == sizeof(payload));
            CHECK(std::memcmp(got.body.data(), payload, sizeof(payload)) == 0);
            (void)a.CloseFlow(flow);
        }
    }

    // --- Unsecured still cannot carry a flow, and two levels is a conflict ---
    {
        flux::FlowHandle flow = a.OpenFlow(4, flux::FlowMode::UNRELIABLE);
        CHECK(!flow.Failed());

        // No tag at all means anyone could mint a packet naming any sequence
        // and poison the receiver's ordering. MacOnly does not have that
        // problem, which is why one is refused and the other is not.
        CHECK(a.BuildPacket().Unsecured().WithFlow(flow)
                .PutBytes(payload, sizeof(payload)).Send(addrB) != common::Error::Ok);

        CHECK(a.BuildPacket().MacOnly().Unsecured().NoFlow()
                .PutBytes(payload, 1).Send(addrB) != common::Error::Ok);
        CHECK(a.BuildPacket().Unsecured().MacOnly().NoFlow()
                .PutBytes(payload, 1).Send(addrB) != common::Error::Ok);

        (void)a.CloseFlow(flow);
    }

    a.Shutdown();
    b.Shutdown();

    // --- Retransmission, on a link that loses most of what it is given ---
    //
    // A resend re-tags the staged body under a fresh counter. If the stale
    // counter survived the copy, the receiver would unmask one it had already
    // seen, the replay window would drop it, and the transfer would stall
    // rather than finish.
    {
        constexpr int TOTAL = 60;
        constexpr int CHUNK = 400;

        flux::Socket::Config lossy = BaseConfig();
        flux::Socket c, d;
        lossy.port = 22610;
        CHECK(c.Init(lossy) == common::Error::Ok);
        lossy.port = 22611;
        CHECK(d.Init(lossy) == common::Error::Ok);

        const flux::Address addrD = Loopback(22611);
        CHECK(c.Connect(addrD) == common::Error::Ok);
        Establish(c, d, addrD);

        // Damage only after the handshake, so what is measured is the resend
        // path rather than how long it took to connect.
        FaultySocket* kernel = FaultySocket::ForPort(22610);
        CHECK(kernel != nullptr);
        FaultySocket::Profile profile{};
        // Enough loss that every run resends many times, low enough that no
        // single packet is likely to burn all HANDSHAKE-era attempts and fail
        // the association. At 12 percent a packet survives eight tries with
        // probability 1 - 1e-7, so exhaustion is not what this measures.
        // Surviving a link bad enough to give up is flow_fault_recovery's job,
        // and it retries at the application level the way a real caller would.
        // What is measured here is only that a resend re-tags correctly.
        profile.applyTo          = FaultySocket::Direction::Send;
        profile.lossPercent      = 12;
        profile.burstLoss        = 1;
        profile.reorderPercent   = 15;
        profile.reorderDepth     = 3;
        profile.duplicatePercent = 10;
        profile.seed             = 0xBEEF;
        kernel->SetProfile(profile);

        flux::FlowHandle flow = c.OpenFlow(9, flux::FlowMode::RELIABLE_ORDERED);
        CHECK(!flow.Failed());

        std::vector<uint8_t> chunk(CHUNK);
        flux::PacketSlotHandle sink[64];
        int sent = 0, got = 0;
        bool ordered = true;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(25);

        while (got < TOTAL && std::chrono::steady_clock::now() < deadline)
        {
            if (sent < TOTAL)
            {
                chunk[0] = static_cast<uint8_t>(sent);
                chunk[1] = static_cast<uint8_t>(sent >> 8);
                if (c.BuildPacket().MacOnly().WithFlow(flow)
                      .PutBytes(chunk.data(), CHUNK).Send(addrD) == common::Error::Ok)
                    ++sent;
            }

            c.Flush();
            c.Update(); c.Poll(sink, 64);
            d.Flush();
            d.Update();

            flux::PollCursor cursor = d.Poll(sink, 64);
            while (cursor.Next())
            {
                const flux::PacketSlot* packet = cursor.Packet().Read();
                if (!packet) continue;
                const uint8_t* body = cursor.Message().Content();
                const int index = body[0] | (body[1] << 8);
                if (index != got) ordered = false; else ++got;
            }
            std::this_thread::sleep_for(std::chrono::microseconds(120));
        }

        if (got != TOTAL)
            std::printf("      diagnostic: got=%d sent=%d flow=%d dropped=%llu\n",
                        got, sent, static_cast<int>(c.GetFlowState(flow, addrD)),
                        static_cast<unsigned long long>(kernel->GetStats().dropped));
        CHECK(got == TOTAL);
        CHECK(ordered);
        CHECK(kernel->GetStats().dropped > 0);   // the link really did lose things

        for (auto& h : sink) h = flux::PacketSlotHandle::Invalid();
        (void)c.CloseFlow(flow);
        c.Shutdown();
        d.Shutdown();
    }

    return test::report();
}
