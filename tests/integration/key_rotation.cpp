// Session key rotation, end to end over real UDP. The key is a chain: a
// rotation derives the next link one-way from the current one, nothing is
// announced on the wire, and the peer discovers the change when a packet
// opens under the next link instead of the current. These cases drive the
// contract from the public surface: the RotateKeys state machine, the
// automatic rotation on the configured byte threshold, discovery and
// confirmation on both ends, and delivery staying intact while both sides
// walk the chain under reliable traffic.
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>

#include "flux_net.h"
#include "harness.h"

#include <vector>

namespace flux = bcp::flux;
namespace common = bcp::common;

namespace
{
    // Pumps both sockets for a bounded number of rounds, collecting every
    // u32 payload the right socket delivers.
    void PumpCollect(flux::Socket& left, flux::Socket& right,
                     std::vector<uint32_t>& delivered, int rounds)
    {
        flux::PacketSlotHandle inbox[16];
        for (int i = 0; i < rounds; ++i)
        {
            left.Flush();
            right.Flush();
            left.Update();
            right.Update();
            {
                flux::PollCursor cursor = left.Poll(inbox, 16);
                while (cursor.Next()) {}
            }
            {
                flux::PollCursor cursor = right.Poll(inbox, 16);
                while (cursor.Next())
                {
                    flux::PacketSlotReader& reader = cursor.Message();
                    uint32_t value = 0;
                    if (reader.TakeU32(value))
                        delivered.push_back(value);
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    uint8_t GenerationOf(flux::Socket& socket, const flux::Address& addr)
    {
        flux::PeerHandle peer = socket.GetPeer(addr);
        return (!peer.Failed() && peer.Read()) ? peer.Read()->keyGeneration : 0xFF;
    }

    bool ConfirmedOf(flux::Socket& socket, const flux::Address& addr)
    {
        flux::PeerHandle peer = socket.GetPeer(addr);
        return !peer.Failed() && peer.Read() && peer.Read()->rotationConfirmed;
    }
}

// RotateKeys walks the guards: unknown peer refused, a rotation goes through,
// a second one is refused until the peer confirms the first, and traffic
// sealed under the new link still arrives.
static void manual_rotation_state_machine()
{
    flux::Socket a, b;
    CHECK(a.Init({ .type = flux_net::BACKEND, .port = 9440,
                   .maxPeers = 16, .pendingPacketCount = 16 }) == common::Error::Ok);
    CHECK(b.Init({ .type = flux_net::BACKEND, .port = 9441,
                   .maxPeers = 16, .pendingPacketCount = 16 }) == common::Error::Ok);

    const flux::Address addrA = flux_net::Loopback(9440);
    const flux::Address addrB = flux_net::Loopback(9441);

    CHECK(a.RotateKeys(addrB) == common::Error::NotFound);   // stranger

    CHECK(a.Connect(addrB) == common::Error::Ok);
    CHECK(flux_net::PumpUntilEstablished(a, addrA, b, addrB));
    CHECK(GenerationOf(a, addrB) == 0);
    CHECK(GenerationOf(b, addrA) == 0);

    // One rotation is accepted, the next is refused until the peer catches
    // up, and the refusal changes nothing.
    CHECK(a.RotateKeys(addrB) == common::Error::Ok);
    CHECK(GenerationOf(a, addrB) == 1);
    CHECK(!ConfirmedOf(a, addrB));
    CHECK(a.RotateKeys(addrB) == common::Error::AlreadyPending);
    CHECK(GenerationOf(a, addrB) == 1);

    // A packet sealed under the new link reaches b, which discovers the
    // rotation by opening it: b commits to the same generation.
    std::vector<uint32_t> atB;
    CHECK(a.BuildPacket().NoFlow().PutU32(11).Send(addrB) == common::Error::Ok);
    PumpCollect(a, b, atB, 50);
    CHECK(atB.size() == 1 && atB[0] == 11);
    CHECK(GenerationOf(b, addrA) == 1);
    CHECK(ConfirmedOf(b, addrA));

    // b's first packet back under the new link is a's confirmation, which
    // re-arms RotateKeys.
    std::vector<uint32_t> atA;
    CHECK(b.BuildPacket().NoFlow().PutU32(22).Send(addrA) == common::Error::Ok);
    flux::PacketSlotHandle inbox[16];
    for (int i = 0; i < 50 && !ConfirmedOf(a, addrB); ++i)
    {
        b.Flush(); a.Flush();
        b.Update(); a.Update();
        flux::PollCursor cursor = a.Poll(inbox, 16);
        while (cursor.Next()) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(ConfirmedOf(a, addrB));
    CHECK(a.RotateKeys(addrB) == common::Error::Ok);
    CHECK(GenerationOf(a, addrB) == 2);
}

// With the threshold at one packet, the first data send after establishment
// rotates before it leaves, so the very first payload arrives sealed under a
// link the receiver has never held and can only reach by deriving it.
// Delivery of that payload IS the discovery working.
static void auto_rotation_on_threshold()
{
    flux::Socket a, b;
    CHECK(a.Init({ .type = flux_net::BACKEND, .port = 9442,
                   .maxPeers = 16, .pendingPacketCount = 16,
                   .rotateAfterBytes = 1200 }) == common::Error::Ok);
    CHECK(b.Init({ .type = flux_net::BACKEND, .port = 9443,
                   .maxPeers = 16, .pendingPacketCount = 16 }) == common::Error::Ok);

    const flux::Address addrA = flux_net::Loopback(9442);
    const flux::Address addrB = flux_net::Loopback(9443);

    CHECK(a.Connect(addrB) == common::Error::Ok);
    CHECK(flux_net::PumpUntilEstablished(a, addrA, b, addrB));

    std::vector<uint32_t> atB;
    CHECK(a.BuildPacket().NoFlow().PutU32(77).Send(addrB) == common::Error::Ok);
    PumpCollect(a, b, atB, 50);

    CHECK(atB.size() == 1 && atB[0] == 77);
    CHECK(GenerationOf(a, addrB) >= 1);   // the threshold fired unprompted
    CHECK(GenerationOf(b, addrA) >= 1);   // and b walked the chain to meet it
}

// Both ends on a two-packet threshold, forty reliable ordered messages, so
// data packets and the acks coming back both keep crossing rotation
// boundaries in both directions. The contract is that none of it shows: every
// message arrives, in order, while the generations climb.
static void reliable_traffic_across_rotations()
{
    flux::Socket a, b;
    CHECK(a.Init({ .type = flux_net::BACKEND, .port = 9444,
                   .maxPeers = 16, .pendingPacketCount = 32,
                   .rotateAfterBytes = 2400,
                   .flows = { .flowCount = 4, .outCount = 4, .inCount = 4 } })
          == common::Error::Ok);
    CHECK(b.Init({ .type = flux_net::BACKEND, .port = 9445,
                   .maxPeers = 16, .pendingPacketCount = 32,
                   .rotateAfterBytes = 2400,
                   .flows = { .flowCount = 4, .outCount = 4, .inCount = 4 } })
          == common::Error::Ok);

    const flux::Address addrA = flux_net::Loopback(9444);
    const flux::Address addrB = flux_net::Loopback(9445);

    CHECK(a.Connect(addrB) == common::Error::Ok);
    CHECK(flux_net::PumpUntilEstablished(a, addrA, b, addrB));

    flux::FlowHandle flow = a.OpenFlow(3, flux::FlowMode::RELIABLE_ORDERED);

    constexpr uint32_t COUNT = 40;
    std::vector<uint32_t> atB;
    for (uint32_t seq = 0; seq < COUNT; ++seq)
    {
        CHECK(a.BuildPacket().WithFlow(flow).PutU32(seq).Send(addrB) == common::Error::Ok);
        PumpCollect(a, b, atB, 3);
    }
    PumpCollect(a, b, atB, 100);

    CHECK(atB.size() == COUNT);
    for (uint32_t i = 0; i < atB.size(); ++i)
        CHECK(atB[i] == i);

    // Both ends actually walked the chain while delivering all of it.
    CHECK(GenerationOf(a, addrB) >= 2);
    CHECK(GenerationOf(b, addrA) >= 2);
}

int main()
{
    manual_rotation_state_machine();
    auto_rotation_on_threshold();
    reliable_traffic_across_rotations();
    return test::report();
}
