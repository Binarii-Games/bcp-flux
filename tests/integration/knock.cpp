// The knock, end to end over real UDP: an opener that carries data. A sender
// holding the receiver's certificate encrypts toward it before any contact, so
// the first packet delivers application data while the ordinary handshake runs
// behind it and proves the address. These cases hold that to its contract: the
// data arrives in the first exchange rather than after one, the handshake
// still completes and replaces the interim key, flow traffic survives that
// replacement intact, and a socket that knows nothing about the receiver falls
// back to the plain handshake instead of opening early.
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>

#include "flux_net.h"
#include "harness.h"

#include <vector>

namespace flux = bcp::flux;
namespace common = bcp::common;

namespace
{
    // Drives both sockets one round and collects whatever the right one
    // delivers, so a case can count how many rounds a payload took.
    void PumpOnce(flux::Socket& left, flux::Socket& right, std::vector<uint32_t>& got)
    {
        flux::PacketSlotHandle inbox[16];
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
                if (reader.TakeU32(value)) got.push_back(value);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // A knocked peer is established from its first packet, so "established"
    // cannot say whether the handshake behind it has finished. The interim key
    // going away is what says it: that happens only in the session commit.
    bool KnockClosed(flux::Socket& socket, const flux::Address& addr)
    {
        flux::PeerHandle peer = socket.GetPeer(addr);
        return !peer.Failed() && peer.Read() && !peer.Read()->knockActive;
    }

    flux::Certificate::IdentityTag TagOf(uint8_t seed)
    {
        flux::Certificate::IdentityTag tag{};
        tag[0] = seed;
        return tag;
    }
}

// A sender holding the receiver's certificate delivers data in the very first
// exchange, and the handshake behind it still completes and takes over.
static void cert_knock_delivers_in_the_first_exchange()
{
    const flux::Certificate::IdentityTag tagB = TagOf(0xB1);
    common::Result<flux::Identity> identityB = flux::Identity::Generate(tagB);
    CHECK(!identityB.isErr());
    const flux::Identity idB = identityB.Take();

    flux::Socket a, b;
    flux::Socket::Config configA{};
    configA.type = flux_net::BACKEND;
    configA.port = 9460;
    configA.maxPeers = 16;
    configA.pendingPacketCount = 16;
    configA.trustedCertCount = 4;
    configA.knock.enable = true;
    CHECK(a.Init(configA) == common::Error::Ok);

    flux::Socket::Config configB{};
    configB.type = flux_net::BACKEND;
    configB.port = 9461;
    configB.maxPeers = 16;
    configB.pendingPacketCount = 16;
    configB.identity = &idB;
    CHECK(b.Init(configB) == common::Error::Ok);

    const flux::Address addrB = flux_net::Loopback(9461);

    // A knows B before ever speaking to it, which is what makes opening early
    // possible at all.
    CHECK(a.LoadCertificate(idB.ToCertificate()) == common::Error::Ok);
    CHECK(a.Connect(addrB, tagB) == common::Error::Ok);

    // One packet out, one round pumped. Anything delivered here rode the
    // opener: a handshake alone could not have carried it yet.
    CHECK(a.BuildPacket().NoFlow().PutU32(4242).Send(addrB) == common::Error::Ok);
    std::vector<uint32_t> atB;
    PumpOnce(a, b, atB);
    CHECK(atB.size() == 1);
    CHECK(!atB.empty() && atB[0] == 4242);

    // The handshake was running behind it and still finishes, which is what
    // replaces the interim key with one both sides derived.
    for (int i = 0; i < 200 && !KnockClosed(a, addrB); ++i)
        PumpOnce(a, b, atB);
    CHECK(KnockClosed(a, addrB));

    // Traffic after the handover arrives under the session key.
    CHECK(a.BuildPacket().NoFlow().PutU32(5150).Send(addrB) == common::Error::Ok);
    for (int i = 0; i < 100 && atB.size() < 2; ++i)
        PumpOnce(a, b, atB);
    CHECK(atB.size() == 2);
    CHECK(atB.size() == 2 && atB[1] == 5150);
}

// Reliable ordered flow traffic started under the interim key arrives whole
// and in order across the moment the real session replaces it.
static void flow_survives_the_key_handover()
{
    const flux::Certificate::IdentityTag tagB = TagOf(0xB2);
    common::Result<flux::Identity> identityB = flux::Identity::Generate(tagB);
    CHECK(!identityB.isErr());
    const flux::Identity idB = identityB.Take();

    flux::Socket a, b;
    flux::Socket::Config configA{};
    configA.type = flux_net::BACKEND;
    configA.port = 9462;
    configA.maxPeers = 16;
    configA.pendingPacketCount = 32;
    configA.trustedCertCount = 4;
    configA.knock.enable = true;
    configA.flows.flowCount = 4;
    configA.flows.outCount  = 4;
    configA.flows.inCount   = 4;
    CHECK(a.Init(configA) == common::Error::Ok);

    flux::Socket::Config configB{};
    configB.type = flux_net::BACKEND;
    configB.port = 9463;
    configB.maxPeers = 16;
    configB.pendingPacketCount = 32;
    configB.identity = &idB;
    configB.flows.flowCount = 4;
    configB.flows.outCount  = 4;
    configB.flows.inCount   = 4;
    CHECK(b.Init(configB) == common::Error::Ok);

    const flux::Address addrB = flux_net::Loopback(9463);
    CHECK(a.LoadCertificate(idB.ToCertificate()) == common::Error::Ok);
    CHECK(a.Connect(addrB, tagB) == common::Error::Ok);

    // The flow opens and sends while the peer is still knocking, so its first
    // packets are sealed under the interim key and its later ones under the
    // session that replaces it.
    flux::FlowHandle flow = a.OpenFlow(5, flux::FlowMode::RELIABLE_ORDERED);
    constexpr uint32_t COUNT = 24;
    std::vector<uint32_t> atB;
    for (uint32_t seq = 0; seq < COUNT; ++seq)
    {
        CHECK(a.BuildPacket().WithFlow(flow).PutU32(seq).Send(addrB) == common::Error::Ok);
        PumpOnce(a, b, atB);
    }
    for (int i = 0; i < 200 && atB.size() < COUNT; ++i)
        PumpOnce(a, b, atB);

    CHECK(atB.size() == COUNT);
    for (uint32_t i = 0; i < atB.size(); ++i)
        CHECK(atB[i] == i);
}

// Without material for the target, a first send takes the plain handshake:
// nothing opens early, and the data still arrives once the session is up.
static void no_material_falls_back_to_the_handshake()
{
    flux::Socket a, b;
    flux::Socket::Config configA{};
    configA.type = flux_net::BACKEND;
    configA.port = 9464;
    configA.maxPeers = 16;
    configA.pendingPacketCount = 16;
    configA.knock.enable = true;   // enabled, but nothing to open with
    CHECK(a.Init(configA) == common::Error::Ok);

    flux::Socket::Config configB{};
    configB.type = flux_net::BACKEND;
    configB.port = 9465;
    configB.maxPeers = 16;
    configB.pendingPacketCount = 16;
    CHECK(b.Init(configB) == common::Error::Ok);

    const flux::Address addrB = flux_net::Loopback(9465);
    const flux::Address addrA = flux_net::Loopback(9464);

    CHECK(a.BuildPacket().NoFlow().PutU32(77).Send(addrB) == common::Error::Ok);

    std::vector<uint32_t> atB;
    PumpOnce(a, b, atB);
    CHECK(atB.empty());   // no material, so nothing could have been carried

    CHECK(KnockClosed(a, addrB));   // nothing armed, so nothing to close

    CHECK(flux_net::PumpUntilEstablished(a, addrA, b, addrB));
    for (int i = 0; i < 100 && atB.empty(); ++i)
        PumpOnce(a, b, atB);
    CHECK(atB.size() == 1);   // parked behind the handshake, delivered after it
    CHECK(!atB.empty() && atB[0] == 77);
}

// An unknown certificate cannot be aimed at: naming one that was never loaded
// is refused rather than silently falling back.
static void naming_an_unknown_identity_is_refused()
{
    flux::Socket a;
    flux::Socket::Config configA{};
    configA.type = flux_net::BACKEND;
    configA.port = 9466;
    configA.maxPeers = 16;
    configA.pendingPacketCount = 16;
    configA.trustedCertCount = 4;
    configA.knock.enable = true;
    CHECK(a.Init(configA) == common::Error::Ok);

    CHECK(a.Connect(flux_net::Loopback(9467), TagOf(0xEE)) == common::Error::NotFound);
}

// An opener spends most of its packet on the material that opens the session,
// so less payload fits than a session packet carries. The caller is told at
// the send rather than the packet going quiet: MaxPayload reports the ceiling
// and a byte past it is refused.
static void oversized_first_packet_is_refused()
{
    const flux::Certificate::IdentityTag tagB = TagOf(0xB3);
    common::Result<flux::Identity> identityB = flux::Identity::Generate(tagB);
    CHECK(!identityB.isErr());
    const flux::Identity idB = identityB.Take();

    flux::Socket a, b;
    flux::Socket::Config configA{};
    configA.type = flux_net::BACKEND;
    configA.port = 9468;
    configA.maxPeers = 16;
    configA.pendingPacketCount = 16;
    configA.trustedCertCount = 4;
    configA.knock.enable = true;
    CHECK(a.Init(configA) == common::Error::Ok);

    flux::Socket::Config configB{};
    configB.type = flux_net::BACKEND;
    configB.port = 9469;
    configB.maxPeers = 16;
    configB.pendingPacketCount = 16;
    configB.identity = &idB;
    CHECK(b.Init(configB) == common::Error::Ok);

    const flux::Address addrB = flux_net::Loopback(9469);
    CHECK(a.LoadCertificate(idB.ToCertificate()) == common::Error::Ok);

    // Before contact the ceiling is the opener's, and it is smaller than a
    // session packet's.
    const uint32_t knockCeiling = a.MaxPayload(addrB);
    CHECK(knockCeiling > 0);
    CHECK(knockCeiling < bcp::flux::internal::MAX_WIRE_PACKET_SIZE);

    CHECK(a.Connect(addrB, tagB) == common::Error::Ok);
    CHECK(a.MaxPayload(addrB) == knockCeiling);

    std::vector<uint8_t> payload(knockCeiling + 1, 0xAB);
    CHECK(a.BuildPacket().NoFlow()
           .PutBytes(payload.data(), static_cast<uint16_t>(payload.size()))
           .Send(addrB) == common::Error::TooLarge);

    // Exactly at the ceiling still goes, and arrives.
    payload.pop_back();
    CHECK(a.BuildPacket().NoFlow()
           .PutBytes(payload.data(), static_cast<uint16_t>(payload.size()))
           .Send(addrB) == common::Error::Ok);

    flux::PacketSlotHandle inbox[8];
    bool sawFull = false;
    for (int i = 0; i < 20 && !sawFull; ++i)
    {
        a.Flush(); b.Flush();
        a.Update(); b.Update();
        flux::PollCursor cursor = b.Poll(inbox, 8);
        while (cursor.Next())
            if (cursor.Message().ContentLength() == payload.size()) sawFull = true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(sawFull);

    // Once the session is up the ceiling grows, because the opener is gone.
    for (int i = 0; i < 200 && !KnockClosed(a, addrB); ++i)
    {
        a.Flush(); b.Flush();
        a.Update(); b.Update();
        flux::PollCursor cursor = b.Poll(inbox, 8);
        while (cursor.Next()) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(KnockClosed(a, addrB));
    CHECK(a.MaxPayload(addrB) > knockCeiling);
}

// The opener rides along only until the far side is known to hold the interim
// key. Its first answer proves that, and the packets after it spend their
// bytes on payload instead, while the key itself is untouched and the
// handshake behind the knock is still running.
static void the_opener_stops_once_the_peer_answers()
{
    const flux::Certificate::IdentityTag tagB = TagOf(0xB4);
    common::Result<flux::Identity> identityB = flux::Identity::Generate(tagB);
    CHECK(!identityB.isErr());
    const flux::Identity idB = identityB.Take();

    flux::Socket a, b;
    flux::Socket::Config configA{};
    configA.type = flux_net::BACKEND;
    configA.port = 9470;
    configA.maxPeers = 16;
    configA.pendingPacketCount = 32;
    configA.trustedCertCount = 4;
    configA.knock.enable = true;
    CHECK(a.Init(configA) == common::Error::Ok);

    flux::Socket::Config configB{};
    configB.type = flux_net::BACKEND;
    configB.port = 9471;
    configB.maxPeers = 16;
    configB.pendingPacketCount = 32;
    configB.identity = &idB;
    CHECK(b.Init(configB) == common::Error::Ok);

    const flux::Address addrA = flux_net::Loopback(9470);
    const flux::Address addrB = flux_net::Loopback(9471);
    CHECK(a.LoadCertificate(idB.ToCertificate()) == common::Error::Ok);
    CHECK(a.Connect(addrB, tagB) == common::Error::Ok);

    const uint32_t opening = a.MaxPayload(addrB);

    // The knock, and only the knock: B is not pumped past receiving it, so its
    // handshake answer stays in its socket while the reply below overtakes it.
    CHECK(a.BuildPacket().NoFlow().PutU32(1).Send(addrB) == common::Error::Ok);
    a.Flush();
    b.Update();

    // B now holds the peer and the interim key, so its ordinary reply is
    // sealed with the very key the opener was announcing.
    CHECK(b.BuildPacket().NoFlow().PutU32(2).Send(addrA) == common::Error::Ok);
    b.Flush();
    a.Update();
    {
        flux::PacketSlotHandle inbox[8];
        flux::PollCursor cursor = a.Poll(inbox, 8);
        while (cursor.Next()) {}
    }

    // The answer landed, so the opener stops. The interim key is still the
    // session key and the handshake has not finished, which is the whole
    // point: this is the knock succeeding, not the handshake completing.
    {
        flux::PeerHandle peer = a.GetPeer(addrB);
        CHECK(!peer.Failed() && peer.Read());
        CHECK(peer.Read() && !peer.Read()->knockFramed);
        CHECK(peer.Read() && peer.Read()->knockActive);
    }
    CHECK(a.MaxPayload(addrB) > opening);

    // Everything still arrives once the rest of the exchange plays out.
    std::vector<uint32_t> atB;
    for (uint32_t seq = 3; seq < 9; ++seq)
        CHECK(a.BuildPacket().NoFlow().PutU32(seq).Send(addrB) == common::Error::Ok);
    for (int i = 0; i < 300 && (atB.size() < 7 || !KnockClosed(a, addrB)); ++i)
        PumpOnce(a, b, atB);
    CHECK(atB.size() == 7);
    CHECK(KnockClosed(a, addrB));   // and the handshake did finish behind it
}

// The always-safe size is exactly that: a caller that never asks what a peer
// can take, and never checks whether one exists, is not refused. Every framing
// the transport has must carry it, and the worst of them is an opener carrying
// a flow packet.
static void the_safe_size_is_never_refused()
{
    const flux::Certificate::IdentityTag tagB = TagOf(0xB5);
    common::Result<flux::Identity> identityB = flux::Identity::Generate(tagB);
    CHECK(!identityB.isErr());
    const flux::Identity idB = identityB.Take();

    flux::Socket a, b;
    flux::Socket::Config configA{};
    configA.type = flux_net::BACKEND;
    configA.port = 9472;
    configA.maxPeers = 16;
    configA.pendingPacketCount = 32;
    configA.trustedCertCount = 4;
    configA.knock.enable = true;
    configA.flows.flowCount = 4;
    configA.flows.outCount  = 4;
    configA.flows.inCount   = 4;
    CHECK(a.Init(configA) == common::Error::Ok);

    flux::Socket::Config configB{};
    configB.type = flux_net::BACKEND;
    configB.port = 9473;
    configB.maxPeers = 16;
    configB.pendingPacketCount = 32;
    configB.identity = &idB;
    configB.flows.flowCount = 4;
    configB.flows.outCount  = 4;
    configB.flows.inCount   = 4;
    CHECK(b.Init(configB) == common::Error::Ok);

    const flux::Address addrB = flux_net::Loopback(9473);
    CHECK(a.LoadCertificate(idB.ToCertificate()) == common::Error::Ok);
    CHECK(a.Connect(addrB, tagB) == common::Error::Ok);

    // Never larger than what the target reports, which is what makes it safe
    // to use without asking.
    CHECK(flux::Socket::SAFE_PAYLOAD_BYTES <= a.MaxPayload(addrB));

    const std::vector<uint8_t> payload(flux::Socket::SAFE_PAYLOAD_BYTES, 0x5A);
    const uint16_t size = static_cast<uint16_t>(payload.size());

    // Under the opener, off a flow and on one.
    CHECK(a.BuildPacket().NoFlow().PutBytes(payload.data(), size).Send(addrB)
          == common::Error::Ok);
    flux::FlowHandle flow = a.OpenFlow(11, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(a.BuildPacket().WithFlow(flow).PutBytes(payload.data(), size).Send(addrB)
          == common::Error::Ok);

    // And again once the session has replaced the opener.
    std::vector<uint32_t> sink;
    for (int i = 0; i < 300 && !KnockClosed(a, addrB); ++i)
        PumpOnce(a, b, sink);
    CHECK(KnockClosed(a, addrB));
    CHECK(flux::Socket::SAFE_PAYLOAD_BYTES <= a.MaxPayload(addrB));
    CHECK(a.BuildPacket().NoFlow().PutBytes(payload.data(), size).Send(addrB)
          == common::Error::Ok);
    CHECK(a.BuildPacket().WithFlow(flow).PutBytes(payload.data(), size).Send(addrB)
          == common::Error::Ok);
}

// A knock aimed at a key the receiver does not hold cannot be opened, and the
// receiver says so the only way that helps: with the ordinary challenge. The
// sender starts its handshake on the next pass rather than waiting out a retry
// interval, and the data it was carrying arrives once the session is up.
static void a_knock_it_cannot_open_gets_the_challenge()
{
    // Two identities: B runs as one, and A aims its opener at the other, which
    // is what a stale or wrong certificate looks like from the receiver's side.
    const flux::Certificate::IdentityTag tagReal  = TagOf(0xB6);
    const flux::Certificate::IdentityTag tagWrong = TagOf(0xB7);
    common::Result<flux::Identity> realId  = flux::Identity::Generate(tagReal);
    common::Result<flux::Identity> otherId = flux::Identity::Generate(tagWrong);
    CHECK(!realId.isErr() && !otherId.isErr());
    const flux::Identity idB    = realId.Take();
    const flux::Identity idOther = otherId.Take();

    flux::Socket a, b;
    flux::Socket::Config configA{};
    configA.type = flux_net::BACKEND;
    configA.port = 9474;
    configA.maxPeers = 16;
    configA.pendingPacketCount = 32;
    configA.trustedCertCount = 4;
    configA.knock.enable = true;
    configA.flows.flowCount = 4;
    configA.flows.outCount  = 4;
    configA.flows.inCount   = 4;
    CHECK(a.Init(configA) == common::Error::Ok);

    flux::Socket::Config configB{};
    configB.type = flux_net::BACKEND;
    configB.port = 9475;
    configB.maxPeers = 16;
    configB.pendingPacketCount = 32;
    configB.identity = &idB;
    configB.flows.flowCount = 4;
    configB.flows.outCount  = 4;
    configB.flows.inCount   = 4;
    CHECK(b.Init(configB) == common::Error::Ok);

    const flux::Address addrB = flux_net::Loopback(9475);

    // A holds a certificate for the wrong key and aims at it.
    CHECK(a.LoadCertificate(idOther.ToCertificate()) == common::Error::Ok);
    CHECK(a.Connect(addrB, tagWrong) == common::Error::Ok);
    {
        flux::PeerHandle peer = a.GetPeer(addrB);
        CHECK(!peer.Failed() && peer.Read() && peer.Read()->knockActive);
    }

    // Three sends into a window that will be refused. Only one of them is
    // retained anywhere, and that is exactly the one that survives: a reliable
    // body sits in staging until its sequence resolves, so the retransmit
    // re-seals it under whatever framing the peer has by then. Nothing keeps a
    // copy of the other two, so a flight nobody opened is where they end.
    CHECK(a.BuildPacket().NoFlow().PutU32(4321).Send(addrB) == common::Error::Ok);
    flux::FlowHandle loose = a.OpenFlow(14, flux::FlowMode::UNRELIABLE);
    CHECK(a.BuildPacket().WithFlow(loose).PutU32(555).Send(addrB) == common::Error::Ok);
    flux::FlowHandle flow = a.OpenFlow(13, flux::FlowMode::RELIABLE_ORDERED);
    CHECK(a.BuildPacket().WithFlow(flow).PutU32(999).Send(addrB) == common::Error::Ok);

    // One exchange each way. B cannot open the opener, so it answers with the
    // challenge, and A has moved off AWAITING_CHALLENGE by the time this
    // returns. Nothing here waits on a retry interval.
    std::vector<uint32_t> atB;
    PumpOnce(a, b, atB);
    PumpOnce(a, b, atB);
    {
        flux::PeerHandle peer = a.GetPeer(addrB);
        CHECK(!peer.Failed() && peer.Read());
        CHECK(peer.Read() && peer.Read()->state != flux::HandshakeState::AWAITING_CHALLENGE);
    }
    CHECK(atB.empty());   // the opener was refused, so nothing was delivered early

    // The handshake finishes, and exactly one of the three arrives.
    for (int i = 0; i < 300 && (atB.empty() || !KnockClosed(a, addrB)); ++i)
        PumpOnce(a, b, atB);
    CHECK(KnockClosed(a, addrB));
    CHECK(atB.size() == 1);
    CHECK(!atB.empty() && atB[0] == 999);
}

int main()
{
    cert_knock_delivers_in_the_first_exchange();
    oversized_first_packet_is_refused();
    flow_survives_the_key_handover();
    the_opener_stops_once_the_peer_answers();
    no_material_falls_back_to_the_handshake();
    the_safe_size_is_never_refused();
    a_knock_it_cannot_open_gets_the_challenge();
    naming_an_unknown_identity_is_refused();
    return test::report();
}
