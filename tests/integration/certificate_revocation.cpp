// Revoking a pinned certificate, end to end over real UDP. Trust here is by
// provenance: a peer is authenticated when it announces a tag this socket has
// pinned AND presents that tag's certified key. Revocation keeps the entry and
// wipes what it certified, so the tag stops naming any key at all.
//
// The claim worth holding to is that this is stronger than never having pinned
// the tag, not merely equal to it. An unknown tag still establishes a session,
// unauthenticated, because a socket may talk to strangers opportunistically. A
// revoked one refuses outright, so a key that leaked cannot be talked to even
// on those terms. These cases drive both sides of that, plus the two ways back:
// a live session is not torn down, and loading a fresh certificate re-trusts
// the tag.
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>

#include "flux_net.h"
#include "harness.h"

#include <chrono>
#include <thread>
#include <vector>

namespace flux = bcp::flux;
namespace common = bcp::common;

namespace
{
    struct Seen
    {
        uint32_t established = 0;
        uint32_t mismatch    = 0;
    };

    void OnEvent(void* context, const flux::EventInfo& info)
    {
        Seen& seen = *static_cast<Seen*>(context);
        if (info.Has(flux::SocketEvent::PEER_ESTABLISHED))  ++seen.established;
        if (info.Has(flux::SocketEvent::PEER_CERT_MISMATCH)) ++seen.mismatch;
    }

    constexpr uint32_t WATCHED =
          flux::ToBits(flux::SocketEvent::PEER_ESTABLISHED)
        | flux::ToBits(flux::SocketEvent::PEER_CERT_MISMATCH);

    flux::Certificate::IdentityTag TagOf(uint8_t seed)
    {
        flux::Certificate::IdentityTag tag{};
        tag[0] = seed;
        return tag;
    }

    flux::Identity Generate(const flux::Certificate::IdentityTag& tag)
    {
        common::Result<flux::Identity> made = flux::Identity::Generate(tag);
        CHECK(!made.isErr());
        return made.Take();
    }

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
        // The handshake retry is paced off a clock, so real time has to pass.
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    bool Established(flux::Socket& socket, const flux::Address& addr)
    {
        flux::PeerHandle peer = socket.GetPeer(addr);
        return !peer.Failed() && peer.Read() && peer.Read()->IsValid();
    }

    bool Authenticated(flux::Socket& socket, const flux::Address& addr)
    {
        flux::PeerHandle peer = socket.GetPeer(addr);
        return !peer.Failed() && peer.Read() && peer.Read()->authenticated;
    }

    void ConfigureClient(flux::Socket::Config& config, uint16_t port, Seen& seen)
    {
        config.type               = flux_net::BACKEND;
        config.port               = port;
        config.maxPeers           = 16;
        config.pendingPacketCount = 32;
        config.trustedCertCount   = 4;
        config.events.hook        = OnEvent;
        config.events.context     = &seen;
        config.events.subscribed  = WATCHED;
    }

    void ConfigureServer(flux::Socket::Config& config, uint16_t port,
                         const flux::Identity& identity)
    {
        config.type               = flux_net::BACKEND;
        config.port               = port;
        config.maxPeers           = 16;
        config.pendingPacketCount = 32;
        config.identity           = &identity;
    }
}

// Revocation names an entry that must exist. A tag nobody pinned was never
// trusted, so there is nothing to withdraw and saying so is the answer.
static void revoking_a_tag_that_was_never_pinned_is_not_found()
{
    const flux::Certificate::IdentityTag pinned  = TagOf(0xD1);
    const flux::Certificate::IdentityTag unknown = TagOf(0xD2);
    const flux::Identity identity = Generate(pinned);

    Seen seen;
    flux::Socket client;
    flux::Socket::Config config{};
    ConfigureClient(config, 9770, seen);
    CHECK(client.Init(config) == common::Error::Ok);

    CHECK(client.RemoveCertificate(unknown) == common::Error::NotFound);

    CHECK(client.LoadCertificate(identity.ToCertificate()) == common::Error::Ok);
    CHECK(client.RemoveCertificate(pinned) == common::Error::Ok);

    // The entry stays, so a second withdrawal is still a withdrawal of
    // something and not a lookup failure.
    CHECK(client.RemoveCertificate(pinned) == common::Error::Ok);
    CHECK(client.RemoveCertificate(unknown) == common::Error::NotFound);
}

// A tag this socket never pinned still gets a session, because a socket may
// talk to strangers. It is just not authenticated, so anything demanding
// proof of identity is refused while ordinary traffic flows.
static void an_unpinned_tag_still_establishes_unauthenticated()
{
    const flux::Certificate::IdentityTag tag = TagOf(0xD3);
    const flux::Identity identity = Generate(tag);

    Seen seen;
    flux::Socket client, server;
    flux::Socket::Config clientConfig{}, serverConfig{};
    ConfigureClient(clientConfig, 9771, seen);
    ConfigureServer(serverConfig, 9772, identity);
    CHECK(client.Init(clientConfig) == common::Error::Ok);
    CHECK(server.Init(serverConfig) == common::Error::Ok);

    const flux::Address addrServer = flux_net::Loopback(9772);

    // No certificate loaded at all: the client has never heard of this tag.
    CHECK(client.Connect(addrServer) == common::Error::Ok);
    std::vector<uint32_t> delivered;
    for (int round = 0; round < 200 && !Established(client, addrServer); ++round)
        PumpOnce(client, server, delivered);

    CHECK(Established(client, addrServer));
    CHECK(!Authenticated(client, addrServer));

    // Opportunistic traffic goes. Traffic that demands identity does not.
    CHECK(client.BuildPacket().NoFlow().PutU32(1).Send(addrServer) == common::Error::Ok);
    CHECK(client.BuildPacket().NoFlow().PutU32(2).SendSecured(addrServer)
          == common::Error::NotAuthenticated);
}

// The same tag, pinned, authenticates. This is the control the revoked case
// is measured against: without it a refusal below could mean the setup never
// worked rather than that revocation did something.
static void a_pinned_tag_authenticates()
{
    const flux::Certificate::IdentityTag tag = TagOf(0xD4);
    const flux::Identity identity = Generate(tag);

    Seen seen;
    flux::Socket client, server;
    flux::Socket::Config clientConfig{}, serverConfig{};
    ConfigureClient(clientConfig, 9773, seen);
    ConfigureServer(serverConfig, 9774, identity);
    CHECK(client.Init(clientConfig) == common::Error::Ok);
    CHECK(server.Init(serverConfig) == common::Error::Ok);

    const flux::Address addrServer = flux_net::Loopback(9774);
    CHECK(client.LoadCertificate(identity.ToCertificate()) == common::Error::Ok);
    CHECK(client.Connect(addrServer) == common::Error::Ok);

    std::vector<uint32_t> delivered;
    for (int round = 0; round < 200 && !Authenticated(client, addrServer); ++round)
        PumpOnce(client, server, delivered);

    CHECK(Established(client, addrServer));
    CHECK(Authenticated(client, addrServer));
    CHECK(client.BuildPacket().NoFlow().PutU32(1).SendSecured(addrServer) == common::Error::Ok);
    CHECK(seen.mismatch == 0);
}

// Revoked, the identical exchange refuses outright. The peer never
// establishes, which is what makes revocation stronger than never having
// pinned the tag: the unpinned case above got a session, this gets none.
static void a_revoked_tag_refuses_the_session_outright()
{
    const flux::Certificate::IdentityTag tag = TagOf(0xD5);
    const flux::Identity identity = Generate(tag);

    Seen seen;
    flux::Socket client, server;
    flux::Socket::Config clientConfig{}, serverConfig{};
    ConfigureClient(clientConfig, 9775, seen);
    ConfigureServer(serverConfig, 9776, identity);
    CHECK(client.Init(clientConfig) == common::Error::Ok);
    CHECK(server.Init(serverConfig) == common::Error::Ok);

    const flux::Address addrServer = flux_net::Loopback(9776);
    CHECK(client.LoadCertificate(identity.ToCertificate()) == common::Error::Ok);
    CHECK(client.RemoveCertificate(tag) == common::Error::Ok);
    CHECK(client.Connect(addrServer) == common::Error::Ok);

    std::vector<uint32_t> delivered;
    for (int round = 0; round < 200; ++round)
        PumpOnce(client, server, delivered);

    // The server presents the key that tag used to certify, and it is refused,
    // because after a revocation the tag certifies nothing.
    CHECK(!Established(client, addrServer));
    CHECK(!Authenticated(client, addrServer));
    CHECK(seen.mismatch >= 1);
    CHECK(seen.established == 0);
}

// Loading a certificate for the tag again puts it back, through the same path
// that first pinned it, and the handshake that was being refused completes.
static void loading_the_certificate_again_restores_trust()
{
    const flux::Certificate::IdentityTag tag = TagOf(0xD6);
    const flux::Identity identity = Generate(tag);

    Seen seen;
    flux::Socket client, server;
    flux::Socket::Config clientConfig{}, serverConfig{};
    ConfigureClient(clientConfig, 9777, seen);
    ConfigureServer(serverConfig, 9778, identity);
    CHECK(client.Init(clientConfig) == common::Error::Ok);
    CHECK(server.Init(serverConfig) == common::Error::Ok);

    const flux::Address addrServer = flux_net::Loopback(9778);
    CHECK(client.LoadCertificate(identity.ToCertificate()) == common::Error::Ok);
    CHECK(client.RemoveCertificate(tag) == common::Error::Ok);
    CHECK(client.Connect(addrServer) == common::Error::Ok);

    std::vector<uint32_t> delivered;
    for (int round = 0; round < 100; ++round)
        PumpOnce(client, server, delivered);
    CHECK(!Established(client, addrServer));

    CHECK(client.LoadCertificate(identity.ToCertificate()) == common::Error::Ok);
    for (int round = 0; round < 400 && !Authenticated(client, addrServer); ++round)
        PumpOnce(client, server, delivered);

    CHECK(Established(client, addrServer));
    CHECK(Authenticated(client, addrServer));
    CHECK(client.BuildPacket().NoFlow().PutU32(1).SendSecured(addrServer) == common::Error::Ok);
}

// A session that authenticated before the revocation keeps running. Trust was
// proven at the handshake and the keys came out of it, so withdrawing the
// certificate changes what can be proven next and not what already was.
static void a_live_session_survives_the_revocation()
{
    const flux::Certificate::IdentityTag tag = TagOf(0xD7);
    const flux::Identity identity = Generate(tag);

    Seen seen;
    flux::Socket client, server;
    flux::Socket::Config clientConfig{}, serverConfig{};
    ConfigureClient(clientConfig, 9779, seen);
    ConfigureServer(serverConfig, 9780, identity);
    CHECK(client.Init(clientConfig) == common::Error::Ok);
    CHECK(server.Init(serverConfig) == common::Error::Ok);

    const flux::Address addrServer = flux_net::Loopback(9780);
    CHECK(client.LoadCertificate(identity.ToCertificate()) == common::Error::Ok);
    CHECK(client.Connect(addrServer) == common::Error::Ok);

    std::vector<uint32_t> delivered;
    for (int round = 0; round < 200 && !Authenticated(client, addrServer); ++round)
        PumpOnce(client, server, delivered);
    CHECK(Authenticated(client, addrServer));

    CHECK(client.RemoveCertificate(tag) == common::Error::Ok);

    // Still authenticated, and still delivering traffic that demands it.
    CHECK(Established(client, addrServer));
    CHECK(Authenticated(client, addrServer));
    const size_t alreadyIn = delivered.size();
    CHECK(client.BuildPacket().NoFlow().PutU32(7).SendSecured(addrServer) == common::Error::Ok);
    for (int round = 0; round < 100 && delivered.size() == alreadyIn; ++round)
        PumpOnce(client, server, delivered);
    CHECK(delivered.size() == alreadyIn + 1);
    CHECK(delivered.size() > alreadyIn && delivered.back() == 7);
}

int main()
{
    revoking_a_tag_that_was_never_pinned_is_not_found();
    an_unpinned_tag_still_establishes_unauthenticated();
    a_pinned_tag_authenticates();
    a_revoked_tag_refuses_the_session_outright();
    loading_the_certificate_again_restores_trust();
    a_live_session_survives_the_revocation();
    return test::report();
}
