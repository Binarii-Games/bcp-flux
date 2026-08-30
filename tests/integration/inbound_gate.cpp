// The inbound-handshake gate: the client posture. A socket that refuses
// inbound handshakes has sessions only where it dialed, so a stranger cannot
// occupy a peer slot, cannot open toward it at all, and cannot 0-RTT in - a
// knock is an inbound handshake carrying data, not an exemption from being
// one.
//
// What must NOT change is everything the socket does on its own initiative:
// its outbound connects complete against a willing responder, and the
// sessionless probe still answers, because a probe registers nothing and is
// governed by its own budget rather than by the handshake gate.
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>

#include "flux_net.h"
#include "harness.h"

#include <chrono>
#include <thread>

namespace flux = bcp::flux;
namespace common = bcp::common;

namespace
{
    constexpr uint16_t GATED = 47601;
    constexpr uint16_t OPEN  = 47602;

    bool Boot(flux::Socket& socket, uint16_t port, bool acceptInbound,
              const flux::Identity* identity = nullptr)
    {
        flux::Socket::Config config{ .type = flux_net::BACKEND, .port = port,
                                     .maxPeers = 8, .pendingPacketCount = 8 };
        config.liveness.acceptInboundHandshakes = acceptInbound;
        config.identity = identity;
        return socket.Init(config) == common::Error::Ok;
    }

    void Pump(flux::Socket& a, flux::Socket& b, int rounds)
    {
        flux::PacketSlotHandle sink[16];
        for (int i = 0; i < rounds; ++i)
        {
            a.Update();
            b.Update();
            a.Poll(sink, 16);
            b.Poll(sink, 16);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}

// A stranger's connect never lands: no session on either side, and no peer
// slot spent on the gated socket. The initiator is left waiting on silence,
// which is exactly what a closed posture should look like from outside.
static void a_stranger_cannot_open_a_session()
{
    flux::Socket gated, stranger;
    CHECK(Boot(gated, GATED, false));
    CHECK(Boot(stranger, OPEN, true));

    const flux::Address addrGated = flux_net::Loopback(GATED);
    CHECK(stranger.Connect(addrGated) == common::Error::Ok);
    Pump(stranger, gated, 100);

    // The stranger holds only its own optimistic entry; the gated side
    // registered nothing at all.
    CHECK(!flux_net::Established(stranger, addrGated));
    CHECK(gated.GetPeer(flux_net::Loopback(OPEN)).Failed());

    gated.Shutdown();
    stranger.Shutdown();
}

// The gate refuses the whole responder side, the opener included: a knock
// toward a gated socket dies silently even when the knocker holds a valid
// certificate for it.
static void a_knock_is_an_inbound_handshake_too()
{
    const flux::Certificate::IdentityTag tag = [] {
        flux::Certificate::IdentityTag t{};
        t[0] = 0xE1;
        return t;
    }();
    common::Result<flux::Identity> made = flux::Identity::Generate(tag);
    CHECK(!made.isErr());
    const flux::Identity identity = made.Take();

    flux::Socket gated, knocker;
    CHECK(Boot(gated, GATED + 2, false, &identity));

    flux::Socket::Config knockerConfig{ .type = flux_net::BACKEND, .port = OPEN + 2,
                                        .maxPeers = 8, .pendingPacketCount = 8 };
    knockerConfig.trustedCertCount = 4;
    knockerConfig.knock.enable = true;
    CHECK(knocker.Init(knockerConfig) == common::Error::Ok);
    CHECK(knocker.LoadCertificate(identity.ToCertificate()) == common::Error::Ok);

    const flux::Address addrGated = flux_net::Loopback(GATED + 2);
    CHECK(knocker.Connect(addrGated, tag) == common::Error::Ok);
    CHECK(knocker.BuildPacket().NoFlow().PutU32(7).Send(addrGated) == common::Error::Ok);
    Pump(knocker, gated, 100);

    CHECK(!flux_net::Established(knocker, addrGated));
    CHECK(gated.GetPeer(flux_net::Loopback(OPEN + 2)).Failed());

    gated.Shutdown();
    knocker.Shutdown();
}

// The socket's own initiative is untouched: it dials out and the session
// completes, because HS_CHLG and HS_FINISH answer a handshake it started and
// pass the gate.
static void its_own_connects_still_complete()
{
    flux::Socket gated, server;
    CHECK(Boot(gated, GATED + 4, false));
    CHECK(Boot(server, OPEN + 4, true));

    const flux::Address addrServer = flux_net::Loopback(OPEN + 4);
    const flux::Address addrGated  = flux_net::Loopback(GATED + 4);
    CHECK(gated.Connect(addrServer) == common::Error::Ok);
    CHECK(flux_net::PumpUntilEstablished(gated, addrGated, server, addrServer));

    gated.Shutdown();
    server.Shutdown();
}

// The probe is not a handshake: it registers nothing and answers under its
// own budget, so a gated socket still measures and is still measurable.
static void probes_pass_the_gate_both_ways()
{
    flux::Socket gated, other;
    CHECK(Boot(gated, GATED + 6, false));
    CHECK(Boot(other, OPEN + 6, true));

    // Gated socket probing out.
    CHECK(gated.ProbeAddress(flux_net::Loopback(OPEN + 6)) == common::Error::Ok);
    // And being probed.
    CHECK(other.ProbeAddress(flux_net::Loopback(GATED + 6)) == common::Error::Ok);

    flux::Socket::ProbeResult mine[4], theirs[4];
    uint32_t gotMine = 0, gotTheirs = 0;
    for (int i = 0; i < 200 && (gotMine == 0 || gotTheirs == 0); ++i)
    {
        gated.Update();
        other.Update();
        if (gotMine == 0)   gotMine   = gated.PollProbes(mine, 4);
        if (gotTheirs == 0) gotTheirs = other.PollProbes(theirs, 4);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    CHECK(gotMine == 1);
    CHECK(gotTheirs == 1);
    if (gotMine == 1)   CHECK(mine[0].rttMicros != 0);
    if (gotTheirs == 1) CHECK(theirs[0].rttMicros != 0);

    // And still: no sessions were created by any of it.
    CHECK(gated.GetPeer(flux_net::Loopback(OPEN + 6)).Failed());
    CHECK(other.GetPeer(flux_net::Loopback(GATED + 6)).Failed());

    gated.Shutdown();
    other.Shutdown();
}

int main()
{
    a_stranger_cannot_open_a_session();
    a_knock_is_an_inbound_handshake_too();
    its_own_connects_still_complete();
    probes_pass_the_gate_both_ways();
    return test::report();
}
