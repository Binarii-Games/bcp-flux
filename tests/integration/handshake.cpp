// Handshake, end to end over real UDP. Two sockets that have never met run the
// connectionless handshake to completion: each proves the other and derives the
// same session, with no prior trust and no shared secret configured. Before the
// exchange neither side is established; after it, both are, and an address
// neither contacted is still a stranger.
#include <flux/socket/socket.h>

#include "flux_net.h"
#include "harness.h"

namespace flux = bcp::flux;
namespace common = bcp::common;

// A client and a server that never met both reach an established session.
static void handshake_establishes_both_sides()
{
    flux::Socket client, server;
    CHECK(client.Init({ .type = flux_net::BACKEND, .port = 9410,
                        .maxPeers = 16, .pendingPacketCount = 16 }) == common::Error::Ok);
    CHECK(server.Init({ .type = flux_net::BACKEND, .port = 9411,
                        .maxPeers = 16, .pendingPacketCount = 16 }) == common::Error::Ok);

    const flux::Address serverAddr = flux_net::Loopback(9411);
    const flux::Address clientAddr = flux_net::Loopback(9410);

    // Nothing has happened yet: strangers on both sides.
    CHECK(!flux_net::Established(client, serverAddr));
    CHECK(!flux_net::Established(server, clientAddr));

    // The client opens the session; pumping both drives it to completion.
    CHECK(client.Connect(serverAddr) == common::Error::Ok);
    CHECK(flux_net::PumpUntilEstablished(client, clientAddr, server, serverAddr));

    // Both now hold a valid, keyed session with the other.
    CHECK(flux_net::Established(client, serverAddr));
    CHECK(flux_net::Established(server, clientAddr));
}

// An address the server never handshaked with is not a peer.
static void unknown_address_is_not_a_peer()
{
    flux::Socket server;
    CHECK(server.Init({ .type = flux_net::BACKEND, .port = 9412,
                        .maxPeers = 16, .pendingPacketCount = 16 }) == common::Error::Ok);

    flux::PeerHandle stranger = server.GetPeer(flux_net::Loopback(9999));
    CHECK(stranger.Failed());
}

int main()
{
    handshake_establishes_both_sides();
    unknown_address_is_not_a_peer();
    return test::report();
}
