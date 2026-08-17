// Session resumption, end to end over real UDP. A process that dies and
// restarts holds a note its peer issued while the session was healthy. Handing
// that note back puts it inside the first packet, and because opening the packet
// proves the sender holds the key the note names, the two together are what the
// handshake would have established. So none of the handshake runs.
//
// The case that gives this its worth is the control: without a note the same
// restart cannot get in at all until the far side evicts the entry it still
// holds, because a confirmed peer is never re-keyed. That is what
// peer_restart_reconnect asserts, and these cases sit against it.
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>

#include "flux_net.h"
#include "harness.h"

#include <chrono>
#include <cstring>
#include <thread>
#include <vector>

namespace flux = bcp::flux;
namespace common = bcp::common;

namespace
{
    struct Seen
    {
        uint32_t notes = 0;
    };

    void OnEvent(void* context, const flux::EventInfo& info)
    {
        if (info.Has(flux::SocketEvent::RESUME_NOTE_RECEIVED))
            ++static_cast<Seen*>(context)->notes;
    }

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
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    void ConfigureServer(flux::Socket::Config& config, uint16_t port,
                         const flux::Identity& identity)
    {
        config.type               = flux_net::BACKEND;
        config.port               = port;
        config.maxPeers           = 16;
        config.pendingPacketCount = 32;
        config.identity           = &identity;
        config.trustedCertCount   = 4;
        config.knock.enable       = true;
    }

    void ConfigureClient(flux::Socket::Config& config, uint16_t port,
                         const flux::Identity& identity, Seen& seen)
    {
        config.type               = flux_net::BACKEND;
        config.port               = port;
        config.maxPeers           = 16;
        config.pendingPacketCount = 32;
        config.identity           = &identity;
        config.trustedCertCount   = 4;
        config.knock.enable       = true;
        config.keepResumeNotes    = true;
        config.events.hook        = OnEvent;
        config.events.context     = &seen;
        config.events.subscribed  = flux::ToBits(flux::SocketEvent::RESUME_NOTE_RECEIVED);
    }

    // Confirmed means a packet from the far side opened under the session key,
    // so it only becomes true in the direction traffic actually flows. Asking
    // it of the side that has sent but not received is asking the wrong thing.
    bool Confirmed(flux::Socket& socket, const flux::Address& addr)
    {
        flux::PeerHandle peer = socket.GetPeer(addr);
        return !peer.Failed() && peer.Read() && peer.Read()->IsValid()
            && peer.Read()->confirmed;
    }

    // A knocked peer reads as established from its first packet, so the window
    // closing is what says the handshake behind it finished.
    bool HandshakeLanded(flux::Socket& socket, const flux::Address& addr)
    {
        flux::PeerHandle peer = socket.GetPeer(addr);
        return !peer.Failed() && peer.Read() && peer.Read()->IsValid()
            && !peer.Read()->knockActive;
    }

    // Runs a session far enough that the far side issues a note, and returns it.
    uint32_t EarnNote(flux::Socket& client, flux::Socket& server,
                      const flux::Address& addrServer, uint8_t* out, uint32_t cap)
    {
        std::vector<uint32_t> ignored;
        uint32_t len = 0;
        for (int round = 0; round < 400 && len == 0; ++round)
        {
            // A note only goes to a peer that has proven it holds its key, and
            // a packet opening under the session is what proves it.
            if (round % 20 == 0)
                CHECK(client.BuildPacket().NoFlow().PutU32(1).Send(addrServer)
                      == common::Error::Ok);
            PumpOnce(client, server, ignored);
            len = client.ResumeNoteFor(addrServer, out, cap);
        }
        return len;
    }
}

// A note is issued once the session proves itself, reported, and the size the
// public constant says it is.
static void a_note_is_issued_once_the_session_proves_itself()
{
    const flux::Certificate::IdentityTag serverTag = TagOf(0xE1);
    const flux::Certificate::IdentityTag clientTag = TagOf(0xE2);
    const flux::Identity idServer = Generate(serverTag);
    const flux::Identity idClient = Generate(clientTag);

    Seen atClient;
    flux::Socket client, server;
    flux::Socket::Config clientConfig{}, serverConfig{};
    ConfigureClient(clientConfig, 9950, idClient, atClient);
    ConfigureServer(serverConfig, 9951, idServer);
    CHECK(client.Init(clientConfig) == common::Error::Ok);
    CHECK(server.Init(serverConfig) == common::Error::Ok);

    const flux::Address addrServer = flux_net::Loopback(9951);
    CHECK(client.LoadCertificate(idServer.ToCertificate()) == common::Error::Ok);
    CHECK(client.Connect(addrServer, serverTag) == common::Error::Ok);

    uint8_t note[flux::Socket::RESUME_NOTE_BYTES];
    const uint32_t len = EarnNote(client, server, addrServer, note, sizeof(note));

    CHECK(len == flux::Socket::RESUME_NOTE_BYTES);
    CHECK(atClient.notes >= 1);
}

// A socket that did not ask to keep notes keeps none, and says nothing about
// them. The issuer is unaffected either way, which is what stops it resending.
static void a_socket_that_did_not_ask_keeps_no_note()
{
    const flux::Certificate::IdentityTag serverTag = TagOf(0xE3);
    const flux::Certificate::IdentityTag clientTag = TagOf(0xE4);
    const flux::Identity idServer = Generate(serverTag);
    const flux::Identity idClient = Generate(clientTag);

    Seen atClient;
    flux::Socket client, server;
    flux::Socket::Config clientConfig{}, serverConfig{};
    ConfigureClient(clientConfig, 9952, idClient, atClient);
    clientConfig.keepResumeNotes = false;
    ConfigureServer(serverConfig, 9953, idServer);
    CHECK(client.Init(clientConfig) == common::Error::Ok);
    CHECK(server.Init(serverConfig) == common::Error::Ok);

    const flux::Address addrServer = flux_net::Loopback(9953);
    const flux::Address addrClient = flux_net::Loopback(9952);
    CHECK(client.LoadCertificate(idServer.ToCertificate()) == common::Error::Ok);
    CHECK(client.Connect(addrServer, serverTag) == common::Error::Ok);

    std::vector<uint32_t> ignored;
    for (int round = 0; round < 300; ++round)
    {
        if (round % 20 == 0)
            CHECK(client.BuildPacket().NoFlow().PutU32(1).Send(addrServer)
                  == common::Error::Ok);
        PumpOnce(client, server, ignored);
    }

    uint8_t note[flux::Socket::RESUME_NOTE_BYTES];
    CHECK(client.ResumeNoteFor(addrServer, note, sizeof(note)) == 0);
    CHECK(atClient.notes == 0);

    // The issuer stopped asking regardless, because the note is acknowledged
    // whether or not the holder kept it.
    flux::PeerHandle peer = server.GetPeer(addrClient);
    CHECK(!peer.Failed() && peer.Read() && !peer.Read()->ticketSendPending);
}

// The case this exists for. The client process goes away, comes back on the
// same address, presents its note, and is live in the first exchange with no
// handshake having run.
static void a_restart_presenting_a_note_resumes_without_a_handshake()
{
    const flux::Certificate::IdentityTag serverTag = TagOf(0xE5);
    const flux::Certificate::IdentityTag clientTag = TagOf(0xE6);
    const flux::Identity idServer = Generate(serverTag);
    const flux::Identity idClient = Generate(clientTag);

    flux::Socket server;
    flux::Socket::Config serverConfig{};
    ConfigureServer(serverConfig, 9955, idServer);
    CHECK(server.Init(serverConfig) == common::Error::Ok);

    const flux::Address addrServer = flux_net::Loopback(9955);
    const flux::Address addrClient = flux_net::Loopback(9954);

    uint8_t note[flux::Socket::RESUME_NOTE_BYTES];
    uint32_t len = 0;
    {
        Seen atClient;
        flux::Socket client;
        flux::Socket::Config clientConfig{};
        ConfigureClient(clientConfig, 9954, idClient, atClient);
        CHECK(client.Init(clientConfig) == common::Error::Ok);
        CHECK(client.LoadCertificate(idServer.ToCertificate()) == common::Error::Ok);
        CHECK(client.Connect(addrServer, serverTag) == common::Error::Ok);
        len = EarnNote(client, server, addrServer, note, sizeof(note));
        CHECK(len == flux::Socket::RESUME_NOTE_BYTES);
    }

    // The process is gone and the server still holds its entry, which is the
    // whole obstacle: a confirmed peer is never re-keyed, so without a note the
    // newcomer would wait for eviction.
    CHECK(!server.GetPeer(addrClient).Failed());

    Seen atSecond;
    flux::Socket second;
    flux::Socket::Config secondConfig{};
    ConfigureClient(secondConfig, 9954, idClient, atSecond);
    CHECK(second.Init(secondConfig) == common::Error::Ok);
    CHECK(second.LoadCertificate(idServer.ToCertificate()) == common::Error::Ok);
    CHECK(second.Connect(addrServer, serverTag, note, len) == common::Error::Ok);

    std::vector<uint32_t> atServer;
    CHECK(second.BuildPacket().NoFlow().PutU32(7777).Send(addrServer) == common::Error::Ok);
    for (int round = 0; round < 10 && atServer.empty(); ++round)
        PumpOnce(second, server, atServer);

    // Data through, and the server's peer already confirmed. Confirmed is what
    // says no handshake was needed: it is otherwise only set by one completing.
    CHECK(atServer.size() == 1);
    CHECK(!atServer.empty() && atServer[0] == 7777);
    CHECK(Confirmed(server, addrClient));

    // And its address was never in question, because a returning peer may
    // legitimately be somewhere new.
    flux::PeerHandle peer = server.GetPeer(addrClient);
    CHECK(!peer.Failed() && peer.Read() && !peer.Read()->awaitingAddressProof);
}

// A note the far side cannot open is not a failure, it is a first contact. The
// opener falls back and the ordinary handshake carries it, so a stale note is
// never worse than no note at all.
static void a_note_that_will_not_open_falls_back_to_the_handshake()
{
    const flux::Certificate::IdentityTag serverTag = TagOf(0xE7);
    const flux::Certificate::IdentityTag clientTag = TagOf(0xE8);
    const flux::Identity idServer = Generate(serverTag);
    const flux::Identity idClient = Generate(clientTag);

    Seen atClient;
    flux::Socket client, server;
    flux::Socket::Config clientConfig{}, serverConfig{};
    ConfigureClient(clientConfig, 9956, idClient, atClient);
    ConfigureServer(serverConfig, 9957, idServer);
    CHECK(client.Init(clientConfig) == common::Error::Ok);
    CHECK(server.Init(serverConfig) == common::Error::Ok);

    const flux::Address addrServer = flux_net::Loopback(9957);
    CHECK(client.LoadCertificate(idServer.ToCertificate()) == common::Error::Ok);

    // Bytes that are the right length and nothing else.
    uint8_t rubbish[flux::Socket::RESUME_NOTE_BYTES];
    for (size_t i = 0; i < sizeof(rubbish); ++i)
        rubbish[i] = static_cast<uint8_t>(i * 7 + 1);
    CHECK(client.Connect(addrServer, serverTag, rubbish, sizeof(rubbish))
          == common::Error::Ok);

    std::vector<uint32_t> atServer;
    CHECK(client.BuildPacket().NoFlow().PutU32(31337).Send(addrServer) == common::Error::Ok);
    for (int round = 0; round < 300 && !HandshakeLanded(client, addrServer); ++round)
        PumpOnce(client, server, atServer);

    // The first flight still arrived, because the opener itself was sound, and
    // the handshake behind it ran and finished, which is what a rubbish note
    // falls back to.
    CHECK(atServer.size() >= 1);
    CHECK(!atServer.empty() && atServer[0] == 31337);
    CHECK(HandshakeLanded(client, addrServer));

    // A wrong length is refused outright rather than sent and declined.
    CHECK(client.Connect(addrServer, serverTag, rubbish, 3) == common::Error::InvalidParam);
}

int main()
{
    a_note_is_issued_once_the_session_proves_itself();
    a_socket_that_did_not_ask_keeps_no_note();
    a_restart_presenting_a_note_resumes_without_a_handshake();
    a_note_that_will_not_open_falls_back_to_the_handshake();
    return test::report();
}
