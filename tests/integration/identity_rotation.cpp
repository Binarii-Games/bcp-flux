// Identity rotation, end to end over real UDP. A socket may replace the
// keypair that proves its tag without changing the tag, so peer relationships
// survive and only the proof is new. The part with consequences is the
// first-flight opener: it is encrypted toward a key its sender read out of a
// certificate, which may be older than the key the receiver now presents.
//
// These cases drive that from the public surface: a retained key still opens
// and still delivers, both ends are told what happened, the sender recovers
// once it holds a fresh certificate, a key that was never kept or has been
// forgotten declines to the plain handshake instead, and the nonce space the
// interim key was agreed in survives the handover even when the rotation moves
// it.
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
    // The two events this feature reports, counted per socket.
    struct Seen
    {
        uint32_t stale    = 0;
        uint32_t mismatch = 0;
    };

    void OnEvent(void* context, const flux::EventInfo& info)
    {
        Seen& seen = *static_cast<Seen*>(context);
        if (info.Has(flux::SocketEvent::PEER_STALE_IDENTITY)) ++seen.stale;
        if (info.Has(flux::SocketEvent::PEER_CERT_MISMATCH))  ++seen.mismatch;
    }

    constexpr uint32_t WATCHED =
          flux::ToBits(flux::SocketEvent::PEER_STALE_IDENTITY)
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

    // Drives both sockets one round and collects every u32 the right one
    // delivers, so a case can count what survived.
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
        // Real time has to pass: the handshake retry is paced off a clock, so
        // a loop that never sleeps never lets it fire.
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // A knocked peer reads as established from its first packet, so the knock
    // window closing is what says the real handshake landed.
    bool HandshakeLanded(flux::Socket& socket, const flux::Address& addr)
    {
        flux::PeerHandle peer = socket.GetPeer(addr);
        return !peer.Failed() && peer.Read() && peer.Read()->IsValid()
            && !peer.Read()->knockActive;
    }

    // Which half of the nonce space this socket sends to that peer in.
    uint8_t NonceLaneTo(flux::Socket& socket, const flux::Address& addr)
    {
        flux::PeerHandle peer = socket.GetPeer(addr);
        return (!peer.Failed() && peer.Read()) ? peer.Read()->nonceLane : 0xFF;
    }

    // Sets up a socket that knocks, holding certificates and reporting events.
    void ConfigureSender(flux::Socket::Config& config, uint16_t port, Seen& seen)
    {
        config.type               = flux_net::BACKEND;
        config.port               = port;
        config.maxPeers           = 16;
        config.pendingPacketCount = 32;
        config.trustedCertCount   = 4;
        config.knock.enable       = true;
        config.events.hook        = OnEvent;
        config.events.context     = &seen;
        config.events.subscribed  = WATCHED;
    }

    void ConfigureReceiver(flux::Socket::Config& config, uint16_t port,
                           const flux::Identity& identity, uint8_t history, Seen& seen)
    {
        config.type               = flux_net::BACKEND;
        config.port               = port;
        config.maxPeers           = 16;
        config.pendingPacketCount = 32;
        config.identity           = &identity;
        config.identityHistory    = history;
        config.events.hook        = OnEvent;
        config.events.context     = &seen;
        config.events.subscribed  = WATCHED;
    }
}

// A rotation changes the key and never the tag, and refuses an identity that
// would change the tag, because the tag is what every peer relationship is
// bound to.
static void rotation_replaces_the_key_and_keeps_the_tag()
{
    const flux::Certificate::IdentityTag tag = TagOf(0xC1);
    const flux::Identity first  = Generate(tag);
    const flux::Identity second = Generate(tag);
    const flux::Identity other  = Generate(TagOf(0xC2));

    Seen seen;
    flux::Socket socket;
    flux::Socket::Config config{};
    ConfigureReceiver(config, 9740, first, 2, seen);
    CHECK(socket.Init(config) == common::Error::Ok);

    CHECK(socket.IdentityTag() == tag);
    CHECK(socket.RotateIdentity(second) == common::Error::Ok);
    CHECK(socket.IdentityTag() == tag);

    // A different tag is a different identity, not a rotation of this one.
    CHECK(socket.RotateIdentity(other) == common::Error::InvalidParam);
    CHECK(socket.IdentityTag() == tag);
}

// A history past what the transport will hold is refused at Init rather than
// clamped, so a caller never believes it kept more keys than it has.
static void a_history_past_the_bound_is_refused()
{
    const flux::Identity identity = Generate(TagOf(0xC3));

    Seen seen;
    flux::Socket socket;
    flux::Socket::Config config{};
    ConfigureReceiver(config, 9741, identity,
                      static_cast<uint8_t>(flux::internal::MAX_IDENTITY_HISTORY + 1), seen);
    CHECK(socket.Init(config) != common::Error::Ok);

    Seen atBound;
    flux::Socket bounded;
    flux::Socket::Config boundedConfig{};
    ConfigureReceiver(boundedConfig, 9742, identity,
                      flux::internal::MAX_IDENTITY_HISTORY, atBound);
    CHECK(bounded.Init(boundedConfig) == common::Error::Ok);
}

// An opener aimed at a key the receiver has rotated away from but still holds
// is opened, and its data arrives in the first exchange exactly as it would
// have before the rotation. Keeping the key is what buys that.
static void a_retained_key_still_opens_the_first_flight()
{
    const flux::Certificate::IdentityTag tag = TagOf(0xB1);
    const flux::Identity before = Generate(tag);
    const flux::Identity after  = Generate(tag);

    Seen atSender, atReceiver;
    flux::Socket sender, receiver;
    flux::Socket::Config senderConfig{}, receiverConfig{};
    ConfigureSender(senderConfig, 9743, atSender);
    ConfigureReceiver(receiverConfig, 9744, before, 2, atReceiver);
    CHECK(sender.Init(senderConfig) == common::Error::Ok);
    CHECK(receiver.Init(receiverConfig) == common::Error::Ok);

    // The receiver moves on before the sender has ever spoken to it, so the
    // certificate the sender holds is one generation behind.
    CHECK(receiver.RotateIdentity(after) == common::Error::Ok);

    const flux::Address addrReceiver = flux_net::Loopback(9744);
    CHECK(sender.LoadCertificate(before.ToCertificate()) == common::Error::Ok);
    CHECK(sender.Connect(addrReceiver, tag) == common::Error::Ok);
    CHECK(sender.BuildPacket().NoFlow().PutU32(4242).Send(addrReceiver) == common::Error::Ok);

    std::vector<uint32_t> delivered;
    PumpOnce(sender, receiver, delivered);
    CHECK(delivered.size() == 1);
    CHECK(!delivered.empty() && delivered[0] == 4242);

    // And the receiver says so, because the application is what has to get a
    // current certificate to that sender.
    CHECK(atReceiver.stale == 1);
}

// The handshake behind that opener announces the key the receiver holds NOW,
// which the sender's pinned certificate refuses. The sender is told, and once
// it holds a fresh certificate its own retry completes the session.
static void a_stale_sender_is_told_and_then_recovers()
{
    const flux::Certificate::IdentityTag tag = TagOf(0xB2);
    const flux::Identity before = Generate(tag);
    const flux::Identity after  = Generate(tag);

    Seen atSender, atReceiver;
    flux::Socket sender, receiver;
    flux::Socket::Config senderConfig{}, receiverConfig{};
    ConfigureSender(senderConfig, 9745, atSender);
    ConfigureReceiver(receiverConfig, 9746, before, 2, atReceiver);
    CHECK(sender.Init(senderConfig) == common::Error::Ok);
    CHECK(receiver.Init(receiverConfig) == common::Error::Ok);
    CHECK(receiver.RotateIdentity(after) == common::Error::Ok);

    const flux::Address addrReceiver = flux_net::Loopback(9746);
    CHECK(sender.LoadCertificate(before.ToCertificate()) == common::Error::Ok);
    CHECK(sender.Connect(addrReceiver, tag) == common::Error::Ok);
    CHECK(sender.BuildPacket().NoFlow().PutU32(1).Send(addrReceiver) == common::Error::Ok);

    std::vector<uint32_t> delivered;
    for (int round = 0; round < 80; ++round)
        PumpOnce(sender, receiver, delivered);

    // The key it was offered does not match the certificate it pinned, so the
    // session is refused and the sender hears why.
    CHECK(atSender.mismatch >= 1);
    CHECK(!HandshakeLanded(sender, addrReceiver));

    // The application fetches the current certificate, which is the whole
    // answer. Nothing else has to happen: the handshake retry does the rest.
    CHECK(sender.LoadCertificate(after.ToCertificate()) == common::Error::Ok);
    for (int round = 0; round < 400 && !HandshakeLanded(sender, addrReceiver); ++round)
        PumpOnce(sender, receiver, delivered);
    CHECK(HandshakeLanded(sender, addrReceiver));

    // And the session that came out of it carries traffic.
    CHECK(sender.BuildPacket().NoFlow().PutU32(5150).Send(addrReceiver) == common::Error::Ok);
    for (int round = 0; round < 100 && delivered.size() < 2; ++round)
        PumpOnce(sender, receiver, delivered);
    CHECK(delivered.size() == 2);
    CHECK(delivered.size() == 2 && delivered[1] == 5150);
}

// With no history configured the previous key is gone the moment it is
// replaced, so an opener naming it cannot be read and gets the ordinary
// challenge instead. Nothing it carried survives, and the receiver has no
// stale peer to report because it recognised no key of its own.
static void a_key_that_was_never_kept_declines_the_opener()
{
    const flux::Certificate::IdentityTag tag = TagOf(0xB3);
    const flux::Identity before = Generate(tag);
    const flux::Identity after  = Generate(tag);

    Seen atSender, atReceiver;
    flux::Socket sender, receiver;
    flux::Socket::Config senderConfig{}, receiverConfig{};
    ConfigureSender(senderConfig, 9747, atSender);
    ConfigureReceiver(receiverConfig, 9748, before, 0, atReceiver);
    CHECK(sender.Init(senderConfig) == common::Error::Ok);
    CHECK(receiver.Init(receiverConfig) == common::Error::Ok);
    CHECK(receiver.RotateIdentity(after) == common::Error::Ok);

    const flux::Address addrReceiver = flux_net::Loopback(9748);
    CHECK(sender.LoadCertificate(before.ToCertificate()) == common::Error::Ok);
    CHECK(sender.Connect(addrReceiver, tag) == common::Error::Ok);
    CHECK(sender.BuildPacket().NoFlow().PutU32(777).Send(addrReceiver) == common::Error::Ok);

    std::vector<uint32_t> delivered;
    for (int round = 0; round < 20; ++round)
        PumpOnce(sender, receiver, delivered);

    CHECK(delivered.empty());
    CHECK(atReceiver.stale == 0);
}

// Forgetting the retained keys takes effect on the next opener that names one,
// which is what makes it an answer to a leaked key rather than a hint.
static void forgetting_the_old_keys_cuts_off_their_senders()
{
    const flux::Certificate::IdentityTag tag = TagOf(0xB4);
    const flux::Identity before = Generate(tag);
    const flux::Identity after  = Generate(tag);

    Seen atSender, atReceiver;
    flux::Socket sender, receiver;
    flux::Socket::Config senderConfig{}, receiverConfig{};
    ConfigureSender(senderConfig, 9749, atSender);
    ConfigureReceiver(receiverConfig, 9750, before, 2, atReceiver);
    CHECK(sender.Init(senderConfig) == common::Error::Ok);
    CHECK(receiver.Init(receiverConfig) == common::Error::Ok);

    CHECK(receiver.RotateIdentity(after) == common::Error::Ok);
    receiver.ForgetPreviousIdentities();

    const flux::Address addrReceiver = flux_net::Loopback(9750);
    CHECK(sender.LoadCertificate(before.ToCertificate()) == common::Error::Ok);
    CHECK(sender.Connect(addrReceiver, tag) == common::Error::Ok);
    CHECK(sender.BuildPacket().NoFlow().PutU32(999).Send(addrReceiver) == common::Error::Ok);

    std::vector<uint32_t> delivered;
    for (int round = 0; round < 20; ++round)
        PumpOnce(sender, receiver, delivered);

    // The key it named was held a moment ago and is not held now.
    CHECK(delivered.empty());
    CHECK(atReceiver.stale == 0);
}

// The interim key an opener runs under is agreed against the key the opener
// named, and the session that replaces it against the key the handshake
// announced. A rotation makes those two different keys, so the nonce space
// each side sends in can move at the handover. Traffic must survive that:
// the previous key is kept precisely so packets still in flight keep opening,
// and it has to be opened in the space it was sealed in.
static void traffic_survives_a_handover_that_moves_the_nonce_space()
{
    const flux::Certificate::IdentityTag tag = TagOf(0xB5);

    // Find a rotation where the sender's half of the nonce space differs
    // before and after, which is the case the handover has to survive. The
    // comparison is over public keys, so this is a search over generated
    // identities and nothing to do with the sockets.
    flux::Identity sender_, before, after;
    bool found = false;
    for (int attempt = 0; attempt < 4000 && !found; ++attempt)
    {
        // Generated directly rather than through the helper above, whose
        // CHECK would make this file's check count depend on how many
        // attempts the search happened to take.
        common::Result<flux::Identity> madeSender = flux::Identity::Generate(TagOf(0xA5));
        common::Result<flux::Identity> madeBefore = flux::Identity::Generate(tag);
        common::Result<flux::Identity> madeAfter  = flux::Identity::Generate(tag);
        if (madeSender.isErr() || madeBefore.isErr() || madeAfter.isErr()) break;
        const flux::Identity candidateSender = madeSender.Take();
        const flux::Identity candidateBefore = madeBefore.Take();
        const flux::Identity candidateAfter  = madeAfter.Take();
        const bool againstBefore = std::memcmp(candidateSender.publicKey.data(),
                                               candidateBefore.publicKey.data(),
                                               candidateSender.publicKey.size()) < 0;
        const bool againstAfter  = std::memcmp(candidateSender.publicKey.data(),
                                               candidateAfter.publicKey.data(),
                                               candidateSender.publicKey.size()) < 0;
        if (againstBefore != againstAfter)
        {
            sender_ = candidateSender;
            before  = candidateBefore;
            after   = candidateAfter;
            found   = true;
        }
    }
    CHECK(found);
    if (!found) return;

    Seen atSender, atReceiver;
    flux::Socket sender, receiver;
    flux::Socket::Config senderConfig{}, receiverConfig{};
    ConfigureSender(senderConfig, 9751, atSender);
    senderConfig.identity = &sender_;
    ConfigureReceiver(receiverConfig, 9752, before, 2, atReceiver);
    CHECK(sender.Init(senderConfig) == common::Error::Ok);
    CHECK(receiver.Init(receiverConfig) == common::Error::Ok);
    CHECK(receiver.RotateIdentity(after) == common::Error::Ok);

    const flux::Address addrReceiver = flux_net::Loopback(9752);
    CHECK(sender.LoadCertificate(before.ToCertificate()) == common::Error::Ok);
    CHECK(sender.Connect(addrReceiver, tag) == common::Error::Ok);

    const uint8_t whileKnocking = NonceLaneTo(sender, addrReceiver);

    // The first flight still lands, on a key the receiver keeps only because
    // it was told to.
    std::vector<uint32_t> delivered;
    CHECK(sender.BuildPacket().NoFlow().PutU32(1).Send(addrReceiver) == common::Error::Ok);
    PumpOnce(sender, receiver, delivered);
    CHECK(delivered.size() == 1);

    CHECK(sender.LoadCertificate(after.ToCertificate()) == common::Error::Ok);
    for (int round = 0; round < 400 && !HandshakeLanded(sender, addrReceiver); ++round)
        PumpOnce(sender, receiver, delivered);
    CHECK(HandshakeLanded(sender, addrReceiver));

    // The premise of the case: this rotation really did move the half of the
    // nonce space the sender writes in. Without that there is nothing here to
    // survive, and the case would be passing for the wrong reason.
    CHECK(whileKnocking != NonceLaneTo(sender, addrReceiver));

    // And the session on the far side of that move carries traffic, in order,
    // which is the property the move must not cost.
    const size_t alreadyIn = delivered.size();
    for (uint32_t value = 100; value < 120; ++value)
    {
        CHECK(sender.BuildPacket().NoFlow().PutU32(value).Send(addrReceiver) == common::Error::Ok);
        PumpOnce(sender, receiver, delivered);
    }
    for (int round = 0; round < 100 && delivered.size() < alreadyIn + 20; ++round)
        PumpOnce(sender, receiver, delivered);
    CHECK(delivered.size() == alreadyIn + 20);
    for (size_t i = 0; i < 20 && alreadyIn + i < delivered.size(); ++i)
        CHECK(delivered[alreadyIn + i] == 100 + i);

    // Not asserted here: that every packet sent DURING the handover arrives.
    // Unreliable traffic loses one across a knock handover about half the time
    // whether or not a rotation is involved, so a count over that window would
    // be measuring the handover's own lossiness rather than anything this case
    // is about.
}

int main()
{
    rotation_replaces_the_key_and_keeps_the_tag();
    a_history_past_the_bound_is_refused();
    a_retained_key_still_opens_the_first_flight();
    a_stale_sender_is_told_and_then_recovers();
    a_key_that_was_never_kept_declines_the_opener();
    forgetting_the_old_keys_cuts_off_their_senders();
    traffic_survives_a_handover_that_moves_the_nonce_space();
    return test::report();
}
