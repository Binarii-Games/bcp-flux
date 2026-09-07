// The C ABI, driven the way a binding drives it: through the table and nothing
// else. No flux C++ type appears below the include.
//
// Two things here cannot be caught any other way. A binding retypes every
// struct by hand, so LayoutCheck's answers have to agree with what the header
// actually describes, and a disagreement is silent corruption rather than a
// compile error. And the table is a list of function pointers filled in by
// hand, so one entry in the wrong position compiles perfectly and calls the
// wrong function forever. Only calling each one and checking what it did will
// find that.
//
// Not covered: that the header parses as C. The test glob is *.cpp, so this
// translation unit is C++ and proves nothing about C compilation.
#include <flux/c/flux_api_v1.h>

#include "harness.h"

#include <chrono>
#include <cstddef>
#include <cstring>
#include <thread>

namespace
{
    const FluxApiV1* Api()
    {
        return static_cast<const FluxApiV1*>(flux_get_api(1));
    }

    void FillTag(uint8_t* tag, uint8_t seed)
    {
        std::memset(tag, 0, FLUX_TAG_SIZE);
        tag[0] = seed;
    }

    // Drives both sockets one round and returns how many u32 payloads the right
    // one delivered, reading them the long way a binding has to.
    uint32_t PumpOnce(const FluxApiV1* api, FluxSocket* left, FluxSocket* right,
                      uint32_t* lastValue, uint32_t* knockedCount = nullptr)
    {
        api->Flush(left);
        api->Flush(right);
        api->Update(left);
        api->Update(right);

        uint32_t delivered = 0;
        FluxSocket* both[2] = { left, right };
        for (int side = 0; side < 2; ++side)
        {
            uint32_t lane = 0;
            FluxPacket packets[8];
            const uint32_t got = api->Poll(both[side], &lane, packets, 8);
            for (uint32_t i = 0; i < got; ++i)
            {
                if (side == 1 && knockedCount != nullptr
                    && api->PacketIsKnock(both[side], packets[i]) != 0)
                    ++(*knockedCount);
                FluxMessage messages[8];
                const uint32_t count =
                    api->Messages(both[side], packets[i], messages, 8, nullptr);
                for (uint32_t m = 0; m < count; ++m)
                {
                    if (side == 1 && messages[m].length >= 4)
                    {
                        uint32_t value = 0;
                        for (int b = 0; b < 4; ++b)
                            value |= static_cast<uint32_t>(messages[m].bytes[b]) << (8 * b);
                        if (lastValue != nullptr) *lastValue = value;
                        ++delivered;
                    }
                }
                (void)api->ReleasePacket(both[side], packets[i]);
            }
            api->EndPoll(both[side], lane);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
        return delivered;
    }
}

// What a binding checks before it trusts anything: that the library's idea of
// every struct matches the one the binding hand-wrote. A mismatch here is why
// LayoutCheck exists at all.
static void the_layout_a_binding_hand_writes_agrees_with_the_library()
{
    const FluxApiV1* api = Api();
    CHECK(api != nullptr);
    if (api == nullptr) return;
    CHECK(api->version == 1);

    FluxLayout layout;
    std::memset(&layout, 0, sizeof(layout));
    api->LayoutCheck(&layout);

    CHECK(layout.sizeofConfig         == sizeof(FluxConfig));
    CHECK(layout.sizeofFlowsConfig    == sizeof(FluxFlowsConfig));
    CHECK(layout.sizeofTimersConfig   == sizeof(FluxTimersConfig));
    CHECK(layout.sizeofLivenessConfig == sizeof(FluxLivenessConfig));
    CHECK(layout.sizeofEventsConfig   == sizeof(FluxEventsConfig));
    CHECK(layout.sizeofKnockConfig    == sizeof(FluxKnockConfig));
    CHECK(layout.sizeofTransferView   == sizeof(FluxTransferView));
    CHECK(layout.sizeofApiTable       == sizeof(FluxApiV1));

    CHECK(layout.offsetofConfigFlows    == offsetof(FluxConfig, flows));
    CHECK(layout.offsetofConfigLiveness == offsetof(FluxConfig, liveness));
    CHECK(layout.offsetofConfigEvents   == offsetof(FluxConfig, events));
    CHECK(layout.offsetofConfigTimers   == offsetof(FluxConfig, timers));
    CHECK(layout.offsetofConfigPort     == offsetof(FluxConfig, port));
    CHECK(layout.offsetofConfigKnock    == offsetof(FluxConfig, knock));
}

// Identity and certificate bytes cross as fixed-size buffers, so a binding can
// mint an identity, derive the certificate to hand out, and persist both
// without ever holding a flux object.
static void identities_and_certificates_cross_as_plain_bytes()
{
    const FluxApiV1* api = Api();
    if (api == nullptr) return;

    uint8_t tag[FLUX_TAG_SIZE];
    FillTag(tag, 0xF1);

    uint8_t identity[FLUX_IDENTITY_SIZE];
    uint8_t cert[FLUX_CERT_SIZE];
    CHECK(api->IdentityGenerate(tag, identity) == FLUX_OK);
    CHECK(api->IdentityCertificate(identity, cert) == FLUX_OK);

    // The certificate is version, key, tag, in that order, which is what a
    // binding relies on when it stores or ships one.
    CHECK(cert[0] == 1);
    CHECK(std::memcmp(cert + 1 + 32, tag, FLUX_TAG_SIZE) == 0);

    // Two generations for the same tag are different keypairs, which is what
    // makes RotateIdentity mean anything.
    uint8_t second[FLUX_IDENTITY_SIZE];
    CHECK(api->IdentityGenerate(tag, second) == FLUX_OK);
    CHECK(std::memcmp(second, identity, FLUX_IDENTITY_SIZE) != 0);

    // Null arguments are refused rather than dereferenced.
    CHECK(api->IdentityGenerate(nullptr, identity) == FLUX_ERR_INVALID_PARAM);
    CHECK(api->IdentityGenerate(tag, nullptr) == FLUX_ERR_INVALID_PARAM);
    CHECK(api->IdentityCertificate(nullptr, cert) == FLUX_ERR_INVALID_PARAM);
}

// Each of the identity and certificate entries does its own job. A table with
// two of these transposed would still compile and still run.
static void every_identity_entry_calls_what_it_says()
{
    const FluxApiV1* api = Api();
    if (api == nullptr) return;

    uint8_t serverTag[FLUX_TAG_SIZE];
    uint8_t otherTag[FLUX_TAG_SIZE];
    FillTag(serverTag, 0xF2);
    FillTag(otherTag, 0xF3);

    uint8_t serverIdentity[FLUX_IDENTITY_SIZE];
    uint8_t rotated[FLUX_IDENTITY_SIZE];
    uint8_t strayIdentity[FLUX_IDENTITY_SIZE];
    uint8_t serverCert[FLUX_CERT_SIZE];
    CHECK(api->IdentityGenerate(serverTag, serverIdentity) == FLUX_OK);
    CHECK(api->IdentityGenerate(serverTag, rotated) == FLUX_OK);
    CHECK(api->IdentityGenerate(otherTag, strayIdentity) == FLUX_OK);
    CHECK(api->IdentityCertificate(serverIdentity, serverCert) == FLUX_OK);

    FluxConfig config;
    api->DefaultConfig(&config);
    config.port = 9960;
    config.maxPeers = 8;
    config.pendingPacketCount = 16;
    config.trustedCertCount = 4;
    config.identity = serverIdentity;
    config.identityHistory = 2;

    FluxSocket* socket = api->CreateSocket();
    CHECK(socket != nullptr);
    CHECK(api->InitSocket(socket, &config) == FLUX_OK);

    // IdentityTag reports the configured tag, and 0 for an anonymous socket.
    uint8_t readBack[FLUX_TAG_SIZE];
    CHECK(api->IdentityTag(socket, readBack) == FLUX_TAG_SIZE);
    CHECK(std::memcmp(readBack, serverTag, FLUX_TAG_SIZE) == 0);

    // Rotation keeps the tag and refuses one that would change it.
    CHECK(api->RotateIdentity(socket, rotated) == FLUX_OK);
    CHECK(api->IdentityTag(socket, readBack) == FLUX_TAG_SIZE);
    CHECK(std::memcmp(readBack, serverTag, FLUX_TAG_SIZE) == 0);
    CHECK(api->RotateIdentity(socket, strayIdentity) == FLUX_ERR_INVALID_PARAM);
    api->ForgetPreviousIdentities(socket);

    // Loading and withdrawing a pinned certificate, and the answer for a tag
    // that was never pinned.
    CHECK(api->LoadCertificate(socket, serverCert) == FLUX_OK);
    CHECK(api->RemoveCertificate(socket, serverTag) == FLUX_OK);
    CHECK(api->RemoveCertificate(socket, otherTag) == FLUX_ERR_NOT_FOUND);

    api->DestroySocket(socket);

    // A history past what the transport holds is refused at Init.
    FluxConfig bad;
    api->DefaultConfig(&bad);
    bad.port = 9961;
    bad.maxPeers = 4;
    bad.pendingPacketCount = 8;
    bad.identityHistory = 99;
    FluxSocket* refused = api->CreateSocket();
    CHECK(api->InitSocket(refused, &bad) != FLUX_OK);
    api->DestroySocket(refused);
}

// The opener, the size a caller may put, and the marker on what arrived. These
// are the entries a binding cannot work without: without MaxPayload it can only
// guess at its limit, and guessing wrong is a hard refusal.
static void the_opener_reports_its_own_limits()
{
    const FluxApiV1* api = Api();
    if (api == nullptr) return;

    uint8_t serverTag[FLUX_TAG_SIZE];
    FillTag(serverTag, 0xF4);
    uint8_t serverIdentity[FLUX_IDENTITY_SIZE];
    uint8_t serverCert[FLUX_CERT_SIZE];
    CHECK(api->IdentityGenerate(serverTag, serverIdentity) == FLUX_OK);
    CHECK(api->IdentityCertificate(serverIdentity, serverCert) == FLUX_OK);

    FluxConfig serverConfig;
    api->DefaultConfig(&serverConfig);
    serverConfig.port = 9963;
    serverConfig.maxPeers = 8;
    serverConfig.pendingPacketCount = 16;
    serverConfig.identity = serverIdentity;
    FluxSocket* server = api->CreateSocket();
    CHECK(api->InitSocket(server, &serverConfig) == FLUX_OK);

    FluxConfig clientConfig;
    api->DefaultConfig(&clientConfig);
    clientConfig.port = 9962;
    clientConfig.maxPeers = 8;
    clientConfig.pendingPacketCount = 16;
    clientConfig.trustedCertCount = 4;
    clientConfig.knock.enable = 1;
    FluxSocket* client = api->CreateSocket();
    CHECK(api->InitSocket(client, &clientConfig) == FLUX_OK);
    CHECK(api->LoadCertificate(client, serverCert) == FLUX_OK);

    // PeerExpecting names the identity, which is what arms the opener.
    const FluxPeer peer = api->PeerExpecting(client, "::1", 9963, serverTag);
    CHECK(peer != FLUX_NONE);

    // Smaller while the first packet still has to open a session, and never
    // below the figure that always fits.
    const uint32_t opening = api->MaxPayload(client, peer);
    CHECK(opening > 0);
    CHECK(opening >= FLUX_SAFE_PAYLOAD_BYTES);

    // A peer that does not exist reports nothing rather than guessing.
    CHECK(api->MaxPayload(client, FLUX_NONE) == 0);

    // Send the always-safe size and the far side takes it.
    FluxPacket packet = api->BuildPacket(client);
    CHECK(packet != FLUX_NONE);
    CHECK(api->NoFlow(client, packet) == FLUX_OK);
    CHECK(api->PutU32(client, packet, 4242u) == FLUX_OK);
    CHECK(api->Send(client, packet, peer) == FLUX_OK);

    uint32_t value = 0;
    uint32_t delivered = 0;
    uint32_t knocked = 0;
    for (int round = 0; round < 20 && delivered == 0; ++round)
        delivered += PumpOnce(api, client, server, &value, &knocked);
    CHECK(delivered >= 1);
    CHECK(value == 4242u);

    // It rode the opener, before the address was proven, which is the one
    // thing a caller has to know to keep what must not repeat off that path.
    CHECK(knocked >= 1);

    // Full once the session has replaced the opener.
    for (int round = 0; round < 300 && api->PeerReady(client, peer) == 0; ++round)
        (void)PumpOnce(api, client, server, nullptr);
    CHECK(api->PeerReady(client, peer) != 0);
    CHECK(api->MaxPayload(client, peer) > opening);

    api->DestroySocket(client);
    api->DestroySocket(server);
}

// Resumption through the C table alone: collect a note, let the process go,
// and hand it back. The whole point is that the second life needs no handshake,
// so RotateKeys is used to show the session is genuinely live.
static void a_note_collected_through_the_table_resumes_a_session()
{
    const FluxApiV1* api = Api();
    if (api == nullptr) return;

    uint8_t serverTag[FLUX_TAG_SIZE];
    uint8_t clientTag[FLUX_TAG_SIZE];
    FillTag(serverTag, 0xF5);
    FillTag(clientTag, 0xF6);

    uint8_t serverIdentity[FLUX_IDENTITY_SIZE];
    uint8_t clientIdentity[FLUX_IDENTITY_SIZE];
    uint8_t serverCert[FLUX_CERT_SIZE];
    CHECK(api->IdentityGenerate(serverTag, serverIdentity) == FLUX_OK);
    CHECK(api->IdentityGenerate(clientTag, clientIdentity) == FLUX_OK);
    CHECK(api->IdentityCertificate(serverIdentity, serverCert) == FLUX_OK);

    FluxConfig serverConfig;
    api->DefaultConfig(&serverConfig);
    serverConfig.port = 9965;
    serverConfig.maxPeers = 8;
    serverConfig.pendingPacketCount = 16;
    serverConfig.identity = serverIdentity;
    serverConfig.trustedCertCount = 4;
    serverConfig.knock.enable = 1;
    FluxSocket* server = api->CreateSocket();
    CHECK(api->InitSocket(server, &serverConfig) == FLUX_OK);

    uint8_t note[FLUX_RESUME_NOTE_BYTES];
    uint32_t noteLen = 0;
    {
        FluxConfig clientConfig;
        api->DefaultConfig(&clientConfig);
        clientConfig.port = 9964;
        clientConfig.maxPeers = 8;
        clientConfig.pendingPacketCount = 16;
        clientConfig.identity = clientIdentity;
        clientConfig.trustedCertCount = 4;
        clientConfig.knock.enable = 1;
        clientConfig.keepResumeNotes = 1;
        FluxSocket* client = api->CreateSocket();
        CHECK(api->InitSocket(client, &clientConfig) == FLUX_OK);
        CHECK(api->LoadCertificate(client, serverCert) == FLUX_OK);

        const FluxPeer peer = api->PeerExpecting(client, "::1", 9965, serverTag);
        CHECK(peer != FLUX_NONE);

        for (int round = 0; round < 400 && noteLen == 0; ++round)
        {
            // A note only goes to a peer that has proven it holds its key.
            if (round % 20 == 0)
            {
                FluxPacket packet = api->BuildPacket(client);
                if (packet != FLUX_NONE)
                {
                    (void)api->NoFlow(client, packet);
                    (void)api->PutU32(client, packet, 1u);
                    (void)api->Send(client, packet, peer);
                }
            }
            (void)PumpOnce(api, client, server, nullptr);
            noteLen = api->PeerResumeNote(client, peer, note, sizeof(note));
        }
        CHECK(noteLen == FLUX_RESUME_NOTE_BYTES);
        api->DestroySocket(client);
    }

    // Second life, same address, presenting the note.
    FluxConfig secondConfig;
    api->DefaultConfig(&secondConfig);
    secondConfig.port = 9964;
    secondConfig.maxPeers = 8;
    secondConfig.pendingPacketCount = 16;
    secondConfig.identity = clientIdentity;
    secondConfig.trustedCertCount = 4;
    secondConfig.knock.enable = 1;
    FluxSocket* second = api->CreateSocket();
    CHECK(api->InitSocket(second, &secondConfig) == FLUX_OK);
    CHECK(api->LoadCertificate(second, serverCert) == FLUX_OK);

    const FluxPeer resumed = api->PeerResuming(second, "::1", 9965, serverTag, note);
    CHECK(resumed != FLUX_NONE);

    FluxPacket packet = api->BuildPacket(second);
    CHECK(packet != FLUX_NONE);
    CHECK(api->NoFlow(second, packet) == FLUX_OK);
    CHECK(api->PutU32(second, packet, 7777u) == FLUX_OK);
    CHECK(api->Send(second, packet, resumed) == FLUX_OK);

    uint32_t value = 0;
    uint32_t delivered = 0;
    for (int round = 0; round < 20 && delivered == 0; ++round)
        delivered += PumpOnce(api, second, server, &value);

    // Through, on a session that never handshook. Before resumption existed
    // this would have waited for the server to evict its stale entry.
    CHECK(delivered >= 1);
    CHECK(value == 7777u);

    // A note refused for its contents costs nothing, and a null one is refused
    // outright rather than sent.
    CHECK(api->PeerResuming(second, "::1", 9965, serverTag, nullptr) == FLUX_NONE);

    api->DestroySocket(second);
    api->DestroySocket(server);
}

// RotateKeys advances one peer's session key, and reports the two refusals its
// contract names rather than doing it anyway.
static void rotating_a_session_key_reports_its_refusals()
{
    const FluxApiV1* api = Api();
    if (api == nullptr) return;

    uint8_t serverTag[FLUX_TAG_SIZE];
    FillTag(serverTag, 0xF7);
    uint8_t serverIdentity[FLUX_IDENTITY_SIZE];
    uint8_t serverCert[FLUX_CERT_SIZE];
    CHECK(api->IdentityGenerate(serverTag, serverIdentity) == FLUX_OK);
    CHECK(api->IdentityCertificate(serverIdentity, serverCert) == FLUX_OK);

    FluxConfig serverConfig;
    api->DefaultConfig(&serverConfig);
    serverConfig.port = 9967;
    serverConfig.maxPeers = 8;
    serverConfig.pendingPacketCount = 16;
    serverConfig.identity = serverIdentity;
    FluxSocket* server = api->CreateSocket();
    CHECK(api->InitSocket(server, &serverConfig) == FLUX_OK);

    FluxConfig clientConfig;
    api->DefaultConfig(&clientConfig);
    clientConfig.port = 9966;
    clientConfig.maxPeers = 8;
    clientConfig.pendingPacketCount = 16;
    clientConfig.trustedCertCount = 4;
    FluxSocket* client = api->CreateSocket();
    CHECK(api->InitSocket(client, &clientConfig) == FLUX_OK);
    CHECK(api->LoadCertificate(client, serverCert) == FLUX_OK);

    // A peer nobody has heard of has no chain to advance.
    CHECK(api->RotateKeys(client, FLUX_NONE) == FLUX_ERR_NOT_FOUND);

    const FluxPeer peer = api->Peer(client, "::1", 9967);
    CHECK(peer != FLUX_NONE);
    for (int round = 0; round < 300 && api->PeerReady(client, peer) == 0; ++round)
        (void)PumpOnce(api, client, server, nullptr);
    CHECK(api->PeerReady(client, peer) != 0);

    // Traffic has to cross before the chain can move, and once it can, a second
    // rotation before the first is confirmed is refused.
    bool rotated = false;
    for (int round = 0; round < 80 && !rotated; ++round)
    {
        FluxPacket packet = api->BuildPacket(client);
        if (packet != FLUX_NONE)
        {
            (void)api->NoFlow(client, packet);
            (void)api->PutU32(client, packet, 5u);
            (void)api->Send(client, packet, peer);
        }
        (void)PumpOnce(api, client, server, nullptr);
        rotated = api->RotateKeys(client, peer) == FLUX_OK;
    }
    CHECK(rotated);
    CHECK(api->RotateKeys(client, peer) == FLUX_ERR_ALREADY_PENDING);

    api->DestroySocket(client);
    api->DestroySocket(server);
}

// The probe, driven the way a binding drives it: an address as bytes goes in,
// a measurement comes back out, and no flux object is held at any point. What
// makes this worth a case of its own is that a binding cannot see the peer
// table, so the promise that nothing was registered has to be observable from
// out here - PeerAt is the only way to ask, and it would have to CREATE the
// peer to answer, so the question is put to the answering socket instead:
// nothing it was never told about may have appeared.
static void a_probe_crosses_as_bytes_and_registers_nothing()
{
    const FluxApiV1* api = Api();
    if (api == nullptr) return;

    FluxConfig proberConfig;
    api->DefaultConfig(&proberConfig);
    proberConfig.port = 9971;
    proberConfig.maxPeers = 8;
    proberConfig.pendingPacketCount = 16;
    FluxSocket* prober = api->CreateSocket();
    CHECK(api->InitSocket(prober, &proberConfig) == FLUX_OK);

    FluxConfig answerConfig;
    api->DefaultConfig(&answerConfig);
    answerConfig.port = 9972;
    answerConfig.maxPeers = 8;
    answerConfig.pendingPacketCount = 16;
    FluxSocket* answerer = api->CreateSocket();
    CHECK(api->InitSocket(answerer, &answerConfig) == FLUX_OK);

    // The address crosses as the canonical bytes, resolved through the table
    // like any other address a binding holds.
    uint8_t addr[FLUX_ADDRESS_SIZE];
    CHECK(api->AddressResolve("::1", 9972, addr) == FLUX_OK);

    CHECK(api->ProbeAddress(prober, addr) == FLUX_OK);

    // Nothing to collect before the answer has had a chance to arrive.
    FluxProbeResult results[4];
    std::memset(results, 0, sizeof(results));

    uint32_t got = 0;
    for (int round = 0; round < 200 && got == 0; ++round)
    {
        api->Update(prober);
        api->Update(answerer);
        got = api->PollProbes(prober, results, 4);
        if (got == 0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    CHECK(got == 1);
    if (got == 1)
    {
        // The address comes back as the bytes that went in, so a binding can
        // match a result to the candidate it asked about.
        CHECK(std::memcmp(results[0].address, addr, FLUX_ADDRESS_SIZE) == 0);

        // A measurement, not the figure a timeout carries.
        CHECK(results[0].rttMicros != 0);
    }

    // Collected once and only once: the slot went back rather than reporting
    // itself forever.
    CHECK(api->PollProbes(prober, results, 4) == 0);

    // The asking socket can go on asking: the slot came back, so a caller
    // weighing a list of candidates is not spending one per question forever.
    CHECK(api->ProbeAddress(prober, addr) == FLUX_OK);

    // That neither side REGISTERED anything is not observable from out here -
    // the only way to ask the table about an address is PeerAt, which would
    // create the entry to answer. tests/integration/probe.cpp proves it from
    // inside, where GetPeer can ask without creating.

    api->DestroySocket(prober);
    api->DestroySocket(answerer);
}

// The refusals a binding has to be able to see, and the one field that answers
// before anything has been measured.
static void path_stats_report_what_has_been_measured_and_refuse_the_rest()
{
    const FluxApiV1* api = Api();
    if (api == nullptr) return;

    FluxConfig config;
    api->DefaultConfig(&config);
    config.port = 9973;
    config.maxPeers = 8;
    config.pendingPacketCount = 16;
    FluxSocket* socket = api->CreateSocket();
    CHECK(api->InitSocket(socket, &config) == FLUX_OK);

    FluxPathStats stats;
    std::memset(&stats, 0xAB, sizeof(stats));

    // A peer that does not exist reports nothing rather than guessing, and
    // zeroes the caller's struct on the way out so a binding that ignores the
    // return value still reads zeros rather than the garbage it passed in.
    CHECK(api->PeerPathStats(socket, FLUX_NONE, &stats) != FLUX_OK);
    CHECK(stats.srttMicros == 0);
    CHECK(stats.minRttMicros == 0);

    // A null out-parameter is refused rather than crossing into a write.
    CHECK(api->PeerPathStats(socket, FLUX_NONE, nullptr) == FLUX_ERR_INVALID_PARAM);

    // A real peer with nothing measured answers zeros, which is what lets a
    // binding tell "no sample yet" from a fast path without a second call.
    uint8_t addr[FLUX_ADDRESS_SIZE];
    CHECK(api->AddressResolve("::1", 9974, addr) == FLUX_OK);
    const FluxPeer peer = api->PeerAt(socket, addr);
    CHECK(peer != FLUX_NONE);

    std::memset(&stats, 0xAB, sizeof(stats));
    CHECK(api->PeerPathStats(socket, peer, &stats) == FLUX_OK);
    CHECK(stats.srttMicros   == 0);
    CHECK(stats.minRttMicros == 0);
    CHECK(stats.queueMicros  == 0);

    api->DestroySocket(socket);
}

// A probe seeds the average of a peer that already exists, and the C API is
// where a binding can watch it happen: zeros before, a figure after, and the
// remembered minimum still empty because no acknowledged packet was timed.
static void a_probe_seeds_the_stats_a_binding_reads()
{
    const FluxApiV1* api = Api();
    if (api == nullptr) return;

    FluxConfig aConfig;
    api->DefaultConfig(&aConfig);
    aConfig.port = 9975;
    aConfig.maxPeers = 8;
    aConfig.pendingPacketCount = 16;
    FluxSocket* a = api->CreateSocket();
    CHECK(api->InitSocket(a, &aConfig) == FLUX_OK);

    FluxConfig bConfig;
    api->DefaultConfig(&bConfig);
    bConfig.port = 9976;
    bConfig.maxPeers = 8;
    bConfig.pendingPacketCount = 16;
    FluxSocket* b = api->CreateSocket();
    CHECK(api->InitSocket(b, &bConfig) == FLUX_OK);

    uint8_t addrB[FLUX_ADDRESS_SIZE];
    CHECK(api->AddressResolve("::1", 9976, addrB) == FLUX_OK);

    // PeerAt registers the peer without measuring anything.
    const FluxPeer peer = api->PeerAt(a, addrB);
    CHECK(peer != FLUX_NONE);

    FluxPathStats before;
    CHECK(api->PeerPathStats(a, peer, &before) == FLUX_OK);
    CHECK(before.srttMicros == 0);

    CHECK(api->ProbeAddress(a, addrB) == FLUX_OK);

    FluxProbeResult results[2];
    uint32_t got = 0;
    for (int round = 0; round < 200 && got == 0; ++round)
    {
        api->Update(a);
        api->Update(b);
        got = api->PollProbes(a, results, 2);
        if (got == 0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(got == 1);

    FluxPathStats after;
    CHECK(api->PeerPathStats(a, peer, &after) == FLUX_OK);

    // Seeded, so a binding choosing between peers has a figure to compare.
    CHECK(after.srttMicros != 0);

    // But the minimum a queue is measured against stays empty, because a probe
    // is a lighter packet than data and must never set that floor.
    CHECK(after.minRttMicros == 0);
    CHECK(after.queueMicros  == 0);

    api->DestroySocket(a);
    api->DestroySocket(b);
}

// A receiver never opened the flow its traffic arrives on, so the only way it
// can honour the sender's guarantees - a relay forwarding on, say - is if the
// packet says what they are. The mode rides every flow packet for exactly
// that, and this is the entry that hands it up.
static void an_arriving_packet_names_the_mode_of_the_flow_it_rode()
{
    const FluxApiV1* api = Api();
    if (api == nullptr) return;

    // Association pools are opt-in, so a socket that never sends flows pays
    // nothing for them. Both sides need them here: one to open, one to admit.
    FluxConfig config;
    api->DefaultConfig(&config);
    config.port = 9971;
    config.maxPeers = 8;
    config.pendingPacketCount = 16;
    config.flows.outCount      = 8;
    config.flows.inCount       = 8;
    config.flows.maxOutPerPeer = 4;
    config.flows.maxInPerPeer  = 4;
    FluxSocket* sender = api->CreateSocket();
    CHECK(api->InitSocket(sender, &config) == FLUX_OK);

    config.port = 9972;
    FluxSocket* receiver = api->CreateSocket();
    CHECK(api->InitSocket(receiver, &config) == FLUX_OK);

    const FluxPeer peer = api->Peer(sender, "::1", 9972);
    CHECK(peer != FLUX_NONE);

    // Two modes, so what arrives is read off the packet rather than assumed.
    const FluxFlow ordered =
        api->OpenFlow(sender, 11, FLUX_FLOW_RELIABLE_ORDERED);
    const FluxFlow unreliable =
        api->OpenFlow(sender, 12, FLUX_FLOW_UNRELIABLE);
    CHECK(ordered != FLUX_NONE);
    CHECK(unreliable != FLUX_NONE);

    const FluxFlow flows[2] = { ordered, unreliable };
    const uint16_t ids[2]   = { 11, 12 };
    const uint8_t  modes[2] = { FLUX_FLOW_RELIABLE_ORDERED, FLUX_FLOW_UNRELIABLE };

    for (int which = 0; which < 2; ++which)
    {
        FluxPacket packet = api->BuildPacket(sender);
        CHECK(packet != FLUX_NONE);
        CHECK(api->WithFlow(sender, packet, flows[which], FLUX_PART_WHOLE) == FLUX_OK);
        CHECK(api->PutU32(sender, packet, 900u + which) == FLUX_OK);
        CHECK(api->Send(sender, packet, peer) == FLUX_OK);

        bool seen = false;
        for (int round = 0; round < 300 && !seen; ++round)
        {
            api->Flush(sender);
            api->Update(sender);
            api->Update(receiver);

            uint32_t lane = 0;
            FluxPacket packets[8];
            const uint32_t got = api->Poll(receiver, &lane, packets, 8);
            for (uint32_t i = 0; i < got; ++i)
            {
                FluxMessage messages[8];
                FluxPacketInfo info;
                std::memset(&info, 0xEE, sizeof(info));
                const uint32_t count =
                    api->Messages(receiver, packets[i], messages, 8, &info);
                if (count > 0 && info.flowId == ids[which])
                {
                    CHECK(info.mode == modes[which]);
                    CHECK(info.part == FLUX_PART_WHOLE);
                    CHECK(info.reserved == 0);
                    seen = true;
                }
                (void)api->ReleasePacket(receiver, packets[i]);
            }
            api->EndPoll(receiver, lane);
            if (!seen) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        CHECK(seen);
    }

    // Outside a flow there is no mode to name, and the sentinel id is what
    // says so - zero would otherwise read as RELIABLE_ORDERED.
    FluxPacket plain = api->BuildPacket(sender);
    CHECK(plain != FLUX_NONE);
    CHECK(api->NoFlow(sender, plain) == FLUX_OK);
    CHECK(api->PutU32(sender, plain, 999u) == FLUX_OK);
    CHECK(api->Send(sender, plain, peer) == FLUX_OK);

    bool sawPlain = false;
    for (int round = 0; round < 300 && !sawPlain; ++round)
    {
        api->Flush(sender);
        api->Update(sender);
        api->Update(receiver);

        uint32_t lane = 0;
        FluxPacket packets[8];
        const uint32_t got = api->Poll(receiver, &lane, packets, 8);
        for (uint32_t i = 0; i < got; ++i)
        {
            FluxMessage messages[8];
            FluxPacketInfo info;
            std::memset(&info, 0xEE, sizeof(info));
            const uint32_t count =
                api->Messages(receiver, packets[i], messages, 8, &info);
            if (count > 0 && info.flowId == 0xFFFF)
            {
                CHECK(info.mode == 0);
                sawPlain = true;
            }
            (void)api->ReleasePacket(receiver, packets[i]);
        }
        api->EndPoll(receiver, lane);
        if (!sawPlain) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(sawPlain);

    CHECK(api->CloseFlow(sender, ordered) == FLUX_OK);
    CHECK(api->CloseFlow(sender, unreliable) == FLUX_OK);
    api->DestroySocket(sender);
    api->DestroySocket(receiver);
}

int main()
{
    the_layout_a_binding_hand_writes_agrees_with_the_library();
    an_arriving_packet_names_the_mode_of_the_flow_it_rode();
    a_probe_crosses_as_bytes_and_registers_nothing();
    path_stats_report_what_has_been_measured_and_refuse_the_rest();
    a_probe_seeds_the_stats_a_binding_reads();
    identities_and_certificates_cross_as_plain_bytes();
    every_identity_entry_calls_what_it_says();
    the_opener_reports_its_own_limits();
    a_note_collected_through_the_table_resumes_a_session();
    rotating_a_session_key_reports_its_refusals();
    return test::report();
}
