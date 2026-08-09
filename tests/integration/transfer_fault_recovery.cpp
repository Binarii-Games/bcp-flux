// Damaged links, one contract: the run arrives whole or it does not arrive.
//
// Loopback never loses anything, so an ordinary transfer exercises none of the
// repair machinery. Each case here puts the fault-injecting kernel under both
// ends and damages the data and the acknowledgements together, because the two
// fail differently. A lost data packet leaves a hole the receiver can name. A
// lost acknowledgement leaves the sender believing a hole exists where none
// does, and its bitmap is what would have said otherwise.
//
// The payload is positional, byte i derived from i, so the check is placement
// and not merely arrival. A transfer writes each packet straight to its own
// offset in the application's buffer, which means the failure modes worth
// catching are a packet written at the wrong offset, a duplicate applied twice
// and a hole never filled. All three survive a length check and none survives
// this one.
//
// The last case is deliberately larger than the window. A transfer tracks
// TRANSFER_WINDOW sequences and indexes its rings by seq & (window - 1), so a
// run of more than that many packets wraps them, and a sender that lets the
// sequence span outrun the window aliases a live entry onto an older one. That
// is not a hypothetical: it is the defect that made a shared link read a 27
// microsecond round trip on a 40 millisecond path. Nothing below a full window
// can see it.
#include "flux_net.h"

#include <flux/internal/constants.h>
#include <flux/socket/platform/faulty_socket.h>
#include <flux/socket/socket.h>
#include <flux/socket/socket_events.h>
#include <flux/transfer/transfer.h>

#include "harness.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <thread>
#include <vector>

namespace flux   = bcp::flux;
namespace common = bcp::common;

using flux::platform::FaultySocket;
using flux_net::Loopback;
using Clock = std::chrono::steady_clock;

namespace
{
    constexpr uint16_t TRANSFER_ID = 5;

    /** Sized against the window rather than picked. A packet carries
        TRANSFER_STRIDE_BYTES, so this many packets is one window exactly, and
        the wrap case below asks for more than that. */
    constexpr size_t WINDOW_BYTES =
        static_cast<size_t>(flux::internal::TRANSFER_WINDOW)
        * flux::internal::TRANSFER_STRIDE_BYTES;

    uint8_t ByteAt(size_t i)
    {
        return static_cast<uint8_t>((i * 131u) ^ (i >> 7) ^ (i >> 15));
    }

    struct Link
    {
        const char* name;
        uint64_t    seed;
        uint8_t     loss, duplicate, reorder, corrupt;
        uint16_t    burstLoss, reorderDepth;
        uint32_t    latencyMicros, jitterMicros;
        size_t      payload;
    };

    /** Six links spanning the range rather than six copies of one. The first is
        barely lossy, the fifth loses a fifth of everything in bursts of three
        while reordering and duplicating, and the sixth trades some of that
        damage for a payload past the window so the wrap is covered under loss
        rather than on a clean link. */
    const Link LINKS[] = {
        { "5% loss",              0xA1000001ull,  5, 0,  0, 0, 1, 1,   0,   0, 192 * 1024 },
        { "10% loss, dup 10%",    0xB2000002ull, 10, 10, 0, 0, 1, 1, 200, 100, 192 * 1024 },
        { "8% loss, reorder 20%", 0xC3000003ull,  8, 0, 20, 0, 1, 4, 150, 400, 192 * 1024 },
        { "12% bursts of 3",      0xD4000004ull, 12, 0,  0, 0, 3, 1, 300, 200, 192 * 1024 },
        { "20% bursts, dup, reorder",
                                  0xE5000005ull, 20, 8, 15, 5, 3, 3, 250, 500, 192 * 1024 },
        { "past the window, 10% bursts of 2",
                                  0xF6000006ull, 10, 0,  8, 0, 2, 2, 150, 200,
                                  WINDOW_BYTES + WINDOW_BYTES / 2 },
    };

    struct Receiver
    {
        flux::Socket*        socket = nullptr;
        std::vector<uint8_t> buffer;
        bool                 allowed = false;
    };

    void OnEvent(void* context, const flux::EventInfo& info)
    {
        if (!info.Has(flux::SocketEvent::TRANSFER_INCOMING)) return;
        Receiver& state = *static_cast<Receiver*>(context);
        flux::TransferRequest request =
            state.socket->PendingTransfer(info.Flow(), info.Peer());
        if (!request.Valid()) return;
        state.buffer.assign(static_cast<size_t>(request.Length()), 0);
        state.allowed = request.Allow(state.buffer.data()) == common::Error::Ok;
    }

    FaultySocket::Profile ProfileFor(const Link& link)
    {
        FaultySocket::Profile profile{};
        profile.seed             = link.seed;
        profile.applyTo          = FaultySocket::Direction::Send;
        profile.lossPercent      = link.loss;
        profile.duplicatePercent = link.duplicate;
        profile.reorderPercent   = link.reorder;
        profile.corruptPercent   = link.corrupt;
        profile.burstLoss        = link.burstLoss;
        profile.reorderDepth     = link.reorderDepth;
        profile.latencyMicros    = link.latencyMicros;
        profile.jitterMicros     = link.jitterMicros;
        return profile;
    }

    flux::Socket::Config Config(uint16_t port)
    {
        flux::Socket::Config config{};
        config.type     = flux::Socket::BackendType::FAULTY;
        config.port     = port;
        config.maxPeers = 4;
        config.flows.outCount         = 4;
        config.flows.inCount          = 4;
        config.flows.transferOutCount = 2;
        config.flows.transferInCount  = 2;
        config.flows.maxTransferBytes = 8ull << 20;
        return config;
    }

    void RunLink(const Link& link, uint16_t basePort)
    {
        const uint16_t senderPort   = basePort;
        const uint16_t receiverPort = static_cast<uint16_t>(basePort + 1);

        Receiver state;
        flux::Socket sender, receiver;

        flux::Socket::Config receiverConfig = Config(receiverPort);
        receiverConfig.events.hook       = OnEvent;
        receiverConfig.events.context    = &state;
        receiverConfig.events.subscribed = flux::ToBits(flux::SocketEvent::TRANSFER_INCOMING);
        state.socket = &receiver;

        CHECK(receiver.Init(receiverConfig) == common::Error::Ok);
        CHECK(sender.Init(Config(senderPort)) == common::Error::Ok);

        const flux::Address to   = Loopback(receiverPort);
        const flux::Address from = Loopback(senderPort);

        // Established on a clean link first. The handshake has its own recovery
        // and its own test, and letting it fail here would only ever report
        // that a transfer cannot start, which says nothing about repair.
        CHECK(sender.Connect(to) == common::Error::Ok);
        CHECK(flux_net::PumpUntilEstablished(sender, from, receiver, to));

        FaultySocket* senderKernel   = FaultySocket::ForPort(senderPort);
        FaultySocket* receiverKernel = FaultySocket::ForPort(receiverPort);
        CHECK(senderKernel != nullptr);
        CHECK(receiverKernel != nullptr);
        if (!senderKernel || !receiverKernel) return;

        // Both directions. The return path carries the acknowledgement bitmap,
        // which is the only thing that tells the sender a hole was filled, so a
        // one-sided profile would leave half the repair logic unexercised.
        senderKernel->SetProfile(ProfileFor(link));
        receiverKernel->SetProfile(ProfileFor(link));

        std::vector<uint8_t> payload(link.payload);
        for (size_t i = 0; i < payload.size(); ++i) payload[i] = ByteAt(i);

        CHECK(sender.SendTransfer(TRANSFER_ID, to, payload.data(), payload.size())
              == common::Error::Ok);

        bool          senderDone = false, receiverDone = false;
        common::Error outcome    = common::Error::Ok;
        const auto    deadline   = Clock::now() + std::chrono::seconds(60);

        flux::PacketSlotHandle inbox[32];
        while ((!senderDone || !receiverDone) && Clock::now() < deadline)
        {
            sender.Update();
            receiver.Update();
            { flux::PollCursor cursor = sender.Poll(inbox, 32);   while (cursor.Next()) {} }
            { flux::PollCursor cursor = receiver.Poll(inbox, 32); while (cursor.Next()) {} }

            flux::TransferView done[2];
            for (size_t i = 0, n = sender.PollTransfers(done, 2); i < n; ++i)
            { senderDone = true; outcome = done[i].Outcome(); }
            for (size_t i = 0, n = receiver.PollTransfers(done, 2); i < n; ++i)
                if (done[i].Bytes()) receiverDone = true;

            sender.Flush();
            receiver.Flush();
        }
        for (auto& handle : inbox) handle = flux::PacketSlotHandle::Invalid();

        const FaultySocket::Stats forward = senderKernel->GetStats();

        std::printf("  %-36s dropped %5llu of %5llu sent, dup %4llu, reordered %4llu\n",
                    link.name,
                    (unsigned long long)forward.dropped,
                    (unsigned long long)forward.sent,
                    (unsigned long long)forward.duplicated,
                    (unsigned long long)forward.reordered);

        CHECK(state.allowed);
        CHECK(senderDone);
        CHECK(receiverDone);
        CHECK(outcome == common::Error::Ok);
        CHECK(state.buffer.size() == payload.size());
        // Placement, not arrival. Compared whole rather than by length.
        CHECK(state.buffer == payload);

        // The link damaged something, or the case proves nothing.
        CHECK(forward.dropped > 0);

        sender.Shutdown();
        receiver.Shutdown();
    }
}

int main()
{
    uint16_t port = 9830;
    for (const Link& link : LINKS)
    {
        RunLink(link, port);
        port = static_cast<uint16_t>(port + 2);
    }
    return test::report();
}
